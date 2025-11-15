"""Secrets and credentials scanner for Docker images."""

import docker
import re
import tempfile
import tarfile
import os
from typing import List, Dict, Any, Set
from pathlib import Path
from .base_scanner import BaseScanner, ScanResult


class SecretsScanner(BaseScanner):
    """Scanner for exposed secrets and credentials in Docker images."""

    def __init__(self):
        super().__init__("SecretsScanner")
        self.client = docker.from_env()

        # Regex patterns for detecting secrets
        self.patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'aws[_\-\s]*secret[_\-\s]*access[_\-\s]*key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})',
            'GitHub Token': r'gh[ps]_[a-zA-Z0-9]{36,255}',
            'Generic API Key': r'api[_\-\s]*key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})',
            'Private Key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'Password in URL': r'[a-zA-Z]{3,10}://[^:]+:([^@\s]+)@',
            'Slack Token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'Heroku API Key': r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            'Generic Secret': r'secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{8,})',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*',
            'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'Database Connection String': r'(?:mysql|postgres|mongodb|redis)://[^\s]+',
            'NPM Token': r'npm_[a-zA-Z0-9]{36}',
            'PyPI Token': r'pypi-[a-zA-Z0-9_]{43,}',
            'Stripe Key': r'(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}',
            'Twilio API Key': r'SK[a-z0-9]{32}',
            'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
            'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
        }

        # Sensitive file patterns
        self.sensitive_files = {
            r'\.env$': 'Environment file',
            r'\.env\.[a-z]+$': 'Environment file',
            r'config\.json$': 'Configuration file',
            r'secrets\.ya?ml$': 'Secrets file',
            r'credentials\.json$': 'Credentials file',
            r'\.aws/credentials$': 'AWS credentials',
            r'\.ssh/id_rsa$': 'SSH private key',
            r'\.ssh/id_dsa$': 'SSH private key',
            r'\.ssh/id_ed25519$': 'SSH private key',
            r'\.pgpass$': 'PostgreSQL password file',
            r'\.netrc$': 'Network credentials file',
            r'\.dockercfg$': 'Docker credentials',
            r'\.npmrc$': 'NPM credentials',
            r'\.pypirc$': 'PyPI credentials',
            r'\.git-credentials$': 'Git credentials',
        }

        # Files to exclude from scanning
        self.exclude_patterns = {
            r'\.git/',
            r'node_modules/',
            r'\.pyc$',
            r'\.so$',
            r'\.dll$',
            r'\.exe$',
            r'\.bin$',
            r'\.jar$',
            r'\.war$',
            r'\.zip$',
            r'\.tar',
            r'\.gz$',
            r'\.jpg$',
            r'\.png$',
            r'\.gif$',
            r'\.pdf$',
        }

    def scan(self, image_name: str) -> List[ScanResult]:
        """
        Scan Docker image for exposed secrets.

        Args:
            image_name: Docker image name or ID

        Returns:
            List of ScanResult objects
        """
        self.clear_results()

        try:
            image = self.client.images.get(image_name)

            # Scan image environment variables
            self._scan_environment(image)

            # Export and scan filesystem
            self._scan_filesystem(image)

            # Scan image history
            self._scan_history(image)

        except docker.errors.ImageNotFound:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='CRITICAL',
                title='Image Not Found',
                description=f'Image {image_name} not found',
                remediation='Ensure the image exists and is pulled locally'
            ))
        except Exception as e:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='HIGH',
                title='Secrets Scan Error',
                description=f'Error scanning for secrets: {str(e)}',
                remediation='Check image accessibility'
            ))

        return self.get_results()

    def _scan_environment(self, image):
        """Scan environment variables for secrets."""
        config = image.attrs.get('Config', {})
        env_vars = config.get('Env', [])

        for env in env_vars:
            if '=' in env:
                key, value = env.split('=', 1)

                # Check value against patterns
                for pattern_name, pattern in self.patterns.items():
                    matches = re.finditer(pattern, value, re.IGNORECASE)
                    for match in matches:
                        self.add_result(ScanResult(
                            scanner_name=self.name,
                            severity='CRITICAL',
                            title=f'Secret in Environment Variable: {pattern_name}',
                            description=f'Detected {pattern_name} in environment variable {key}',
                            remediation='Remove secrets from environment variables. Use Docker secrets or external secret management.',
                            metadata={
                                'variable': key,
                                'pattern': pattern_name,
                                'location': 'environment'
                            }
                        ))

    def _scan_filesystem(self, image):
        """Scan image filesystem for secrets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                # Create temporary container to export filesystem
                container = self.client.containers.create(image.id)

                # Export container filesystem
                tar_stream = container.export()
                tar_path = os.path.join(tmpdir, 'image.tar')

                with open(tar_path, 'wb') as f:
                    for chunk in tar_stream:
                        f.write(chunk)

                # Extract tar
                extract_dir = os.path.join(tmpdir, 'extracted')
                os.makedirs(extract_dir, exist_ok=True)

                with tarfile.open(tar_path) as tar:
                    tar.extractall(extract_dir)

                # Scan extracted files
                self._scan_directory(extract_dir)

                # Clean up container
                container.remove()

            except Exception as e:
                pass  # Silently handle extraction errors

    def _scan_directory(self, directory: str):
        """Recursively scan directory for secrets."""
        for root, dirs, files in os.walk(directory):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if not any(
                re.search(pattern, os.path.join(root, d))
                for pattern in self.exclude_patterns
            )]

            for filename in files:
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, directory)

                # Check if file should be excluded
                if any(re.search(pattern, filepath) for pattern in self.exclude_patterns):
                    continue

                # Check for sensitive filenames
                self._check_sensitive_filename(relative_path)

                # Scan file contents
                self._scan_file_contents(filepath, relative_path)

    def _check_sensitive_filename(self, filepath: str):
        """Check if filename indicates sensitive data."""
        for pattern, description in self.sensitive_files.items():
            if re.search(pattern, filepath, re.IGNORECASE):
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='HIGH',
                    title=f'Sensitive File: {description}',
                    description=f'Found sensitive file in image: {filepath}',
                    remediation='Remove sensitive files from image or add to .dockerignore',
                    metadata={
                        'file': filepath,
                        'type': description,
                        'location': 'filesystem'
                    }
                ))

    def _scan_file_contents(self, filepath: str, relative_path: str):
        """Scan file contents for secrets."""
        try:
            # Only scan text files (simple heuristic)
            if os.path.getsize(filepath) > 10 * 1024 * 1024:  # Skip files > 10MB
                return

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 1024)  # Read max 1MB

            # Scan content for patterns
            for pattern_name, pattern in self.patterns.items():
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Get line number
                    line_num = content[:match.start()].count('\n') + 1

                    # Get context (the line containing the match)
                    lines = content.split('\n')
                    context = lines[line_num - 1][:100] if line_num <= len(lines) else ''

                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='CRITICAL',
                        title=f'Secret in File: {pattern_name}',
                        description=f'Detected {pattern_name} in {relative_path}:{line_num}',
                        remediation='Remove hardcoded secrets from files. Use environment variables or secret management.',
                        metadata={
                            'file': relative_path,
                            'line': line_num,
                            'pattern': pattern_name,
                            'context': context,
                            'location': 'filesystem'
                        }
                    ))

        except Exception:
            pass  # Skip files that can't be read

    def _scan_history(self, image):
        """Scan image history for secrets in build commands."""
        history = image.history()

        for idx, layer in enumerate(history):
            created_by = layer.get('CreatedBy', '')

            # Check for secrets in build commands
            for pattern_name, pattern in self.patterns.items():
                matches = re.finditer(pattern, created_by, re.IGNORECASE)
                for match in matches:
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='HIGH',
                        title=f'Secret in Build Command: {pattern_name}',
                        description=f'Detected {pattern_name} in image layer build command',
                        remediation='Use multi-stage builds and ARG for secrets that should not persist',
                        metadata={
                            'layer': idx,
                            'pattern': pattern_name,
                            'command': created_by[:200],
                            'location': 'history'
                        }
                    ))

            # Check for common mistakes
            if '--build-arg' in created_by and any(
                keyword in created_by.upper()
                for keyword in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']
            ):
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='MEDIUM',
                    title='Potential Secret in Build Argument',
                    description='Build argument name suggests it may contain sensitive data',
                    remediation='Ensure build-time secrets are not persisted in layers',
                    metadata={
                        'layer': idx,
                        'command': created_by[:200],
                        'location': 'history'
                    }
                ))

"""Package vulnerability scanner using CVE databases."""

import docker
import requests
import json
import re
import tempfile
import tarfile
import os
from typing import List, Dict, Any, Optional
from packaging import version
from .base_scanner import BaseScanner, ScanResult


class PackageVulnerabilityScanner(BaseScanner):
    """Scanner for package vulnerabilities using CVE databases."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("PackageVulnerabilityScanner")
        self.client = docker.from_env()
        self.api_key = api_key
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cve_cache = {}

    def scan(self, image_name: str) -> List[ScanResult]:
        """
        Scan packages in image for known vulnerabilities.

        Args:
            image_name: Docker image name or ID

        Returns:
            List of ScanResult objects
        """
        self.clear_results()

        try:
            image = self.client.images.get(image_name)

            # Detect OS and package manager
            os_info = self._detect_os(image)

            # Extract and scan packages
            if os_info['os_type'] == 'debian':
                packages = self._get_debian_packages(image)
                self._scan_debian_packages(packages, os_info)
            elif os_info['os_type'] == 'alpine':
                packages = self._get_alpine_packages(image)
                self._scan_alpine_packages(packages, os_info)
            elif os_info['os_type'] == 'redhat':
                packages = self._get_rpm_packages(image)
                self._scan_rpm_packages(packages, os_info)

            # Scan Python packages if present
            python_packages = self._get_python_packages(image)
            if python_packages:
                self._scan_python_packages(python_packages)

            # Scan Node.js packages if present
            node_packages = self._get_node_packages(image)
            if node_packages:
                self._scan_node_packages(node_packages)

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
                title='Package Scan Error',
                description=f'Error scanning packages: {str(e)}',
                remediation='Check image accessibility and package manager compatibility'
            ))

        return self.get_results()

    def _detect_os(self, image) -> Dict[str, str]:
        """Detect operating system in the image."""
        os_info = {'os_type': 'unknown', 'os_version': 'unknown'}

        try:
            # Try to read /etc/os-release
            container = self.client.containers.create(image.id, command='cat /etc/os-release', detach=True)
            container.start()
            container.wait(timeout=10)
            output = container.logs().decode('utf-8')
            container.remove()

            if 'alpine' in output.lower():
                os_info['os_type'] = 'alpine'
                version_match = re.search(r'VERSION_ID=(\S+)', output)
                if version_match:
                    os_info['os_version'] = version_match.group(1).strip('"')
            elif 'debian' in output.lower() or 'ubuntu' in output.lower():
                os_info['os_type'] = 'debian'
                version_match = re.search(r'VERSION_ID="?([^"]+)"?', output)
                if version_match:
                    os_info['os_version'] = version_match.group(1)
            elif 'centos' in output.lower() or 'rhel' in output.lower() or 'fedora' in output.lower():
                os_info['os_type'] = 'redhat'
                version_match = re.search(r'VERSION_ID="?([^"]+)"?', output)
                if version_match:
                    os_info['os_version'] = version_match.group(1)

        except Exception:
            # Fallback: check image tags
            for tag in image.tags:
                if 'alpine' in tag:
                    os_info['os_type'] = 'alpine'
                elif 'debian' in tag or 'ubuntu' in tag:
                    os_info['os_type'] = 'debian'
                elif 'centos' in tag or 'rhel' in tag:
                    os_info['os_type'] = 'redhat'

        return os_info

    def _get_debian_packages(self, image) -> List[Dict[str, str]]:
        """Get list of installed Debian/Ubuntu packages."""
        packages = []

        try:
            container = self.client.containers.create(
                image.id,
                command='dpkg-query -W -f="${Package}\t${Version}\n"',
                detach=True
            )
            container.start()
            container.wait(timeout=10)
            output = container.logs().decode('utf-8')
            container.remove()

            for line in output.split('\n'):
                if '\t' in line:
                    name, ver = line.split('\t', 1)
                    packages.append({'name': name.strip(), 'version': ver.strip()})

        except Exception:
            pass

        return packages

    def _get_alpine_packages(self, image) -> List[Dict[str, str]]:
        """Get list of installed Alpine packages."""
        packages = []

        try:
            container = self.client.containers.create(
                image.id,
                command='apk info -v',
                detach=True
            )
            container.start()
            container.wait(timeout=10)
            output = container.logs().decode('utf-8')
            container.remove()

            for line in output.split('\n'):
                line = line.strip()
                if line:
                    # Alpine format: package-version-release
                    match = re.match(r'(.+?)-(\d+\..+)', line)
                    if match:
                        packages.append({'name': match.group(1), 'version': match.group(2)})

        except Exception:
            pass

        return packages

    def _get_rpm_packages(self, image) -> List[Dict[str, str]]:
        """Get list of installed RPM packages."""
        packages = []

        try:
            container = self.client.containers.create(
                image.id,
                command='rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\n"',
                detach=True
            )
            container.start()
            container.wait(timeout=10)
            output = container.logs().decode('utf-8')
            container.remove()

            for line in output.split('\n'):
                if '\t' in line:
                    name, ver = line.split('\t', 1)
                    packages.append({'name': name.strip(), 'version': ver.strip()})

        except Exception:
            pass

        return packages

    def _get_python_packages(self, image) -> List[Dict[str, str]]:
        """Get list of installed Python packages."""
        packages = []

        try:
            container = self.client.containers.create(
                image.id,
                command='pip list --format=json',
                detach=True
            )
            container.start()
            container.wait(timeout=10)
            output = container.logs().decode('utf-8')
            container.remove()

            pip_packages = json.loads(output)
            for pkg in pip_packages:
                packages.append({'name': pkg['name'], 'version': pkg['version']})

        except Exception:
            pass

        return packages

    def _get_node_packages(self, image) -> List[Dict[str, str]]:
        """Get list of installed Node.js packages."""
        packages = []

        try:
            container = self.client.containers.create(
                image.id,
                command='npm list -g --json',
                detach=True
            )
            container.start()
            container.wait(timeout=10)
            output = container.logs().decode('utf-8')
            container.remove()

            npm_data = json.loads(output)
            if 'dependencies' in npm_data:
                for name, info in npm_data['dependencies'].items():
                    if 'version' in info:
                        packages.append({'name': name, 'version': info['version']})

        except Exception:
            pass

        return packages

    def _scan_debian_packages(self, packages: List[Dict], os_info: Dict):
        """Scan Debian/Ubuntu packages for vulnerabilities."""
        # Known vulnerable packages (example database)
        vulnerable_packages = self._get_debian_vulnerabilities()

        for pkg in packages:
            pkg_name = pkg['name']
            pkg_version = pkg['version']

            if pkg_name in vulnerable_packages:
                for vuln in vulnerable_packages[pkg_name]:
                    if self._is_version_affected(pkg_version, vuln['affected_versions']):
                        self.add_result(ScanResult(
                            scanner_name=self.name,
                            severity=vuln['severity'],
                            title=f"Vulnerable Package: {pkg_name}",
                            description=vuln['description'],
                            remediation=f"Update {pkg_name} to version {vuln['fixed_version']} or later",
                            cve_id=vuln.get('cve_id'),
                            cvss_score=vuln.get('cvss_score'),
                            affected_package=f"{pkg_name}@{pkg_version}"
                        ))

    def _scan_alpine_packages(self, packages: List[Dict], os_info: Dict):
        """Scan Alpine packages for vulnerabilities."""
        vulnerable_packages = self._get_alpine_vulnerabilities()

        for pkg in packages:
            pkg_name = pkg['name']
            pkg_version = pkg['version']

            if pkg_name in vulnerable_packages:
                for vuln in vulnerable_packages[pkg_name]:
                    if self._is_version_affected(pkg_version, vuln['affected_versions']):
                        self.add_result(ScanResult(
                            scanner_name=self.name,
                            severity=vuln['severity'],
                            title=f"Vulnerable Package: {pkg_name}",
                            description=vuln['description'],
                            remediation=f"Update {pkg_name} to version {vuln['fixed_version']} or later",
                            cve_id=vuln.get('cve_id'),
                            cvss_score=vuln.get('cvss_score'),
                            affected_package=f"{pkg_name}@{pkg_version}"
                        ))

    def _scan_rpm_packages(self, packages: List[Dict], os_info: Dict):
        """Scan RPM packages for vulnerabilities."""
        vulnerable_packages = self._get_rpm_vulnerabilities()

        for pkg in packages:
            pkg_name = pkg['name']
            pkg_version = pkg['version']

            if pkg_name in vulnerable_packages:
                for vuln in vulnerable_packages[pkg_name]:
                    if self._is_version_affected(pkg_version, vuln['affected_versions']):
                        self.add_result(ScanResult(
                            scanner_name=self.name,
                            severity=vuln['severity'],
                            title=f"Vulnerable Package: {pkg_name}",
                            description=vuln['description'],
                            remediation=f"Update {pkg_name} to version {vuln['fixed_version']} or later",
                            cve_id=vuln.get('cve_id'),
                            cvss_score=vuln.get('cvss_score'),
                            affected_package=f"{pkg_name}@{pkg_version}"
                        ))

    def _scan_python_packages(self, packages: List[Dict]):
        """Scan Python packages for vulnerabilities."""
        # Check against PyPI advisory database
        for pkg in packages:
            vulnerabilities = self._check_pypi_vulnerabilities(pkg['name'], pkg['version'])
            for vuln in vulnerabilities:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity=vuln['severity'],
                    title=f"Vulnerable Python Package: {pkg['name']}",
                    description=vuln['description'],
                    remediation=vuln['remediation'],
                    cve_id=vuln.get('cve_id'),
                    cvss_score=vuln.get('cvss_score'),
                    affected_package=f"{pkg['name']}@{pkg['version']}"
                ))

    def _scan_node_packages(self, packages: List[Dict]):
        """Scan Node.js packages for vulnerabilities."""
        for pkg in packages:
            vulnerabilities = self._check_npm_vulnerabilities(pkg['name'], pkg['version'])
            for vuln in vulnerabilities:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity=vuln['severity'],
                    title=f"Vulnerable npm Package: {pkg['name']}",
                    description=vuln['description'],
                    remediation=vuln['remediation'],
                    cve_id=vuln.get('cve_id'),
                    cvss_score=vuln.get('cvss_score'),
                    affected_package=f"{pkg['name']}@{pkg['version']}"
                ))

    def _is_version_affected(self, current_version: str, affected_range: str) -> bool:
        """Check if version is in affected range."""
        try:
            # Simple version comparison
            if '<' in affected_range:
                max_version = affected_range.replace('<', '').strip()
                return version.parse(current_version) < version.parse(max_version)
            elif '=' in affected_range:
                exact_version = affected_range.replace('=', '').strip()
                return version.parse(current_version) == version.parse(exact_version)
            return False
        except Exception:
            return False

    def _get_debian_vulnerabilities(self) -> Dict:
        """Get Debian vulnerability database (example/mock data)."""
        return {
            'openssl': [{
                'cve_id': 'CVE-2022-0778',
                'severity': 'HIGH',
                'description': 'Infinite loop in BN_mod_sqrt() reachable when parsing certificates',
                'affected_versions': '<1.1.1n',
                'fixed_version': '1.1.1n',
                'cvss_score': 7.5
            }],
            'curl': [{
                'cve_id': 'CVE-2023-38545',
                'severity': 'HIGH',
                'description': 'SOCKS5 heap buffer overflow',
                'affected_versions': '<8.4.0',
                'fixed_version': '8.4.0',
                'cvss_score': 9.8
            }],
            'libssl1.1': [{
                'cve_id': 'CVE-2022-0778',
                'severity': 'HIGH',
                'description': 'Infinite loop in BN_mod_sqrt()',
                'affected_versions': '<1.1.1n',
                'fixed_version': '1.1.1n',
                'cvss_score': 7.5
            }]
        }

    def _get_alpine_vulnerabilities(self) -> Dict:
        """Get Alpine vulnerability database (example/mock data)."""
        return {
            'openssl': [{
                'cve_id': 'CVE-2022-0778',
                'severity': 'HIGH',
                'description': 'Infinite loop in BN_mod_sqrt()',
                'affected_versions': '<1.1.1n',
                'fixed_version': '1.1.1n',
                'cvss_score': 7.5
            }],
            'musl': [{
                'cve_id': 'CVE-2020-28928',
                'severity': 'CRITICAL',
                'description': 'Integer overflow in musl libc',
                'affected_versions': '<1.2.2',
                'fixed_version': '1.2.2',
                'cvss_score': 9.8
            }]
        }

    def _get_rpm_vulnerabilities(self) -> Dict:
        """Get RPM vulnerability database (example/mock data)."""
        return {
            'openssl': [{
                'cve_id': 'CVE-2022-0778',
                'severity': 'HIGH',
                'description': 'Infinite loop in BN_mod_sqrt()',
                'affected_versions': '<1.1.1n',
                'fixed_version': '1.1.1n',
                'cvss_score': 7.5
            }]
        }

    def _check_pypi_vulnerabilities(self, package: str, version: str) -> List[Dict]:
        """Check Python package against vulnerability databases."""
        vulnerabilities = []

        # Known vulnerable Python packages (example)
        vuln_db = {
            'django': [{
                'cve_id': 'CVE-2023-43665',
                'severity': 'CRITICAL',
                'description': 'Potential denial of service vulnerability in UsernameField',
                'affected_versions': '<4.2.5',
                'fixed_version': '4.2.5',
                'cvss_score': 7.5
            }],
            'requests': [{
                'cve_id': 'CVE-2023-32681',
                'severity': 'MEDIUM',
                'description': 'Unintended leak of Proxy-Authorization header',
                'affected_versions': '<2.31.0',
                'fixed_version': '2.31.0',
                'cvss_score': 6.1
            }],
            'pillow': [{
                'cve_id': 'CVE-2023-44271',
                'severity': 'HIGH',
                'description': 'Uncontrolled resource consumption',
                'affected_versions': '<10.0.1',
                'fixed_version': '10.0.1',
                'cvss_score': 7.5
            }]
        }

        if package.lower() in vuln_db:
            for vuln in vuln_db[package.lower()]:
                if self._is_version_affected(version, vuln['affected_versions']):
                    vuln['remediation'] = f"Upgrade {package} to {vuln['fixed_version']} or later"
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_npm_vulnerabilities(self, package: str, version: str) -> List[Dict]:
        """Check npm package against vulnerability databases."""
        vulnerabilities = []

        # Known vulnerable npm packages (example)
        vuln_db = {
            'lodash': [{
                'cve_id': 'CVE-2021-23337',
                'severity': 'HIGH',
                'description': 'Command injection vulnerability',
                'affected_versions': '<4.17.21',
                'fixed_version': '4.17.21',
                'cvss_score': 7.2
            }],
            'express': [{
                'cve_id': 'CVE-2022-24999',
                'severity': 'HIGH',
                'description': 'Open redirect vulnerability',
                'affected_versions': '<4.17.3',
                'fixed_version': '4.17.3',
                'cvss_score': 6.1
            }],
            'axios': [{
                'cve_id': 'CVE-2023-45857',
                'severity': 'MEDIUM',
                'description': 'Inefficient regular expression complexity',
                'affected_versions': '<1.6.0',
                'fixed_version': '1.6.0',
                'cvss_score': 5.3
            }]
        }

        if package.lower() in vuln_db:
            for vuln in vuln_db[package.lower()]:
                if self._is_version_affected(version, vuln['affected_versions']):
                    vuln['remediation'] = f"Upgrade {package} to {vuln['fixed_version']} or later"
                    vulnerabilities.append(vuln)

        return vulnerabilities

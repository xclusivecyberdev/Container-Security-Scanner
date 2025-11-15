"""Base image vulnerability scanner."""

import docker
import requests
import re
from typing import List, Dict, Any
from .base_scanner import BaseScanner, ScanResult


class ImageVulnerabilityScanner(BaseScanner):
    """Scanner for base image vulnerabilities."""

    def __init__(self):
        super().__init__("ImageVulnerabilityScanner")
        self.client = docker.from_env()

        # Known vulnerable base images patterns
        self.vulnerable_tags = {
            'latest': 'Using "latest" tag is not recommended - version should be pinned',
            'alpine:3.2': 'Alpine 3.2 is EOL and contains known vulnerabilities',
            'alpine:3.3': 'Alpine 3.3 is EOL and contains known vulnerabilities',
            'ubuntu:14.04': 'Ubuntu 14.04 (Trusty) reached EOL in April 2019',
            'ubuntu:16.04': 'Ubuntu 16.04 (Xenial) reached EOL in April 2021',
            'debian:7': 'Debian 7 (Wheezy) reached EOL in May 2018',
            'debian:8': 'Debian 8 (Jessie) reached EOL in June 2020',
            'centos:6': 'CentOS 6 reached EOL in November 2020',
            'centos:7': 'CentOS 7 reached EOL in June 2024',
        }

    def scan(self, image_name: str) -> List[ScanResult]:
        """
        Scan base image for vulnerabilities.

        Args:
            image_name: Docker image name or ID

        Returns:
            List of ScanResult objects
        """
        self.clear_results()

        try:
            image = self.client.images.get(image_name)

            # Check image tags
            self._check_image_tags(image)

            # Check base image age
            self._check_image_age(image)

            # Check for known vulnerable base images
            self._check_known_vulnerabilities(image)

            # Check image layers
            self._check_image_layers(image)

            # Check official image status
            self._check_official_image(image)

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
                title='Scan Error',
                description=f'Error scanning image: {str(e)}',
                remediation='Check Docker daemon connection and image accessibility'
            ))

        return self.get_results()

    def _check_image_tags(self, image):
        """Check if image uses unsafe tags."""
        tags = image.tags

        if not tags:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='MEDIUM',
                title='Untagged Image',
                description='Image has no tags assigned',
                remediation='Tag your images with specific versions'
            ))
            return

        for tag in tags:
            if ':latest' in tag or not ':' in tag:
                self.add_result(ScanResult(
                    scanner_name=self.name,
                    severity='MEDIUM',
                    title='Floating Tag Usage',
                    description=f'Image uses floating tag: {tag}',
                    remediation='Pin to a specific version tag instead of using "latest"',
                    metadata={'tag': tag}
                ))

    def _check_image_age(self, image):
        """Check if image is outdated."""
        from datetime import datetime, timedelta

        created = image.attrs.get('Created', '')
        if created:
            try:
                created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
                age_days = (datetime.now(created_date.tzinfo) - created_date).days

                if age_days > 365:
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='HIGH',
                        title='Outdated Base Image',
                        description=f'Image is {age_days} days old (over 1 year)',
                        remediation='Update to a more recent base image version',
                        metadata={'age_days': age_days, 'created': created}
                    ))
                elif age_days > 180:
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity='MEDIUM',
                        title='Old Base Image',
                        description=f'Image is {age_days} days old (over 6 months)',
                        remediation='Consider updating to a more recent base image version',
                        metadata={'age_days': age_days, 'created': created}
                    ))
            except Exception:
                pass

    def _check_known_vulnerabilities(self, image):
        """Check against known vulnerable base images."""
        tags = image.tags

        for tag in tags:
            # Extract base image info
            for pattern, description in self.vulnerable_tags.items():
                if pattern in tag.lower():
                    severity = 'CRITICAL' if 'EOL' in description else 'MEDIUM'
                    self.add_result(ScanResult(
                        scanner_name=self.name,
                        severity=severity,
                        title='Known Vulnerable Base Image',
                        description=description,
                        remediation=f'Upgrade from {pattern} to a supported version',
                        metadata={'tag': tag, 'pattern': pattern}
                    ))

    def _check_image_layers(self, image):
        """Check number of layers for complexity."""
        history = image.history()
        layer_count = len(history)

        if layer_count > 50:
            self.add_result(ScanResult(
                scanner_name=self.name,
                severity='LOW',
                title='Excessive Image Layers',
                description=f'Image has {layer_count} layers which may indicate complexity',
                remediation='Consider optimizing Dockerfile to reduce layers using multi-stage builds',
                metadata={'layer_count': layer_count}
            ))

    def _check_official_image(self, image):
        """Check if using official Docker Hub images."""
        tags = image.tags

        for tag in tags:
            # Check if it's from Docker Hub and not official library
            if '/' in tag and not tag.startswith('docker.io/library/'):
                parts = tag.split('/')
                if len(parts) >= 2:
                    registry = parts[0]
                    if '.' not in registry and registry != 'docker.io':
                        # Likely a user repository
                        self.add_result(ScanResult(
                            scanner_name=self.name,
                            severity='INFO',
                            title='Third-Party Base Image',
                            description=f'Using third-party image: {tag}',
                            remediation='Verify the trustworthiness of third-party images',
                            metadata={'tag': tag}
                        ))

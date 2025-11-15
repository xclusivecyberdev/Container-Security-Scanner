"""Tests for security scanners."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.scanners.base_scanner import ScanResult
from src.scanners.image_scanner import ImageVulnerabilityScanner
from src.scanners.misconfiguration_scanner import MisconfigurationScanner


class TestScanResult:
    """Test ScanResult class."""

    def test_scan_result_creation(self):
        """Test creating a scan result."""
        result = ScanResult(
            scanner_name="TestScanner",
            severity="HIGH",
            title="Test Issue",
            description="This is a test issue",
            remediation="Fix the issue"
        )

        assert result.scanner_name == "TestScanner"
        assert result.severity == "HIGH"
        assert result.title == "Test Issue"
        assert result.description == "This is a test issue"
        assert result.remediation == "Fix the issue"

    def test_scan_result_to_dict(self):
        """Test converting scan result to dictionary."""
        result = ScanResult(
            scanner_name="TestScanner",
            severity="CRITICAL",
            title="Critical Issue",
            description="Critical problem",
            cve_id="CVE-2023-12345",
            cvss_score=9.8
        )

        result_dict = result.to_dict()

        assert result_dict['scanner'] == "TestScanner"
        assert result_dict['severity'] == "CRITICAL"
        assert result_dict['cve_id'] == "CVE-2023-12345"
        assert result_dict['cvss_score'] == 9.8


class TestImageVulnerabilityScanner:
    """Test ImageVulnerabilityScanner."""

    @patch('src.scanners.image_scanner.docker.from_env')
    def test_scanner_initialization(self, mock_docker):
        """Test scanner initialization."""
        scanner = ImageVulnerabilityScanner()
        assert scanner.name == "ImageVulnerabilityScanner"
        assert len(scanner.results) == 0

    @patch('src.scanners.image_scanner.docker.from_env')
    def test_check_floating_tag(self, mock_docker):
        """Test detection of floating tags."""
        # Create mock Docker client and image
        mock_client = MagicMock()
        mock_docker.return_value = mock_client

        mock_image = MagicMock()
        mock_image.tags = ['nginx:latest']
        mock_image.attrs = {
            'Created': '2023-01-01T00:00:00.000Z',
            'Config': {}
        }
        mock_image.history.return_value = []

        mock_client.images.get.return_value = mock_image

        scanner = ImageVulnerabilityScanner()
        results = scanner.scan('nginx:latest')

        # Should detect :latest tag usage
        floating_tag_results = [r for r in results if 'Floating Tag' in r.title]
        assert len(floating_tag_results) > 0


class TestMisconfigurationScanner:
    """Test MisconfigurationScanner."""

    @patch('src.scanners.misconfiguration_scanner.docker.from_env')
    def test_root_user_detection(self, mock_docker):
        """Test detection of root user."""
        mock_client = MagicMock()
        mock_docker.return_value = mock_client

        mock_image = MagicMock()
        mock_image.attrs = {
            'Config': {
                'User': '',  # Empty user means root
                'ExposedPorts': {},
                'Env': []
            }
        }
        mock_image.history.return_value = []

        mock_client.images.get.return_value = mock_image

        scanner = MisconfigurationScanner()
        results = scanner.scan('test:latest', target_type='image')

        # Should detect root user
        root_results = [r for r in results if 'root' in r.title.lower()]
        assert len(root_results) > 0

    @patch('src.scanners.misconfiguration_scanner.docker.from_env')
    def test_privileged_container_detection(self, mock_docker):
        """Test detection of privileged container."""
        mock_client = MagicMock()
        mock_docker.return_value = mock_client

        mock_container = MagicMock()
        mock_container.attrs = {
            'HostConfig': {
                'Privileged': True,
                'SecurityOpt': [],
                'CapAdd': [],
                'Memory': 0,
                'CpuQuota': 0,
                'NetworkMode': 'bridge',
                'Binds': [],
                'PidMode': '',
                'IpcMode': ''
            }
        }

        mock_client.containers.get.return_value = mock_container

        scanner = MisconfigurationScanner()
        results = scanner.scan('test-container', target_type='container')

        # Should detect privileged mode
        privileged_results = [r for r in results if 'Privileged' in r.title]
        assert len(privileged_results) > 0
        assert any(r.severity == 'CRITICAL' for r in privileged_results)


def test_severity_counts():
    """Test severity counting."""
    from src.scanners.base_scanner import BaseScanner

    class TestScanner(BaseScanner):
        def scan(self, target):
            return []

    scanner = TestScanner("TestScanner")

    # Add various severity results
    scanner.add_result(ScanResult("TestScanner", "CRITICAL", "Issue 1", "Desc"))
    scanner.add_result(ScanResult("TestScanner", "HIGH", "Issue 2", "Desc"))
    scanner.add_result(ScanResult("TestScanner", "HIGH", "Issue 3", "Desc"))
    scanner.add_result(ScanResult("TestScanner", "MEDIUM", "Issue 4", "Desc"))

    counts = scanner.get_severity_counts()

    assert counts['CRITICAL'] == 1
    assert counts['HIGH'] == 2
    assert counts['MEDIUM'] == 1
    assert counts['LOW'] == 0


if __name__ == '__main__':
    pytest.main([__file__])

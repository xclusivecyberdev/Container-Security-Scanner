"""Tests for report generators."""

import pytest
import json
from src.reporters.report_generator import ReportGenerator
from src.scanners.base_scanner import ScanResult


class TestReportGenerator:
    """Test ReportGenerator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.generator = ReportGenerator()

        # Create sample results
        self.sample_results = [
            ScanResult(
                scanner_name="TestScanner",
                severity="CRITICAL",
                title="Critical Issue",
                description="Critical security problem",
                remediation="Fix immediately",
                cve_id="CVE-2023-12345",
                cvss_score=9.8
            ),
            ScanResult(
                scanner_name="TestScanner",
                severity="HIGH",
                title="High Priority Issue",
                description="High severity problem",
                remediation="Fix soon"
            ),
            ScanResult(
                scanner_name="TestScanner",
                severity="MEDIUM",
                title="Medium Issue",
                description="Medium priority",
                remediation="Address when possible"
            )
        ]

        self.metadata = {
            'target': 'test:latest',
            'type': 'image'
        }

    def test_generate_json(self):
        """Test JSON report generation."""
        report = self.generator.generate_json(self.sample_results, self.metadata)

        # Parse JSON
        data = json.loads(report)

        assert 'scan_metadata' in data
        assert 'summary' in data
        assert 'findings' in data

        assert data['scan_metadata']['target'] == 'test:latest'
        assert data['scan_metadata']['total_findings'] == 3

        assert data['summary']['CRITICAL'] == 1
        assert data['summary']['HIGH'] == 1
        assert data['summary']['MEDIUM'] == 1

        assert len(data['findings']) == 3

    def test_generate_html(self):
        """Test HTML report generation."""
        report = self.generator.generate_html(self.sample_results, self.metadata)

        # Check HTML content
        assert '<!DOCTYPE html>' in report
        assert 'Docker Security Scan Report' in report
        assert 'test:latest' in report
        assert 'Critical Issue' in report
        assert 'CVE-2023-12345' in report

        # Check severity sections
        assert 'CRITICAL' in report
        assert 'HIGH' in report
        assert 'MEDIUM' in report

    def test_calculate_summary(self):
        """Test summary calculation."""
        summary = self.generator._calculate_summary(self.sample_results)

        assert summary['CRITICAL'] == 1
        assert summary['HIGH'] == 1
        assert summary['MEDIUM'] == 1
        assert summary['LOW'] == 0
        assert summary['INFO'] == 0

    def test_escape_html(self):
        """Test HTML escaping."""
        text = '<script>alert("XSS")</script>'
        escaped = self.generator._escape_html(text)

        assert '<script>' not in escaped
        assert '&lt;script&gt;' in escaped
        assert '&lt;/script&gt;' in escaped


if __name__ == '__main__':
    pytest.main([__file__])

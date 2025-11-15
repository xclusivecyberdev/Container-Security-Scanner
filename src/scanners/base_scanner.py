"""Base scanner class for all security scanners."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
from datetime import datetime


class ScanResult:
    """Represents a security scan result."""

    def __init__(
        self,
        scanner_name: str,
        severity: str,
        title: str,
        description: str,
        remediation: str = "",
        cve_id: str = None,
        cvss_score: float = None,
        affected_package: str = None,
        metadata: Dict[str, Any] = None
    ):
        self.scanner_name = scanner_name
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.title = title
        self.description = description
        self.remediation = remediation
        self.cve_id = cve_id
        self.cvss_score = cvss_score
        self.affected_package = affected_package
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'scanner': self.scanner_name,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'remediation': self.remediation,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'affected_package': self.affected_package,
            'metadata': self.metadata,
            'timestamp': self.timestamp
        }


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    def __init__(self, name: str):
        self.name = name
        self.results: List[ScanResult] = []

    @abstractmethod
    def scan(self, target: Any) -> List[ScanResult]:
        """
        Perform security scan on the target.

        Args:
            target: The target to scan (image, container, etc.)

        Returns:
            List of ScanResult objects
        """
        pass

    def add_result(self, result: ScanResult):
        """Add a scan result."""
        self.results.append(result)

    def get_results(self) -> List[ScanResult]:
        """Get all scan results."""
        return self.results

    def clear_results(self):
        """Clear all results."""
        self.results = []

    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of findings by severity."""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in self.results:
            if result.severity in counts:
                counts[result.severity] += 1
        return counts

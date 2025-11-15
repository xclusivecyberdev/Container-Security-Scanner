#!/usr/bin/env python3
"""
Example script demonstrating programmatic usage of Docker Security Scanner.
"""

import sys
sys.path.insert(0, '../src')

from scanners.image_scanner import ImageVulnerabilityScanner
from scanners.package_scanner import PackageVulnerabilityScanner
from scanners.misconfiguration_scanner import MisconfigurationScanner
from scanners.secrets_scanner import SecretsScanner
from analyzers.privilege_analyzer import PrivilegeEscalationAnalyzer
from analyzers.benchmark_analyzer import DockerBenchmarkAnalyzer
from reporters.report_generator import ReportGenerator


def main():
    """Run security scans programmatically."""

    # Image to scan
    image_name = "nginx:latest"

    print(f"🔍 Scanning {image_name}...")
    print("=" * 60)

    all_results = []

    # 1. Base Image Vulnerability Scan
    print("\n📦 Scanning base image vulnerabilities...")
    scanner = ImageVulnerabilityScanner()
    results = scanner.scan(image_name)
    all_results.extend(results)
    print(f"   Found {len(results)} issues")

    # 2. Package Vulnerability Scan
    print("\n🔎 Scanning package vulnerabilities...")
    scanner = PackageVulnerabilityScanner()
    results = scanner.scan(image_name)
    all_results.extend(results)
    print(f"   Found {len(results)} issues")

    # 3. Misconfiguration Scan
    print("\n⚙️  Scanning for misconfigurations...")
    scanner = MisconfigurationScanner()
    results = scanner.scan(image_name, target_type='image')
    all_results.extend(results)
    print(f"   Found {len(results)} issues")

    # 4. Secrets Scan
    print("\n🔐 Scanning for exposed secrets...")
    scanner = SecretsScanner()
    results = scanner.scan(image_name)
    all_results.extend(results)
    print(f"   Found {len(results)} issues")

    # 5. Privilege Escalation Analysis
    print("\n🔓 Analyzing privilege escalation risks...")
    analyzer = PrivilegeEscalationAnalyzer()
    results = analyzer.scan(image_name, target_type='image')
    all_results.extend(results)
    print(f"   Found {len(results)} issues")

    # 6. CIS Benchmark Compliance
    print("\n📋 Checking CIS Benchmark compliance...")
    analyzer = DockerBenchmarkAnalyzer()
    results = analyzer.scan(image_name, target_type='image')
    all_results.extend(results)
    print(f"   Found {len(results)} issues")

    # Calculate summary
    print("\n" + "=" * 60)
    print("📊 SUMMARY")
    print("=" * 60)

    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for result in all_results:
        if result.severity in severity_counts:
            severity_counts[result.severity] += 1

    print(f"\nTotal Issues: {len(all_results)}")
    print(f"  🔴 Critical: {severity_counts['CRITICAL']}")
    print(f"  🟠 High:     {severity_counts['HIGH']}")
    print(f"  🟡 Medium:   {severity_counts['MEDIUM']}")
    print(f"  🔵 Low:      {severity_counts['LOW']}")
    print(f"  ⚪ Info:     {severity_counts['INFO']}")

    # Generate reports
    print("\n📄 Generating reports...")
    generator = ReportGenerator()
    metadata = {'target': image_name, 'type': 'image'}

    # JSON report
    json_report = generator.generate_json(all_results, metadata)
    with open('example-scan-results.json', 'w') as f:
        f.write(json_report)
    print("   ✅ JSON report: example-scan-results.json")

    # HTML report
    html_report = generator.generate_html(all_results, metadata)
    with open('example-scan-results.html', 'w') as f:
        f.write(html_report)
    print("   ✅ HTML report: example-scan-results.html")

    # PDF report
    try:
        generator.generate_pdf(all_results, metadata, 'example-scan-results.pdf')
        print("   ✅ PDF report:  example-scan-results.pdf")
    except Exception as e:
        print(f"   ⚠️  PDF report: Failed ({str(e)})")

    print("\n" + "=" * 60)
    print("✨ Scan complete!")
    print("=" * 60)

    # Display some critical/high findings
    critical_high = [r for r in all_results if r.severity in ['CRITICAL', 'HIGH']]
    if critical_high:
        print(f"\n⚠️  Top {min(5, len(critical_high))} Critical/High Issues:")
        for i, result in enumerate(critical_high[:5], 1):
            print(f"\n{i}. [{result.severity}] {result.title}")
            print(f"   {result.description}")
            if result.remediation:
                print(f"   Fix: {result.remediation}")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

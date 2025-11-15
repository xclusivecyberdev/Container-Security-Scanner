"""Main CLI application."""

import click
import sys
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.markdown import Markdown

from ..scanners.image_scanner import ImageVulnerabilityScanner
from ..scanners.package_scanner import PackageVulnerabilityScanner
from ..scanners.misconfiguration_scanner import MisconfigurationScanner
from ..scanners.secrets_scanner import SecretsScanner
from ..analyzers.privilege_analyzer import PrivilegeEscalationAnalyzer
from ..analyzers.benchmark_analyzer import DockerBenchmarkAnalyzer
from ..reporters.report_generator import ReportGenerator

console = Console()


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Docker Security Scanner - Comprehensive container security analysis tool."""
    pass


@cli.command()
@click.argument('image')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'html', 'pdf']), default='text',
              help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--severity', '-s', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
              help='Minimum severity level to report')
@click.option('--scan-all', is_flag=True, help='Run all scanners (default)')
@click.option('--scan-image', is_flag=True, help='Scan base image vulnerabilities')
@click.option('--scan-packages', is_flag=True, help='Scan package vulnerabilities')
@click.option('--scan-misconfig', is_flag=True, help='Scan for misconfigurations')
@click.option('--scan-secrets', is_flag=True, help='Scan for exposed secrets')
@click.option('--scan-privileges', is_flag=True, help='Analyze privilege escalation risks')
@click.option('--scan-benchmark', is_flag=True, help='Check CIS Benchmark compliance')
def scan_image(image, format, output, severity, scan_all, scan_image, scan_packages,
               scan_misconfig, scan_secrets, scan_privileges, scan_benchmark):
    """Scan a Docker image for security issues."""

    # If no specific scanner is selected, run all
    if not any([scan_image, scan_packages, scan_misconfig, scan_secrets,
                scan_privileges, scan_benchmark]):
        scan_all = True

    all_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:

        # Image vulnerability scanner
        if scan_all or scan_image:
            task = progress.add_task("[cyan]Scanning base image...", total=None)
            scanner = ImageVulnerabilityScanner()
            results = scanner.scan(image)
            all_results.extend(results)
            progress.remove_task(task)
            console.print(f"[green]✓[/green] Base image scan complete: {len(results)} findings")

        # Package vulnerability scanner
        if scan_all or scan_packages:
            task = progress.add_task("[cyan]Scanning packages for CVEs...", total=None)
            scanner = PackageVulnerabilityScanner()
            results = scanner.scan(image)
            all_results.extend(results)
            progress.remove_task(task)
            console.print(f"[green]✓[/green] Package scan complete: {len(results)} findings")

        # Misconfiguration scanner
        if scan_all or scan_misconfig:
            task = progress.add_task("[cyan]Checking for misconfigurations...", total=None)
            scanner = MisconfigurationScanner()
            results = scanner.scan(image, target_type='image')
            all_results.extend(results)
            progress.remove_task(task)
            console.print(f"[green]✓[/green] Misconfiguration scan complete: {len(results)} findings")

        # Secrets scanner
        if scan_all or scan_secrets:
            task = progress.add_task("[cyan]Scanning for exposed secrets...", total=None)
            scanner = SecretsScanner()
            results = scanner.scan(image)
            all_results.extend(results)
            progress.remove_task(task)
            console.print(f"[green]✓[/green] Secrets scan complete: {len(results)} findings")

        # Privilege escalation analyzer
        if scan_all or scan_privileges:
            task = progress.add_task("[cyan]Analyzing privilege escalation risks...", total=None)
            analyzer = PrivilegeEscalationAnalyzer()
            results = analyzer.scan(image, target_type='image')
            all_results.extend(results)
            progress.remove_task(task)
            console.print(f"[green]✓[/green] Privilege analysis complete: {len(results)} findings")

        # CIS Benchmark analyzer
        if scan_all or scan_benchmark:
            task = progress.add_task("[cyan]Checking CIS Benchmark compliance...", total=None)
            analyzer = DockerBenchmarkAnalyzer()
            results = analyzer.scan(image, target_type='image')
            all_results.extend(results)
            progress.remove_task(task)
            console.print(f"[green]✓[/green] Benchmark check complete: {len(results)} findings")

    # Filter by severity if specified
    if severity:
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_index = severity_order.index(severity)
        all_results = [r for r in all_results if severity_order.index(r.severity) >= min_index]

    # Generate report
    generator = ReportGenerator()

    if format == 'text':
        _display_text_report(all_results, image)
        if output:
            _save_text_report(all_results, output, image)
    elif format == 'json':
        report = generator.generate_json(all_results, {'target': image, 'type': 'image'})
        if output:
            with open(output, 'w') as f:
                f.write(report)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(report)
    elif format == 'html':
        report = generator.generate_html(all_results, {'target': image, 'type': 'image'})
        output_path = output or 'security_report.html'
        with open(output_path, 'w') as f:
            f.write(report)
        console.print(f"[green]HTML report saved to {output_path}[/green]")
    elif format == 'pdf':
        output_path = output or 'security_report.pdf'
        generator.generate_pdf(all_results, {'target': image, 'type': 'image'}, output_path)
        console.print(f"[green]PDF report saved to {output_path}[/green]")


@cli.command()
@click.argument('container')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'html', 'pdf']), default='text',
              help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--severity', '-s', type=click.Choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
              help='Minimum severity level to report')
def scan_container(container, format, output, severity):
    """Scan a running Docker container for security issues."""

    all_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:

        # Misconfiguration scanner
        task = progress.add_task("[cyan]Checking container configuration...", total=None)
        scanner = MisconfigurationScanner()
        results = scanner.scan(container, target_type='container')
        all_results.extend(results)
        progress.remove_task(task)
        console.print(f"[green]✓[/green] Configuration scan complete: {len(results)} findings")

        # Privilege escalation analyzer
        task = progress.add_task("[cyan]Analyzing runtime privileges...", total=None)
        analyzer = PrivilegeEscalationAnalyzer()
        results = analyzer.scan(container, target_type='container')
        all_results.extend(results)
        progress.remove_task(task)
        console.print(f"[green]✓[/green] Privilege analysis complete: {len(results)} findings")

        # CIS Benchmark analyzer
        task = progress.add_task("[cyan]Checking CIS Benchmark compliance...", total=None)
        analyzer = DockerBenchmarkAnalyzer()
        results = analyzer.scan(container, target_type='container')
        all_results.extend(results)
        progress.remove_task(task)
        console.print(f"[green]✓[/green] Benchmark check complete: {len(results)} findings")

    # Filter by severity if specified
    if severity:
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_index = severity_order.index(severity)
        all_results = [r for r in all_results if severity_order.index(r.severity) >= min_index]

    # Generate report
    generator = ReportGenerator()

    if format == 'text':
        _display_text_report(all_results, container)
        if output:
            _save_text_report(all_results, output, container)
    elif format == 'json':
        report = generator.generate_json(all_results, {'target': container, 'type': 'container'})
        if output:
            with open(output, 'w') as f:
                f.write(report)
            console.print(f"[green]Report saved to {output}[/green]")
        else:
            console.print(report)
    elif format == 'html':
        report = generator.generate_html(all_results, {'target': container, 'type': 'container'})
        output_path = output or 'security_report.html'
        with open(output_path, 'w') as f:
            f.write(report)
        console.print(f"[green]HTML report saved to {output_path}[/green]")
    elif format == 'pdf':
        output_path = output or 'security_report.pdf'
        generator.generate_pdf(all_results, {'target': container, 'type': 'container'}, output_path)
        console.print(f"[green]PDF report saved to {output_path}[/green]")


def _display_text_report(results, target):
    """Display results in terminal."""
    console.print()
    console.print(Panel(f"[bold]Security Scan Results for: {target}[/bold]",
                       style="bold blue"))
    console.print()

    # Severity summary
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for result in results:
        if result.severity in severity_counts:
            severity_counts[result.severity] += 1

    summary_table = Table(title="Severity Summary", show_header=True)
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    for severity, count in severity_counts.items():
        if count > 0:
            color = {
                'CRITICAL': 'red',
                'HIGH': 'orange1',
                'MEDIUM': 'yellow',
                'LOW': 'blue',
                'INFO': 'cyan'
            }.get(severity, 'white')
            summary_table.add_row(f"[{color}]{severity}[/{color}]", str(count))

    console.print(summary_table)
    console.print()

    # Group results by severity
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        severity_results = [r for r in results if r.severity == severity]

        if not severity_results:
            continue

        color = {
            'CRITICAL': 'red',
            'HIGH': 'orange1',
            'MEDIUM': 'yellow',
            'LOW': 'blue',
            'INFO': 'cyan'
        }.get(severity, 'white')

        console.print(f"\n[bold {color}]{severity} Severity Issues ({len(severity_results)})[/bold {color}]")
        console.print("=" * 80)

        for idx, result in enumerate(severity_results, 1):
            console.print(f"\n[bold]{idx}. {result.title}[/bold]")
            console.print(f"   Scanner: {result.scanner_name}")
            console.print(f"   Description: {result.description}")
            if result.remediation:
                console.print(f"   [green]Remediation:[/green] {result.remediation}")
            if result.cve_id:
                console.print(f"   CVE: {result.cve_id}")
            if result.cvss_score:
                console.print(f"   CVSS Score: {result.cvss_score}")

    console.print()
    console.print(f"[bold]Total Issues Found: {len(results)}[/bold]")
    console.print()


def _save_text_report(results, output_path, target):
    """Save text report to file."""
    with open(output_path, 'w') as f:
        f.write(f"Docker Security Scan Report\n")
        f.write(f"Target: {target}\n")
        f.write(f"{'=' * 80}\n\n")

        # Severity summary
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in results:
            if result.severity in severity_counts:
                severity_counts[result.severity] += 1

        f.write("Severity Summary:\n")
        for severity, count in severity_counts.items():
            if count > 0:
                f.write(f"  {severity}: {count}\n")
        f.write("\n")

        # Detailed findings
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_results = [r for r in results if r.severity == severity]

            if not severity_results:
                continue

            f.write(f"\n{severity} Severity Issues ({len(severity_results)})\n")
            f.write("=" * 80 + "\n")

            for idx, result in enumerate(severity_results, 1):
                f.write(f"\n{idx}. {result.title}\n")
                f.write(f"   Scanner: {result.scanner_name}\n")
                f.write(f"   Description: {result.description}\n")
                if result.remediation:
                    f.write(f"   Remediation: {result.remediation}\n")
                if result.cve_id:
                    f.write(f"   CVE: {result.cve_id}\n")
                if result.cvss_score:
                    f.write(f"   CVSS Score: {result.cvss_score}\n")

        f.write(f"\n\nTotal Issues Found: {len(results)}\n")

    console.print(f"[green]Report saved to {output_path}[/green]")


@cli.command()
def list_scanners():
    """List all available security scanners."""
    table = Table(title="Available Security Scanners")
    table.add_column("Scanner", style="cyan")
    table.add_column("Description")

    scanners = [
        ("ImageVulnerabilityScanner", "Scans base image for known vulnerabilities"),
        ("PackageVulnerabilityScanner", "Scans packages for CVEs from vulnerability databases"),
        ("MisconfigurationScanner", "Detects Docker security misconfigurations"),
        ("SecretsScanner", "Finds exposed secrets and credentials"),
        ("PrivilegeEscalationAnalyzer", "Analyzes privilege escalation risks"),
        ("DockerBenchmarkAnalyzer", "Checks compliance with CIS Docker Benchmark"),
    ]

    for name, description in scanners:
        table.add_row(name, description)

    console.print(table)


if __name__ == '__main__':
    cli()

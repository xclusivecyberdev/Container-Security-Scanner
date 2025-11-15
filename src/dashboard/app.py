"""Web dashboard for Docker Security Scanner."""

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import docker
import json
import tempfile
from datetime import datetime

from ..scanners.image_scanner import ImageVulnerabilityScanner
from ..scanners.package_scanner import PackageVulnerabilityScanner
from ..scanners.misconfiguration_scanner import MisconfigurationScanner
from ..scanners.secrets_scanner import SecretsScanner
from ..analyzers.privilege_analyzer import PrivilegeEscalationAnalyzer
from ..analyzers.benchmark_analyzer import DockerBenchmarkAnalyzer
from ..reporters.report_generator import ReportGenerator

app = Flask(__name__)
CORS(app)

# Store scan results in memory (in production, use a database)
scan_history = []


@app.route('/')
def index():
    """Render main dashboard."""
    return render_template('index.html')


@app.route('/api/images', methods=['GET'])
def list_images():
    """List all Docker images."""
    try:
        client = docker.from_env()
        images = client.images.list()

        image_list = []
        for img in images:
            image_list.append({
                'id': img.short_id,
                'tags': img.tags,
                'created': img.attrs.get('Created', ''),
                'size': img.attrs.get('Size', 0)
            })

        return jsonify({'images': image_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/containers', methods=['GET'])
def list_containers():
    """List all Docker containers."""
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)

        container_list = []
        for container in containers:
            container_list.append({
                'id': container.short_id,
                'name': container.name,
                'image': container.image.tags[0] if container.image.tags else container.image.short_id,
                'status': container.status,
                'created': container.attrs.get('Created', '')
            })

        return jsonify({'containers': container_list})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/image', methods=['POST'])
def scan_image():
    """Scan a Docker image."""
    data = request.get_json()
    image_name = data.get('image')
    scanners = data.get('scanners', ['all'])

    if not image_name:
        return jsonify({'error': 'Image name required'}), 400

    try:
        all_results = []

        # Run selected scanners
        if 'all' in scanners or 'image' in scanners:
            scanner = ImageVulnerabilityScanner()
            all_results.extend(scanner.scan(image_name))

        if 'all' in scanners or 'packages' in scanners:
            scanner = PackageVulnerabilityScanner()
            all_results.extend(scanner.scan(image_name))

        if 'all' in scanners or 'misconfig' in scanners:
            scanner = MisconfigurationScanner()
            all_results.extend(scanner.scan(image_name, target_type='image'))

        if 'all' in scanners or 'secrets' in scanners:
            scanner = SecretsScanner()
            all_results.extend(scanner.scan(image_name))

        if 'all' in scanners or 'privileges' in scanners:
            analyzer = PrivilegeEscalationAnalyzer()
            all_results.extend(analyzer.scan(image_name, target_type='image'))

        if 'all' in scanners or 'benchmark' in scanners:
            analyzer = DockerBenchmarkAnalyzer()
            all_results.extend(analyzer.scan(image_name, target_type='image'))

        # Convert results to dict
        results_dict = [r.to_dict() for r in all_results]

        # Calculate summary
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in all_results:
            if result.severity in summary:
                summary[result.severity] += 1

        # Store in history
        scan_record = {
            'id': len(scan_history),
            'target': image_name,
            'type': 'image',
            'timestamp': datetime.utcnow().isoformat(),
            'total_findings': len(results_dict),
            'summary': summary,
            'results': results_dict
        }
        scan_history.append(scan_record)

        return jsonify(scan_record)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/container', methods=['POST'])
def scan_container():
    """Scan a Docker container."""
    data = request.get_json()
    container_name = data.get('container')

    if not container_name:
        return jsonify({'error': 'Container name required'}), 400

    try:
        all_results = []

        # Run scanners
        scanner = MisconfigurationScanner()
        all_results.extend(scanner.scan(container_name, target_type='container'))

        analyzer = PrivilegeEscalationAnalyzer()
        all_results.extend(analyzer.scan(container_name, target_type='container'))

        analyzer = DockerBenchmarkAnalyzer()
        all_results.extend(analyzer.scan(container_name, target_type='container'))

        # Convert results to dict
        results_dict = [r.to_dict() for r in all_results]

        # Calculate summary
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in all_results:
            if result.severity in summary:
                summary[result.severity] += 1

        # Store in history
        scan_record = {
            'id': len(scan_history),
            'target': container_name,
            'type': 'container',
            'timestamp': datetime.utcnow().isoformat(),
            'total_findings': len(results_dict),
            'summary': summary,
            'results': results_dict
        }
        scan_history.append(scan_record)

        return jsonify(scan_record)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scans', methods=['GET'])
def get_scan_history():
    """Get scan history."""
    return jsonify({'scans': scan_history})


@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get specific scan results."""
    if scan_id < len(scan_history):
        return jsonify(scan_history[scan_id])
    return jsonify({'error': 'Scan not found'}), 404


@app.route('/api/scan/<int:scan_id>/export', methods=['GET'])
def export_scan(scan_id):
    """Export scan results."""
    if scan_id >= len(scan_history):
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = scan_history[scan_id]
    format_type = request.args.get('format', 'json')

    # Convert dict back to ScanResult objects for report generation
    # For simplicity, we'll just export the raw JSON
    # In production, you'd reconstruct ScanResult objects

    generator = ReportGenerator()

    if format_type == 'json':
        return jsonify(scan_data)
    elif format_type == 'html':
        # For HTML, we'd need to reconstruct ScanResult objects
        # Simplified version: just return JSON representation in HTML
        html = f"""
<!DOCTYPE html>
<html>
<head><title>Scan Results</title></head>
<body>
    <h1>Scan Results</h1>
    <pre>{json.dumps(scan_data, indent=2)}</pre>
</body>
</html>
"""
        return html
    else:
        return jsonify({'error': 'Unsupported format'}), 400


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get overall statistics."""
    if not scan_history:
        return jsonify({
            'total_scans': 0,
            'total_findings': 0,
            'severity_totals': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        })

    total_findings = sum(scan['total_findings'] for scan in scan_history)
    severity_totals = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}

    for scan in scan_history:
        for severity, count in scan['summary'].items():
            if severity in severity_totals:
                severity_totals[severity] += count

    return jsonify({
        'total_scans': len(scan_history),
        'total_findings': total_findings,
        'severity_totals': severity_totals
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

"""Report generator for security scan results."""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path


class ReportGenerator:
    """Generates security reports in various formats."""

    def __init__(self):
        self.template_dir = Path(__file__).parent / 'templates'

    def generate_json(self, results: List, metadata: Dict[str, Any]) -> str:
        """Generate JSON report."""
        report = {
            'scan_metadata': {
                'target': metadata.get('target', 'unknown'),
                'target_type': metadata.get('type', 'unknown'),
                'scan_date': datetime.utcnow().isoformat(),
                'total_findings': len(results)
            },
            'summary': self._calculate_summary(results),
            'findings': [r.to_dict() for r in results]
        }

        return json.dumps(report, indent=2)

    def generate_html(self, results: List, metadata: Dict[str, Any]) -> str:
        """Generate HTML report."""
        summary = self._calculate_summary(results)

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Docker Security Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .metadata {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            color: white;
        }}
        .critical {{ background-color: #c0392b; }}
        .high {{ background-color: #e67e22; }}
        .medium {{ background-color: #f39c12; }}
        .low {{ background-color: #3498db; }}
        .info {{ background-color: #95a5a6; }}
        .summary-card h3 {{
            margin: 0;
            font-size: 2em;
        }}
        .summary-card p {{
            margin: 5px 0 0 0;
            font-size: 0.9em;
        }}
        .finding {{
            border-left: 4px solid #3498db;
            padding: 15px;
            margin-bottom: 15px;
            background-color: #f9f9f9;
        }}
        .finding.critical {{ border-left-color: #c0392b; }}
        .finding.high {{ border-left-color: #e67e22; }}
        .finding.medium {{ border-left-color: #f39c12; }}
        .finding.low {{ border-left-color: #3498db; }}
        .finding.info {{ border-left-color: #95a5a6; }}
        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .finding-meta {{
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 10px;
        }}
        .remediation {{
            background-color: #d5f4e6;
            padding: 10px;
            border-radius: 3px;
            margin-top: 10px;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }}
        .severity-badge {{
            color: white;
        }}
        .severity-badge.critical {{ background-color: #c0392b; }}
        .severity-badge.high {{ background-color: #e67e22; }}
        .severity-badge.medium {{ background-color: #f39c12; }}
        .severity-badge.low {{ background-color: #3498db; }}
        .severity-badge.info {{ background-color: #95a5a6; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Docker Security Scan Report</h1>

        <div class="metadata">
            <strong>Target:</strong> {metadata.get('target', 'unknown')}<br>
            <strong>Type:</strong> {metadata.get('type', 'unknown')}<br>
            <strong>Scan Date:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
            <strong>Total Findings:</strong> {len(results)}
        </div>

        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card critical">
                <h3>{summary['CRITICAL']}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card high">
                <h3>{summary['HIGH']}</h3>
                <p>High</p>
            </div>
            <div class="summary-card medium">
                <h3>{summary['MEDIUM']}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card low">
                <h3>{summary['LOW']}</h3>
                <p>Low</p>
            </div>
            <div class="summary-card info">
                <h3>{summary['INFO']}</h3>
                <p>Info</p>
            </div>
        </div>

        <h2>Detailed Findings</h2>
"""

        # Group by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_results = [r for r in results if r.severity == severity]

            if not severity_results:
                continue

            html += f"<h3>{severity} Severity ({len(severity_results)})</h3>\n"

            for result in severity_results:
                html += f"""
        <div class="finding {severity.lower()}">
            <div class="finding-title">
                <span class="badge severity-badge {severity.lower()}">{severity}</span>
                {self._escape_html(result.title)}
            </div>
            <div class="finding-meta">
                <strong>Scanner:</strong> {result.scanner_name}
"""

                if result.cve_id:
                    html += f" | <strong>CVE:</strong> {result.cve_id}"
                if result.cvss_score:
                    html += f" | <strong>CVSS:</strong> {result.cvss_score}"

                html += """
            </div>
            <div>
                <strong>Description:</strong> {desc}
            </div>
""".format(desc=self._escape_html(result.description))

                if result.remediation:
                    html += f"""
            <div class="remediation">
                <strong>🔧 Remediation:</strong> {self._escape_html(result.remediation)}
            </div>
"""

                html += "        </div>\n"

        html += """
    </div>
</body>
</html>
"""

        return html

    def generate_pdf(self, results: List, metadata: Dict[str, Any], output_path: str):
        """Generate PDF report."""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError:
            raise ImportError("reportlab is required for PDF generation. Install with: pip install reportlab")

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        story.append(Paragraph("Docker Security Scan Report", title_style))
        story.append(Spacer(1, 12))

        # Metadata
        metadata_data = [
            ['Target:', metadata.get('target', 'unknown')],
            ['Type:', metadata.get('type', 'unknown')],
            ['Scan Date:', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Total Findings:', str(len(results))]
        ]

        metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 20))

        # Summary
        story.append(Paragraph("Summary", styles['Heading2']))
        story.append(Spacer(1, 12))

        summary = self._calculate_summary(results)
        summary_data = [['Severity', 'Count']]
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if summary[severity] > 0:
                summary_data.append([severity, str(summary[severity])])

        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(summary_table)
        story.append(PageBreak())

        # Detailed findings
        story.append(Paragraph("Detailed Findings", styles['Heading2']))
        story.append(Spacer(1, 12))

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_results = [r for r in results if r.severity == severity]

            if not severity_results:
                continue

            story.append(Paragraph(f"{severity} Severity ({len(severity_results)})", styles['Heading3']))
            story.append(Spacer(1, 6))

            for idx, result in enumerate(severity_results, 1):
                # Finding title
                story.append(Paragraph(f"<b>{idx}. {result.title}</b>", styles['Normal']))
                story.append(Spacer(1, 6))

                # Details
                details = f"<b>Scanner:</b> {result.scanner_name}<br/>"
                details += f"<b>Severity:</b> {result.severity}<br/>"
                if result.cve_id:
                    details += f"<b>CVE:</b> {result.cve_id}<br/>"
                if result.cvss_score:
                    details += f"<b>CVSS Score:</b> {result.cvss_score}<br/>"
                details += f"<b>Description:</b> {result.description}<br/>"
                if result.remediation:
                    details += f"<b>Remediation:</b> {result.remediation}"

                story.append(Paragraph(details, styles['Normal']))
                story.append(Spacer(1, 12))

        doc.build(story)

    def _calculate_summary(self, results: List) -> Dict[str, int]:
        """Calculate severity summary."""
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for result in results:
            if result.severity in summary:
                summary[result.severity] += 1
        return summary

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))

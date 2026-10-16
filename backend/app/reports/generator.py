import csv
import io
import json
import os
import time
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from backend.app.core.config import settings
from backend.app.db.models import ScanJob, Finding, Asset, ReportRecord

def generate_report_data(job: ScanJob, asset: Optional[Asset], findings: List[Finding]) -> Dict[str, Any]:
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.severity or "Info"
        if sev in sev_counts:
            sev_counts[sev] += 1

    report_data = {
        "report_id": f"VR-{job.id}-{int(time.time())}",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "target": job.target,
        "job_title": job.title,
        "asset_name": asset.name if asset else "Unlinked Host",
        "asset_criticality": asset.criticality if asset else "medium",
        "asset_environment": asset.environment if asset else "production",
        "scan_started": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(job.started_at)) if job.started_at else "N/A",
        "scan_finished": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(job.finished_at)) if job.finished_at else "N/A",
        "severity_summary": sev_counts,
        "total_findings": len(findings),
        "disclaimer": "This report contains security assessment findings conducted under authorized rules of engagement. Unassessed areas or low-confidence indicators do not guarantee immunity from vulnerability.",
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "cve": f.cve,
                "cwe": f.cwe,
                "confidence": f.confidence,
                "detection_method": f.detection_method,
                "is_credentialed": f.is_credentialed,
                "port": f.port,
                "protocol": f.protocol,
                "affected_component": f.affected_component,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "status": f.status
            }
            for f in findings
        ]
    }
    return report_data

def export_json_report(data: Dict[str, Any], output_path: str) -> str:
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)
    return output_path

def export_csv_report(data: Dict[str, Any], output_path: str) -> str:
    fieldnames = [
        "Finding_ID", "Title", "Severity", "CVSS_Score", "CVE", "CWE",
        "Confidence", "Port", "Protocol", "Affected_Component",
        "Status", "Description", "Evidence", "Remediation"
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=fieldnames)
        writer.writeheader()
        for f in data.get("findings", []):
            writer.writerow({
                "Finding_ID": f["id"],
                "Title": f["title"],
                "Severity": f["severity"],
                "CVSS_Score": f["cvss_score"],
                "CVE": f["cve"] or "N/A",
                "CWE": f["cwe"] or "N/A",
                "Confidence": f["confidence"],
                "Port": f["port"] or "N/A",
                "Protocol": f["protocol"],
                "Affected_Component": f["affected_component"],
                "Status": f["status"],
                "Description": f["description"].replace("\n", " "),
                "Evidence": (f["evidence"] or "").replace("\n", " ")[:300],
                "Remediation": (f["remediation"] or "").replace("\n", " ")
            })
    return output_path

def export_html_report(data: Dict[str, Any], output_path: str) -> str:
    sev = data["severity_summary"]
    findings_html = ""
    for f in data["findings"]:
        sev_color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Info": "#64748b"
        }.get(f["severity"], "#64748b")

        findings_html += f"""
        <div class="finding-card" style="border-left: 5px solid {sev_color}; margin-bottom: 20px; padding: 16px; background: #ffffff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h3 style="margin:0; color:#1e293b; font-size:1.15rem;">{f['title']}</h3>
                <span style="background:{sev_color}; color:#fff; padding:3px 10px; border-radius:12px; font-weight:bold; font-size:0.8rem;">{f['severity']} (CVSS {f['cvss_score']})</span>
            </div>
            <p style="color:#64748b; font-size:0.9rem; margin: 8px 0;"><strong>Component:</strong> {f['affected_component']} | <strong>Port:</strong> {f['port']}/{f['protocol']} | <strong>CVE:</strong> {f['cve'] or 'N/A'} | <strong>Confidence:</strong> {f['confidence']}</p>
            <p style="color:#334155; line-height:1.5;">{f['description']}</p>
            {f'<div style="background:#f8fafc; border:1px solid #e2e8f0; padding:10px; border-radius:6px; font-family:monospace; font-size:0.85rem; margin:10px 0;"><strong>Observed Evidence:</strong><br>{f["evidence"]}</div>' if f["evidence"] else ''}
            <div style="background:#ecfdf5; border-left:4px solid #10b981; padding:10px; border-radius:4px; font-size:0.9rem; color:#065f46;">
                <strong>Remediation Advisory:</strong> {f['remediation']}
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VulnForge Enterprise Vulnerability Assessment - {data['target']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f1f5f9; color: #0f172a; margin: 0; padding: 40px; }}
        .header {{ background: #0f172a; color: #ffffff; padding: 30px; border-radius: 12px; margin-bottom: 30px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }}
        .card {{ background: #ffffff; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .metric {{ font-size: 2rem; font-weight: bold; margin-top: 5px; }}
        .disclaimer {{ background: #fffbeb; border-left: 4px solid #f59e0b; padding: 15px; border-radius: 6px; font-size: 0.9rem; color: #92400e; margin-bottom: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1 style="margin:0; font-size:2rem;">VulnForge Enterprise™ Vulnerability Assessment</h1>
        <p style="margin:8px 0 0; color:#94a3b8;">Target: <strong>{data['target']}</strong> | Asset: <strong>{data['asset_name']}</strong> ({data['asset_environment']}) | Report ID: {data['report_id']}</p>
        <p style="margin:4px 0 0; color:#94a3b8; font-size:0.85rem;">Generated: {data['generated_at']} | Scan Window: {data['scan_started']} to {data['scan_finished']}</p>
    </div>

    <div class="summary-grid">
        <div class="card" style="border-top: 4px solid #dc2626;"><div style="color:#64748b; font-size:0.85rem;">CRITICAL</div><div class="metric" style="color:#dc2626;">{sev['Critical']}</div></div>
        <div class="card" style="border-top: 4px solid #ea580c;"><div style="color:#64748b; font-size:0.85rem;">HIGH</div><div class="metric" style="color:#ea580c;">{sev['High']}</div></div>
        <div class="card" style="border-top: 4px solid #d97706;"><div style="color:#64748b; font-size:0.85rem;">MEDIUM</div><div class="metric" style="color:#d97706;">{sev['Medium']}</div></div>
        <div class="card" style="border-top: 4px solid #2563eb;"><div style="color:#64748b; font-size:0.85rem;">LOW</div><div class="metric" style="color:#2563eb;">{sev['Low']}</div></div>
        <div class="card" style="border-top: 4px solid #64748b;"><div style="color:#64748b; font-size:0.85rem;">INFO</div><div class="metric" style="color:#64748b;">{sev['Info']}</div></div>
    </div>

    <div class="disclaimer">
        <strong>Notice & Limitations:</strong> {data['disclaimer']}
    </div>

    <h2>Technical Vulnerability Findings ({data['total_findings']})</h2>
    {findings_html}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write(html)
    return output_path

def export_pdf_report(data: Dict[str, Any], output_path: str) -> str:
    doc = SimpleDocTemplate(output_path, pagesize=letter, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=10
    )
    story.append(Paragraph("VulnForge Enterprise™ Vulnerability Assessment", title_style))
    story.append(Paragraph(f"<b>Target:</b> {data['target']} | <b>Report ID:</b> {data['report_id']} | <b>Generated:</b> {data['generated_at']}", styles['Normal']))
    story.append(Spacer(1, 15))

    # Summary Table
    sev = data["severity_summary"]
    summary_data = [
        ["Critical", "High", "Medium", "Low", "Info", "Total"],
        [str(sev["Critical"]), str(sev["High"]), str(sev["Medium"]), str(sev["Low"]), str(sev["Info"]), str(data["total_findings"])]
    ]
    t = Table(summary_data, colWidths=[90, 90, 90, 90, 90, 90])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Technical Findings:</b>", styles['Heading2']))
    for f in data["findings"]:
        finding_box = [
            [f"{f['title']} [{f['severity']} - CVSS {f['cvss_score']}]"],
            [f"Component: {f['affected_component']} | Port: {f['port']}/{f['protocol']} | CVE: {f['cve'] or 'None'}"],
            [f"{f['description']}"],
            [f"Remediation: {f['remediation']}"]
        ]
        ft = Table(finding_box, colWidths=[540])
        ft.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ]))
        story.append(ft)
        story.append(Spacer(1, 10))

    doc.build(story)
    return output_path

import os
import tempfile
from backend.app.reports.generator import (
    generate_report_data,
    export_html_report,
    export_json_report,
    export_csv_report,
    export_pdf_report
)
from backend.app.db.models import ScanJob, Finding, Asset

def test_report_generation(db_session):
    job = ScanJob(id=1, title="Test Job", target="192.168.1.50", status="completed")
    asset = Asset(id=1, name="Asset-01", criticality="high", environment="production")
    finding = Finding(
        id=1,
        asset_id=1,
        job_id=1,
        fingerprint="fp123",
        title="Telnet Cleartext Service",
        description="Telnet running on 23",
        severity="High",
        cvss_score=7.5,
        confidence="Confirmed",
        affected_component="Telnet",
        port=23,
        protocol="tcp",
        remediation="Disable telnet"
    )

    data = generate_report_data(job, asset, [finding])
    assert data["target"] == "192.168.1.50"
    assert data["severity_summary"]["High"] == 1

    with tempfile.TemporaryDirectory() as tmpdir:
        html_p = os.path.join(tmpdir, "report.html")
        json_p = os.path.join(tmpdir, "report.json")
        csv_p = os.path.join(tmpdir, "report.csv")
        pdf_p = os.path.join(tmpdir, "report.pdf")

        export_html_report(data, html_p)
        export_json_report(data, json_p)
        export_csv_report(data, csv_p)
        export_pdf_report(data, pdf_p)

        assert os.path.exists(html_p) and os.path.getsize(html_p) > 0
        assert os.path.exists(json_p) and os.path.getsize(json_p) > 0
        assert os.path.exists(csv_p) and os.path.getsize(csv_p) > 0
        assert os.path.exists(pdf_p) and os.path.getsize(pdf_p) > 0

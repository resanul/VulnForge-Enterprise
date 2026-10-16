import os
import time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.audit import log_audit_event
from backend.app.db.base import get_db
from backend.app.db.models import ReportRecord, ScanJob, Finding, Asset, User
from backend.app.api.deps import get_current_user, require_roles
from backend.app.reports.generator import (
    generate_report_data,
    export_html_report,
    export_json_report,
    export_csv_report,
    export_pdf_report
)

router = APIRouter(prefix="/reports", tags=["Reporting Center"])

class ReportGenerateRequest(BaseModel):
    job_id: int
    report_type: str = "technical"  # executive, technical, compliance
    report_format: str = "html"  # html, json, csv, pdf
    title: Optional[str] = None

class ReportResponse(BaseModel):
    id: int
    title: str
    report_type: str
    report_format: str
    file_path: str
    created_at: int

@router.get("", response_model=List[ReportResponse])
def list_reports(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(ReportRecord).order_by(ReportRecord.id.desc()).all()

@router.post("/generate", response_model=ReportResponse)
def generate_report(
    req: ReportGenerateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst", "auditor"]))
):
    job = db.query(ScanJob).filter(ScanJob.id == req.job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    asset = db.query(Asset).filter(Asset.id == job.asset_id).first() if job.asset_id else None
    findings = db.query(Finding).filter(Finding.job_id == job.id).all()

    report_data = generate_report_data(job, asset, findings)
    title = req.title or f"Vulnerability Assessment - {job.target} ({req.report_format.upper()})"

    filename = f"report_job_{job.id}_{int(time.time())}.{req.report_format.lower()}"
    file_path = os.path.join(settings.REPORTS_STORAGE_DIR, filename)

    fmt = req.report_format.lower()
    if fmt == "html":
        export_html_report(report_data, file_path)
    elif fmt == "json":
        export_json_report(report_data, file_path)
    elif fmt == "csv":
        export_csv_report(report_data, file_path)
    elif fmt == "pdf":
        export_pdf_report(report_data, file_path)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {req.report_format}")

    record = ReportRecord(
        title=title,
        report_type=req.report_type,
        report_format=fmt,
        file_path=file_path,
        created_at=int(time.time()),
        metadata_json="{}"
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    log_audit_event(
        action="REPORT_GENERATED",
        user_id=user.id,
        username=user.username,
        resource_type="Report",
        resource_id=str(record.id),
        details={"job_id": job.id, "format": fmt}
    )

    return record

@router.get("/download/{id}")
def download_report(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    record = db.query(ReportRecord).filter(ReportRecord.id == id).first()
    if not record or not os.path.exists(record.file_path):
        raise HTTPException(status_code=404, detail="Report file not found")

    media_type = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf"
    }.get(record.report_format, "application/octet-stream")

    return FileResponse(
        record.file_path,
        media_type=media_type,
        filename=os.path.basename(record.file_path)
    )

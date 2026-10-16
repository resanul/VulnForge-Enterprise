import time
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.audit import log_audit_event
from backend.app.db.base import get_db
from backend.app.db.models import ScanJob, ScanProfile, Asset, Credential, User
from backend.app.api.deps import get_current_user, require_roles
from backend.app.tasks.worker import dispatch_scan_job, cancel_job

router = APIRouter(prefix="/scans", tags=["Scan Center"])

class ProfileCreate(BaseModel):
    name: str
    description: Optional[str] = None
    categories: str = "network,tls,web"
    safe_mode: bool = True
    ports_mode: str = "standard"
    custom_ports: Optional[str] = None
    credential_id: Optional[int] = None
    timeout_seconds: int = 1800

class ProfileResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    categories: str
    safe_mode: bool
    ports_mode: str
    custom_ports: Optional[str]
    credential_id: Optional[int]
    timeout_seconds: int
    created_at: int

class LaunchScanRequest(BaseModel):
    title: str
    target: str
    asset_id: Optional[int] = None
    profile_id: Optional[int] = None
    credential_id: Optional[int] = None

class ScanJobResponse(BaseModel):
    id: int
    title: str
    target: str
    asset_id: Optional[int]
    profile_id: Optional[int]
    credential_id: Optional[int]
    status: str
    progress: int
    started_at: Optional[int]
    finished_at: Optional[int]
    error_message: Optional[str]
    log_output: Optional[str]
    summary_stats: Optional[str]
    findings_count: Optional[int] = 0

@router.get("/profiles", response_model=List[ProfileResponse])
def list_profiles(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    profiles = db.query(ScanProfile).all()
    return profiles

@router.post("/profiles", response_model=ProfileResponse)
def create_profile(
    req: ProfileCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    profile = ScanProfile(
        name=req.name,
        description=req.description,
        categories=req.categories,
        safe_mode=req.safe_mode,
        ports_mode=req.ports_mode,
        custom_ports=req.custom_ports,
        credential_id=req.credential_id,
        timeout_seconds=req.timeout_seconds,
        created_at=int(time.time())
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    log_audit_event(
        action="SCAN_PROFILE_CREATED",
        user_id=user.id,
        username=user.username,
        resource_type="ScanProfile",
        resource_id=str(profile.id),
        details={"name": profile.name}
    )
    return profile

@router.get("/jobs", response_model=List[ScanJobResponse])
def list_scan_jobs(
    status: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    query = db.query(ScanJob).order_by(ScanJob.id.desc())
    if status:
        query = query.filter(ScanJob.status == status)
    jobs = query.limit(limit).all()

    results = []
    for j in jobs:
        results.append(ScanJobResponse(
            id=j.id,
            title=j.title,
            target=j.target,
            asset_id=j.asset_id,
            profile_id=j.profile_id,
            credential_id=j.credential_id,
            status=j.status,
            progress=j.progress,
            started_at=j.started_at,
            finished_at=j.finished_at,
            error_message=j.error_message,
            log_output=j.log_output,
            summary_stats=j.summary_stats,
            findings_count=len(j.findings)
        ))
    return results

@router.post("/launch", response_model=ScanJobResponse)
async def launch_scan(
    req: LaunchScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    # Create Job record
    job = ScanJob(
        title=req.title,
        target=req.target.strip(),
        asset_id=req.asset_id,
        profile_id=req.profile_id,
        credential_id=req.credential_id,
        status="pending",
        progress=0,
        log_output="[QUEUED] Scan request registered.\n"
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    log_audit_event(
        action="SCAN_LAUNCHED",
        user_id=user.id,
        username=user.username,
        resource_type="ScanJob",
        resource_id=str(job.id),
        details={"target": job.target, "title": job.title}
    )

    # Dispatch to background task runner
    background_tasks.add_task(dispatch_scan_job, job.id)

    return ScanJobResponse(
        id=job.id,
        title=job.title,
        target=job.target,
        asset_id=job.asset_id,
        profile_id=job.profile_id,
        credential_id=job.credential_id,
        status=job.status,
        progress=job.progress,
        started_at=job.started_at,
        finished_at=job.finished_at,
        error_message=job.error_message,
        log_output=job.log_output,
        summary_stats=job.summary_stats,
        findings_count=0
    )

@router.get("/jobs/{id}", response_model=ScanJobResponse)
def get_scan_job(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    job = db.query(ScanJob).filter(ScanJob.id == id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    return ScanJobResponse(
        id=job.id,
        title=job.title,
        target=job.target,
        asset_id=job.asset_id,
        profile_id=job.profile_id,
        credential_id=job.credential_id,
        status=job.status,
        progress=job.progress,
        started_at=job.started_at,
        finished_at=job.finished_at,
        error_message=job.error_message,
        log_output=job.log_output,
        summary_stats=job.summary_stats,
        findings_count=len(job.findings)
    )

@router.post("/jobs/{id}/cancel")
def cancel_scan_job(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    job = db.query(ScanJob).filter(ScanJob.id == id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    cancel_job(id)
    if job.status in ["pending", "running"]:
        job.status = "cancelled"
        job.finished_at = int(time.time())
        db.commit()

    log_audit_event(
        action="SCAN_CANCELLED",
        user_id=user.id,
        username=user.username,
        resource_type="ScanJob",
        resource_id=str(id),
        details={"title": job.title}
    )

    return {"status": "success", "message": f"Scan job {id} cancelled."}

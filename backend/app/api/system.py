import time
import json
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.core.config import settings
from backend.app.core.audit import log_audit_event
from backend.app.db.base import get_db
from backend.app.db.models import ApprovedScope, AuditEventRecord, Asset, ScanJob, Finding, User
from backend.app.api.deps import get_current_user, require_roles
from backend.app.engines import get_all_engine_metadata

router = APIRouter(prefix="/system", tags=["System Administration"])

class ScopeCreate(BaseModel):
    target_pattern: str  # e.g. 192.168.1.0/24, scanme.nmap.org, 10.0.0.0/8
    description: Optional[str] = None

class ScopeResponse(BaseModel):
    id: int
    target_pattern: str
    description: Optional[str]
    approved_by: str
    is_active: bool
    created_at: int

class AuditEventResponse(BaseModel):
    id: int
    action: str
    user_id: Optional[int]
    username: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    client_ip: Optional[str]
    status: str
    details_json: str
    created_at: int

@router.get("/health")
def system_health(db: Session = Depends(get_db)):
    db_healthy = True
    try:
        db.execute(func.now() if not settings.DATABASE_URL.startswith("sqlite") else func.time()).scalar()
    except Exception:
        db_healthy = False

    engines = get_all_engine_metadata()
    available_engines = sum(1 for e in engines if e["is_available"])

    return {
        "status": "healthy" if db_healthy else "degraded",
        "app_name": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "database_connected": db_healthy,
        "total_engines": len(engines),
        "active_engines": available_engines,
        "uptime_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }

@router.get("/engines")
def list_engines(user: User = Depends(get_current_user)):
    return get_all_engine_metadata()

@router.get("/scopes", response_model=List[ScopeResponse])
def list_scopes(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(ApprovedScope).filter(ApprovedScope.is_active == True).all()

@router.post("/scopes", response_model=ScopeResponse)
def add_scope(
    req: ScopeCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin"]))
):
    scope = ApprovedScope(
        target_pattern=req.target_pattern.strip(),
        description=req.description,
        approved_by=user.username,
        is_active=True,
        created_at=int(time.time())
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)

    log_audit_event(
        action="SCOPE_ADDED",
        user_id=user.id,
        username=user.username,
        resource_type="ApprovedScope",
        resource_id=str(scope.id),
        details={"pattern": scope.target_pattern}
    )
    return scope

@router.delete("/scopes/{id}")
def delete_scope(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin"]))
):
    scope = db.query(ApprovedScope).filter(ApprovedScope.id == id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope pattern not found")

    scope.is_active = False
    db.commit()

    log_audit_event(
        action="SCOPE_REVOKED",
        user_id=user.id,
        username=user.username,
        resource_type="ApprovedScope",
        resource_id=str(id),
        details={"pattern": scope.target_pattern}
    )
    return {"status": "success", "message": f"Scope {id} revoked."}

@router.get("/audit-logs", response_model=List[AuditEventResponse])
def list_audit_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "auditor"]))
):
    events = db.query(AuditEventRecord).order_by(AuditEventRecord.id.desc()).limit(limit).all()
    return events

@router.get("/dashboard-stats")
def get_dashboard_stats(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    total_assets = db.query(Asset).count()
    total_scans = db.query(ScanJob).count()
    active_scans = db.query(ScanJob).filter(ScanJob.status == "running").count()
    failed_scans = db.query(ScanJob).filter(ScanJob.status == "failed").count()

    total_findings = db.query(Finding).count()
    crit_findings = db.query(Finding).filter(Finding.severity == "Critical", Finding.status == "Open").count()
    high_findings = db.query(Finding).filter(Finding.severity == "High", Finding.status == "Open").count()
    med_findings = db.query(Finding).filter(Finding.severity == "Medium", Finding.status == "Open").count()
    low_findings = db.query(Finding).filter(Finding.severity == "Low", Finding.status == "Open").count()
    info_findings = db.query(Finding).filter(Finding.severity == "Info").count()

    return {
        "assets_count": total_assets,
        "scans_count": total_scans,
        "active_scans_count": active_scans,
        "failed_scans_count": failed_scans,
        "total_findings": total_findings,
        "open_findings_by_severity": {
            "Critical": crit_findings,
            "High": high_findings,
            "Medium": med_findings,
            "Low": low_findings,
            "Info": info_findings
        },
        "critical_exposure_index": crit_findings * 10 + high_findings * 5
    }

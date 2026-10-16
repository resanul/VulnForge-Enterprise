import time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.audit import log_audit_event
from backend.app.db.base import get_db
from backend.app.db.models import Finding, Asset, User
from backend.app.api.deps import get_current_user, require_roles

router = APIRouter(prefix="/findings", tags=["Vulnerability Management"])

class FindingResponse(BaseModel):
    id: int
    asset_id: int
    job_id: Optional[int]
    fingerprint: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str]
    cve: Optional[str]
    cwe: Optional[str]
    confidence: str
    detection_method: str
    is_credentialed: bool
    affected_component: str
    port: Optional[int]
    protocol: str
    evidence: Optional[str]
    remediation: Optional[str]
    status: str
    first_seen: int
    last_seen: int
    suppression_reason: Optional[str]
    asset_name: Optional[str] = None
    target_value: Optional[str] = None

class StatusUpdateRequest(BaseModel):
    status: str  # Open, Remediated, Accepted, Suppressed, FalsePositive
    justification: Optional[str] = None
    expires_at: Optional[int] = None

@router.get("", response_model=List[FindingResponse])
def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    cve: Optional[str] = None,
    asset_id: Optional[int] = None,
    job_id: Optional[int] = None,
    search: Optional[str] = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    query = db.query(Finding).join(Asset, Finding.asset_id == Asset.id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if status:
        query = query.filter(Finding.status == status)
    if cve:
        query = query.filter(Finding.cve == cve)
    if asset_id:
        query = query.filter(Finding.asset_id == asset_id)
    if job_id:
        query = query.filter(Finding.job_id == job_id)
    if search:
        query = query.filter(
            (Finding.title.contains(search)) |
            (Finding.description.contains(search)) |
            (Finding.affected_component.contains(search))
        )

    findings = query.order_by(Finding.cvss_score.desc()).limit(limit).all()
    results = []
    for f in findings:
        results.append(FindingResponse(
            id=f.id,
            asset_id=f.asset_id,
            job_id=f.job_id,
            fingerprint=f.fingerprint,
            title=f.title,
            description=f.description,
            severity=f.severity,
            cvss_score=f.cvss_score,
            cvss_vector=f.cvss_vector,
            cve=f.cve,
            cwe=f.cwe,
            confidence=f.confidence,
            detection_method=f.detection_method,
            is_credentialed=f.is_credentialed,
            affected_component=f.affected_component,
            port=f.port,
            protocol=f.protocol,
            evidence=f.evidence,
            remediation=f.remediation,
            status=f.status,
            first_seen=f.first_seen,
            last_seen=f.last_seen,
            suppression_reason=f.suppression_reason,
            asset_name=f.asset.name if f.asset else None,
            target_value=f.asset.target_value if f.asset else None
        ))
    return results

@router.get("/{id}", response_model=FindingResponse)
def get_finding(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    f = db.query(Finding).filter(Finding.id == id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingResponse(
        id=f.id,
        asset_id=f.asset_id,
        job_id=f.job_id,
        fingerprint=f.fingerprint,
        title=f.title,
        description=f.description,
        severity=f.severity,
        cvss_score=f.cvss_score,
        cvss_vector=f.cvss_vector,
        cve=f.cve,
        cwe=f.cwe,
        confidence=f.confidence,
        detection_method=f.detection_method,
        is_credentialed=f.is_credentialed,
        affected_component=f.affected_component,
        port=f.port,
        protocol=f.protocol,
        evidence=f.evidence,
        remediation=f.remediation,
        status=f.status,
        first_seen=f.first_seen,
        last_seen=f.last_seen,
        suppression_reason=f.suppression_reason,
        asset_name=f.asset.name if f.asset else None,
        target_value=f.asset.target_value if f.asset else None
    )

@router.post("/{id}/status")
def update_finding_status(
    id: int,
    req: StatusUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    f = db.query(Finding).filter(Finding.id == id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    old_status = f.status
    f.status = req.status
    if req.justification:
        f.suppression_reason = req.justification
    if req.expires_at:
        f.suppression_expires_at = req.expires_at

    db.commit()

    log_audit_event(
        action="FINDING_STATUS_CHANGED",
        user_id=user.id,
        username=user.username,
        resource_type="Finding",
        resource_id=str(f.id),
        details={
            "old_status": old_status,
            "new_status": req.status,
            "justification": req.justification
        }
    )

    return {"status": "success", "finding_id": id, "new_status": f.status}

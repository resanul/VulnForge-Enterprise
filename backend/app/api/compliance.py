import time
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.audit import log_audit_event
from backend.app.db.base import get_db
from backend.app.db.models import ComplianceResult, Asset, User
from backend.app.api.deps import get_current_user, require_roles
from backend.app.engines.compliance_engine import CompliancePolicyEngine, ComplianceRule

router = APIRouter(prefix="/compliance", tags=["Compliance Center"])

class ComplianceResultResponse(BaseModel):
    id: int
    job_id: Optional[int]
    asset_id: Optional[int]
    framework: str
    rule_id: str
    title: str
    description: Optional[str]
    status: str
    severity: str
    observed_value: Optional[str]
    expected_value: Optional[str]
    remediation: Optional[str]
    created_at: int

class RunComplianceRequest(BaseModel):
    asset_id: int
    benchmark: str = "CIS-Linux-v2.0"
    facts: Dict[str, Any]

@router.get("/results", response_model=List[ComplianceResultResponse])
def list_compliance_results(
    framework: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[int] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    query = db.query(ComplianceResult)
    if framework:
        query = query.filter(ComplianceResult.framework == framework)
    if status:
        query = query.filter(ComplianceResult.status == status)
    if asset_id:
        query = query.filter(ComplianceResult.asset_id == asset_id)

    return query.all()

@router.post("/evaluate", response_model=List[ComplianceResultResponse])
def evaluate_compliance(
    req: RunComplianceRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    asset = db.query(Asset).filter(Asset.id == req.asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    engine = CompliancePolicyEngine()
    builtin_rules = [
        ComplianceRule(
            rule_id="CIS-5.2.1",
            benchmark=req.benchmark,
            title="Ensure SSH PermitRootLogin is disabled",
            description="Direct root login over SSH must be prohibited.",
            severity="High",
            expected_value="no",
            check_type="config_match",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
        ),
        ComplianceRule(
            rule_id="CIS-5.2.2",
            benchmark=req.benchmark,
            title="Ensure SSH Protocol version 2 is enforced",
            description="Legacy SSHv1 contains protocol flaws.",
            severity="High",
            expected_value="2",
            check_type="config_match",
            remediation="Ensure OpenSSH enforces Protocol 2."
        ),
        ComplianceRule(
            rule_id="CIS-3.5.1",
            benchmark=req.benchmark,
            title="Ensure host firewall is active",
            description="Host-based firewall must be active.",
            severity="Medium",
            expected_value="active",
            check_type="config_match",
            remediation="Execute 'systemctl enable --now firewalld'."
        ),
        ComplianceRule(
            rule_id="CIS-1.1.21",
            benchmark=req.benchmark,
            title="Ensure sticky bit is set on world-writable directories",
            description="Sticky bit prevents deletion of files by non-owners.",
            severity="Low",
            expected_value="true",
            check_type="boolean",
            remediation="Apply sticky bit: chmod +t <directory>"
        )
    ]

    evaluated = engine.evaluate_rules(builtin_rules, req.facts)
    saved_records = []

    for item in evaluated:
        record = ComplianceResult(
            asset_id=asset.id,
            framework=item.benchmark,
            rule_id=item.rule_id,
            title=item.title,
            description=item.description,
            status=item.status,
            severity=item.severity,
            observed_value=item.observed_value,
            expected_value=item.expected_value,
            remediation=item.remediation,
            created_at=int(time.time())
        )
        db.add(record)
        saved_records.append(record)

    db.commit()

    log_audit_event(
        action="COMPLIANCE_EVALUATED",
        user_id=user.id,
        username=user.username,
        resource_type="Asset",
        resource_id=str(asset.id),
        details={"benchmark": req.benchmark, "rules_evaluated": len(saved_records)}
    )

    return saved_records

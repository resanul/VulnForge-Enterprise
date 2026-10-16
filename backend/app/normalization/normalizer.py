import hashlib
import time
from typing import List, Tuple
from sqlalchemy.orm import Session
from backend.app.db.models import Finding
from backend.app.normalization.schema import NormalizedFinding

def generate_fingerprint(asset_id: int, finding: NormalizedFinding) -> str:
    """
    Computes a deterministic hash fingerprint representing the unique combination of:
    asset_id + title + cve + affected_component + port + protocol
    """
    key_str = f"{asset_id}|{finding.title.strip().lower()}|{finding.cve or ''}|{finding.affected_component.strip().lower()}|{finding.port or 0}|{finding.protocol.lower()}"
    return hashlib.sha256(key_str.encode('utf-8')).hexdigest()

def normalize_and_store_findings(
    db: Session,
    asset_id: int,
    job_id: int,
    findings: List[NormalizedFinding]
) -> Tuple[int, int]:
    """
    Normalizes findings and saves them to the database.
    - If a finding already exists for this asset with the same fingerprint:
      updates last_seen, evidence, job_id, but preserves first_seen, status, and remediation ownership.
    - If it's a new finding: inserts it with first_seen and last_seen set to now.
    Returns (created_count, updated_count).
    """
    created_count = 0
    updated_count = 0
    now = int(time.time())

    for f in findings:
        fp = generate_fingerprint(asset_id, f)
        existing = db.query(Finding).filter(
            Finding.asset_id == asset_id,
            Finding.fingerprint == fp
        ).first()

        if existing:
            existing.last_seen = now
            existing.job_id = job_id
            if f.evidence:
                existing.evidence = f.evidence
            if f.cvss_score > existing.cvss_score:
                existing.cvss_score = f.cvss_score
                existing.severity = f.severity.value
            updated_count += 1
        else:
            new_finding = Finding(
                asset_id=asset_id,
                job_id=job_id,
                fingerprint=fp,
                title=f.title,
                description=f.description,
                severity=f.severity.value,
                cvss_score=f.cvss_score,
                cvss_vector=f.cvss_vector,
                cve=f.cve,
                cwe=f.cwe,
                confidence=f.confidence.value,
                detection_method=f.detection_method,
                is_credentialed=f.is_credentialed,
                affected_component=f.affected_component,
                port=f.port,
                protocol=f.protocol,
                evidence=f.evidence,
                remediation=f.remediation,
                status="Open",
                first_seen=now,
                last_seen=now
            )
            db.add(new_finding)
            created_count += 1

    db.commit()
    return created_count, updated_count

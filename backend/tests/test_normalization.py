from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel
from backend.app.normalization.cve_intelligence import enrich_cve, score_to_severity
from backend.app.normalization.normalizer import generate_fingerprint, normalize_and_store_findings
from backend.app.db.models import Finding

def test_cve_intelligence_enrichment():
    data = enrich_cve("CVE-2021-44228")
    assert data is not None
    assert "Log4j" in data["title"]
    assert data["severity"] == SeverityLevel.CRITICAL
    assert data["cvss_score"] == 10.0

def test_score_to_severity():
    assert score_to_severity(9.8) == SeverityLevel.CRITICAL
    assert score_to_severity(7.5) == SeverityLevel.HIGH
    assert score_to_severity(5.0) == SeverityLevel.MEDIUM
    assert score_to_severity(2.5) == SeverityLevel.LOW
    assert score_to_severity(0.0) == SeverityLevel.INFO

def test_finding_deduplication(db_session):
    finding = NormalizedFinding(
        title="Insecure Cleartext Protocol: Telnet Detected",
        description="Telnet service open on port 23.",
        severity=SeverityLevel.HIGH,
        cvss_score=7.5,
        confidence=ConfidenceLevel.CONFIRMED,
        affected_component="Telnet:23",
        port=23,
        protocol="tcp",
        evidence="Banner: Cisco IOS Telnet"
    )

    # First scan run: finding should be created
    created, updated = normalize_and_store_findings(db_session, asset_id=1, job_id=101, findings=[finding])
    assert created == 1
    assert updated == 0
    assert db_session.query(Finding).count() == 1

    # Second scan run with same issue: should update last_seen, NOT create duplicate!
    created2, updated2 = normalize_and_store_findings(db_session, asset_id=1, job_id=102, findings=[finding])
    assert created2 == 0
    assert updated2 == 1
    assert db_session.query(Finding).count() == 1

    stored = db_session.query(Finding).first()
    assert stored.job_id == 102

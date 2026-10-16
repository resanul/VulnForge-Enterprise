#!/usr/bin/env python3
"""
VulnForge Enterprise Demo Data Seeder
Populates realistic assets, scan jobs, findings, and compliance checks.
"""
import sys
import os
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.db.base import Base, engine, SessionLocal
from backend.app.core.security import get_password_hash
from backend.app.db.models import (
    User, Asset, ScanProfile, ScanJob, Finding,
    ComplianceResult, RemediationTask, ApprovedScope
)

def seed_demo_data():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    now = int(time.time())

    print("[INFO] Seeding VulnForge Enterprise Demo Environment...")

    # 1. Admin User
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        admin = User(
            username="admin",
            email="admin@vulnforge.internal",
            hashed_password=get_password_hash("VulnForgeAdmin2026!"),
            full_name="Chief Information Security Officer",
            role="admin",
            is_active=True,
            created_at=now
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)

    # 2. Approved Scopes
    scopes_data = [
        ("192.168.1.0/24", "Corporate Internal DMZ"),
        ("10.100.0.0/16", "PCI-DSS Cardholder Data Environment (CDE)"),
        ("scanme.nmap.org", "Authorized External Verification Target"),
        ("127.0.0.1/32", "Localhost Test Harness")
    ]
    for pattern, desc in scopes_data:
        if not db.query(ApprovedScope).filter(ApprovedScope.target_pattern == pattern).first():
            db.add(ApprovedScope(target_pattern=pattern, description=desc, approved_by="admin", is_active=True, created_at=now))
    db.commit()

    # 3. Assets
    assets_data = [
        ("Prod-API-Gateway", "ip", "192.168.1.10", "critical", "production", "dmz", "DevSecOps"),
        ("DB-Cluster-Primary", "ip", "10.100.5.20", "critical", "production", "internal", "DBA Team"),
        ("Core-Switch-01", "ip", "192.168.1.1", "high", "production", "network", "NetOps"),
        ("Legacy-Billing-Svc", "ip", "10.100.20.15", "high", "production", "cde", "FinTech Team"),
        ("Staging-Web-App", "hostname", "staging.corp.internal", "medium", "staging", "dmz", "QA Team")
    ]
    created_assets = []
    for name, t_type, t_val, crit, env, zone, owner in assets_data:
        asset = db.query(Asset).filter(Asset.target_value == t_val).first()
        if not asset:
            asset = Asset(
                name=name, target_type=t_type, target_value=t_val,
                criticality=crit, environment=env, network_zone=zone,
                owner=owner, authorized=True, created_at=now, updated_at=now
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)
        created_assets.append(asset)

    # 4. Scan Profiles
    prof = db.query(ScanProfile).filter(ScanProfile.name == "PCI-DSS Technical Control Audit").first()
    if not prof:
        prof = ScanProfile(
            name="PCI-DSS Technical Control Audit",
            description="Deep inspection of cardholder environments including TLS, cleartext protocols, and configuration",
            categories="network,tls,web,compliance",
            safe_mode=True,
            ports_mode="standard",
            timeout_seconds=1800,
            created_at=now
        )
        db.add(prof)
        db.commit()
        db.refresh(prof)

    # 5. Scan Job
    target_asset = created_assets[0]
    job = db.query(ScanJob).filter(ScanJob.title == "Automated Perimeter & Web Audit").first()
    if not job:
        job = ScanJob(
            title="Automated Perimeter & Web Audit",
            target=target_asset.target_value,
            asset_id=target_asset.id,
            profile_id=prof.id,
            status="completed",
            progress=100,
            started_at=now - 3600,
            finished_at=now - 3300,
            log_output="[INFO] Scan initialized.\n[INFO] Scope validation verified.\n[INFO] Running network discovery...\n[INFO] Found open ports: 80, 443, 22, 23.\n[INFO] Running TLS inspection...\n[INFO] Scan completed successfully.",
            summary_stats='{"Critical": 1, "High": 2, "Medium": 2, "Low": 1, "Info": 4}'
        )
        db.add(job)
        db.commit()
        db.refresh(job)

    # 6. Realistic Normalized Findings
    findings_data = [
        {
            "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
            "desc": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
            "sev": "Critical",
            "score": 10.0,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cve": "CVE-2021-44228",
            "cwe": "CWE-502",
            "comp": "Log4j-Core:8080",
            "port": 8080,
            "proto": "tcp",
            "evidence": "Observed vulnerable Log4j-core 2.14.1 jar package in web classpath.",
            "remed": "Upgrade to Apache Log4j 2.17.1 or higher immediately."
        },
        {
            "title": "Insecure Cleartext Protocol: Telnet Detected",
            "desc": "The Telnet service is active on port 23. Passwords and session data are sent unencrypted.",
            "sev": "High",
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cve": None,
            "cwe": "CWE-319",
            "comp": "Telnet:23",
            "port": 23,
            "proto": "tcp",
            "evidence": "Telnet service banner received: Cisco IOS Software Telnet Service.",
            "remed": "Disable Telnet service and enforce SSHv2 across all management lines."
        },
        {
            "title": "Deprecated TLS 1.0 / 1.1 Protocol Negotiation Allowed",
            "desc": "Server allows TLS 1.0/1.1 negotiation, violating PCI-DSS 4.0 technical controls.",
            "sev": "High",
            "score": 7.4,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cve": None,
            "cwe": "CWE-326",
            "comp": "TLS:443",
            "port": 443,
            "proto": "tcp",
            "evidence": "Handshake succeeded with TLSv1.0 (TLS_RSA_WITH_AES_128_CBC_SHA).",
            "remed": "Disable TLS 1.0 and 1.1 in web server and reverse proxy configs; require TLS 1.2+."
        },
        {
            "title": "Missing HTTP Strict Transport Security (HSTS) Header",
            "desc": "HSTS header is missing, allowing potential SSL stripping attacks.",
            "sev": "Medium",
            "score": 5.4,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cve": None,
            "cwe": "CWE-319",
            "comp": "HTTP:443",
            "port": 443,
            "proto": "tcp",
            "evidence": "Response headers lack Strict-Transport-Security.",
            "remed": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
        }
    ]

    for item in findings_data:
        fp = f"demo-{target_asset.id}-{item['title']}"
        if not db.query(Finding).filter(Finding.fingerprint == fp).first():
            f = Finding(
                asset_id=target_asset.id,
                job_id=job.id,
                fingerprint=fp,
                title=item["title"],
                description=item["desc"],
                severity=item["sev"],
                cvss_score=item["score"],
                cvss_vector=item["vector"],
                cve=item["cve"],
                cwe=item["cwe"],
                confidence="Confirmed",
                detection_method="automated-scanner",
                affected_component=item["comp"],
                port=item["port"],
                protocol=item["proto"],
                evidence=item["evidence"],
                remediation=item["remed"],
                status="Open",
                first_seen=now - 86400,
                last_seen=now
            )
            db.add(f)
            db.commit()
            db.refresh(f)

            # Create remediation task for Critical/High findings
            if item["sev"] in ["Critical", "High"]:
                db.add(RemediationTask(
                    finding_id=f.id,
                    title=f"Remediate: {f.title}",
                    priority="Urgent" if item["sev"] == "Critical" else "High",
                    assignee="SecOps Lead",
                    due_date="Within 48h (SLA)",
                    notes="Assigned via automated SLA policy.",
                    status="Open",
                    created_at=now,
                    updated_at=now
                ))
                db.commit()

    # 7. Compliance Baseline Results
    comp_rules = [
        ("CIS-Linux", "CIS-5.2.1", "Ensure SSH PermitRootLogin is disabled", "FAIL", "High", "PermitRootLogin yes", "PermitRootLogin no"),
        ("CIS-Linux", "CIS-5.2.2", "Ensure SSH Protocol version 2 is enforced", "PASS", "High", "Protocol 2", "Protocol 2"),
        ("CIS-Linux", "CIS-3.5.1", "Ensure host firewall is active", "PASS", "Medium", "firewalld active", "active"),
        ("PCI-DSS-4.0", "PCI-2.2.4", "Configure system security parameters to prevent misuse", "FAIL", "High", "Telnet active on port 23", "Insecure services disabled"),
    ]
    for fw, r_id, title, stat, sev, obs, exp in comp_rules:
        if not db.query(ComplianceResult).filter(ComplianceResult.rule_id == r_id, ComplianceResult.asset_id == target_asset.id).first():
            db.add(ComplianceResult(
                job_id=job.id,
                asset_id=target_asset.id,
                framework=fw,
                rule_id=r_id,
                title=title,
                status=stat,
                severity=sev,
                observed_value=obs,
                expected_value=exp,
                remediation=f"Review and apply hardening advisory for {r_id}",
                created_at=now
            ))
    db.commit()
    db.close()
    print("[SUCCESS] VulnForge Enterprise demo environment seeded successfully!")

if __name__ == "__main__":
    seed_demo_data()

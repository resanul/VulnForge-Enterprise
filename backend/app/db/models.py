import time
from sqlalchemy import Column, Integer, String, Boolean, Float, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from backend.app.db.base import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    full_name = Column(String(128), nullable=True)
    role = Column(String(32), default="analyst")  # admin, analyst, auditor, viewer
    is_active = Column(Boolean, default=True)
    mfa_enabled = Column(Boolean, default=False)
    created_at = Column(Integer, default=lambda: int(time.time()))
    last_login = Column(Integer, nullable=True)

class ApprovedScope(Base):
    __tablename__ = "approved_scopes"

    id = Column(Integer, primary_key=True, index=True)
    target_pattern = Column(String(256), nullable=False)  # CIDR, IP, or hostname domain
    description = Column(String(256), nullable=True)
    approved_by = Column(String(64), default="admin")
    is_active = Column(Boolean, default=True)
    created_at = Column(Integer, default=lambda: int(time.time()))

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    target_type = Column(String(32), default="ip")  # ip, hostname, cidr, url
    target_value = Column(String(256), nullable=False, index=True)
    ip_address = Column(String(64), nullable=True)
    criticality = Column(String(32), default="medium")  # critical, high, medium, low
    environment = Column(String(32), default="production")  # production, staging, development
    network_zone = Column(String(64), default="dmz")  # dmz, internal, cloud, edge
    owner = Column(String(128), nullable=True)
    tags = Column(String(256), default="")  # comma-separated tags
    authorized = Column(Boolean, default=True)
    created_at = Column(Integer, default=lambda: int(time.time()))
    updated_at = Column(Integer, default=lambda: int(time.time()))

    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")

class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    cred_type = Column(String(32), nullable=False)  # ssh_key, password, winrm, snmp, db, cloud
    username = Column(String(128), nullable=True)
    encrypted_secret = Column(Text, nullable=False)
    encrypted_passphrase = Column(Text, nullable=True)
    domain = Column(String(128), nullable=True)
    port = Column(Integer, nullable=True)
    extra_data = Column(Text, default="{}")  # JSON metadata (e.g. cloud region, DB name)
    created_at = Column(Integer, default=lambda: int(time.time()))
    updated_at = Column(Integer, default=lambda: int(time.time()))

class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    description = Column(String(256), nullable=True)
    categories = Column(Text, default="network,web,tls")  # comma-separated
    safe_mode = Column(Boolean, default=True)
    ports_mode = Column(String(32), default="standard")  # standard, fast, all, custom
    custom_ports = Column(String(256), nullable=True)
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    timeout_seconds = Column(Integer, default=1800)
    created_at = Column(Integer, default=lambda: int(time.time()))

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(128), nullable=False)
    target = Column(String(256), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=True)
    credential_id = Column(Integer, ForeignKey("credentials.id"), nullable=True)
    status = Column(String(32), default="pending")  # pending, running, completed, failed, cancelled
    progress = Column(Integer, default=0)
    started_at = Column(Integer, nullable=True)
    finished_at = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    log_output = Column(Text, default="")
    summary_stats = Column(Text, default="{}")  # JSON stats: critical, high, medium, low, info count

    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=True, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)  # composite hash for deduplication
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(32), nullable=False, index=True)  # Critical, High, Medium, Low, Info
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(128), nullable=True)
    cve = Column(String(64), nullable=True, index=True)
    cwe = Column(String(64), nullable=True)
    confidence = Column(String(32), default="Confirmed")  # Confirmed, Suspected, Tentative
    detection_method = Column(String(64), default="remote")
    is_credentialed = Column(Boolean, default=False)
    affected_component = Column(String(128), default="general")
    port = Column(Integer, nullable=True)
    protocol = Column(String(16), default="tcp")
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(String(32), default="Open")  # Open, Remediated, Accepted, Suppressed, FalsePositive
    first_seen = Column(Integer, default=lambda: int(time.time()))
    last_seen = Column(Integer, default=lambda: int(time.time()))
    suppression_reason = Column(String(256), nullable=True)
    suppression_expires_at = Column(Integer, nullable=True)

    asset = relationship("Asset", back_populates="findings")
    job = relationship("ScanJob", back_populates="findings")

    __table_args__ = (
        Index('idx_asset_fingerprint', 'asset_id', 'fingerprint', unique=True),
    )

class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("scan_jobs.id"), nullable=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    framework = Column(String(64), nullable=False)  # CIS, PCI-DSS, NIST-800-53
    rule_id = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="NOT_ASSESSED")  # PASS, FAIL, NA, NOT_ASSESSED
    severity = Column(String(32), default="Medium")
    observed_value = Column(Text, nullable=True)
    expected_value = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    created_at = Column(Integer, default=lambda: int(time.time()))

class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    title = Column(String(256), nullable=False)
    status = Column(String(32), default="Open")  # Open, In_Progress, Resolved, Closed
    priority = Column(String(32), default="Medium")  # Urgent, High, Medium, Low
    assignee = Column(String(128), default="Unassigned")
    due_date = Column(String(32), nullable=True)
    notes = Column(Text, default="")
    created_at = Column(Integer, default=lambda: int(time.time()))
    updated_at = Column(Integer, default=lambda: int(time.time()))

class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(64), nullable=False)
    user_id = Column(Integer, nullable=True)
    username = Column(String(64), default="system")
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(64), nullable=True)
    client_ip = Column(String(64), nullable=True)
    status = Column(String(32), default="SUCCESS")
    details_json = Column(Text, default="{}")
    created_at = Column(Integer, default=lambda: int(time.time()))

class ReportRecord(Base):
    __tablename__ = "report_records"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(128), nullable=False)
    report_type = Column(String(32), default="technical")  # executive, technical, compliance
    report_format = Column(String(16), default="html")  # html, json, csv, pdf
    file_path = Column(String(256), nullable=False)
    created_at = Column(Integer, default=lambda: int(time.time()))
    metadata_json = Column(Text, default="{}")

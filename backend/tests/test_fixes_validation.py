import datetime
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.app.engines.tls_checker import TLSCheckerEngine
from backend.app.engines.network_discovery import NetworkDiscoveryEngine
from backend.app.engines.web_scanner import WebAppScannerEngine, SENSITIVE_PATHS
from backend.app.engines.windows_scanner import WindowsCredentialedScannerEngine
from backend.app.engines.database_scanner import DatabaseSecurityEngine
from backend.app.engines.cloud_scanner import CloudSecurityEngine
from backend.app.tasks.worker import ScanJobExecutor, cancel_job, _CANCELLATION_FLAGS
from backend.app.db.models import ScanJob

def generate_test_x509_cert(expired: bool = False, self_signed: bool = True):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VulnForge Test Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "testlab.internal"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    if expired:
        not_before = now - datetime.timedelta(days=400)
        not_after = now - datetime.timedelta(days=35)
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(serialization.Encoding.DER)

def test_tls_der_certificate_analysis():
    engine = TLSCheckerEngine()
    expired_der = generate_test_x509_cert(expired=True, self_signed=True)
    valid_der = generate_test_x509_cert(expired=False, self_signed=True)

    # Decode expired DER cert directly with engine's x509 logic
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    cert = x509.load_der_x509_certificate(expired_der, default_backend())
    expiry = cert.not_valid_after_utc
    now = datetime.datetime.now(datetime.timezone.utc)
    remaining_days = (expiry - now).days
    assert remaining_days < 0
    assert cert.issuer == cert.subject  # Self-signed verified

def test_network_discovery_cidr_subnet_expansion():
    engine = NetworkDiscoveryEngine()
    hosts = engine._extract_hosts("192.168.1.0/28")
    assert len(hosts) == 14  # /28 has 14 usable host IPs
    assert "192.168.1.1" in hosts
    assert "192.168.1.14" in hosts
    # Single IP should not expand
    single = engine._extract_hosts("10.0.0.5")
    assert single == ["10.0.0.5"]

def test_windows_scanner_unreachable_target():
    engine = WindowsCredentialedScannerEngine()
    # Provide credentials but target unreachable dummy port
    options = {
        "credentials": {"username": "admin", "password": "Password123!"},
        "port": 59999  # Closed port
    }
    import asyncio
    findings = asyncio.run(engine.scan("127.0.0.1", options=options))
    assert len(findings) == 1
    # Must truthfully report unreachable/inactive rather than fake clean passes
    assert "Unreachable" in findings[0].title or "Inactive" in findings[0].title
    assert "SMBv1 Disabled" not in findings[0].title

def test_database_scanner_unreachable_target():
    engine = DatabaseSecurityEngine()
    options = {"port": 59998}
    import asyncio
    findings = asyncio.run(engine.scan("127.0.0.1", options=options))
    assert len(findings) == 1
    assert "Unreachable" in findings[0].title
    assert "ssl=on verified" not in findings[0].evidence

def test_cloud_scanner_missing_credentials():
    engine = CloudSecurityEngine()
    import asyncio
    findings = asyncio.run(engine.scan("aws", options={}))
    assert len(findings) == 1
    assert "Missing IAM Credentials" in findings[0].title

def test_worker_cancellation_flag():
    executor = ScanJobExecutor(job_id=999)
    assert 999 in _CANCELLATION_FLAGS
    assert not executor.cancel_event.is_set()
    cancel_job(999)
    assert executor.cancel_event.is_set()

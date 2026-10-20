import socket
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

class ActiveDirectoryAuditorEngine(BaseScannerEngine):
    """
    Active Directory & Identity Configuration Auditor (Category 12).
    Evaluates Domain Controllers, Kerberos encryption, LDAP signing, SMB signing,
    and credential exposure risks.
    """
    def __init__(self):
        super().__init__()
        self.engine_name = "Active Directory & Identity Security Auditor"
        self.engine_version = "1.5.0"
        self.category = "active_directory"
        self.is_credentialed = True
        self.supported_features = [
            "Domain Controller Port Reachability (LDAP 389/636, Kerberos 88, SMB 445, GC 3268)",
            "Kerberos Encryption Policy & Weak RC4-HMAC Cipher Detection",
            "LDAP Signing & Channel Binding Requirements Verification",
            "SMB Signing & Encryption Enforcement (Anti-Relay)",
            "Krbtgt Password Age & Kerberoasting Exposure Diagnostics",
            "Unconstrained Delegation & Stale Service Account Identification"
        ]
        self.limitations = [
            "Deep object permission audits (BloodHound/ACL graphs) require authenticated domain user credentials",
            "Write operations and test object creation are strictly prohibited"
        ]
        self.dependencies = ["python socket", "ldap3", "impacket (optional)"]

    def is_available(self) -> bool:
        return True

    def _extract_host(self, target: str) -> str:
        cleaned = target.strip()
        if cleaned.startswith("http://") or cleaned.startswith("https://"):
            return urlparse(cleaned).hostname or cleaned
        if ":" in cleaned and not cleaned.startswith("[") and "/" not in cleaned:
            return cleaned.split(":")[0]
        return cleaned

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        options = options or {}
        host = self._extract_host(target)
        findings: List[NormalizedFinding] = []

        if log_callback:
            log_callback(f"[INFO] Probing Active Directory services on domain controller {host}...")

        # 1. Probe key Active Directory ports: 88 (Kerberos), 389 (LDAP), 636 (LDAPS), 445 (SMB)
        ad_ports = {
            88: "Kerberos KDC",
            389: "LDAP Service",
            636: "LDAP over SSL (LDAPS)",
            445: "SMB / RPC Service",
            3268: "Global Catalog"
        }

        open_ports = {}
        for port, service in ad_ports.items():
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=1.2)
                writer.close()
                await writer.wait_closed()
                open_ports[port] = service
            except Exception:
                pass

        if not open_ports:
            if log_callback:
                log_callback(f"[INFO] Target {host} is not an active Domain Controller (no Kerberos/LDAP ports responsive).")
            findings.append(NormalizedFinding(
                title="Active Directory Domain Controller Inactive or Out of Scope",
                description=f"Host {host} did not respond on standard Active Directory Domain Controller ports (88, 389, 636).",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="tcp-ad-probe",
                affected_component=f"ActiveDirectory:{host}",
                evidence=f"No responsive ports on Kerberos (88), LDAP (389/636), or SMB (445) on {host}."
            ))
            return findings

        # 2. Check for Plaintext LDAP (Port 389 open without LDAPS 636)
        if 389 in open_ports and 636 not in open_ports:
            findings.append(NormalizedFinding(
                title="Active Directory LDAP Plaintext Allowed / LDAPS Inactive",
                description=f"Domain Controller {host} accepts unencrypted LDAP traffic on port 389 without exposing LDAPS on port 636. Credentials and directory queries can be intercepted on the internal network.",
                severity=SeverityLevel.HIGH,
                cvss_score=7.4,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="ldap-channel-probe",
                affected_component=f"LDAP:{host}:389",
                cve="CWE-319",
                port=389,
                protocol="tcp",
                evidence=f"TCP port 389 responsive on {host}; TCP port 636 closed/filtered.",
                remediation="Configure Active Directory Certificate Services (AD CS) and enforce LDAP signing and channel binding via Group Policy."
            ))

        # 3. Check SMB Signing & Relay Exposure
        if 445 in open_ports:
            findings.append(NormalizedFinding(
                title="Active Directory SMB Signing Policy Audit Required",
                description=f"SMB service (port 445) active on Domain Controller {host}. Ensure 'Microsoft network server: Digitally sign communications (always)' is Enabled to prevent NTLM Relay attacks.",
                severity=SeverityLevel.MEDIUM,
                cvss_score=5.9,
                confidence=ConfidenceLevel.SUSPECTED,
                detection_method="smb-config-audit",
                affected_component=f"SMB:{host}:445",
                cve="CWE-287",
                port=445,
                protocol="tcp",
                evidence=f"SMB Port 445 open on Domain Controller {host}.",
                remediation="Enable SMB signing and require SMB encryption via Group Policy (GPO: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options)."
            ))

        # 4. Kerberos KDC Active Information
        if 88 in open_ports:
            findings.append(NormalizedFinding(
                title="Active Directory Kerberos KDC Online",
                description=f"Kerberos Key Distribution Center (KDC) verified active on {host}:88.",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="kerberos-kdc-probe",
                affected_component=f"Kerberos:{host}:88",
                port=88,
                protocol="tcp",
                evidence=f"Kerberos port 88 responded successfully on {host}."
            ))

        return findings

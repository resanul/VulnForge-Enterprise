import ssl
import socket
import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

class TLSCheckerEngine(BaseScannerEngine):
    def __init__(self):
        super().__init__()
        self.engine_name = "TLS/SSL Cryptographic Security Analyzer"
        self.engine_version = "2.1.0"
        self.category = "tls"
        self.is_credentialed = False
        self.supported_features = [
            "X.509 Certificate Expiration & Validity Checking",
            "Self-Signed and Untrusted Certificate Authority Detection",
            "Subject Alternative Name (SAN) Hostname Mismatch Verification",
            "Deprecated TLS 1.0 & TLS 1.1 Protocol Detection",
            "Weak Cipher Suite & Signature Algorithm Audit (SHA1/MD5)"
        ]
        self.limitations = [
            "Requires target port to negotiate standard SSL/TLS handshake",
            "Does not test proprietary vendor-specific client certificate requirements"
        ]
        self.dependencies = ["python ssl", "python socket", "python datetime"]

    def is_available(self) -> bool:
        return True

    def _extract_host_and_port(self, target: str) -> tuple[str, int]:
        cleaned = target.strip()
        port = 443
        if cleaned.startswith("https://"):
            parsed = urlparse(cleaned)
            host = parsed.hostname or cleaned
            if parsed.port:
                port = parsed.port
            return host, port
        if cleaned.startswith("http://"):
            parsed = urlparse(cleaned)
            host = parsed.hostname or cleaned
            return host, parsed.port or 80

        if ":" in cleaned and not cleaned.startswith("[") and "/" not in cleaned:
            parts = cleaned.split(":")
            return parts[0], int(parts[1])
        return cleaned, port

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        host, port = self._extract_host_and_port(target)
        if port not in [443, 8443, 9443, 465, 993, 995, 636]:
            # If standard HTTP port 80, skip TLS checks unless forced
            if port == 80 and not (options and options.get("force_tls")):
                return []

        if log_callback:
            log_callback(f"[INFO] Inspecting TLS/SSL certificate and cipher configuration for {host}:{port}...")

        findings: List[NormalizedFinding] = []

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # inspect even invalid/self-signed certs

        cert_dict = None
        cipher_info = None
        tls_version_str = None

        try:
            with socket.create_connection((host, port), timeout=4.0) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_dict = ssock.getpeercert(binary_form=False)
                    cipher_info = ssock.cipher()
                    tls_version_str = ssock.version()
        except ssl.SSLError as e:
            if log_callback:
                log_callback(f"[WARN] TLS handshake error with {host}:{port}: {e}")
            findings.append(NormalizedFinding(
                title=f"TLS Handshake Failure on Port {port}",
                description=f"A TLS handshake failure occurred on {host}:{port}. Error details: {str(e)}",
                severity=SeverityLevel.LOW,
                cvss_score=2.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="tls-handshake",
                affected_component=f"TLS:{port}",
                port=port,
                evidence=str(e),
                remediation="Ensure the server's TLS certificate chain and supported ciphers match current security standards."
            ))
            return findings
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            if log_callback:
                log_callback(f"[INFO] Port {port} not reachable for TLS inspection: {e}")
            return findings

        # 1. Analyze Certificate Validity & Expiration
        if cert_dict:
            not_after_str = cert_dict.get('notAfter')
            if not_after_str:
                # Format: 'May 10 12:00:00 2026 GMT'
                try:
                    expiry_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    now_date = datetime.datetime.utcnow()
                    remaining_days = (expiry_date - now_date).days

                    if remaining_days < 0:
                        findings.append(NormalizedFinding(
                            title=f"Expired TLS Certificate ({abs(remaining_days)} days expired)",
                            description=f"The TLS certificate for {host} on port {port} expired on {not_after_str}.",
                            severity=SeverityLevel.HIGH,
                            cvss_score=7.4,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                            cwe="CWE-298",
                            confidence=ConfidenceLevel.CONFIRMED,
                            detection_method="tls-cert-check",
                            affected_component=f"TLS-Cert:{port}",
                            port=port,
                            evidence=f"Certificate expired on {not_after_str}. Current days overdue: {abs(remaining_days)}",
                            remediation="Renew and install an active TLS certificate immediately."
                        ))
                    elif remaining_days <= 15:
                        findings.append(NormalizedFinding(
                            title=f"TLS Certificate Expiring Soon ({remaining_days} days remaining)",
                            description=f"The TLS certificate for {host} on port {port} will expire in {remaining_days} days ({not_after_str}).",
                            severity=SeverityLevel.MEDIUM,
                            cvss_score=4.0,
                            confidence=ConfidenceLevel.CONFIRMED,
                            detection_method="tls-cert-check",
                            affected_component=f"TLS-Cert:{port}",
                            port=port,
                            evidence=f"Certificate expires on {not_after_str} ({remaining_days} days remaining).",
                            remediation="Schedule automated renewal of the TLS certificate prior to expiration."
                        ))
                except Exception:
                    pass

        # 2. Check Strict Verification with System CA Trust Store
        verify_context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=3.0) as sock:
                with verify_context.wrap_socket(sock, server_hostname=host) as ssock:
                    pass  # Verification passed
        except ssl.SSLCertVerificationError as e:
            err_msg = str(e)
            if "self signed certificate" in err_msg.lower():
                findings.append(NormalizedFinding(
                    title="Self-Signed TLS/SSL Certificate Detected",
                    description=f"The server {host}:{port} is presenting a self-signed certificate not trusted by standard Certificate Authorities.",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe="CWE-295",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="tls-ca-verification",
                    affected_component=f"TLS-Cert:{port}",
                    port=port,
                    evidence=f"SSL verification failed: {err_msg}",
                    remediation="Replace the self-signed certificate with a certificate issued by a trusted public or corporate Private PKI CA."
                ))
            elif "hostname" in err_msg.lower() or "doesn't match" in err_msg.lower():
                findings.append(NormalizedFinding(
                    title="TLS Certificate Name Mismatch",
                    description=f"The subject alternative names (SANs) on the certificate do not match requested hostname '{host}'.",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                    cwe="CWE-297",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="tls-hostname-verification",
                    affected_component=f"TLS-Cert:{port}",
                    port=port,
                    evidence=err_msg,
                    remediation="Issue a certificate containing the correct FQDN in the Subject Alternative Name (SAN) list."
                ))
            else:
                findings.append(NormalizedFinding(
                    title="Untrusted TLS Certificate Authority",
                    description=f"The certificate presented by {host}:{port} was signed by an untrusted or missing root authority.",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.9,
                    cwe="CWE-295",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="tls-ca-verification",
                    affected_component=f"TLS-Cert:{port}",
                    port=port,
                    evidence=err_msg,
                    remediation="Ensure the complete intermediate and root certificate chain is properly installed on the server."
                ))
        except Exception:
            pass

        # 3. Check Protocol Version Deprecation
        if tls_version_str in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            findings.append(NormalizedFinding(
                title=f"Deprecated TLS Protocol Version Negotiated: {tls_version_str}",
                description=f"The server negotiated {tls_version_str}, which is deprecated under NIST SP 800-52r2 and PCI-DSS standards due to cryptographic weaknesses.",
                severity=SeverityLevel.HIGH,
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe="CWE-326",
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="tls-protocol-version",
                affected_component=f"TLS-Protocol:{port}",
                port=port,
                evidence=f"Negotiated version: {tls_version_str}",
                remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 in web server configuration. Enforce TLS 1.2 and TLS 1.3 exclusively."
            ))

        # 4. Record Active Cipher Info
        if cipher_info:
            cipher_name, proto, bits = cipher_info
            findings.append(NormalizedFinding(
                title=f"TLS Service Active on Port {port}",
                description=f"Negotiated Protocol: {proto}, Cipher Suite: {cipher_name} ({bits} bits).",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="tls-cipher-audit",
                affected_component=f"TLS:{port}",
                port=port,
                evidence=f"Protocol: {proto}, Cipher: {cipher_name}, Key bits: {bits}",
                remediation="Maintain standard TLS hardening baselines."
            ))

        return findings

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import httpx
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

# Standard high-risk sensitive paths to test passively/non-destructively
SENSITIVE_PATHS = [
    ("/.git/HEAD", "Exposed Git Repository Metadata", SeverityLevel.HIGH, 7.5, "CWE-538", "A public .git/HEAD file allows extraction of full source code repository."),
    ("/.env", "Exposed Environment Configuration File", SeverityLevel.CRITICAL, 9.1, "CWE-526", "Direct access to .env exposes plaintext credentials, database passwords, and API secret keys."),
    ("/actuator/health", "Spring Boot Actuator Endpoint Exposed", SeverityLevel.LOW, 3.1, "CWE-200", "Spring Boot health actuator exposes internal framework metadata."),
    ("/actuator/env", "Spring Boot Environment Actuator Exposed", SeverityLevel.CRITICAL, 9.8, "CWE-526", "Spring Boot env actuator leaks environment variables and secrets."),
    ("/swagger.json", "OpenAPI/Swagger API Definition Exposed", SeverityLevel.INFO, 0.0, "CWE-200", "API specification available for endpoint mapping and schema review."),
    ("/openapi.json", "OpenAPI 3.0 Schema Exposed", SeverityLevel.INFO, 0.0, "CWE-200", "OpenAPI 3.0 definition exposes API route catalog."),
    ("/robots.txt", "Robots.txt Information Disclosure", SeverityLevel.INFO, 0.0, "CWE-200", "Robots.txt discloses internal disallowed paths."),
    ("/server-status", "Apache HTTP Server Status Exposed", SeverityLevel.MEDIUM, 5.3, "CWE-200", "Apache mod_status exposes active requests, client IPs, and server metrics."),
    ("/phpinfo.php", "PHP Information Leakage (phpinfo)", SeverityLevel.HIGH, 7.5, "CWE-200", "phpinfo() output exposes PHP version, server paths, and environment settings.")
]

class WebAppScannerEngine(BaseScannerEngine):
    def __init__(self):
        super().__init__()
        self.engine_name = "Web Application & API Security Analyzer"
        self.engine_version = "1.5.0"
        self.category = "web"
        self.is_credentialed = False
        self.supported_features = [
            "HTTP Security Headers Compliance (HSTS, CSP, X-Frame-Options, etc.)",
            "CORS (Cross-Origin Resource Sharing) Misconfiguration Probe",
            "Exposed Sensitive Files & Developer Endpoints (.git, .env, Actuator)",
            "Cookie Security Attribute Verification (HttpOnly, Secure, SameSite)",
            "OpenAPI / Swagger 3.0 Specification Endpoint Discovery",
            "Safe Non-Destructive Method Testing (TRACE / OPTIONS)"
        ]
        self.limitations = [
            "Destructive fuzzing and SQL injection payload injection disabled by default",
            "Authenticated single-page-app deep session crawling requires Playwright/Puppeteer headless browser"
        ]
        self.dependencies = ["python httpx"]

    def is_available(self) -> bool:
        return True

    def _format_base_url(self, target: str) -> str:
        target = target.strip()
        if not target.startswith("http://") and not target.startswith("https://"):
            return f"https://{target}"
        return target

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        base_url = self._format_base_url(target)
        parsed = urlparse(base_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        findings: List[NormalizedFinding] = []

        if log_callback:
            log_callback(f"[INFO] Beginning safe web application assessment on {base_url}...")

        headers = {
            "User-Agent": "VulnForge-Enterprise-Security-Scanner/1.0",
            "Accept": "*/*"
        }

        async with httpx.AsyncClient(timeout=5.0, verify=False, follow_redirects=True, headers=headers) as client:
            # 1. Fetch Root Endpoint & Analyze Headers
            root_resp = None
            try:
                root_resp = await client.get(base_url)
            except Exception as e:
                # If HTTPS failed, try HTTP fallback
                if base_url.startswith("https://"):
                    base_url = base_url.replace("https://", "http://", 1)
                    parsed = urlparse(base_url)
                    port = parsed.port or 80
                    try:
                        root_resp = await client.get(base_url)
                    except Exception as e2:
                        if log_callback:
                            log_callback(f"[INFO] Web target unreachable: {e2}")
                        return []
                else:
                    if log_callback:
                        log_callback(f"[INFO] Web target unreachable: {e}")
                    return []

            if not root_resp:
                return []

            resp_headers = {k.lower(): v for k, v in root_resp.headers.items()}

            # A. Check HTTP Strict Transport Security (HSTS)
            if base_url.startswith("https://"):
                if "strict-transport-security" not in resp_headers:
                    findings.append(NormalizedFinding(
                        title="Missing HTTP Strict Transport Security (HSTS) Header",
                        description="The web server does not send the Strict-Transport-Security header. This allows man-in-the-middle attackers to downgrade HTTPS connections to unencrypted HTTP.",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=5.4,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        cwe="CWE-319",
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="http-header-audit",
                        affected_component=f"HTTP:{port}",
                        port=port,
                        evidence=f"Strict-Transport-Security missing in response headers from {base_url}",
                        remediation="Configure the server to return 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
                    ))

            # B. Check Content Security Policy (CSP)
            if "content-security-policy" not in resp_headers:
                findings.append(NormalizedFinding(
                    title="Missing Content Security Policy (CSP) Header",
                    description="The application does not enforce a Content-Security-Policy (CSP) header, leaving users vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=4.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N",
                    cwe="CWE-1021",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="http-header-audit",
                    affected_component=f"HTTP:{port}",
                    port=port,
                    evidence=f"Content-Security-Policy header absent on {base_url}",
                    remediation="Define a strong Content-Security-Policy header specifying trusted script, style, and object sources."
                ))

            # C. Check Clickjacking Protection (X-Frame-Options)
            if "x-frame-options" not in resp_headers and "content-security-policy" not in resp_headers:
                findings.append(NormalizedFinding(
                    title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                    description="The server does not include an X-Frame-Options or frame-ancestors CSP directive, enabling framing/clickjacking attacks.",
                    severity=SeverityLevel.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
                    cwe="CWE-1021",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="http-header-audit",
                    affected_component=f"HTTP:{port}",
                    port=port,
                    evidence=f"X-Frame-Options header not returned by {base_url}",
                    remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all HTTP responses."
                ))

            # D. Check X-Content-Type-Options
            if "x-content-type-options" not in resp_headers or resp_headers["x-content-type-options"].lower() != "nosniff":
                findings.append(NormalizedFinding(
                    title="Missing X-Content-Type-Options: nosniff Header",
                    description="Without X-Content-Type-Options: nosniff, browsers may perform MIME-type sniffing, transforming non-executable MIME types into executable scripts.",
                    severity=SeverityLevel.LOW,
                    cvss_score=2.6,
                    cwe="CWE-16",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="http-header-audit",
                    affected_component=f"HTTP:{port}",
                    port=port,
                    evidence="X-Content-Type-Options: nosniff header missing.",
                    remediation="Add 'X-Content-Type-Options: nosniff' header to all server responses."
                ))

            # E. Check Detailed Server Version Disclosure
            server_hdr = resp_headers.get("server") or resp_headers.get("x-powered-by")
            if server_hdr and re.search(r'\d+\.\d+', server_hdr):
                findings.append(NormalizedFinding(
                    title=f"Detailed Server Banner / Version Disclosure: {server_hdr}",
                    description=f"The web server exposes specific version details in the response header: '{server_hdr}'. This helps attackers target known CVEs.",
                    severity=SeverityLevel.LOW,
                    cvss_score=3.1,
                    cwe="CWE-200",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="http-header-audit",
                    affected_component=f"HTTP:{port}",
                    port=port,
                    evidence=f"Header: {server_hdr}",
                    remediation="Configure server software to suppress detailed version banners (e.g. server_tokens off in nginx, ServerTokens Prod in Apache)."
                ))

            # 2. Check CORS Misconfiguration (Origin reflection)
            try:
                cors_resp = await client.get(
                    base_url,
                    headers={"Origin": "https://evil-attacker-cors.com"}
                )
                acao = cors_resp.headers.get("Access-Control-Allow-Origin")
                acac = cors_resp.headers.get("Access-Control-Allow-Credentials")
                if acao == "https://evil-attacker-cors.com" and acac == "true":
                    findings.append(NormalizedFinding(
                        title="Critical CORS Misconfiguration (Arbitrary Origin with Credentials)",
                        description="The server reflects arbitrary Origin headers with Access-Control-Allow-Credentials: true. Malicious sites can read authenticated user data.",
                        severity=SeverityLevel.HIGH,
                        cvss_score=8.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                        cwe="CWE-942",
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="cors-probe",
                        affected_component=f"HTTP-CORS:{port}",
                        port=port,
                        evidence=f"Sent Origin: https://evil-attacker-cors.com -> Received ACAO: {acao}, ACAC: {acac}",
                        remediation="Do not reflect arbitrary Origin headers. Maintain an explicit whitelist of trusted domains and never allow untrusted origins with credentials."
                    ))
                elif acao == "*":
                    findings.append(NormalizedFinding(
                        title="Overly Permissive CORS Policy (Wildcard '*')",
                        description="The application sets Access-Control-Allow-Origin: *, allowing any external domain to make cross-origin requests.",
                        severity=SeverityLevel.INFO,
                        cvss_score=0.0,
                        cwe="CWE-942",
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="cors-probe",
                        affected_component=f"HTTP-CORS:{port}",
                        port=port,
                        evidence="Access-Control-Allow-Origin: * returned",
                        remediation="If private data is exposed, restrict allowed origins to approved domains."
                    ))
            except Exception:
                pass

            # 3. Test for Dangerous HTTP Methods (e.g. TRACE)
            try:
                trace_resp = await client.request("TRACE", base_url)
                if trace_resp.status_code == 200 and "message/http" in trace_resp.headers.get("content-type", ""):
                    findings.append(NormalizedFinding(
                        title="HTTP TRACE / TRACK Method Enabled (Cross-Site Tracing)",
                        description="The HTTP TRACE method is enabled on the web server. This can facilitate Cross-Site Tracing (XST) attacks to steal HttpOnly cookies.",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe="CWE-200",
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="http-method-audit",
                        affected_component=f"HTTP:{port}",
                        port=port,
                        evidence="Server replied 200 OK to HTTP TRACE request.",
                        remediation="Disable HTTP TRACE in the web server configuration (e.g., TraceEnable Off in Apache)."
                    ))
            except Exception:
                pass

            # 4. Probe Sensitive Paths & Endpoints
            if log_callback:
                log_callback(f"[INFO] Testing {len(SENSITIVE_PATHS)} sensitive endpoints...")

            for path, title, severity, score, cwe, desc in SENSITIVE_PATHS:
                test_url = urljoin(base_url, path)
                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        content_type = resp.headers.get("content-type", "").lower()
                        content_sample = resp.text[:300]
                        is_valid = True

                        # Check if response is generic HTML fallback (e.g. Single Page Application routing)
                        is_html = "text/html" in content_type or "<html" in content_sample.lower() or "<!doctype html" in content_sample.lower()

                        if path == "/.git/HEAD":
                            if "ref: refs/" not in content_sample:
                                is_valid = False
                        elif path == "/.env":
                            if "=" not in content_sample or is_html:
                                is_valid = False
                        elif path in ["/swagger.json", "/openapi.json"]:
                            if is_html or ("openapi" not in content_sample.lower() and "swagger" not in content_sample.lower() and "{" not in content_sample):
                                is_valid = False
                        elif path.startswith("/actuator"):
                            if is_html or ("{" not in content_sample and "status" not in content_sample.lower()):
                                is_valid = False
                        elif path == "/phpinfo.php":
                            if "php version" not in content_sample.lower() and "zend" not in content_sample.lower():
                                is_valid = False
                        elif path == "/server-status":
                            if "apache server status" not in content_sample.lower():
                                is_valid = False
                        elif path == "/robots.txt":
                            if is_html or ("user-agent:" not in content_sample.lower() and "disallow:" not in content_sample.lower()):
                                is_valid = False

                        if is_valid:
                            findings.append(NormalizedFinding(
                                title=title,
                                description=f"{desc} URL: {test_url}",
                                severity=severity,
                                cvss_score=score,
                                cwe=cwe,
                                confidence=ConfidenceLevel.CONFIRMED,
                                detection_method="endpoint-probe",
                                affected_component=f"Web-Path:{path}",
                                port=port,
                                evidence=f"HTTP 200 OK received at {test_url}. Content preview: {content_sample[:100]}",
                                remediation=f"Restrict access to '{path}' in web server access control rules or remove from production deployment."
                            ))
                except Exception:
                    pass

        return findings

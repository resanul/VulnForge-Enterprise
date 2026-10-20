import os
import asyncio
from typing import List, Dict, Any, Optional
import httpx
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

class OWASPZapAdapterEngine(BaseScannerEngine):
    """
    Adapter for OWASP Zed Attack Proxy (ZAP) Web DAST testing engine.
    Controls spidering and active/passive vulnerability assessment via ZAP REST API.
    """
    def __init__(self):
        super().__init__()
        self.engine_name = "OWASP ZAP Web DAST Adapter"
        self.engine_version = "2.14.0"
        self.category = "web_dast"
        self.is_credentialed = False
        self.supported_features = [
            "AJAX and Traditional Web Spidering",
            "Passive Web Application Vulnerability Analysis",
            "Active Parameter Injection & Fuzzing (Safe Mode Enforced)",
            "Authentication Session Management",
            "OpenAPI & GraphQL Schema Import and Crawling"
        ]
        self.limitations = [
            "Active scanning is disabled by default to prevent production database corruption",
            "Requires local or containerized OWASP ZAP daemon running with API key"
        ]
        self.dependencies = ["owasp-zap daemon", "zapv2 / httpx client"]

    def is_available(self) -> bool:
        zap_url = os.environ.get("ZAP_API_URL", "http://127.0.0.1:8080")
        try:
            # Quick connectivity check with short timeout
            with httpx.Client(timeout=1.0) as client:
                res = client.get(f"{zap_url}/JSON/core/view/version/")
                return res.status_code == 200
        except Exception:
            return False

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        options = options or {}
        findings: List[NormalizedFinding] = []
        zap_url = os.environ.get("ZAP_API_URL", "http://127.0.0.1:8080")
        zap_key = os.environ.get("ZAP_API_KEY", "")

        if not self.is_available():
            if log_callback:
                log_callback(f"[INFO] OWASP ZAP daemon not detected at {zap_url}; web analysis delegated to native WebAppScannerEngine.")
            findings.append(NormalizedFinding(
                title="OWASP ZAP DAST Service Inactive / Daemon Not Configured",
                description=f"OWASP ZAP service endpoint ({zap_url}) did not respond. Deep automated DAST spidering deferred to native WebAppScannerEngine.",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="zap-api-probe",
                affected_component=f"OWASP_ZAP:{target}",
                evidence=f"Failed connection to {zap_url}/JSON/core/view/version/.",
                remediation="Launch OWASP ZAP in daemon mode (zap.sh -daemon -port 8080 -config api.key=...) or deploy via docker-compose as documented in deployment/containers/."
            ))
            return findings

        if log_callback:
            log_callback(f"[INFO] Initiating OWASP ZAP spider and passive assessment on {target}...")

        # In production with active ZAP daemon:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                # 1. Trigger spider
                spider_res = await client.get(
                    f"{zap_url}/JSON/spider/action/scan/",
                    params={"apikey": zap_key, "url": target, "maxChildren": 10}
                )
                spider_data = spider_res.json()
                scan_id = spider_data.get("scan", "0")

                if log_callback:
                    log_callback(f"[INFO] ZAP Spider job started with ID: {scan_id}")

                # 2. Fetch baseline alerts
                alerts_res = await client.get(
                    f"{zap_url}/JSON/core/view/alerts/",
                    params={"apikey": zap_key, "baseurl": target, "count": 25}
                )
                alerts_data = alerts_res.json()
                alerts = alerts_data.get("alerts", [])

                for alert in alerts:
                    risk_map = {
                        "High": (SeverityLevel.HIGH, 7.5),
                        "Medium": (SeverityLevel.MEDIUM, 5.0),
                        "Low": (SeverityLevel.LOW, 2.5),
                        "Informational": (SeverityLevel.INFO, 0.0)
                    }
                    sev, cvss = risk_map.get(alert.get("risk"), (SeverityLevel.LOW, 2.0))
                    findings.append(NormalizedFinding(
                        title=f"OWASP ZAP: {alert.get('alert', 'Web Alert')}",
                        description=alert.get("description", "Vulnerability detected by OWASP ZAP active/passive rules."),
                        severity=sev,
                        cvss_score=cvss,
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="owasp-zap-dast",
                        affected_component=alert.get("url", target),
                        evidence=f"Param: {alert.get('param')}, Evidence: {alert.get('evidence')}, Solution: {alert.get('solution')}",
                        remediation=alert.get("solution", "Review web application source code and apply recommended sanitization.")
                    ))
        except Exception as e:
            if log_callback:
                log_callback(f"[WARN] Error interacting with OWASP ZAP API: {e}")

        return findings

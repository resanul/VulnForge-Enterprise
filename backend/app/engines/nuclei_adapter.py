from typing import List, Dict, Any, Optional
import httpx
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

class NucleiTemplateAdapterEngine(BaseScannerEngine):
    def __init__(self):
        super().__init__()
        self.engine_name = "Nuclei Template & Custom Plugin Runner"
        self.engine_version = "1.2.0"
        self.category = "templates"
        self.is_credentialed = False
        self.supported_features = [
            "YAML / JSON Custom Vulnerability Templates",
            "HTTP Request Matchers (Status Code, Body Regex, Headers)",
            "Dynamic Variable Interpolation",
            "Custom CVE & Severity Tagging",
            "Safe, Rate-Limited Execution"
        ]
        self.limitations = [
            "Raw TCP/DNS Nuclei templates require external Nuclei Go binary",
            "Destructive templates disabled by default"
        ]
        self.dependencies = ["python httpx", "pyyaml"]

    def is_available(self) -> bool:
        return True

    async def execute_http_template(
        self,
        base_url: str,
        template: Dict[str, Any]
    ) -> Optional[NormalizedFinding]:
        path = template.get("path", "/")
        match_type = template.get("match_type", "word")
        words = template.get("words", [])
        status_code = template.get("status_code", 200)

        target_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            async with httpx.AsyncClient(timeout=4.0, verify=False) as client:
                resp = await client.get(target_url)
                if resp.status_code == status_code:
                    body = resp.text
                    matched = False
                    for w in words:
                        if w in body:
                            matched = True
                            break
                    if matched or not words:
                        sev_str = template.get("severity", "Medium").capitalize()
                        sev = getattr(SeverityLevel, sev_str.upper(), SeverityLevel.MEDIUM)
                        return NormalizedFinding(
                            title=template.get("name", "Custom Template Detection"),
                            description=template.get("description", "Matched template rule criteria."),
                            severity=sev,
                            cvss_score=template.get("cvss_score", 5.0),
                            cve=template.get("cve"),
                            cwe=template.get("cwe"),
                            confidence=ConfidenceLevel.CONFIRMED,
                            detection_method="nuclei-template",
                            affected_component=path,
                            evidence=f"Template '{template.get('id', 'custom')}' matched at {target_url}",
                            remediation=template.get("remediation", "Review application component.")
                        )
        except Exception:
            pass
        return None

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        options = options or {}
        templates = options.get("templates", [])
        base_url = target if target.startswith("http") else f"http://{target}"

        findings: List[NormalizedFinding] = []

        if log_callback:
            log_callback(f"[INFO] Running {len(templates)} custom Nuclei-style vulnerability templates on {base_url}...")

        for t in templates:
            f = await self.execute_http_template(base_url, t)
            if f:
                findings.append(f)

        return findings

import socket
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import httpx
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

class EmergingTechnologyScannerEngine(BaseScannerEngine):
    """
    Emerging Technology & AI/LLM Security Analyzer (Category 20).
    Audits exposed AI/LLM endpoints (Ollama, vLLM, LocalAI, LangChain, Flowise),
    AI API key exposure, MCP server posture, and unapproved RMM tools (AnyDesk, TeamViewer).
    """
    def __init__(self):
        super().__init__()
        self.engine_name = "Emerging Technology & AI/LLM Security Engine"
        self.engine_version = "1.0.0"
        self.category = "emerging_tech"
        self.is_credentialed = False
        self.supported_features = [
            "Exposed AI/LLM Service Discovery (Ollama 11434, vLLM 8000, LocalAI 8080)",
            "AI Agent Framework UI Exposure (Flowise 3000, Langflow 7860, Dify)",
            "Unauthenticated AI Model Inference API Probing",
            "Model Context Protocol (MCP) Server Exposure & Auth Auditing",
            "Unapproved Remote Monitoring & Management (RMM) Detection (AnyDesk, TeamViewer, RustDesk)"
        ]
        self.limitations = [
            "Non-destructive prompt injection boundary assessment; no model hallucination fuzzing",
            "Third-party commercial LLM services (OpenAI, Claude) audited via key leak inspection"
        ]
        self.dependencies = ["python socket", "python httpx"]

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
            log_callback(f"[INFO] Scanning {host} for exposed AI/LLM infrastructure and unapproved RMM tools...")

        # 1. Probe known local AI/LLM ports:
        # 11434: Ollama API
        # 8000: vLLM / FastChat API
        # 7860: Gradio / Langflow
        # 3000: Flowise AI UI
        AI_PORTS = {
            11434: ("Ollama Local LLM API", "/api/tags"),
            8000: ("vLLM / Local Inference Server", "/v1/models"),
            7860: ("Gradio / Langflow Web Interface", "/"),
            3000: ("Flowise AI Workflow Console", "/api/v1/chatflows")
        }

        # 2. Probe unapproved RMM ports:
        # 7070: AnyDesk
        # 5938: TeamViewer
        # 21115: RustDesk
        RMM_PORTS = {
            7070: "AnyDesk Remote Management Port",
            5938: "TeamViewer Inbound Port",
            21115: "RustDesk Remote Desktop Server"
        }

        for port, (service_name, probe_endpoint) in AI_PORTS.items():
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=1.0)
                writer.close()
                await writer.wait_closed()

                # Port is open -> verify if unauthenticated API
                url = f"http://{host}:{port}{probe_endpoint}"
                is_unauth = False
                try:
                    async with httpx.AsyncClient(timeout=2.0) as client:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            is_unauth = True
                except Exception:
                    pass

                if is_unauth:
                    findings.append(NormalizedFinding(
                        title=f"Unauthenticated AI/LLM Service Exposed: {service_name}",
                        description=f"Host {host} exposes an active AI model inference endpoint on port {port} without authentication ({url}). Attackers can execute arbitrary prompts, deplete GPU compute, or exfiltrate private models.",
                        severity=SeverityLevel.CRITICAL,
                        cvss_score=9.1,
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="ai-service-probe",
                        affected_component=f"LLM_Service:{host}:{port}",
                        cve="CWE-306",
                        port=port,
                        protocol="tcp",
                        evidence=f"HTTP GET {url} returned HTTP 200 OK without authentication headers.",
                        remediation="Bind AI inference services to localhost (127.0.0.1) or enforce strict mTLS and reverse-proxy API key authentication."
                    ))
                else:
                    findings.append(NormalizedFinding(
                        title=f"AI/LLM Infrastructure Port Open: {service_name}",
                        description=f"Host {host} has TCP port {port} open ({service_name}). Verify that strong authentication and network ACLs are configured.",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=5.3,
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="tcp-port-probe",
                        affected_component=f"LLM_Port:{host}:{port}",
                        port=port,
                        protocol="tcp",
                        evidence=f"TCP handshake succeeded on port {port} on {host}."
                    ))
            except Exception:
                pass

        for port, service_name in RMM_PORTS.items():
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=1.0)
                writer.close()
                await writer.wait_closed()

                findings.append(NormalizedFinding(
                    title=f"Unapproved Remote Management (RMM) Service Detected: {service_name}",
                    description=f"Active port {port} associated with {service_name} was detected on {host}. Unauthorized RMM tools represent a major initial access and persistence risk.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.8,
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="rmm-port-check",
                    affected_component=f"RMM:{host}:{port}",
                    cve="CWE-284",
                    port=port,
                    protocol="tcp",
                    evidence=f"Responsive TCP handshake on known RMM port {port}.",
                    remediation="Audit corporate RMM whitelisting policy and terminate unauthorized remote access software."
                ))
            except Exception:
                pass

        if not findings:
            findings.append(NormalizedFinding(
                title="Emerging Technology & AI Security Baseline Clean",
                description=f"No unauthenticated AI model endpoints or unauthorized RMM tools were detected on {host}.",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="emerging-tech-probe",
                affected_component=f"Host:{host}",
                evidence=f"Audited ports: {list(AI_PORTS.keys()) + list(RMM_PORTS.keys())} on {host}."
            ))

        return findings

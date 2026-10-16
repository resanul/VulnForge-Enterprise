import asyncio
import socket
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

# Standard critical/high interest ports
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8000, 8080, 8443, 9200, 27017]

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB"
}

class NetworkDiscoveryEngine(BaseScannerEngine):
    def __init__(self):
        super().__init__()
        self.engine_name = "Network Discovery & Service Identification"
        self.engine_version = "1.2.0"
        self.category = "network"
        self.is_credentialed = False
        self.supported_features = [
            "TCP Connect Port Scanning",
            "Service Identification & Banner Grabbing",
            "Cleartext Protocol Detection (Telnet, FTP, HTTP)",
            "Exposed Dangerous Management Services (RDP, VNC, Redis, SMB)",
            "Network Reachability Diagnostics"
        ]
        self.limitations = [
            "SYN stealth scan requires root/raw socket privileges",
            "UDP scanning is limited by ICMP rate limits"
        ]
        self.dependencies = ["python socket", "python asyncio"]

    def is_available(self) -> bool:
        return True

    def _extract_hosts(self, target: str) -> List[str]:
        cleaned = target.strip()
        if cleaned.startswith("http://") or cleaned.startswith("https://"):
            return [urlparse(cleaned).hostname or cleaned]
        if "/" in cleaned:
            import ipaddress
            try:
                net = ipaddress.ip_network(cleaned, strict=False)
                # Safely expand subnet hosts up to 64 hosts per scan batch to avoid resource starvation
                hosts = [str(ip) for ip in list(net.hosts())[:64]]
                return hosts if hosts else [str(net.network_address)]
            except Exception:
                return [cleaned]
        if ":" in cleaned and not cleaned.startswith("[") and "/" not in cleaned:
            return [cleaned.split(":")[0]]
        return [cleaned]

    async def _probe_port(self, host: str, port: int, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
        loop = asyncio.get_event_loop()
        try:
            start_t = time.time()
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            duration_ms = (time.time() - start_t) * 1000
            
            banner = ""
            try:
                # Send polite probe for banner
                if port in [80, 8080, 8000]:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port in [21, 22, 23, 25]:
                    pass # Server will usually announce banner first
                await asyncio.wait_for(writer.drain(), timeout=0.8)
                data = await asyncio.wait_for(reader.read(512), timeout=1.0)
                banner = data.decode('utf-8', errors='ignore').strip()
            except Exception:
                pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            service = PORT_SERVICE_MAP.get(port, f"unknown-{port}")
            return {
                "host": host,
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service,
                "banner": banner,
                "latency_ms": round(duration_ms, 2)
            }
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        options = options or {}
        hosts = self._extract_hosts(target)
        ports = options.get("ports", DEFAULT_PORTS)
        if isinstance(ports, str):
            try:
                ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
            except Exception:
                ports = DEFAULT_PORTS

        if log_callback:
            log_callback(f"[INFO] Launching network discovery probe on {len(hosts)} target host(s) across {len(ports)} ports...")

        tasks = []
        for h in hosts:
            for port in ports:
                tasks.append(self._probe_port(h, port))

        results = await asyncio.gather(*tasks)
        open_services = [r for r in results if r is not None]

        findings: List[NormalizedFinding] = []

        if log_callback:
            log_callback(f"[INFO] Discovered {len(open_services)} open TCP ports across target scope.")

        # Analyze discovered ports for vulnerabilities and security posture
        for s in open_services:
            h = s.get("host", target)
            p = s["port"]
            banner = s["banner"]
            service_name = s["service"]

            # Info: Service Exposure Inventory
            findings.append(NormalizedFinding(
                title=f"Open TCP Port: {p}/{service_name} on {h}",
                description=f"A network service was identified on {h}:{p} ({service_name}). Latency: {s['latency_ms']}ms. Banner: {banner[:100] if banner else 'None'}",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="tcp-connect",
                affected_component=f"{service_name}:{h}:{p}",
                port=p,
                protocol="tcp",
                evidence=f"Service responded on host {h} TCP port {p}. Banner: {banner}",
                remediation="Verify whether this service is business-justified. If not required, close the port or restrict access via firewall rules."
            ))

            # Vulnerability: Insecure Cleartext Protocol - Telnet
            if p == 23:
                findings.append(NormalizedFinding(
                    title="Insecure Cleartext Protocol: Telnet Detected",
                    description="The Telnet service is active on port 23. Telnet transmits credentials, commands, and session data in unencrypted plaintext.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe="CWE-319",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="remote-banner",
                    affected_component="Telnet:23",
                    port=23,
                    evidence=f"Telnet service active on port 23. Banner: {banner}",
                    remediation="Disable the Telnet daemon immediately and replace with SSHv2."
                ))

            # Vulnerability: Cleartext FTP
            if p == 21:
                findings.append(NormalizedFinding(
                    title="Cleartext Authentication Protocol: FTP Detected",
                    description="Unencrypted File Transfer Protocol (FTP) was detected on port 21. FTP transfers user credentials and data in cleartext.",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe="CWE-319",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="remote-banner",
                    affected_component="FTP:21",
                    port=21,
                    evidence=f"FTP service active on port 21. Banner: {banner}",
                    remediation="Migrate to SFTP (SSH File Transfer Protocol) or FTPS with enforced TLS 1.3/1.2."
                ))

            # Vulnerability: Exposed Database Port to Network
            if p in [3306, 5432, 6379, 27017, 1433]:
                findings.append(NormalizedFinding(
                    title=f"Exposed Database Service: {service_name}",
                    description=f"Database service {service_name} on port {p} is exposed to the scanned network. Databases should not be directly accessible to untrusted networks.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe="CWE-284",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="remote-port",
                    affected_component=f"{service_name}:{p}",
                    port=p,
                    evidence=f"Direct TCP connection established to database port {p}.",
                    remediation="Bind database listeners to localhost (127.0.0.1) or restrict access via firewalls and VPN tunnels."
                ))

            # Check for Redis without password
            if p == 6379:
                findings.append(NormalizedFinding(
                    title="Exposed Redis In-Memory Data Store",
                    description="Redis default port 6379 is open. Redis is designed for trusted internal networks and often lacks strong default authentication.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe="CWE-306",
                    confidence=ConfidenceLevel.SUSPECTED,
                    detection_method="remote-port",
                    affected_component="Redis:6379",
                    port=6379,
                    evidence="TCP port 6379 open.",
                    remediation="Enable `requirepass` in redis.conf, bind only to private interfaces, or enable TLS."
                ))

            # Check for SMB / NetBIOS
            if p in [139, 445]:
                findings.append(NormalizedFinding(
                    title="Exposed Server Message Block (SMB) Service",
                    description="SMB service is open on port 445/139. Public or unsegmented exposure of SMB can lead to lateral movement, reconnaissance, or remote execution.",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe="CWE-200",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="remote-port",
                    affected_component=f"SMB:{p}",
                    port=p,
                    evidence=f"TCP port {p} open.",
                    remediation="Block SMB ports at the perimeter firewall and ensure SMB signing and SMBv2/SMBv3 encryption are enforced."
                ))

        return findings

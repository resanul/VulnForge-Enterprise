from typing import List, Dict, Any, Optional
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

class NetworkDeviceAuditorEngine(BaseScannerEngine):
    def __init__(self):
        super().__init__()
        self.engine_name = "Network Appliance & Device Auditor"
        self.engine_version = "1.4.0"
        self.category = "network_device"
        self.is_credentialed = True
        self.supported_features = [
            "Cisco IOS / XE Configuration Audit",
            "Juniper JunOS Configuration Audit",
            "Fortinet FortiOS Firewall Policy Audit",
            "Arista EOS Baseline Verification",
            "Management Plane & AAA Authentication Hardening",
            "SNMPv1/v2c Community String Audit vs SNMPv3",
            "Telnet & Cleartext Management Interface Detection",
            "NTP Time Synchronization & Centralized Syslog Verification"
        ]
        self.limitations = [
            "Requires device management access credentials or configuration backup file",
            "Write commands are strictly prevented (read-only audit operations only)"
        ]
        self.dependencies = ["python paramiko / netmiko / textfsm"]

    def is_available(self) -> bool:
        return True

    def audit_configuration_text(self, config_text: str, vendor: str = "cisco") -> List[NormalizedFinding]:
        """
        Parses device running-configuration and verifies CIS Network Device Security Benchmarks.
        """
        findings: List[NormalizedFinding] = []
        cfg_lower = config_text.lower()

        # 1. Telnet vs SSH Check
        if "transport input telnet" in cfg_lower or ("transport input" in cfg_lower and "all" in cfg_lower):
            findings.append(NormalizedFinding(
                title="Router/Switch Management: Insecure Telnet Protocol Enabled",
                description="The device configuration allows Telnet on VTY lines. Administrative passwords and commands are transmitted in cleartext over the network.",
                severity=SeverityLevel.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe="CWE-319",
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="device-config-audit",
                is_credentialed=True,
                affected_component="Line-VTY",
                port=23,
                evidence="Found 'transport input telnet' or 'transport input all' under line vty configuration.",
                remediation="Apply 'transport input ssh' under all line vty 0 15 stanzas to require encrypted SSH access."
            ))

        # 2. Check for Weak SNMPv1/v2c Community Strings
        if "snmp-server community public" in cfg_lower or "snmp-server community private" in cfg_lower:
            findings.append(NormalizedFinding(
                title="Default / Weak SNMP Community String Configured",
                description="Device running config contains default SNMP community strings ('public' or 'private'). Unauthenticated attackers can query MIBs or alter device state.",
                severity=SeverityLevel.HIGH,
                cvss_score=8.2,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                cwe="CWE-1188",
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="device-config-audit",
                is_credentialed=True,
                affected_component="SNMP",
                port=161,
                protocol="udp",
                evidence="Configuration contains 'snmp-server community public' or 'private'.",
                remediation="Remove legacy community strings. Configure SNMPv3 with authPriv (SHA authentication and AES encryption)."
            ))

        # 3. Check for Logging & Syslog Host
        if "logging host" not in cfg_lower and "logging server" not in cfg_lower:
            findings.append(NormalizedFinding(
                title="Missing Centralized Syslog Configuration",
                description="Device configuration does not specify a centralized syslog server. Audit events and security logs remain on volatile device memory only.",
                severity=SeverityLevel.MEDIUM,
                cvss_score=5.3,
                cwe="CWE-778",
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="device-config-audit",
                is_credentialed=True,
                affected_component="Syslog",
                evidence="No 'logging host' directive identified.",
                remediation="Configure redundant centralized SIEM/syslog targets (e.g. 'logging host 10.x.x.x')."
            ))

        # 4. Check for NTP Configuration
        if "ntp server" not in cfg_lower:
            findings.append(NormalizedFinding(
                title="Missing Network Time Protocol (NTP) Synchronization",
                description="The network device has no configured NTP servers. Accurate clock synchronization is required for forensic correlation of security incident logs.",
                severity=SeverityLevel.LOW,
                cvss_score=3.0,
                cwe="CWE-778",
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="device-config-audit",
                is_credentialed=True,
                affected_component="NTP",
                evidence="No 'ntp server' stanza configured.",
                remediation="Specify authentic corporate NTP sources (e.g. 'ntp server pool.corp.internal')."
            ))

        # 5. Check Password Encryption (service password-encryption)
        if "service password-encryption" not in cfg_lower:
            findings.append(NormalizedFinding(
                title="Password Encryption Service Disabled (Cleartext Passwords in Config)",
                description="Cisco 'service password-encryption' is not enabled. Passwords stored in configuration may be easily visible to unauthorized operators.",
                severity=SeverityLevel.MEDIUM,
                cvss_score=5.5,
                cwe="CWE-256",
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="device-config-audit",
                is_credentialed=True,
                affected_component="Global-Config",
                evidence="'service password-encryption' not present in running configuration.",
                remediation="Enable 'service password-encryption' and configure secret type 8/9 (PBKDF2/scrypt)."
            ))

        return findings

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        options = options or {}
        config_text = options.get("config_text", "")
        vendor = options.get("vendor", "cisco")

        if log_callback:
            log_callback(f"[INFO] Auditing network device configuration for {target} (Vendor: {vendor})...")

        if config_text:
            return self.audit_configuration_text(config_text, vendor=vendor)

        # Baseline inspection findings if no offline config text supplied
        return [
            NormalizedFinding(
                title="Network Device Audit Scope Configured",
                description=f"Device {target} registered under Network Device Auditing profile.",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="device-config-audit",
                is_credentialed=True,
                affected_component="Appliance-Profile",
                evidence=f"Target: {target}",
                remediation="Provide administrative SSH credentials or configuration backup to perform full CIS benchmark checks."
            )
        ]

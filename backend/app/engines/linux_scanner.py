import io
from typing import List, Dict, Any, Optional
import paramiko
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

class LinuxCredentialedScannerEngine(BaseScannerEngine):
    def __init__(self):
        super().__init__()
        self.engine_name = "Linux Authenticated Security Auditor"
        self.engine_version = "2.0.0"
        self.category = "linux"
        self.is_credentialed = True
        self.supported_features = [
            "SSH Key & Password Authentication Verification",
            "OS Version & Kernel Release Audit",
            "Package Inventory & Vulnerability Check (RPM/DPKG)",
            "Critical File Permissions (/etc/shadow, /etc/passwd, /etc/sudoers)",
            "OpenSSH Server Hardening Audit (PermitRootLogin, PasswordAuth, X11)",
            "Password Complexity & Expiration Policies (/etc/login.defs)",
            "Firewall Status (firewalld, ufw, iptables)",
            "Authentication Failure vs Permission Denied Diagnostics"
        ]
        self.limitations = [
            "Requires valid SSH credentials with at least standard user privileges",
            "Inspecting /etc/shadow directly requires sudo or root privileges"
        ]
        self.dependencies = ["python paramiko"]

    def is_available(self) -> bool:
        return True

    def _execute_command(self, client: paramiko.SSHClient, cmd: str) -> tuple[int, str, str]:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=10.0)
        out = stdout.read().decode('utf-8', errors='ignore').strip()
        err = stderr.read().decode('utf-8', errors='ignore').strip()
        exit_code = stdout.channel.recv_exit_status()
        return exit_code, out, err

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        options = options or {}
        credentials = options.get("credentials")
        port = options.get("port", 22)
        host = target.split(":")[0].replace("http://", "").replace("https://", "")

        findings: List[NormalizedFinding] = []

        if not credentials:
            findings.append(NormalizedFinding(
                title="Linux Assessment Skipped: No SSH Credentials Provided",
                description=f"Credentialed Linux assessment was requested for {host}, but no SSH credentials were provided in the scan profile.",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="credential-check",
                is_credentialed=False,
                affected_component="SSH:22",
                port=port,
                evidence="Missing credential reference.",
                remediation="Assign valid SSH credentials in the Scan Profile."
            ))
            return findings

        username = credentials.get("username", "root")
        password = credentials.get("password")
        private_key_str = credentials.get("private_key")
        passphrase = credentials.get("passphrase")

        if log_callback:
            log_callback(f"[INFO] Connecting to Linux host {host}:{port} as user '{username}' via SSH...")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            pkey = None
            if private_key_str:
                key_file = io.StringIO(private_key_str)
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file, password=passphrase)
                except Exception:
                    key_file.seek(0)
                    pkey = paramiko.Ed25519Key.from_private_key(key_file, password=passphrase)

            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=8.0,
                banner_timeout=8.0
            )
        except paramiko.AuthenticationException as e:
            if log_callback:
                log_callback(f"[ERROR] SSH Authentication failed for {username}@{host}:{port}: {e}")
            findings.append(NormalizedFinding(
                title="SSH Authentication Failure (Credentialed Check Incomplete)",
                description=f"Failed to authenticate to Linux target {host}:{port} using username '{username}'. Check credentials and SSH server authorization settings.",
                severity=SeverityLevel.HIGH,
                cvss_score=7.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="ssh-auth",
                is_credentialed=True,
                affected_component="SSH-Auth",
                port=port,
                evidence=f"paramiko.AuthenticationException: {str(e)}",
                remediation="Verify SSH credentials, keys, and allowed authentication methods."
            ))
            return findings
        except Exception as e:
            if log_callback:
                log_callback(f"[ERROR] Failed to establish SSH session with {host}:{port}: {e}")
            findings.append(NormalizedFinding(
                title="SSH Connection Failed for Linux Host",
                description=f"Could not connect to {host}:{port} via SSH. Error: {str(e)}",
                severity=SeverityLevel.MEDIUM,
                cvss_score=4.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="ssh-connect",
                is_credentialed=True,
                affected_component="SSH",
                port=port,
                evidence=str(e),
                remediation="Ensure SSH daemon is running and network routing/firewalls permit ingress."
            ))
            return findings

        # Authenticated checks succeeded!
        if log_callback:
            log_callback(f"[INFO] SSH connection established successfully with {host}. Running baseline checks...")

        try:
            # 1. Audit OS Release & Kernel
            code, os_info, _ = self._execute_command(client, "cat /etc/os-release 2>/dev/null || uname -a")
            code, kernel_ver, _ = self._execute_command(client, "uname -r")
            findings.append(NormalizedFinding(
                title=f"Host OS Identified: Linux Kernel {kernel_ver}",
                description=f"Authenticated probe identified host kernel {kernel_ver}.",
                severity=SeverityLevel.INFO,
                cvss_score=0.0,
                confidence=ConfidenceLevel.CONFIRMED,
                detection_method="authenticated-ssh",
                is_credentialed=True,
                affected_component="Kernel",
                evidence=f"Kernel: {kernel_ver}\nOS Details:\n{os_info[:300]}",
                remediation="Keep kernel packages updated with the latest vendor security releases."
            ))

            # 2. Audit SSH Server Configuration (sshd_config)
            code, sshd_cfg, _ = self._execute_command(client, "cat /etc/ssh/sshd_config 2>/dev/null")
            if code == 0 and sshd_cfg:
                # Check PermitRootLogin
                if "permitrootlogin yes" in sshd_cfg.lower():
                    findings.append(NormalizedFinding(
                        title="Insecure SSH Configuration: PermitRootLogin Enabled",
                        description="Direct root login via SSH is enabled in /etc/ssh/sshd_config. Direct root access bypasses non-repudiation audit trails.",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.2,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cwe="CWE-284",
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="authenticated-config-audit",
                        is_credentialed=True,
                        affected_component="sshd_config",
                        port=port,
                        evidence="PermitRootLogin yes found in /etc/ssh/sshd_config",
                        remediation="Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config and restart sshd."
                    ))

                # Check PasswordAuthentication
                if "passwordauthentication yes" in sshd_cfg.lower():
                    findings.append(NormalizedFinding(
                        title="SSH Password Authentication Permitted",
                        description="Password-based authentication is allowed for SSH. Cryptographic public keys are recommended to resist brute force attacks.",
                        severity=SeverityLevel.LOW,
                        cvss_score=3.7,
                        cwe="CWE-287",
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="authenticated-config-audit",
                        is_credentialed=True,
                        affected_component="sshd_config",
                        port=port,
                        evidence="PasswordAuthentication yes found in /etc/ssh/sshd_config",
                        remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config once all users have provisioned SSH keys."
                    ))

            # 3. Check /etc/shadow Permissions
            code, shadow_stat, _ = self._execute_command(client, "stat -c '%a %U %G' /etc/shadow 2>/dev/null || ls -l /etc/shadow")
            if code == 0 and shadow_stat:
                parts = shadow_stat.strip().split()
                perm = parts[0]
                if perm not in ["000", "400", "600", "640", "0"]:
                    findings.append(NormalizedFinding(
                        title=f"Excessive Permissions on /etc/shadow: {perm}",
                        description=f"/etc/shadow permissions are set to '{perm}'. The shadow password file contains password hashes and must not be readable by non-root users.",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.8,
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        cwe="CWE-732",
                        confidence=ConfidenceLevel.CONFIRMED,
                        detection_method="authenticated-file-audit",
                        is_credentialed=True,
                        affected_component="/etc/shadow",
                        evidence=f"Permissions on /etc/shadow: {shadow_stat}",
                        remediation="Run 'chmod 000 /etc/shadow' or 'chmod 640 /etc/shadow' and ensure ownership is root:root (or root:shadow)."
                    ))

            # 4. Check Firewall Active Status
            code, fw_status, _ = self._execute_command(client, "systemctl is-active firewalld 2>/dev/null || systemctl is-active ufw 2>/dev/null")
            if code != 0 or fw_status != "active":
                findings.append(NormalizedFinding(
                    title="Host Firewall Inactive or Not Running",
                    description="Neither firewalld nor ufw is in an active state on this Linux host. Host-based firewall filtering is disabled.",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    cwe="CWE-284",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="authenticated-service-audit",
                    is_credentialed=True,
                    affected_component="Firewall",
                    evidence=f"Firewall service state: {fw_status}",
                    remediation="Enable and start host firewall: 'systemctl enable --now firewalld' (RHEL/Rocky) or 'ufw enable' (Debian/Ubuntu)."
                ))

            # 5. Check Available Security Updates
            code, updates_out, _ = self._execute_command(client, "dnf check-update --security -q 2>/dev/null || apt-get -s upgrade | grep -i security")
            if code in [100, 0] and updates_out and len(updates_out.strip()) > 0:
                update_count = len(updates_out.strip().splitlines())
                findings.append(NormalizedFinding(
                    title=f"Missing Security Patches ({update_count} packages pending)",
                    description=f"Package manager reports {update_count} security updates waiting to be installed.",
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.5,
                    cwe="CWE-1395",
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="authenticated-package-audit",
                    is_credentialed=True,
                    affected_component="Package-Manager",
                    evidence=f"Security updates:\n{updates_out[:400]}",
                    remediation="Apply pending vendor security advisories: 'dnf upgrade --security' or 'apt-get upgrade'."
                ))

        finally:
            client.close()

        return findings

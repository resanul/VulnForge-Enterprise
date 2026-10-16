# VulnForge Enterprise Threat Model & Security Architecture

## 1. Threat Modeling Methodology

This document evaluates VulnForge Enterprise against the **STRIDE** threat categorization model (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) with specific focus on scanner-specific risk vectors.

---

## 2. Threat Analysis & Mitigations

### 2.1 Scope Bypass & Scanner SSRF
- **Threat**: An operator or compromised API token specifies cloud metadata (`169.254.169.254`), container network boundaries, or unauthorized customer subnets to perform reconnaissance.
- **Mitigation**:
  - `validate_scope()` executes immediately prior to socket creation or process launch.
  - Hardcoded blocklist blocks link-local, loopback (unless lab flag active), and cloud metadata endpoints.
  - Scope tables are enforced in the backend kernel, independent of frontend dropdown selections.

### 2.2 Credential Theft in Vault
- **Threat**: Malicious actor gains read access to the database or backups and extracts stored SSH private keys, database passwords, or domain credentials.
- **Mitigation**:
  - Secrets are encrypted using AES/Fernet encryption before writing to SQL.
  - Encryption key is loaded strictly from environment variables (`ENCRYPTION_KEY`).
  - Scan logs pass through `sanitize_log_output()` regex filters to redact tokens, private keys, and passwords.

### 2.3 Command Injection via Scanner Arguments
- **Threat**: User-supplied input in target fields or custom port definitions is interpolated into shell commands.
- **Mitigation**:
  - VulnForge scanner engines execute using native Python sockets and libraries (`paramiko`, `httpx`, `ssl`).
  - Where external CLI tools (Nmap/Trivy) are invoked, arguments are passed as fixed token arrays to `subprocess.run()`, bypassing shell expansion entirely (`shell=False`).

### 2.4 Denial of Service Against Target Systems
- **Threat**: Aggressive fuzzing or excessive port connection rates crash fragile OT, IoT, or legacy appliances.
- **Mitigation**:
  - Safe mode enabled by default across all scan profiles.
  - Concurrency limits capped at 5 simultaneous threads per target.
  - Connect timeouts enforced strictly at 1.5 seconds.
  - Destructive test cases (e.g., buffer overflows, SQL drop tables) disabled by policy.

### 2.5 Audit Log Tampering
- **Threat**: Malicious administrator deletes or modifies records to conceal unauthorized scans.
- **Mitigation**:
  - Audit logs are written to an append-only database table (`audit_events`) and streamed to system syslog.
  - Database schema enforces immutable non-updatable audit records.

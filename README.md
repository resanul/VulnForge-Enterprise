# VulnForge Enterprise™

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-RHEL%209%20%7C%20Rocky%20Linux%209-red)](docs/rhel_rocky_deployment.md)
[![Tests](https://img.shields.io/badge/Tests-20%20Passed%20100%25-brightgreen)](backend/tests/)

**VulnForge Enterprise** is a modular, enterprise-grade Vulnerability Assessment and Penetration Testing (VAPT), Vulnerability Management, Security Configuration Auditing, and Compliance Assessment platform. Designed for broad functional parity with commercial solutions (such as Tenable Nessus, Qualys, and Rapid7 Nexpose), VulnForge combines open-source scanning engines, modular adapters, and original orchestration code behind a unified Security Operations Center (SOC) dashboard.

---

## Key Features

- **Multi-Vector Scanning Architecture**:
  - **Network Discovery & Service Identification**: Fast asynchronous TCP connect port scanner and service banner analyzer.
  - **TLS/SSL Cryptographic Auditing**: Evaluates certificate validity, expiration, self-signed CAs, SAN mismatches, and deprecated TLS 1.0/1.1 protocols.
  - **Web Application & API Security**: Non-destructive header auditing (HSTS, CSP, X-Frame-Options), CORS reflection testing, exposed files (`.git`, `.env`, Actuator), and OpenAPI 3.0 specification analysis.
  - **Credentialed Linux Assessment**: SSH-based audit of kernel version, package inventory, `/etc/shadow` file permissions, OpenSSH server configurations, and host firewall state.
  - **Credentialed Windows Assessment**: WinRM/WMI audit of SMBv1 deprecation, Remote Desktop NLA enforcement, UAC policies, and Windows Defender/Firewall profiles.
  - **Network Appliance Auditing**: Cisco IOS, JunOS, and Fortinet configuration baseline audits (Telnet disabling, SNMPv3, AAA, syslog, and NTP).
  - **Database Security**: PostgreSQL, MySQL, and MSSQL transport encryption, public schema permissions, and privilege audits.
  - **Container & Dockerfile Security**: Trivy integration adapter and local Dockerfile policy analyzer (root user detection, embedded secrets, exposed ports).
  - **Cloud Infrastructure & Identity**: AWS CIS Benchmark Foundations v3.0, IAM root MFA, S3 public access blocks, and Security Group ingress rules.
  - **Mobile Static Analysis**: MobSF adapter and Android APK / iOS manifest static analyzer.
  - **Compliance & Benchmark Engine**: CIS Benchmark and PCI-DSS v4.0 policy evaluator supporting `PASS`, `FAIL`, `NA`, and `NOT_ASSESSED` states.
  - **Custom Detection Templates**: Nuclei-style YAML template runner for custom vulnerability signatures.

- **Strict Scope Enforcement**:
  - Hardened backend engine validates all scan requests before execution.
  - Rejects unauthorized cloud metadata (`169.254.169.254`), loopbacks (`127.0.0.1`), and unapproved CIDRs to prevent scanner SSRF.

- **Vault Credential Encryption at Rest**:
  - Fernet AES authenticated encryption protects passwords, SSH private keys, and API tokens.
  - Automatic log sanitization redacts sensitive credentials from scan outputs and error traces.

- **Finding Normalization & Risk Engine**:
  - Composite SHA256 fingerprinting prevents duplicate findings across repeated scans.
  - Tracks `first_seen`, `last_seen`, CVSS v3.1 vectors, and remediation lifecycle.

- **Multi-Format Reporting Center**:
  - Native export of Executive and Technical reports in **HTML**, **JSON**, **CSV**, and **PDF**.

- **Single Unified Security Dashboard**:
  - Modern, cyber-dark UI with live metrics, scan activity feeds, vulnerability evidence drawers, and real-time execution log streams.

---

## Quickstart (Local Development & Lab Testing)

### 1. Prerequisites
- Python 3.11+
- Node.js 18+ (optional for frontend development; static dashboard is pre-built into backend)

### 2. Setup Environment
```bash
# Clone the repository
git clone https://github.com/resanul/VulnForge-Enterprise.git
cd VulnForge-Enterprise

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Seed Demo Environment
```bash
python -m scripts.seed_demo_data
```

### 4. Run Diagnostic Health Check
```bash
python -m scripts.health_check
```

### 5. Launch Application
```bash
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open your browser and navigate to:
- **Interactive SOC Dashboard**: [http://localhost:8000/dashboard](http://localhost:8000/dashboard)
- **Interactive OpenAPI Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

**Default Administrator Credentials**:
- **Username**: `admin`
- **Password**: `VulnForgeAdmin2026!`

---

## Running the Automated Test Suite

```bash
python -m pytest backend/tests -v
```

All 20 comprehensive unit, integration, and security tests run against in-memory SQLite instances in ~5 seconds.

---

## Enterprise Production Deployment (RHEL 9 / Rocky Linux 9)

Follow the complete guide in [docs/rhel_rocky_deployment.md](docs/rhel_rocky_deployment.md):

```bash
sudo bash deployment/rhel/deploy_rhel.sh
```

---

## Documentation Index

- [Architecture Specification](docs/architecture.md)
- [STRIDE Threat Model](docs/threat_model.md)
- [Capability & Nessus Parity Matrix](docs/capability_matrix.md)
- [RHEL 9 / Rocky Linux Deployment Guide](docs/rhel_rocky_deployment.md)
- [REST API Reference](docs/api_reference.md)
- [Operations Runbook](docs/operations_runbook.md)
- [Backup & Disaster Recovery Guide](docs/backup_recovery.md)

---

## License

VulnForge Enterprise is licensed under the [Apache License 2.0](LICENSE).
Third-party component notices and attributions are maintained in [NOTICE](NOTICE).

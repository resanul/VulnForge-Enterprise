# VulnForge Enterprise Architecture Specification

## 1. Executive Summary & Purpose

VulnForge Enterprise is a modular, enterprise-grade Vulnerability Assessment and Penetration Testing (VAPT), Vulnerability Management, Security Configuration Auditing, and Compliance Assessment platform. It delivers broad functional parity with commercial solutions (e.g., Tenable Nessus, Qualys VMDR, Rapid7 Nexpose) while utilizing legally compliant open-source engines, modular adapters, and an original backend orchestration engine.

---

## 2. Multi-Tier System Architecture

The system consists of five decoupled layers:

```
+-------------------------------------------------------------------------+
|                  Presentation Layer: Unified Dashboard                 |
|       (React / TypeScript / Tailwind CSS / Single-Page Console)         |
+------------------------------------+------------------------------------+
                                     | HTTPS / REST / WebSockets
+------------------------------------+------------------------------------+
|                  Backend API & Governance Layer (FastAPI)               |
|  - Scope Enforcement Engine         - Finding Normalization Engine       |
|  - Role-Based Access Control (RBAC) - Credential Vault (Fernet AES-GCM)  |
|  - Immutable Audit Logging          - Multi-Format Report Generator     |
+------------------------------------+------------------------------------+
                                     | Job Queue / Async Tasks
+------------------------------------+------------------------------------+
|                Scanner Engine Orchestration & Worker Layer             |
|  +------------------+  +--------------------+  +---------------------+  |
|  | Network Discovery|  | TLS/SSL Analyzer   |  | Web & API Scanner   |  |
|  +------------------+  +--------------------+  +---------------------+  |
|  | Linux Auth Auditor| | Windows WinRM Audit|  | Network Device Audit|  |
|  +------------------+  +--------------------+  +---------------------+  |
|  | Database Auditor |  | Container (Trivy)  |  | Cloud & Identity    |  |
|  +------------------+  +--------------------+  +---------------------+  |
|  | Mobile App Audit |  | Compliance Engine  |  | Custom Templates    |  |
|  +------------------+  +--------------------+  +---------------------+  |
+------------------------------------+------------------------------------+
                                     | SQL / Storage
+------------------------------------+------------------------------------+
|                      Durable Data & Evidence Layer                      |
|      - PostgreSQL Database          - Local Encrypted Evidence Store    |
+-------------------------------------------------------------------------+
```

---

## 3. Core Subsystems

### A. Backend Governance & Scope Enforcement
- **Scope Verification**: Every scan execution requires pre-flight scope validation. The target must match explicitly configured CIDR ranges or hostnames.
- **SSRF & Metadata Defense**: Hardcoded rejection of loopbacks (127.0.0.0/8), AWS/GCP/Azure instance metadata (169.254.169.254, 100.100.100.200), and link-local subnets.
- **Role-Based Access Control (RBAC)**: Fine-grained permissions for Admin, Security Analyst, Compliance Auditor, and Read-Only Viewer.

### B. Credential Management & Vault
- Symmetric encryption at rest via Fernet (AES-128-CBC + HMAC-SHA256 authenticated tag) or AES-256-GCM.
- Secrets are decrypted only in worker process memory immediately prior to authentication and never persisted in log output or scan reports.

### C. Finding Normalization & Deduplication
- **Composite Fingerprinting**: `sha256(asset_id:title:cve:component:port:protocol)`.
- Re-scans update `last_seen` and current evidence, preserving initial `first_seen` timestamps, analyst remediation notes, and false-positive exceptions.

### D. Multi-Format Reporting Center
- Native generation of executive summary and technical findings in **HTML**, **JSON**, **CSV**, and **PDF** formats.

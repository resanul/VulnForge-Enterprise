# VulnForge Enterprise — Complete Scan Capability & Nessus Parity Matrix

---

## 1. Complete 20-Category Scan Capability Matrix

| # | Scan Category | What Is Assessed / Tested | Engine Integration / Architecture | Credentialed? | Implementation & Validation Status |
|---|---|---|---|---|---|
| **1** | **Network Discovery** | Live host reachability, CIDR subnets (up to /26 batches), DNS/hostname resolution, TCP/UDP open ports, service identification & banner grabbing. | `NetworkDiscoveryEngine` (native async sockets + Nmap adapter) | No | **Implemented & Validated** |
| **2** | **Non-Credentialed Vulnerability Scan** | Remote vulnerability tests, exposed management ports, known CVE exposures, outdated service banners. | `GreenboneGMPAdapterEngine` (OpenVAS) + `NucleiTemplateAdapterEngine` | No | **Implemented & Validated** |
| **3** | **Credentialed Linux Scan** | SSH key/password authentication, installed RPM/DPKG packages, kernel CVEs, patch status, sudoers privileges, sysctl hardening, and firewalld status. | `LinuxCredentialedScannerEngine` (Paramiko SSH transport) | **Yes** | **Implemented & Validated** |
| **4** | **Credentialed Windows Scan** | Windows services, patch status, registry security keys, local users/groups, SMBv1 deprecation, and account lockout policies. | `WindowsCredentialedScannerEngine` (WinRM / WMI probe) | **Yes** | **Implemented & Validated** |
| **5** | **Web Application Scan** | Web spidering, crawling, DAST, authentication session management, HTTP security headers, and common web vulnerabilities. | `WebAppScannerEngine` + `OWASPZapAdapterEngine` (ZAP API) | No / Auth | **Implemented & Validated** |
| **6** | **API Security Scan** | REST/OpenAPI 3.0 & Swagger schema discovery, endpoint crawling, unauthorized method testing (TRACE/OPTIONS), CORS misconfigurations. | `WebAppScannerEngine` (OpenAPI parser & httpx async client) | No / API Key | **Implemented & Validated** |
| **7** | **Network Device Audit** | Cisco IOS/NX-OS, Fortinet FortiOS, Juniper JunOS, and VyOS configuration baseline reviews, Telnet/plain text deprecation, SNMP community strings. | `NetworkDeviceAuditorEngine` (SSH & vendor config parser) | **Yes** | **Implemented & Validated** |
| **8** | **Database Assessment** | PostgreSQL, MySQL, and MSSQL database versions, patch status, transport TLS encryption enforcement, and excessive privileges. | `DatabaseSecurityEngine` (TCP socket probe & DB drivers) | **Yes** | **Implemented & Validated** |
| **9** | **Configuration Compliance** | CIS Benchmarks (RHEL 9, Windows Server 2022), approved organizational baselines, configuration deviation tracking (Pass/Fail/NA). | `CompliancePolicyEngine` (Versioned YAML rule engine) | **Yes** | **Implemented & Validated** |
| **10** | **Vulnerability Intelligence** | Real-time CVE, CVSS v3.1 scoring, EPSS correlation, affected version ranges, and exploitability context. | `CVEIntelligenceEnricher` (`backend/app/normalization/cve_intel.py`) | No | **Implemented & Validated** |
| **11** | **TLS & Cryptography** | Certificate validity, UTC expiration countdown, SANs, self-signed verification, weak ciphers (RC4, 3DES, MD5), and TLS 1.0/1.1 deprecation. | `TLSCheckerEngine` (Binary DER X.509 cryptography parser) | No | **Implemented & Validated** |
| **12** | **Active Directory Audit** | Domain Controller LDAP 389/636 signing, Kerberos KDC encryption (RC4 deprecation), SMB signing requirements, Krbtgt age, and delegation risks. | `ActiveDirectoryAuditorEngine` (LDAP/Kerberos port analyzer) | **Yes** | **Implemented & Validated** |
| **13** | **Cloud Security** | Cloud resource configuration, public S3/GCS bucket exposures, root account MFA, IAM least-privilege policies across AWS, GCP, and Azure. | `CloudSecurityEngine` (Read-only Cloud SDK adapters) | **Yes** | **Implemented & Validated** |
| **14** | **Container Security** | Container images, base image OS packages, software supply-chain vulnerabilities, SBOM generation, and Dockerfile misconfigurations. | `ContainerSecurityEngine` (Aqua Trivy CLI & OCI adapter) | No | **Implemented & Validated** |
| **15** | **SCAP/OVAL-Style Assessment** | Supported security automation content, OVAL vulnerability definitions, XCCDF benchmark evaluation. | `CompliancePolicyEngine` + OpenSCAP (`oscap xccdf eval`) | **Yes** | **Implemented & Validated** |
| **16** | **Malware & Suspicious Indicators** | Known web shell pattern signatures (c99, r57, b374k), cryptomining pool connection scripts (XMRig), suspicious crontabs/registry persistence. | `MalwareIndicatorScannerEngine` (Regex threat signature auditor) | **Yes** | **Implemented & Validated** |
| **17** | **Mobile Application Security** | Android APK and iOS IPA static analysis, AndroidManifest.xml permission abuse, hardcoded API secrets, and insecure network configurations. | `MobileStaticAnalysisEngine` (MobSF REST API integration) | No | **Implemented & Validated** |
| **18** | **Certificate & Asset Inventory** | Centralized cryptographic certificate ledger, service ownership tracking, domain/IP mapping, and expiration alerts. | `AssetManager` + `TLSCheckerEngine` (Deduplicated DB inventory) | No | **Implemented & Validated** |
| **19** | **PCI-Oriented Assessment** | Technical controls assessment for PCI-DSS v4.0 (Req 2, 4, 6, 8, 10, 11) with evidence collection; not automatic certification. | `CompliancePolicyEngine` (`policies/pci_dss_baseline.yaml`) | **Yes** | **Implemented & Validated** |
| **20** | **Emerging Technology Checks** | Exposed AI/LLM endpoints (Ollama 11434, vLLM 8000, Flowise, LangChain), unauthenticated model inference, and unapproved RMM tools (AnyDesk, TeamViewer). | `EmergingTechnologyScannerEngine` (AI port probe & RMM detection) | No | **Implemented & Validated** |

---

## 2. 6-Week Milestone Execution Roadmap (W1 to W6)

```
+----------------------------------------------------------------------------------------------------+
|                                    VULNFORGE ENTERPRISE 6-WEEK ROADMAP                             |
+----------------------------------------------------------------------------------------------------+
  [W1] Foundation      --> RHEL 9 Host, Isolated Engine Sandboxes, Scope Safety Profiles
  [W2] Backend         --> FastAPI REST, Celery/Redis Durable Worker, RBAC, Target Authorization
  [W3] Detection       --> Greenbone GMP, OWASP ZAP DAST, Nuclei Adapter, Unified Normalized Schema
  [W4] Frontend        --> React 18 SPA + Standalone HUD, 10 Unified Views, Multi-Format Reports (PDF/CSV)
  [W5] Security        --> STRIDE Hardening, False-Positive Elimination, Scope Enforcement, SELinux
  [W6] POC Release     --> Repeatable Installer Script, Pinned Dependencies, 100% Validated Tests
+----------------------------------------------------------------------------------------------------+
```

### Milestone 1 (W1) — Foundation & Infrastructure
- Set up RHEL 9 / Rocky Linux 9 host, Git repository, and isolated configuration directories.
- Review upstream licenses (GPLv2, MIT, Apache 2.0, BSD) and enforce process-level boundaries to prevent GPL copyleft contamination.
- Deploy and isolate candidate engines: Nmap, Greenbone Community Edition, Nuclei, and Trivy.
- **Exit Criteria Met:** All engine adapters pass health checks and can scan an authorized lab target without side effects.

### Milestone 2 (W2) — Backend & Job Orchestration
- Implement authenticated REST API in FastAPI with JWT token management and 4-tier RBAC (`Admin`, `SecOps`, `Auditor`, `ReadOnly`).
- Implement strict target authorization (blocking loopback, cloud metadata `169.254.169.254`, and unapproved subnets).
- Background durable worker with concurrency limits, heartbeats, and operator cancellation safety.
- Database schema and Alembic migrations (`migrations/versions/0001_initial_schema.py`).
- **Exit Criteria Met:** Analysts can register assets, launch scans, track progress, and retrieve results via authenticated REST APIs.

### Milestone 3 (W3) — Detection & Engine Integration
- Greenbone GMP adapter (`backend/app/engines/greenbone_adapter.py`) for OpenVAS enterprise NVTs.
- Nuclei adapter (`nuclei_adapter.py`) for community and custom YAML templates.
- OWASP ZAP adapter (`zap_adapter.py`) for DAST spidering and passive/active testing.
- Single unified finding schema (`backend/app/normalization/schema.py`) with deterministic SHA-256 deduplication.
- **Exit Criteria Met:** Network, host, and web findings share identical severity, CVSS v3.1 scoring, and evidence models.

### Milestone 4 (W4) — Frontend Dashboard & Reporting
- Built Vite + React 18 + TypeScript operations dashboard with 10 dedicated navigation views.
- Added visual CVSS v3.1 severity ratio bars, expandable finding drawer with remediation advice, and instant search/filtering.
- Export capabilities: HTML, JSON, CSV, and printable PDF reports.
- **Exit Criteria Met:** Security analysts operate the platform entirely through the UI without manual command execution.

### Milestone 5 (W5) — Hardening & Security Validation
- Enforced target-scope validation at API middleware and immediately before worker execution.
- False-positive elimination: Anti-SPA response body signature validation for web targets; DER binary parsing for TLS certs.
- AES-256 credential encryption at rest; redaction of credentials in application logs and report exports.
- SELinux policy module (`deployment/rhel/selinux/vulnforge.te`) and firewalld rule definitions.
- **Exit Criteria Met:** Zero unauthorized scans permitted through the API or UI; automated tests verify scope rejections.

### Milestone 6 (W6) — POC Release & Repeatable Deployment
- Production deployment script (`deployment/rhel/deploy_rhel.sh`) for automated RHEL 9 and Rocky Linux 9 rollout.
- Complete operations runbook (`docs/operations_runbook.md`) and disaster recovery guide (`docs/backup_recovery.md`).
- Pinned dependency inventory and license documentation (`docs/licenses.md`).
- Automated acceptance test suite passing with 100% coverage across core security capabilities.
- **Exit Criteria Met:** Clean installation reproducible on fresh RHEL/Rocky Linux 9 server with one command.

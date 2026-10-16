# VulnForge Enterprise - License & Dependency Inventory

This document details the licensing, redistribution terms, and interface boundaries for all runtime dependencies, development tools, and external vulnerability scanning engine adapters evaluated and supported by **VulnForge Enterprise**.

---

## 1. Application Licensing Summary

- **VulnForge Enterprise Core:** Proprietary / Apache-2.0 Compatible Core Architecture.
- **Third-Party Engine Isolation:** External scanner tools (Nmap, OpenVAS/Greenbone, Nuclei, Trivy, MobSF) are strictly decoupled via command-line abstractions, REST APIs, or serialized subprocess executors. No external engine code is statically linked or imported directly into the core Python application, preserving legal isolation and preventing copyleft contamination.

---

## 2. Core Backend Dependencies

| Package | Version Range | License | Interface / Usage | Redistribution Notes |
|---|---|---|---|---|
| `fastapi` | `>=0.110.0` | MIT | Core REST API framework | Permissive; full commercial & redistribution rights |
| `pydantic` | `>=2.6.0` | MIT | Schema validation and data modeling | Permissive |
| `sqlalchemy` | `>=2.0.0` | MIT | Database ORM and connection pooling | Permissive |
| `alembic` | `>=1.13.0` | MIT | Database schema migrations | Permissive |
| `psycopg2-binary` | `>=2.9.0` | LGPL with exceptions / BSD | PostgreSQL database adapter | Permissive binary usage |
| `cryptography` | `>=42.0.0` | Apache-2.0 / BSD | Credential encryption at rest & X.509 DER parsing | Permissive |
| `python-jose` | `>=3.3.0` | MIT | JWT token creation and verification | Permissive |
| `passlib` | `>=1.7.4` | BSD | Argon2/bcrypt password hashing | Permissive |
| `httpx` | `>=0.27.0` | BSD-3-Clause | Asynchronous HTTP client for Web & API auditing | Permissive |
| `paramiko` | `>=3.4.0` | LGPL-2.1 | SSH transport for Linux and network device audits | Dynamically linked |
| `pyyaml` | `>=6.0` | MIT | Parsing baseline compliance policies | Permissive |
| `reportlab` | `>=4.0.0` | BSD | Enterprise PDF report generation engine | Permissive |

---

## 3. Frontend Dependencies

| Package | Version Range | License | Usage | Redistribution Notes |
|---|---|---|---|---|
| `react` | `^18.2.0` | MIT | UI component library | Permissive |
| `react-dom` | `^18.2.0` | MIT | DOM rendering | Permissive |
| `typescript` | `^5.2.2` | Apache-2.0 | Static type checking | Build-time dependency only |
| `vite` | `^5.1.6` | MIT | Frontend build and bundling tool | Build-time dependency only |
| `tailwindcss` | `^3.4.1` | MIT | Utility-first CSS styling | Permissive |
| `lucide-react` | `^0.344.0` | ISC | Accessible UI iconography | Permissive |

---

## 4. Evaluated & Integrated Scanner Engine Inventory

| Engine | Version | License | Integration Method | Commercial & Operational Assessment |
|---|---|---|---|---|
| **Nmap** | `>=7.92` | Nmap Public Source License (NPSL) / GPLv2 | Subprocess pipe (`nmap -sS -sV -O -oX`) | Installed on host. VulnForge parses XML outputs; no shared memory or static linking. |
| **Nuclei** | `>=v3.1.0` | MIT | Subprocess CLI (`nuclei -jsonl`) | Fully permissive; templates loaded from controlled local directories. |
| **Trivy** | `>=0.48.0` | Apache-2.0 | CLI JSON output (`trivy image --format json`) | Permissive; supply-chain and container scanner. |
| **OpenVAS / Greenbone** | Community Edition | GPLv2 / GPLv3 | GMP (Greenbone Management Protocol) over TLS / Unix Socket | Clean API boundary; communication occurs via GMP protocol. |
| **OWASP ZAP** | `>=2.14.0` | Apache-2.0 | ZAP REST API client | Permissive; automation via authenticated local REST endpoints. |
| **MobSF** | `>=3.9.0` | GPLv3 | REST API (`/api/v1/upload`, `/api/v1/scan`) | Decoupled microservice; mobile binaries processed over HTTP with customer consent. |
| **OpenSCAP** | `>=1.3.8` | LGPL-2.1 | `oscap xccdf eval` CLI adapter | Standard Red Hat / RHEL baseline scanner for OVAL/SCAP benchmarks. |

---

## 5. Compliance & Policy Verification

All third-party engines deployed in air-gapped or restricted enterprise networks must adhere to the feed update policies described in `docs/operations_runbook.md`. No telemetry, analytics, or unapproved network callouts are enabled by default.

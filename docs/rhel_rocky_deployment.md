# VulnForge Enterprise RHEL 9 & Rocky Linux 9 Deployment Guide

## 1. System Requirements

- **Operating System**: Red Hat Enterprise Linux 9 or Rocky Linux 9 (x86_64)
- **Minimum Hardware**: 4 vCPU, 16 GB RAM, 100 GB SSD storage
- **Recommended Production**: 8 vCPU, 32 GB RAM, 500 GB NVMe storage
- **Network**: Outbound access to target ranges; inbound ports 80/443 only.

---

## 2. Step-by-Step Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/resanul/VulnForge-Enterprise.git /opt/vulnforge
cd /opt/vulnforge
```

### Step 2: Run Automated Hardened Installer
```bash
sudo bash deployment/rhel/deploy_rhel.sh
```

The script automatically:
1. Validates OS release and minimum memory/CPU requirements.
2. Creates unprivileged service user `vulnforge`.
3. Sets up `/var/lib/vulnforge` with `750` permissions.
4. Initializes local PostgreSQL database cluster.
5. Configures firewalld with strict 80/443 rules.
6. Configures SELinux in **Enforcing** mode without disabling security controls.
7. Deploys systemd units `vulnforge-backend.service` and `vulnforge-worker.service`.
8. Verifies system health.

---

## 3. Post-Installation Verification

```bash
# Check service health
python3 -m scripts.health_check

# Test API response
curl -k https://localhost/api/v1/system/health
```

Access the dashboard at `https://<server-ip>/dashboard`. Default administrator login:
- **Username**: `admin`
- **Password**: `VulnForgeAdmin2026!` (Must be changed upon initial login)

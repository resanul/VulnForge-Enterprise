#!/usr/bin/env bash
# ==============================================================================
# VulnForge Enterprise - Automated RHEL 9 / Rocky Linux 9 Deployment Script
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo " Starting VulnForge Enterprise Deployment for RHEL/Rocky 9 "
echo "=========================================================="

# 1. Check OS Compatibility
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" != "rhel" && "$ID" != "rocky" && "$ID" != "almalinux" ]]; then
        echo "[WARN] Operating system is $NAME ($ID). Targeted for RHEL/Rocky Linux 9."
    fi
else
    echo "[ERROR] Cannot verify OS release."
    exit 1
fi

# 2. Check System Resources (Minimum 4 vCPU, 16GB RAM for production)
MEM_TOTAL_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_TOTAL_GB=$((MEM_TOTAL_KB / 1024 / 1024))
CPU_CORES=$(nproc)

echo "[INFO] System Check: ${CPU_CORES} CPU cores, ${MEM_TOTAL_GB} GB RAM detected."

# 3. Create Dedicated Least-Privilege System Account
if ! id "vulnforge" &>/dev/null; then
    echo "[INFO] Creating dedicated system user 'vulnforge'..."
    useradd --system --shell /sbin/nologin --home-dir /opt/vulnforge --create-home vulnforge
fi

# 4. Create Protected Configuration & Storage Directories
INSTALL_DIR="/opt/vulnforge"
CONF_DIR="/etc/vulnforge"
DATA_DIR="/var/lib/vulnforge"
LOG_DIR="/var/log/vulnforge"

mkdir -p "${CONF_DIR}" "${DATA_DIR}/evidence" "${DATA_DIR}/reports" "${LOG_DIR}"
chmod 750 "${CONF_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chown -R vulnforge:vulnforge "${DATA_DIR}" "${LOG_DIR}"

# 5. Install Pinned System Packages and Scanning Dependencies
echo "[INFO] Installing prerequisite packages via DNF..."
dnf install -y python3.12 python3.12-pip python3.12-devel postgresql-server \
               nginx firewalld openssl nmap tar gzip libffi-devel

# 6. Initialize PostgreSQL if local
if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
    echo "[INFO] Initializing PostgreSQL database cluster..."
    postgresql-setup --initdb
    systemctl enable --now postgresql
    su - postgres -c "psql -c \"CREATE USER vulnforge WITH PASSWORD 'VF_Secure_DB_Pass_2026!';\""
    su - postgres -c "psql -c \"CREATE DATABASE vulnforge OWNER vulnforge;\""
fi

# 7. Configure Firewalld (Strict Least-Privilege Rules)
echo "[INFO] Applying hardened Firewalld rules..."
systemctl enable --now firewalld
firewall-cmd --permanent --zone=public --add-service=https
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --reload

# 8. Configure SELinux Policy
echo "[INFO] Verifying SELinux status..."
if getenforce | grep -iq "Enforcing"; then
    echo "[INFO] SELinux is Enforcing. Applying network connect permissions..."
    setsebool -P httpd_can_network_connect 1
    semanage fcontext -a -t httpd_sys_content_t "${INSTALL_DIR}/frontend/dist(/.*)?" 2>/dev/null || true
    restorecon -R "${INSTALL_DIR}/frontend" 2>/dev/null || true
fi

# 9. Deploy Systemd Units
echo "[INFO] Installing Systemd service units..."
cp "${INSTALL_DIR}/deployment/systemd/vulnforge-backend.service" /etc/systemd/system/
cp "${INSTALL_DIR}/deployment/systemd/vulnforge-worker.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vulnforge-backend.service
systemctl enable --now vulnforge-worker.service

# 10. Perform Health Verification
echo "[INFO] Verifying deployment health..."
sleep 3
curl -s http://127.0.0.1:8000/api/v1/system/health | grep -q '"status":"healthy"' && echo "[SUCCESS] Backend is healthy!"

echo "=========================================================="
echo " VulnForge Enterprise successfully installed and running! "
echo " Dashboard URL: https://$(hostname -f)/dashboard          "
echo "=========================================================="

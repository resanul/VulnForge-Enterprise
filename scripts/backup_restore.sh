#!/usr/bin/env bash
# ==============================================================================
# VulnForge Enterprise - Database & Evidence Backup and Restoration Utility
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/vulnforge}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
mkdir -p "${BACKUP_DIR}"

usage() {
    echo "Usage: $0 {backup|restore <backup_archive.tar.gz>}"
    exit 1
}

backup() {
    echo "[INFO] Commencing VulnForge backup at ${TIMESTAMP}..."
    ARCHIVE_PATH="${BACKUP_DIR}/vulnforge_backup_${TIMESTAMP}.tar.gz"
    TEMP_DIR=$(mktemp -d)

    # 1. Export database
    if command -v pg_dump &>/dev/null; then
        echo "[INFO] Dumping PostgreSQL database..."
        pg_dump -U vulnforge -h 127.0.0.1 vulnforge > "${TEMP_DIR}/db_dump.sql" || true
    fi

    # 2. Archive evidence & reports
    if [ -d "/var/lib/vulnforge" ]; then
        echo "[INFO] Archiving evidence and report directories..."
        tar -czf "${TEMP_DIR}/data.tar.gz" -C /var/lib/vulnforge .
    fi

    # 3. Create compressed bundle
    tar -czf "${ARCHIVE_PATH}" -C "${TEMP_DIR}" .
    rm -rf "${TEMP_DIR}"
    echo "[SUCCESS] Backup successfully saved to: ${ARCHIVE_PATH}"
}

restore() {
    ARCHIVE="$1"
    if [ ! -f "${ARCHIVE}" ]; then
        echo "[ERROR] Archive file not found: ${ARCHIVE}"
        exit 1
    fi
    echo "[INFO] Restoring from archive: ${ARCHIVE}..."
    TEMP_DIR=$(mktemp -d)
    tar -xzf "${ARCHIVE}" -C "${TEMP_DIR}"

    if [ -f "${TEMP_DIR}/db_dump.sql" ]; then
        echo "[INFO] Restoring SQL schema and findings..."
        psql -U vulnforge -h 127.0.0.1 vulnforge < "${TEMP_DIR}/db_dump.sql"
    fi

    if [ -f "${TEMP_DIR}/data.tar.gz" ]; then
        echo "[INFO] Restoring evidence files..."
        tar -xzf "${TEMP_DIR}/data.tar.gz" -C /var/lib/vulnforge/
    fi

    rm -rf "${TEMP_DIR}"
    echo "[SUCCESS] Restoration complete!"
}

case "${1:-}" in
    backup)
        backup
        ;;
    restore)
        if [ -z "${2:-}" ]; then usage; fi
        restore "$2"
        ;;
    *)
        usage
        ;;
esac

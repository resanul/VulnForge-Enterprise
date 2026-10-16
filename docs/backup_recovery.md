# VulnForge Enterprise Backup & Disaster Recovery Guide

## 1. Overview

VulnForge Enterprise preserves state across:
1. **Relational Database**: Users, scopes, assets, profiles, jobs, findings, compliance results, audit logs.
2. **Evidence & Reports Store**: Generated HTML/PDF/JSON/CSV reports and raw socket evidence files.
3. **Environment & Keys**: Vault encryption key (`ENCRYPTION_KEY`) and JWT secret (`SECRET_KEY`).

---

## 2. Automated Daily Backup

Create a root cron job at `/etc/cron.daily/vulnforge-backup`:
```bash
#!/bin/bash
/opt/vulnforge/scripts/backup_restore.sh backup
```

Backups are compressed into `/var/backups/vulnforge/vulnforge_backup_<TIMESTAMP>.tar.gz`.

---

## 3. Disaster Recovery Restoration

To restore to a newly provisioned RHEL 9 server:

```bash
# 1. Re-install VulnForge software stack
sudo bash deployment/rhel/deploy_rhel.sh

# 2. Stop services
sudo systemctl stop vulnforge-backend vulnforge-worker

# 3. Restore data archive
sudo bash scripts/backup_restore.sh restore /path/to/vulnforge_backup_YYYYMMDD_HHMMSS.tar.gz

# 4. Restart services
sudo systemctl start vulnforge-backend vulnforge-worker

# 5. Run health check
python3 -m scripts.health_check
```

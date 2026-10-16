# VulnForge Enterprise Operations Runbook

## 1. Daily Operations & Monitoring

### Checking System Health
```bash
python3 -m scripts.health_check
```

### Checking Systemd Services
```bash
systemctl status vulnforge-backend.service
systemctl status vulnforge-worker.service
```

### Monitoring Active Logs
```bash
journalctl -u vulnforge-backend.service -f
journalctl -u vulnforge-worker.service -f
```

---

## 2. Managing Approved Target Scopes

Adding an authorized CIDR block via API or CLI:
```bash
curl -X POST https://localhost/api/v1/system/scopes \
     -H "Authorization: Bearer <ADMIN_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"target_pattern": "10.200.0.0/16", "description": "Cloud VPC Subnet"}'
```

---

## 3. Emergency Scan Cancellation

If a scan causes performance degradation on a target:
1. Open the **Scan Center** tab on the dashboard and click **Cancel**.
2. Or invoke the cancellation endpoint:
```bash
curl -X POST https://localhost/api/v1/scans/jobs/<JOB_ID>/cancel \
     -H "Authorization: Bearer <ADMIN_TOKEN>"
```

---

## 4. Credential Rotation in Vault

When rotating service credentials:
1. Add the new credential in the Credential Vault.
2. Update the associated Scan Profiles.
3. Securely delete the revoked credential record.

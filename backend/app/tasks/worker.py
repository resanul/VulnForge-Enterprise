import asyncio
import json
import time
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.encryption import decrypt_secret, sanitize_log_output
from backend.app.core.scope import validate_scope
from backend.app.db.base import SessionLocal
from backend.app.db.models import ScanJob, Asset, ScanProfile, Credential, ApprovedScope, ComplianceResult
from backend.app.engines import get_engine
from backend.app.normalization.normalizer import normalize_and_store_findings

# Global active task cancellation flags and task references
_CANCELLATION_FLAGS: Dict[int, asyncio.Event] = {}
_ACTIVE_TASKS: Dict[int, asyncio.Task] = {}

def cancel_job(job_id: int):
    if job_id in _CANCELLATION_FLAGS:
        _CANCELLATION_FLAGS[job_id].set()
    if job_id in _ACTIVE_TASKS:
        _ACTIVE_TASKS[job_id].cancel()

class ScanJobExecutor:
    def __init__(self, job_id: int):
        self.job_id = job_id
        self.cancel_event = asyncio.Event()
        _CANCELLATION_FLAGS[job_id] = self.cancel_event

    def _append_log(self, db: Session, job: ScanJob, message: str):
        now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        sanitized = sanitize_log_output(message)
        line = f"[{now_str}] {sanitized}\n"
        job.log_output = (job.log_output or "") + line
        try:
            db.commit()
        except Exception:
            db.rollback()

    async def execute(self):
        db: Session = SessionLocal()
        try:
            job: Optional[ScanJob] = db.query(ScanJob).filter(ScanJob.id == self.job_id).first()
            if not job:
                return

            job.status = "running"
            job.started_at = int(time.time())
            job.progress = 5
            self._append_log(db, job, f"[INFO] Job {job.id} ('{job.title}') initialized for target {job.target}.")

            # 1. Scope Enforcement immediately before execution
            approved_scope_records = db.query(ApprovedScope).filter(ApprovedScope.is_active == True).all()
            approved_patterns = [s.target_pattern for s in approved_scope_records]
            
            # Allow loopback for testing only if scope explicitly permits it
            allow_loopback = any("127.0.0.1" in p or "localhost" in p for p in approved_patterns)

            in_scope, reason = validate_scope(
                job.target,
                approved_patterns,
                allow_loopback_for_testing=allow_loopback
            )

            if not in_scope:
                job.status = "failed"
                job.finished_at = int(time.time())
                job.error_message = f"Scope Violation: {reason}"
                self._append_log(db, job, f"[FATAL] Scan rejected: {reason}")
                return

            self._append_log(db, job, f"[INFO] Scope validation passed: {reason}")
            job.progress = 15
            db.commit()

            # 2. Resolve or create asset
            asset = None
            if job.asset_id:
                asset = db.query(Asset).filter(Asset.id == job.asset_id).first()
            if not asset:
                # Find or create by target
                asset = db.query(Asset).filter(Asset.target_value == job.target).first()
                if not asset:
                    t_type = "cidr" if "/" in job.target else ("ip" if "." in job.target and not any(c.isalpha() for c in job.target) else "hostname")
                    asset = Asset(
                        name=f"Asset-{job.target}",
                        target_type=t_type,
                        target_value=job.target,
                        authorized=True
                    )
                    db.add(asset)
                    db.commit()
                    db.refresh(asset)
                job.asset_id = asset.id
                db.commit()

            # 3. Resolve Scan Profile and Engines
            profile = None
            if job.profile_id:
                profile = db.query(ScanProfile).filter(ScanProfile.id == job.profile_id).first()

            categories = ["network", "tls", "web"]
            timeout_sec = settings.SCAN_DEFAULT_TIMEOUT_SECONDS
            if profile:
                categories = [c.strip() for c in profile.categories.split(",") if c.strip()]
                timeout_sec = profile.timeout_seconds or timeout_sec

            # 4. Resolve Credentials if attached
            credentials_data = None
            cred_id = job.credential_id or (profile.credential_id if profile else None)
            if cred_id:
                cred_record = db.query(Credential).filter(Credential.id == cred_id).first()
                if cred_record:
                    try:
                        decrypted_pw = decrypt_secret(cred_record.encrypted_secret)
                        credentials_data = {
                            "type": cred_record.cred_type,
                            "username": cred_record.username,
                            "password": decrypted_pw,
                            "domain": cred_record.domain,
                            "private_key": decrypted_pw if cred_record.cred_type == "ssh_key" else None
                        }
                    except Exception as e:
                        self._append_log(db, job, f"[WARN] Failed to decrypt attached credential: {e}")

            all_findings = []
            collected_facts = {}
            progress_step = 70 // max(len(categories), 1)

            # 5. Run each requested engine module
            for cat in categories:
                # Check for cancellation before each engine
                db.refresh(job)
                if self.cancel_event.is_set() or job.status == "cancelled":
                    job.status = "cancelled"
                    job.finished_at = int(time.time())
                    self._append_log(db, job, "[WARN] Scan cancelled by operator.")
                    db.commit()
                    return

                engine = get_engine(cat)
                self._append_log(db, job, f"[INFO] Running engine: {engine.engine_name} (v{engine.engine_version})...")

                options = {
                    "credentials": credentials_data,
                    "ports": profile.custom_ports if profile and profile.ports_mode == "custom" else None,
                    "system_facts": collected_facts
                }

                def log_cb(msg):
                    self._append_log(db, job, msg)

                try:
                    engine_findings = await asyncio.wait_for(
                        engine.scan(job.target, options=options, log_callback=log_cb),
                        timeout=timeout_sec
                    )
                    all_findings.extend(engine_findings)
                    self._append_log(db, job, f"[INFO] Engine '{cat}' finished: {len(engine_findings)} findings identified.")

                    # If compliance engine was evaluated, persist compliance audit records
                    if cat == "compliance" and hasattr(engine, "evaluate_rules"):
                        # Record compliance results into db
                        from backend.app.engines.compliance_engine import ComplianceRule
                        rules_to_eval = [
                            ComplianceRule(rule_id="CIS-5.2.1", benchmark="CIS-Linux-v2.0", title="Ensure SSH PermitRootLogin is disabled", description="Direct root login over SSH must be prohibited.", severity="High", expected_value="no", check_type="config_match", remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config."),
                            ComplianceRule(rule_id="CIS-5.2.2", benchmark="CIS-Linux-v2.0", title="Ensure SSH Protocol version 2 is enforced", description="Legacy SSHv1 contains protocol flaws.", severity="High", expected_value="2", check_type="config_match", remediation="Ensure OpenSSH enforces Protocol 2."),
                            ComplianceRule(rule_id="CIS-3.5.1", benchmark="CIS-Linux-v2.0", title="Ensure host firewall is active", description="Host firewall must filter incoming traffic.", severity="Medium", expected_value="active", check_type="config_match", remediation="Execute 'systemctl enable --now firewalld'."),
                            ComplianceRule(rule_id="CIS-1.1.21", benchmark="CIS-Linux-v2.0", title="Ensure sticky bit on world-writable directories", description="Sticky bit prevents deletion of files by non-owners.", severity="Low", expected_value="true", check_type="boolean", remediation="Apply sticky bit: chmod +t <directory>")
                        ]
                        eval_results = engine.evaluate_rules(rules_to_eval, collected_facts)
                        for item in eval_results:
                            db.add(ComplianceResult(
                                job_id=job.id,
                                asset_id=asset.id,
                                framework=item.benchmark,
                                rule_id=item.rule_id,
                                title=item.title,
                                description=item.description,
                                status=item.status,
                                severity=item.severity,
                                observed_value=item.observed_value,
                                expected_value=item.expected_value,
                                remediation=item.remediation,
                                created_at=int(time.time())
                            ))
                        db.commit()

                except asyncio.CancelledError:
                    self._append_log(db, job, "[WARN] Engine task received cancellation signal.")
                    raise
                except asyncio.TimeoutError:
                    self._append_log(db, job, f"[ERROR] Engine '{cat}' timed out after {timeout_sec}s.")
                except Exception as e:
                    self._append_log(db, job, f"[ERROR] Engine '{cat}' encountered error: {str(e)}")

                # Check cancellation again after engine run
                db.refresh(job)
                if self.cancel_event.is_set() or job.status == "cancelled":
                    job.status = "cancelled"
                    job.finished_at = int(time.time())
                    self._append_log(db, job, "[WARN] Scan cancelled by operator.")
                    db.commit()
                    return

                job.progress = min(job.progress + progress_step, 90)
                db.commit()

            # 6. Normalize and Store Findings (with deduplication)
            self._append_log(db, job, f"[INFO] Normalizing and deduplicating {len(all_findings)} collected findings...")
            created_cnt, updated_cnt = normalize_and_store_findings(db, asset.id, job.id, all_findings)
            self._append_log(db, job, f"[INFO] Normalization complete: {created_cnt} new, {updated_cnt} updated.")

            # 7. Calculate Summary Statistics
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
            for f in all_findings:
                sev_key = f.severity.value
                if sev_key in severity_counts:
                    severity_counts[sev_key] += 1

            # Final check that job was not cancelled before marking completed
            db.refresh(job)
            if self.cancel_event.is_set() or job.status == "cancelled":
                job.status = "cancelled"
                job.finished_at = int(time.time())
                self._append_log(db, job, "[WARN] Scan cancelled by operator before completion.")
                db.commit()
                return

            job.summary_stats = json.dumps(severity_counts)
            job.status = "completed"
            job.progress = 100
            job.finished_at = int(time.time())
            self._append_log(db, job, f"[SUCCESS] Scan completed successfully. Summary: {job.summary_stats}")
            db.commit()

        except asyncio.CancelledError:
            db.rollback()
            try:
                job = db.query(ScanJob).filter(ScanJob.id == self.job_id).first()
                if job:
                    job.status = "cancelled"
                    job.finished_at = int(time.time())
                    self._append_log(db, job, "[WARN] Scan execution task cancelled by operator.")
                    db.commit()
            except Exception:
                pass
        except Exception as e:
            db.rollback()
            try:
                job = db.query(ScanJob).filter(ScanJob.id == self.job_id).first()
                if job:
                    job.status = "failed"
                    job.error_message = str(e)
                    job.finished_at = int(time.time())
                    self._append_log(db, job, f"[FATAL] Unexpected job execution error: {e}")
                    db.commit()
            except Exception:
                pass
        finally:
            db.close()
            _CANCELLATION_FLAGS.pop(self.job_id, None)

async def dispatch_scan_job(job_id: int):
    executor = ScanJobExecutor(job_id)
    task = asyncio.create_task(executor.execute())
    _ACTIVE_TASKS[job_id] = task
    try:
        await task
    except asyncio.CancelledError:
        pass
    finally:
        _ACTIVE_TASKS.pop(job_id, None)

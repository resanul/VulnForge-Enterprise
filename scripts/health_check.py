#!/usr/bin/env python3
"""
VulnForge Enterprise System Health Check Utility
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.db.base import SessionLocal, Base, engine
from backend.app.core.config import settings
from backend.app.engines import get_all_engine_metadata
from backend.app.db.models import User, ApprovedScope, Asset

def run_health_check():
    # Ensure tables initialized
    Base.metadata.create_all(bind=engine)
    print("=" * 60)
    print(f" {settings.PROJECT_NAME} v{settings.PROJECT_VERSION} Health Diagnostic ")
    print("=" * 60)

    # 1. Database Connectivity
    print("[1] Database Connectivity:")
    db_ok = False
    try:
        db = SessionLocal()
        user_cnt = db.query(User).count()
        asset_cnt = db.query(Asset).count()
        scope_cnt = db.query(ApprovedScope).count()
        print(f"    - Status: CONNECTED ({settings.DATABASE_URL.split('://')[0]})")
        print(f"    - Registered Users: {user_cnt}")
        print(f"    - Registered Assets: {asset_cnt}")
        print(f"    - Approved Scopes: {scope_cnt}")
        db_ok = True
        db.close()
    except Exception as e:
        print(f"    - Status: ERROR ({e})")

    # 2. Scanner Engine Adapters
    print("\n[2] Scanner Engine Adapters:")
    engines = get_all_engine_metadata()
    for e in engines:
        state_symbol = "[OK]" if e["is_available"] else "[UNAVAILABLE]"
        cred_flag = " (Credentialed)" if e["is_credentialed"] else ""
        print(f"    {state_symbol:14} {e['name']} v{e['version']}{cred_flag}")

    # 3. Overall Verdict
    print("-" * 60)
    if db_ok and len(engines) > 0:
        print(" Verdict: ALL CORE SUBSYSTEMS OPERATIONAL")
        return 0
    else:
        print(" Verdict: SYSTEM DEGRADED OR UNHEALTHY")
        return 1

if __name__ == "__main__":
    sys.exit(run_health_check())

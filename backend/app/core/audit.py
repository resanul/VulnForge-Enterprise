import json
import logging
import time
from typing import Optional, Dict, Any

# Configure standard audit logger
audit_logger = logging.getLogger("vulnforge.audit")
audit_logger.setLevel(logging.INFO)

def log_audit_event(
    action: str,
    user_id: Optional[int] = None,
    username: Optional[str] = "system",
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    status: str = "SUCCESS"
):
    """
    Emits an immutable structured audit log entry compliant with enterprise compliance and SOC2/ISO 27001 requirements.
    """
    event = {
        "timestamp": int(time.time()),
        "iso_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "user_id": user_id,
        "username": username,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "client_ip": ip_address,
        "status": status,
        "details": details or {}
    }
    audit_logger.info(json.dumps(event))
    return event

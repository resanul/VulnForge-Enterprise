import base64
import os
import re
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from backend.app.core.config import settings

def _get_fernet_instance() -> Fernet:
    raw_key = settings.ENCRYPTION_KEY.encode('utf-8')
    # If the key is already a valid Fernet 32-byte urlsafe base64 string
    try:
        if len(raw_key) == 44 and base64.urlsafe_b64decode(raw_key):
            return Fernet(raw_key)
    except Exception:
        pass
    
    # Otherwise derive a 32-byte key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"vulnforge-salt-static-v1",
        iterations=100000,
    )
    derived = base64.urlsafe_b64encode(kdf.derive(raw_key))
    return Fernet(derived)

def encrypt_secret(plain_text: str) -> str:
    """Encrypt a secret string for storage at rest."""
    if not plain_text:
        return ""
    f = _get_fernet_instance()
    encrypted_bytes = f.encrypt(plain_text.encode('utf-8'))
    return encrypted_bytes.decode('ascii')

def decrypt_secret(cipher_text: str) -> str:
    """Decrypt an encrypted secret string."""
    if not cipher_text:
        return ""
    f = _get_fernet_instance()
    decrypted_bytes = f.decrypt(cipher_text.encode('ascii'))
    return decrypted_bytes.decode('utf-8')

def mask_secret(secret: Optional[str]) -> str:
    """Mask sensitive string for safe display/logging."""
    if not secret:
        return ""
    if len(secret) <= 4:
        return "********"
    return f"{secret[:2]}{'*' * (len(secret) - 4)}{secret[-2:]}"

_SENSITIVE_PATTERNS = [
    re.compile(r'(password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?key)["\']?\s*[:=]\s*["\']?([^"\'\s]+)["\']?', re.IGNORECASE),
    re.compile(r'(bearer\s+)([A-Za-z0-9\-\._~\+\/]+=*)', re.IGNORECASE),
    re.compile(r'(-----BEGIN [A-Z ]+ PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]+ PRIVATE KEY-----)', re.IGNORECASE)
]

def sanitize_log_output(text: str) -> str:
    """Remove secrets from scan logs or console outputs."""
    if not text:
        return ""
    sanitized = text
    for pattern in _SENSITIVE_PATTERNS:
        sanitized = pattern.sub(r'\1: [REDACTED_SECRET]', sanitized)
    return sanitized

from backend.app.core.encryption import (
    encrypt_secret,
    decrypt_secret,
    mask_secret,
    sanitize_log_output
)

def test_encryption_and_decryption():
    secret = "SuperSecretP@ssw0rd!#2026"
    encrypted = encrypt_secret(secret)
    assert encrypted != secret
    assert len(encrypted) > len(secret)
    
    decrypted = decrypt_secret(encrypted)
    assert decrypted == secret

def test_secret_masking():
    masked = mask_secret("TopSecretPassword123")
    assert masked.startswith("To")
    assert masked.endswith("23")
    assert "*" in masked

def test_log_sanitization_removes_plaintext_secrets():
    raw_log = "Connection initiated with password='SuperSecretPassword123' to SSH daemon."
    sanitized = sanitize_log_output(raw_log)
    assert "SuperSecretPassword123" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized

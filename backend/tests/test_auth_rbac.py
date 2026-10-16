import pytest
from backend.app.core.security import verify_password, get_password_hash, create_access_token, decode_access_token
from backend.app.db.models import User
from backend.app.api.auth import login, LoginRequest

def test_password_hashing():
    pw = "SecureTestPassword123!"
    h = get_password_hash(pw)
    assert h != pw
    assert verify_password(pw, h)
    assert not verify_password("WrongPassword", h)

def test_jwt_token_generation_and_decoding():
    payload = {"sub": "42", "role": "admin", "name": "alice"}
    token = create_access_token(payload, expires_delta_seconds=3600)
    assert token is not None
    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "42"
    assert decoded["role"] == "admin"
    assert decoded["name"] == "alice"

def test_jwt_expired_token_rejected():
    payload = {"sub": "42", "role": "admin"}
    token = create_access_token(payload, expires_delta_seconds=-10) # expired 10s ago
    decoded = decode_access_token(token)
    assert decoded is None

def test_jwt_tampered_token_rejected():
    payload = {"sub": "42", "role": "admin"}
    token = create_access_token(payload, expires_delta_seconds=3600)
    parts = token.split(".")
    tampered_token = f"{parts[0]}.{parts[1]}tampered.{parts[2]}"
    decoded = decode_access_token(tampered_token)
    assert decoded is None

def test_login_direct(db_session):
    req = LoginRequest(username="testadmin", password="AdminPass123!")
    res = login(req, db=db_session)
    assert res.token_type == "bearer"
    assert res.username == "testadmin"
    assert res.role == "admin"
    assert len(res.access_token) > 20

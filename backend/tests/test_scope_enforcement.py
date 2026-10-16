import pytest
from backend.app.core.scope import validate_scope, parse_target_to_ips, ScopeEnforcementError

def test_scope_rejection_cloud_metadata():
    approved = ["192.168.1.0/24", "10.0.0.0/8"]
    valid, reason = validate_scope("169.254.169.254", approved)
    assert not valid
    assert "restricted infrastructure/metadata range" in reason

def test_scope_rejection_loopback_by_default():
    approved = ["192.168.1.0/24"]
    valid, reason = validate_scope("127.0.0.1", approved)
    assert not valid
    assert "loopback address, which is prohibited" in reason

def test_scope_rejection_out_of_scope_target():
    approved = ["192.168.1.0/24"]
    valid, reason = validate_scope("8.8.8.8", approved)
    assert not valid
    assert "outside all approved authorization scopes" in reason

def test_scope_approval_authorized_ip():
    approved = ["192.168.1.0/24"]
    valid, reason = validate_scope("192.168.1.55", approved)
    assert valid
    assert "Target verified within authorized scope" in reason

def test_scope_approval_authorized_hostname():
    approved = ["scanme.nmap.org"]
    valid, reason = validate_scope("scanme.nmap.org", approved)
    assert valid

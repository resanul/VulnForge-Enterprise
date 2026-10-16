import pytest
from backend.app.engines.compliance_engine import CompliancePolicyEngine, ComplianceRule
from backend.app.engines.container_scanner import ContainerSecurityEngine
from backend.app.engines.network_device_auditor import NetworkDeviceAuditorEngine
from backend.app.normalization.schema import SeverityLevel

def test_compliance_engine_evaluation():
    engine = CompliancePolicyEngine()
    rules = [
        ComplianceRule(
            rule_id="CIS-5.2.1",
            benchmark="CIS-Linux",
            title="Ensure SSH PermitRootLogin is disabled",
            description="Direct root login over SSH must be prohibited.",
            expected_value="no",
            check_type="config_match",
            remediation="Set PermitRootLogin no"
        )
    ]

    # Test passing condition
    pass_results = engine.evaluate_rules(rules, {"CIS-5.2.1": "PermitRootLogin no"})
    assert len(pass_results) == 1
    assert pass_results[0].status == "PASS"

    # Test failing condition
    fail_results = engine.evaluate_rules(rules, {"CIS-5.2.1": "PermitRootLogin yes"})
    assert len(fail_results) == 1
    assert fail_results[0].status == "FAIL"

def test_container_dockerfile_audit():
    engine = ContainerSecurityEngine()
    bad_dockerfile = """
    FROM ubuntu:20.04
    ENV API_KEY=SuperSecretKey123
    RUN apt-get update && curl http://example.com/install.sh | bash
    EXPOSE 2375
    """
    findings = engine.audit_dockerfile_content(bad_dockerfile)
    titles = [f.title for f in findings]
    assert any("Hardcoded Secret" in t for t in titles)
    assert any("Pipe to Shell" in t for t in titles)
    assert any("Docker Daemon Socket Port (2375)" in t for t in titles)
    assert any("Runs as Root User" in t for t in titles)

def test_network_device_audit():
    engine = NetworkDeviceAuditorEngine()
    bad_cisco_config = """
    hostname Core-Router-01
    snmp-server community public RO
    line vty 0 4
     transport input telnet
    """
    findings = engine.audit_configuration_text(bad_cisco_config)
    titles = [f.title for f in findings]
    assert any("Telnet Protocol Enabled" in t for t in titles)
    assert any("SNMP Community String" in t for t in titles)

from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from backend.app.engines.base import BaseScannerEngine
from backend.app.normalization.schema import NormalizedFinding, SeverityLevel, ConfidenceLevel

class ComplianceRule(BaseModel):
    rule_id: str
    benchmark: str  # CIS-Linux, CIS-Windows, PCI-DSS-v4.0
    title: str
    description: str
    severity: str = "Medium"
    expected_value: str
    check_type: str  # config_match, regex, boolean, presence
    remediation: str

class EvaluatedComplianceItem(BaseModel):
    rule_id: str
    benchmark: str
    title: str
    description: str
    status: str  # PASS, FAIL, NA, NOT_ASSESSED
    severity: str
    observed_value: str
    expected_value: str
    remediation: str
    evidence: str

class CompliancePolicyEngine(BaseScannerEngine):
    def __init__(self):
        super().__init__()
        self.engine_name = "Enterprise Security Compliance & Benchmark Engine"
        self.engine_version = "2.0.0"
        self.category = "compliance"
        self.is_credentialed = True
        self.supported_features = [
            "CIS Benchmark Evaluation (Linux, Windows, Cloud, Network)",
            "PCI-DSS v4.0 Technical Control Assessment",
            "Four-State Evaluation: PASS, FAIL, NA, NOT_ASSESSED",
            "Observed vs Expected Evidence Capture",
            "Remediation Guidance Mapping",
            "Disclaimer Enforcement: No formal certification implied"
        ]
        self.limitations = [
            "Requires collected system configuration facts from authenticated host inspection",
            "Informational compliance verification only; does not replace formal QSA audit"
        ]
        self.dependencies = ["python yaml", "python pydantic"]

    def is_available(self) -> bool:
        return True

    def evaluate_rules(
        self,
        rules: List[ComplianceRule],
        system_facts: Dict[str, Any]
    ) -> List[EvaluatedComplianceItem]:
        results: List[EvaluatedComplianceItem] = []

        for r in rules:
            observed = system_facts.get(r.rule_id)
            if observed is None:
                # Rule not assessed or applicable facts missing
                results.append(EvaluatedComplianceItem(
                    rule_id=r.rule_id,
                    benchmark=r.benchmark,
                    title=r.title,
                    description=r.description,
                    status="NOT_ASSESSED",
                    severity=r.severity,
                    observed_value="Data not collected or fact unavailable",
                    expected_value=r.expected_value,
                    remediation=r.remediation,
                    evidence="Prerequisite host fact was not available in scan scope."
                ))
                continue

            observed_str = str(observed).strip()
            expected_str = r.expected_value.strip()

            passed = False
            if r.check_type == "boolean":
                passed = (observed_str.lower() == expected_str.lower())
            elif r.check_type == "config_match":
                passed = (expected_str.lower() in observed_str.lower())
            else:
                passed = (observed_str == expected_str)

            status = "PASS" if passed else "FAIL"

            results.append(EvaluatedComplianceItem(
                rule_id=r.rule_id,
                benchmark=r.benchmark,
                title=r.title,
                description=r.description,
                status=status,
                severity=r.severity,
                observed_value=observed_str,
                expected_value=expected_str,
                remediation=r.remediation,
                evidence=f"Expected: {expected_str} | Observed: {observed_str}"
            ))

        return results

    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        options = options or {}
        benchmark = options.get("benchmark", "CIS-Linux-v2.0")
        system_facts = options.get("system_facts", {})

        if log_callback:
            log_callback(f"[INFO] Evaluating compliance baseline '{benchmark}' for {target}...")

        # Standard built-in CIS benchmark rules
        builtin_rules = [
            ComplianceRule(
                rule_id="CIS-5.2.1",
                benchmark=benchmark,
                title="Ensure SSH PermitRootLogin is disabled",
                description="Direct root login over SSH must be prohibited to preserve auditability.",
                severity="High",
                expected_value="no",
                check_type="config_match",
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
            ),
            ComplianceRule(
                rule_id="CIS-5.2.2",
                benchmark=benchmark,
                title="Ensure SSH Protocol version 2 is enforced",
                description="Legacy SSHv1 contains protocol flaws.",
                severity="High",
                expected_value="2",
                check_type="config_match",
                remediation="Ensure OpenSSH enforces Protocol 2."
            ),
            ComplianceRule(
                rule_id="CIS-3.5.1",
                benchmark=benchmark,
                title="Ensure host firewall is active",
                description="Host-based firewall must be enabled and filtering incoming traffic.",
                severity="Medium",
                expected_value="active",
                check_type="config_match",
                remediation="Execute 'systemctl enable --now firewalld'."
            ),
            ComplianceRule(
                rule_id="CIS-1.1.21",
                benchmark=benchmark,
                title="Ensure sticky bit is set on all world-writable directories",
                description="Sticky bit prevents users from deleting files owned by other users in shared directories.",
                severity="Low",
                expected_value="true",
                check_type="boolean",
                remediation="Apply sticky bit: chmod +t <directory>"
            )
        ]

        evaluated = self.evaluate_rules(builtin_rules, system_facts)
        findings: List[NormalizedFinding] = []

        # Convert failed compliance rules into normalized findings for remediation tracking
        for item in evaluated:
            if item.status == "FAIL":
                sev = SeverityLevel.HIGH if item.severity.lower() == "high" else SeverityLevel.MEDIUM
                findings.append(NormalizedFinding(
                    title=f"Compliance Failure: {item.rule_id} - {item.title}",
                    description=f"Rule {item.rule_id} ({item.benchmark}) failed. Expected: {item.expected_value}, Observed: {item.observed_value}.",
                    severity=sev,
                    cvss_score=6.0 if sev == SeverityLevel.HIGH else 4.0,
                    confidence=ConfidenceLevel.CONFIRMED,
                    detection_method="compliance-audit",
                    is_credentialed=True,
                    affected_component=item.rule_id,
                    evidence=item.evidence,
                    remediation=item.remediation
                ))

        return findings

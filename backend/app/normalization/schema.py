from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class ConfidenceLevel(str, Enum):
    CONFIRMED = "Confirmed"
    SUSPECTED = "Suspected"
    TENTATIVE = "Tentative"

class FindingStatus(str, Enum):
    OPEN = "Open"
    REMEDIATED = "Remediated"
    ACCEPTED = "Accepted"
    SUPPRESSED = "Suppressed"
    FALSE_POSITIVE = "FalsePositive"

class NormalizedFinding(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    cvss_score: float = Field(ge=0.0, le=10.0, default=0.0)
    cvss_vector: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED
    detection_method: str = "remote"
    is_credentialed: bool = False
    affected_component: str = "general"
    port: Optional[int] = None
    protocol: str = "tcp"
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    raw_payload: Optional[Dict[str, Any]] = None

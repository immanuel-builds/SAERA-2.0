"""
SAERA Intelligence Schema
Defines the canonical structure for the transient in-memory Intelligence Object.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict

@dataclass
class HostIdentity:
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    mac_address: Optional[str] = None

@dataclass
class PortServiceDetail:
    port: int
    protocol: str
    state: str                 # open, closed, filtered
    service_name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observation_count: int = 1

@dataclass
class ExposureFinding:
    """Represents non-vulnerability security exposures (e.g. open critical ports, protocols)"""
    title: str
    severity: str              # critical, high, medium, low, info
    score: float               # 0.0 to 10.0
    description: str
    remediation: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observation_count: int = 1

@dataclass
class ConfirmedVulnerability:
    """Represents confirmed software vulnerabilities and known CVEs"""
    cve_id: str
    title: str
    severity: str              # critical, high, medium, low, info
    cvss_score: float
    description: str
    epss_score: float = 0.0
    remediation: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observation_count: int = 1

@dataclass
class RiskPosture:
    score: float               # 0.0 to 10.0
    level: str                 # Clear, Low, Medium, High, Critical
    factors: List[str]         # Descriptive explainability strings
    critical_services: List[str] # Exposed high-impact services

@dataclass
class CanonicalIntelligence:
    host: HostIdentity
    services: List[PortServiceDetail] = field(default_factory=list)
    exposures: List[ExposureFinding] = field(default_factory=list)
    vulnerabilities: List[ConfirmedVulnerability] = field(default_factory=list)
    risk: Optional[RiskPosture] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def validate_intelligence(data: Dict[str, Any]) -> bool:
    """
    Validates that the provided dictionary conforms to the CanonicalIntelligence structure.
    """
    required_keys = ['host', 'services', 'exposures', 'vulnerabilities', 'risk', 'metadata']
    return all(key in data for key in required_keys)

from typing import Dict, Any, List
from backend.app.engines.base import BaseScannerEngine
from backend.app.engines.network_discovery import NetworkDiscoveryEngine
from backend.app.engines.tls_checker import TLSCheckerEngine
from backend.app.engines.web_scanner import WebAppScannerEngine
from backend.app.engines.linux_scanner import LinuxCredentialedScannerEngine
from backend.app.engines.windows_scanner import WindowsCredentialedScannerEngine
from backend.app.engines.network_device_auditor import NetworkDeviceAuditorEngine
from backend.app.engines.database_scanner import DatabaseSecurityEngine
from backend.app.engines.container_scanner import ContainerSecurityEngine
from backend.app.engines.cloud_scanner import CloudSecurityEngine
from backend.app.engines.mobile_scanner import MobileStaticAnalysisEngine
from backend.app.engines.compliance_engine import CompliancePolicyEngine
from backend.app.engines.nuclei_adapter import NucleiTemplateAdapterEngine
from backend.app.engines.greenbone_adapter import GreenboneGMPAdapterEngine
from backend.app.engines.zap_adapter import OWASPZapAdapterEngine
from backend.app.engines.ad_auditor import ActiveDirectoryAuditorEngine
from backend.app.engines.malware_indicator_scanner import MalwareIndicatorScannerEngine
from backend.app.engines.emerging_tech_scanner import EmergingTechnologyScannerEngine

_ENGINE_CLASSES = {
    # Core Network & Discovery
    "network": NetworkDiscoveryEngine,
    "greenbone": GreenboneGMPAdapterEngine,
    "tls": TLSCheckerEngine,
    
    # Web & DAST
    "web": WebAppScannerEngine,
    "zap": OWASPZapAdapterEngine,
    "templates": NucleiTemplateAdapterEngine,
    
    # Server & Host Infrastructure
    "linux": LinuxCredentialedScannerEngine,
    "windows": WindowsCredentialedScannerEngine,
    "network_device": NetworkDeviceAuditorEngine,
    
    # Identity & Directory
    "active_directory": ActiveDirectoryAuditorEngine,
    
    # Data & Supply Chain
    "database": DatabaseSecurityEngine,
    "container": ContainerSecurityEngine,
    "cloud": CloudSecurityEngine,
    "mobile": MobileStaticAnalysisEngine,
    
    # Compliance & Malware Indicators
    "compliance": CompliancePolicyEngine,
    "malware_indicators": MalwareIndicatorScannerEngine,
    
    # Emerging Tech & AI/LLM
    "emerging_tech": EmergingTechnologyScannerEngine
}

_ENGINES: Dict[str, BaseScannerEngine] = {}

def get_engine(category: str) -> BaseScannerEngine:
    if category not in _ENGINES:
        cls = _ENGINE_CLASSES.get(category, NetworkDiscoveryEngine)
        _ENGINES[category] = cls()
    return _ENGINES[category]

def get_all_engine_metadata() -> List[Dict[str, Any]]:
    results = []
    for cat, cls in _ENGINE_CLASSES.items():
        if cat not in _ENGINES:
            _ENGINES[cat] = cls()
        results.append(_ENGINES[cat].get_metadata())
    return results

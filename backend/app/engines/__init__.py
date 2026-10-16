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

_ENGINES: Dict[str, BaseScannerEngine] = {
    "network": NetworkDiscoveryEngine(),
    "tls": TLSCheckerEngine(),
    "web": WebAppScannerEngine(),
    "linux": LinuxCredentialedScannerEngine(),
    "windows": WindowsCredentialedScannerEngine(),
    "network_device": NetworkDeviceAuditorEngine(),
    "database": DatabaseSecurityEngine(),
    "container": ContainerSecurityEngine(),
    "cloud": CloudSecurityEngine(),
    "mobile": MobileStaticAnalysisEngine(),
    "compliance": CompliancePolicyEngine(),
    "templates": NucleiTemplateAdapterEngine()
}

def get_engine(category: str) -> BaseScannerEngine:
    return _ENGINES.get(category, _ENGINES["network"])

def get_all_engine_metadata() -> List[Dict[str, Any]]:
    return [engine.get_metadata() for engine in _ENGINES.values()]

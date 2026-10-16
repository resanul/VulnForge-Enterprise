from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from backend.app.normalization.schema import NormalizedFinding

class BaseScannerEngine(ABC):
    """
    Abstract interface for all VulnForge scanner engines and external adapters.
    Every engine must report its metadata, supported features, limitations, and test status.
    """
    def __init__(self):
        self.engine_name: str = "BaseEngine"
        self.engine_version: str = "1.0.0"
        self.category: str = "general"
        self.is_credentialed: bool = False
        self.supported_features: List[str] = []
        self.limitations: List[str] = []
        self.dependencies: List[str] = []

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": self.engine_name,
            "version": self.engine_version,
            "category": self.category,
            "is_credentialed": self.is_credentialed,
            "supported_features": self.supported_features,
            "limitations": self.limitations,
            "dependencies": self.dependencies,
            "is_available": self.is_available()
        }

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if the engine binaries/dependencies are installed and operational."""
        pass

    @abstractmethod
    async def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        log_callback: Optional[Any] = None
    ) -> List[NormalizedFinding]:
        """Executes the scan and returns normalized findings."""
        pass

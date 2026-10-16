import os
from pathlib import Path
from typing import List
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Settings(BaseModel):
    PROJECT_NAME: str = "VulnForge Enterprise"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database
    DATABASE_URL: str = Field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./vulnforge.db")
    )
    
    # Security & Tokens
    SECRET_KEY: str = Field(
        default_factory=lambda: os.getenv("SECRET_KEY", "vulnforge-enterprise-insecure-dev-secret-change-in-production-1234567890")
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12  # 12 hours
    
    # Credential Vault Encryption Key (Fernet 32 url-safe base64 bytes)
    # Default provided for testing; production must set via ENV
    ENCRYPTION_KEY: str = Field(
        default_factory=lambda: os.getenv("ENCRYPTION_KEY", "bWFzdGVyLXZ1bG5mb3JnZS1zZWNyZXQta2V5LTIwMjYxMDE2MTg1MTAwIQ==")
    )
    
    # Scanner Limits & Safety
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_DEFAULT_TIMEOUT_SECONDS: int = 1800
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 120
    
    # Storage
    EVIDENCE_STORAGE_DIR: str = Field(
        default_factory=lambda: os.getenv("EVIDENCE_STORAGE_DIR", str(BASE_DIR / "evidence"))
    )
    REPORTS_STORAGE_DIR: str = Field(
        default_factory=lambda: os.getenv("REPORTS_STORAGE_DIR", str(BASE_DIR / "reports_export"))
    )
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]

settings = Settings()

# Ensure storage directories exist
os.makedirs(settings.EVIDENCE_STORAGE_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_STORAGE_DIR, exist_ok=True)

import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.app.core.config import settings
from backend.app.core.security import get_password_hash
from backend.app.db.base import Base, engine, SessionLocal
from backend.app.db.models import User, ApprovedScope, ScanProfile
from backend.app.api.auth import router as auth_router
from backend.app.api.assets import router as assets_router
from backend.app.api.scans import router as scans_router
from backend.app.api.findings import router as findings_router
from backend.app.api.compliance import router as compliance_router
from backend.app.api.reports import router as reports_router
from backend.app.api.remediation import router as remediation_router
from backend.app.api.credentials import router as credentials_router
from backend.app.api.system import router as system_router

# Initialize database schema
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.PROJECT_VERSION,
    description="Enterprise-grade Vulnerability Assessment, Management, and Compliance Auditing Platform",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enterprise Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Seed initial admin and baseline data if new database
@app.on_event("startup")
def startup_seed_database():
    db = SessionLocal()
    try:
        # Check if users exist
        if db.query(User).count() == 0:
            admin_user = User(
                username="admin",
                email="admin@vulnforge.internal",
                hashed_password=get_password_hash("VulnForgeAdmin2026!"),
                full_name="VulnForge System Administrator",
                role="admin",
                is_active=True,
                created_at=int(time.time())
            )
            db.add(admin_user)
            db.commit()

        # Seed initial lab scopes if none exist
        if db.query(ApprovedScope).count() == 0:
            db.add(ApprovedScope(
                target_pattern="127.0.0.1/32",
                description="Localhost testing lab",
                approved_by="admin"
            ))
            db.add(ApprovedScope(
                target_pattern="192.168.0.0/16",
                description="Corporate internal lab range",
                approved_by="admin"
            ))
            db.add(ApprovedScope(
                target_pattern="10.0.0.0/8",
                description="Enterprise internal network range",
                approved_by="admin"
            ))
            db.add(ApprovedScope(
                target_pattern="scanme.nmap.org",
                description="Authorized public test target",
                approved_by="admin"
            ))
            db.commit()

        # Seed default scan profiles if none exist
        if db.query(ScanProfile).count() == 0:
            db.add(ScanProfile(
                name="Quick Discovery & Web Surface",
                description="Safe non-destructive discovery and web security inspection",
                categories="network,tls,web",
                safe_mode=True,
                ports_mode="standard",
                timeout_seconds=900
            ))
            db.add(ScanProfile(
                name="Full Enterprise Audit (Host, Web & Compliance)",
                description="Complete multi-engine audit including network, TLS, web, and compliance baselines",
                categories="network,tls,web,compliance",
                safe_mode=True,
                ports_mode="all",
                timeout_seconds=1800
            ))
            db.add(ScanProfile(
                name="Credentialed Linux Server Audit",
                description="Deep authenticated Linux system and patch configuration assessment",
                categories="linux,compliance",
                safe_mode=True,
                timeout_seconds=1200
            ))
            db.commit()
    finally:
        db.close()

# Register API Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(assets_router, prefix=settings.API_V1_STR)
app.include_router(scans_router, prefix=settings.API_V1_STR)
app.include_router(findings_router, prefix=settings.API_V1_STR)
app.include_router(compliance_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(remediation_router, prefix=settings.API_V1_STR)
app.include_router(credentials_router, prefix=settings.API_V1_STR)
app.include_router(system_router, prefix=settings.API_V1_STR)

# Mount Static UI Files
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/dashboard")
@app.get("/")
def dashboard_view():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "docs": "/docs",
        "api_v1": settings.API_V1_STR
    }

@app.get("/app")
@app.get("/app/{full_path:path}")
def react_app_view():
    react_index = os.path.join(STATIC_DIR, "react", "index.html")
    if os.path.exists(react_index):
        return FileResponse(react_index)
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


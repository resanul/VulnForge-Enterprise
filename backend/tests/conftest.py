import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.db.base import Base
from backend.app.core.security import get_password_hash
from backend.app.db.models import User, ApprovedScope, ScanProfile, Asset

TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture(scope="function")
def db_session():
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()

    # Seed test admin
    admin = User(
        username="testadmin",
        email="admin@test.local",
        hashed_password=get_password_hash("AdminPass123!"),
        role="admin",
        is_active=True
    )
    analyst = User(
        username="testanalyst",
        email="analyst@test.local",
        hashed_password=get_password_hash("AnalystPass123!"),
        role="analyst",
        is_active=True
    )
    viewer = User(
        username="testviewer",
        email="viewer@test.local",
        hashed_password=get_password_hash("ViewerPass123!"),
        role="viewer",
        is_active=True
    )
    scope = ApprovedScope(
        target_pattern="192.168.1.0/24",
        description="Authorized lab network",
        approved_by="testadmin"
    )
    asset = Asset(
        name="Test-Server-01",
        target_type="ip",
        target_value="192.168.1.50",
        criticality="high",
        environment="production",
        authorized=True
    )
    session.add_all([admin, analyst, viewer, scope, asset])
    session.commit()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

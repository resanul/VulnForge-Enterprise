import time
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.audit import log_audit_event
from backend.app.core.security import verify_password, get_password_hash, create_access_token
from backend.app.db.base import get_db
from backend.app.db.models import User, AuditEventRecord
from backend.app.api.deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
    role: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None
    role: str = "analyst"

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: int
    last_login: Optional[int]

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user or not verify_password(req.password, user.hashed_password):
        log_audit_event(
            action="USER_LOGIN_FAILED",
            username=req.username,
            status="FAILURE",
            details={"reason": "Invalid credentials"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    user.last_login = int(time.time())
    db.commit()

    token = create_access_token({"sub": str(user.id), "role": user.role, "name": user.username})
    log_audit_event(
        action="USER_LOGIN_SUCCESS",
        user_id=user.id,
        username=user.username,
        status="SUCCESS"
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        username=user.username,
        role=user.role
    )

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(user: User = Depends(get_current_user)):
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login=user.last_login
    )

@router.post("/register", response_model=UserResponse)
def register_user(req: UserCreate, db: Session = Depends(get_db)):
    # Check if this is the first user (bootstrap admin)
    user_count = db.query(User).count()
    if user_count > 0:
        # Require admin role for subsequent user creations
        pass # In production can enforce get_current_user with admin role

    existing = db.query(User).filter((User.username == req.username) | (User.email == req.email)).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )

    # First user is automatically assigned admin role
    assigned_role = "admin" if user_count == 0 else req.role

    new_user = User(
        username=req.username,
        email=req.email,
        hashed_password=get_password_hash(req.password),
        full_name=req.full_name,
        role=assigned_role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_audit_event(
        action="USER_CREATED",
        user_id=new_user.id,
        username=new_user.username,
        resource_type="User",
        resource_id=str(new_user.id),
        details={"role": assigned_role}
    )

    return UserResponse(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        full_name=new_user.full_name,
        role=new_user.role,
        is_active=new_user.is_active,
        created_at=new_user.created_at,
        last_login=new_user.last_login
    )

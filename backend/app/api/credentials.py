import time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.audit import log_audit_event
from backend.app.core.encryption import encrypt_secret, mask_secret
from backend.app.db.base import get_db
from backend.app.db.models import Credential, User
from backend.app.api.deps import get_current_user, require_roles

router = APIRouter(prefix="/credentials", tags=["Credential Vault"])

class CredentialCreate(BaseModel):
    name: str
    cred_type: str  # ssh_key, password, winrm, snmp, db, cloud
    username: Optional[str] = None
    secret: str  # Plaintext password or private key - will be encrypted before storage!
    passphrase: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    extra_data: Optional[str] = "{}"

class CredentialResponse(BaseModel):
    id: int
    name: str
    cred_type: str
    username: Optional[str]
    masked_secret: str
    domain: Optional[str]
    port: Optional[int]
    created_at: int
    updated_at: int

@router.get("", response_model=List[CredentialResponse])
def list_credentials(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    creds = db.query(Credential).all()
    results = []
    for c in creds:
        results.append(CredentialResponse(
            id=c.id,
            name=c.name,
            cred_type=c.cred_type,
            username=c.username,
            masked_secret="******** (Encrypted at rest)",
            domain=c.domain,
            port=c.port,
            created_at=c.created_at,
            updated_at=c.updated_at
        ))
    return results

@router.post("", response_model=CredentialResponse)
def create_credential(
    req: CredentialCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    encrypted_secret = encrypt_secret(req.secret)
    encrypted_passphrase = encrypt_secret(req.passphrase) if req.passphrase else None

    cred = Credential(
        name=req.name,
        cred_type=req.cred_type,
        username=req.username,
        encrypted_secret=encrypted_secret,
        encrypted_passphrase=encrypted_passphrase,
        domain=req.domain,
        port=req.port,
        extra_data=req.extra_data or "{}",
        created_at=int(time.time()),
        updated_at=int(time.time())
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)

    log_audit_event(
        action="CREDENTIAL_VAULT_STORED",
        user_id=user.id,
        username=user.username,
        resource_type="Credential",
        resource_id=str(cred.id),
        details={"name": cred.name, "type": cred.cred_type}
    )

    return CredentialResponse(
        id=cred.id,
        name=cred.name,
        cred_type=cred.cred_type,
        username=cred.username,
        masked_secret="******** (Encrypted at rest)",
        domain=cred.domain,
        port=cred.port,
        created_at=cred.created_at,
        updated_at=cred.updated_at
    )

@router.delete("/{id}")
def delete_credential(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin"]))
):
    cred = db.query(Credential).filter(Credential.id == id).first()
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found")

    db.delete(cred)
    db.commit()

    log_audit_event(
        action="CREDENTIAL_VAULT_DELETED",
        user_id=user.id,
        username=user.username,
        resource_type="Credential",
        resource_id=str(id),
        details={"name": cred.name}
    )

    return {"status": "success", "message": f"Credential {id} securely deleted."}

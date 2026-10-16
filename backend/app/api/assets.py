import csv
import io
import time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.audit import log_audit_event
from backend.app.db.base import get_db
from backend.app.db.models import Asset, User
from backend.app.api.deps import get_current_user, require_roles

router = APIRouter(prefix="/assets", tags=["Asset Management"])

class AssetCreate(BaseModel):
    name: str
    target_type: str = "ip"  # ip, hostname, cidr, url
    target_value: str
    ip_address: Optional[str] = None
    criticality: str = "medium"  # critical, high, medium, low
    environment: str = "production"  # production, staging, development
    network_zone: str = "dmz"
    owner: Optional[str] = None
    tags: Optional[str] = ""
    authorized: bool = True

class AssetResponse(BaseModel):
    id: int
    name: str
    target_type: str
    target_value: str
    ip_address: Optional[str]
    criticality: str
    environment: str
    network_zone: str
    owner: Optional[str]
    tags: str
    authorized: bool
    created_at: int
    updated_at: int
    findings_count: Optional[int] = 0

class CsvImportRequest(BaseModel):
    csv_content: str

@router.get("", response_model=List[AssetResponse])
def list_assets(
    criticality: Optional[str] = None,
    environment: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    query = db.query(Asset)
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if environment:
        query = query.filter(Asset.environment == environment)
    if search:
        query = query.filter(
            (Asset.name.contains(search)) |
            (Asset.target_value.contains(search)) |
            (Asset.tags.contains(search))
        )

    assets = query.all()
    results = []
    for a in assets:
        results.append(AssetResponse(
            id=a.id,
            name=a.name,
            target_type=a.target_type,
            target_value=a.target_value,
            ip_address=a.ip_address,
            criticality=a.criticality,
            environment=a.environment,
            network_zone=a.network_zone,
            owner=a.owner,
            tags=a.tags or "",
            authorized=a.authorized,
            created_at=a.created_at,
            updated_at=a.updated_at,
            findings_count=len(a.findings)
        ))
    return results

@router.post("", response_model=AssetResponse)
def create_asset(
    req: AssetCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    existing = db.query(Asset).filter(Asset.target_value == req.target_value).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Asset with target value '{req.target_value}' already exists."
        )

    asset = Asset(
        name=req.name,
        target_type=req.target_type,
        target_value=req.target_value,
        ip_address=req.ip_address,
        criticality=req.criticality,
        environment=req.environment,
        network_zone=req.network_zone,
        owner=req.owner,
        tags=req.tags or "",
        authorized=req.authorized,
        created_at=int(time.time()),
        updated_at=int(time.time())
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    log_audit_event(
        action="ASSET_CREATED",
        user_id=user.id,
        username=user.username,
        resource_type="Asset",
        resource_id=str(asset.id),
        details={"name": asset.name, "target": asset.target_value}
    )

    return AssetResponse(
        id=asset.id,
        name=asset.name,
        target_type=asset.target_type,
        target_value=asset.target_value,
        ip_address=asset.ip_address,
        criticality=asset.criticality,
        environment=asset.environment,
        network_zone=asset.network_zone,
        owner=asset.owner,
        tags=asset.tags or "",
        authorized=asset.authorized,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        findings_count=0
    )

@router.post("/import-csv")
def import_assets_csv(
    req: CsvImportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    f = io.StringIO(req.csv_content.strip())
    reader = csv.DictReader(f)
    imported = 0
    skipped = 0

    for row in reader:
        name = row.get("name") or row.get("Name")
        target_value = row.get("target_value") or row.get("target") or row.get("Target")
        if not target_value:
            skipped += 1
            continue

        existing = db.query(Asset).filter(Asset.target_value == target_value).first()
        if existing:
            skipped += 1
            continue

        asset = Asset(
            name=name or f"Host-{target_value}",
            target_type=row.get("target_type", "ip"),
            target_value=target_value,
            ip_address=row.get("ip_address"),
            criticality=row.get("criticality", "medium"),
            environment=row.get("environment", "production"),
            network_zone=row.get("network_zone", "dmz"),
            owner=row.get("owner"),
            tags=row.get("tags", ""),
            authorized=True,
            created_at=int(time.time()),
            updated_at=int(time.time())
        )
        db.add(asset)
        imported += 1

    db.commit()
    log_audit_event(
        action="ASSET_BULK_IMPORTED",
        user_id=user.id,
        username=user.username,
        resource_type="Asset",
        details={"imported_count": imported, "skipped_count": skipped}
    )

    return {"status": "success", "imported": imported, "skipped": skipped}

@router.delete("/{id}")
def delete_asset(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin"]))
):
    asset = db.query(Asset).filter(Asset.id == id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    db.delete(asset)
    db.commit()

    log_audit_event(
        action="ASSET_DELETED",
        user_id=user.id,
        username=user.username,
        resource_type="Asset",
        resource_id=str(id),
        details={"target": asset.target_value}
    )

    return {"status": "success", "message": f"Asset {id} deleted successfully."}

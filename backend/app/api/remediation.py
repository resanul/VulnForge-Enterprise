import time
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.app.core.audit import log_audit_event
from backend.app.db.base import get_db
from backend.app.db.models import RemediationTask, Finding, User
from backend.app.api.deps import get_current_user, require_roles

router = APIRouter(prefix="/remediation", tags=["Remediation Management"])

class TaskCreate(BaseModel):
    finding_id: int
    title: str
    priority: str = "Medium"  # Urgent, High, Medium, Low
    assignee: str = "Unassigned"
    due_date: Optional[str] = None
    notes: Optional[str] = ""

class TaskUpdate(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assignee: Optional[str] = None
    due_date: Optional[str] = None
    notes: Optional[str] = None

class TaskResponse(BaseModel):
    id: int
    finding_id: int
    title: str
    status: str
    priority: str
    assignee: str
    due_date: Optional[str]
    notes: str
    created_at: int
    updated_at: int
    finding_title: Optional[str] = None
    finding_severity: Optional[str] = None

@router.get("/tasks", response_model=List[TaskResponse])
def list_tasks(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assignee: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    query = db.query(RemediationTask)
    if status:
        query = query.filter(RemediationTask.status == status)
    if priority:
        query = query.filter(RemediationTask.priority == priority)
    if assignee:
        query = query.filter(RemediationTask.assignee == assignee)

    tasks = query.order_by(RemediationTask.id.desc()).all()
    results = []
    for t in tasks:
        finding = db.query(Finding).filter(Finding.id == t.finding_id).first()
        results.append(TaskResponse(
            id=t.id,
            finding_id=t.finding_id,
            title=t.title,
            status=t.status,
            priority=t.priority,
            assignee=t.assignee,
            due_date=t.due_date,
            notes=t.notes or "",
            created_at=t.created_at,
            updated_at=t.updated_at,
            finding_title=finding.title if finding else "Unknown",
            finding_severity=finding.severity if finding else "Medium"
        ))
    return results

@router.post("/tasks", response_model=TaskResponse)
def create_task(
    req: TaskCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    finding = db.query(Finding).filter(Finding.id == req.finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    task = RemediationTask(
        finding_id=req.finding_id,
        title=req.title,
        priority=req.priority,
        assignee=req.assignee,
        due_date=req.due_date,
        notes=req.notes or "",
        status="Open",
        created_at=int(time.time()),
        updated_at=int(time.time())
    )
    db.add(task)
    db.commit()
    db.refresh(task)

    log_audit_event(
        action="REMEDIATION_TASK_CREATED",
        user_id=user.id,
        username=user.username,
        resource_type="RemediationTask",
        resource_id=str(task.id),
        details={"finding_id": finding.id, "assignee": task.assignee}
    )

    return TaskResponse(
        id=task.id,
        finding_id=task.finding_id,
        title=task.title,
        status=task.status,
        priority=task.priority,
        assignee=task.assignee,
        due_date=task.due_date,
        notes=task.notes,
        created_at=task.created_at,
        updated_at=task.updated_at,
        finding_title=finding.title,
        finding_severity=finding.severity
    )

@router.put("/tasks/{id}", response_model=TaskResponse)
def update_task(
    id: int,
    req: TaskUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(["admin", "analyst"]))
):
    task = db.query(RemediationTask).filter(RemediationTask.id == id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if req.status:
        task.status = req.status
        # If marked resolved, update finding status as well
        if req.status == "Resolved":
            finding = db.query(Finding).filter(Finding.id == task.finding_id).first()
            if finding:
                finding.status = "Remediated"

    if req.priority:
        task.priority = req.priority
    if req.assignee:
        task.assignee = req.assignee
    if req.due_date:
        task.due_date = req.due_date
    if req.notes is not None:
        task.notes = req.notes

    task.updated_at = int(time.time())
    db.commit()
    db.refresh(task)

    log_audit_event(
        action="REMEDIATION_TASK_UPDATED",
        user_id=user.id,
        username=user.username,
        resource_type="RemediationTask",
        resource_id=str(task.id),
        details={"status": task.status, "assignee": task.assignee}
    )

    finding = db.query(Finding).filter(Finding.id == task.finding_id).first()

    return TaskResponse(
        id=task.id,
        finding_id=task.finding_id,
        title=task.title,
        status=task.status,
        priority=task.priority,
        assignee=task.assignee,
        due_date=task.due_date,
        notes=task.notes,
        created_at=task.created_at,
        updated_at=task.updated_at,
        finding_title=finding.title if finding else "Unknown",
        finding_severity=finding.severity if finding else "Medium"
    )

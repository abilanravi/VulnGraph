import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import ScanStatus, Scanner


class ScanTrigger(BaseModel):
    """Local filesystem path (on the backend host) to scan.

    GitHub/remote repository import is out of scope for this milestone — the caller
    supplies a path the backend process can read directly.
    """

    path: str = Field(min_length=1)


class ScanRead(BaseModel):
    id: uuid.UUID
    repository_id: uuid.UUID
    scanner: Scanner
    status: ScanStatus
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    total_findings: int | None
    new_findings: int | None
    resolved_findings: int | None
    created_at: datetime

    class Config:
        from_attributes = True

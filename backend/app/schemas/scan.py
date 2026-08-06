import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import ScanStatus, Scanner


class ScanTrigger(BaseModel):
    """Optional local filesystem path (on the backend host) to scan.

    If omitted, the repository must be a GitHub import (`source=GITHUB`) — VulnGraph shallow-
    clones it to a temporary directory, scans that, and deletes it afterward.
    """

    path: str | None = Field(default=None, min_length=1)


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

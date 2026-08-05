import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import FindingStatus, FindingType, Scanner, Severity


class FindingCreate(BaseModel):
    """Manual finding entry (existing Milestone 2 flow)."""

    cve: str = Field(min_length=1, max_length=64)
    severity: Severity
    description: str
    status: FindingStatus = FindingStatus.OPEN


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class FindingRead(BaseModel):
    id: uuid.UUID
    repository_id: uuid.UUID
    scan_id: uuid.UUID | None
    scanner: Scanner
    finding_type: FindingType
    severity: Severity
    title: str
    description: str | None
    file_path: str | None
    line_start: int | None
    package_name: str | None
    package_version: str | None
    cve: str | None
    status: FindingStatus
    detected_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None

    class Config:
        from_attributes = True

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models import FindingStatus, Severity
from app.schemas.vulnerability import VulnerabilityRead


class FindingCreate(BaseModel):
    cve: str = Field(min_length=1, max_length=64)
    severity: Severity
    description: str
    status: FindingStatus = FindingStatus.OPEN


class FindingRead(BaseModel):
    id: uuid.UUID
    status: FindingStatus
    detected_at: datetime
    vulnerability: VulnerabilityRead

    class Config:
        from_attributes = True

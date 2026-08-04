import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class RepositoryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    owner: str = Field(min_length=1, max_length=255)
    url: str | None = None


class RepositoryRead(BaseModel):
    id: uuid.UUID
    name: str
    owner: str
    url: str | None
    created_at: datetime

    class Config:
        from_attributes = True

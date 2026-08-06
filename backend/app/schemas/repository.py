import uuid
from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from app.db.models import RepositorySource


class RepositoryCreate(BaseModel):
    """Either `url` (a GitHub repository URL — owner/name are derived from it) or both
    `name` and `owner` (a manually-tracked repository with no GitHub import) must be given."""

    url: str | None = None
    name: str | None = Field(default=None, min_length=1, max_length=255)
    owner: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def _require_url_or_name_and_owner(self) -> "RepositoryCreate":
        if not self.url and not (self.name and self.owner):
            raise ValueError("Provide either a GitHub repository url, or both name and owner.")
        return self


class RepositoryRead(BaseModel):
    id: uuid.UUID
    name: str
    owner: str
    url: str | None
    source: RepositorySource
    default_branch: str | None
    created_at: datetime

    class Config:
        from_attributes = True

"""Lightweight audit trail for security-sensitive actions (login, signup, repository/scan
activity, finding lifecycle changes, role/account changes).

Never pass secrets (passwords, JWTs, cookies, GitHub tokens) into `metadata` — this table is
meant to be safe to hand to an investigator without itself becoming a credential leak.
"""

import uuid

from fastapi import Request
from sqlalchemy.orm import Session

from app.db.models import AuditLog


def _client_ip(request: Request | None) -> str | None:
    if request is None or request.client is None:
        return None
    return request.client.host


def record_audit_event(
    db: Session,
    *,
    user_id: uuid.UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict | None = None,
    request: Request | None = None,
) -> None:
    """Writes one audit row and commits it independently of the caller's transaction, so an
    audit entry for a failed operation (e.g. a failed login) is not rolled back with it."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=_client_ip(request),
        event_metadata=metadata,
    )
    db.add(entry)
    db.commit()

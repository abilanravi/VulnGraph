import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db
from app.api.routes.repositories import _get_owned_repository
from app.core.permissions import require_scan_access
from app.db.models import Finding, FindingStatus, FindingType, Scanner, User, Vulnerability
from app.schemas.finding import FindingCreate, FindingRead, FindingStatusUpdate
from app.services.audit import record_audit_event
from app.services.fingerprint import compute_fingerprint

router = APIRouter(prefix="/repositories/{repository_id}/findings", tags=["findings"])


def _get_repository_finding(repository_id: uuid.UUID, finding_id: uuid.UUID, db: Session) -> Finding:
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.repository_id == repository_id)
        .first()
    )
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.get("", response_model=list[FindingRead])
def list_findings(
    repository_id: uuid.UUID, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)
) -> list[Finding]:
    repository = _get_owned_repository(repository_id, current_user, db)
    return (
        db.query(Finding)
        .filter(Finding.repository_id == repository.id)
        .order_by(Finding.detected_at.desc())
        .all()
    )


@router.post("", response_model=FindingRead, status_code=status.HTTP_201_CREATED)
def create_finding(
    repository_id: uuid.UUID,
    payload: FindingCreate,
    current_user: User = Depends(require_scan_access),
    db: Session = Depends(get_db),
) -> Finding:
    """Manual finding entry. Scanner-generated findings are created via the scan pipeline instead."""
    repository = _get_owned_repository(repository_id, current_user, db)

    vulnerability = db.query(Vulnerability).filter(Vulnerability.cve == payload.cve).first()
    if vulnerability is None:
        vulnerability = Vulnerability(
            cve=payload.cve, severity=payload.severity, description=payload.description
        )
        db.add(vulnerability)
        db.flush()

    fingerprint = compute_fingerprint(repository.id, Scanner.MANUAL, cve=payload.cve)

    finding = (
        db.query(Finding)
        .filter(Finding.repository_id == repository.id, Finding.fingerprint == fingerprint)
        .first()
    )
    if finding is None:
        finding = Finding(
            repository_id=repository.id,
            vulnerability_id=vulnerability.id,
            scanner=Scanner.MANUAL,
            finding_type=FindingType.MANUAL,
            severity=payload.severity,
            title=payload.cve,
            description=payload.description,
            cve=payload.cve,
            fingerprint=fingerprint,
            status=payload.status,
        )
        db.add(finding)
    else:
        finding.vulnerability_id = vulnerability.id
        finding.severity = payload.severity
        finding.description = payload.description
        finding.status = payload.status

    db.commit()
    db.refresh(finding)
    return finding


@router.patch("/{finding_id}", response_model=FindingRead)
def update_finding_status(
    repository_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    request: Request,
    current_user: User = Depends(require_scan_access),
    db: Session = Depends(get_db),
) -> Finding:
    repository = _get_owned_repository(repository_id, current_user, db)
    finding = _get_repository_finding(repository.id, finding_id, db)

    previous_status = finding.status
    finding.status = payload.status
    finding.resolved_at = datetime.now(timezone.utc) if payload.status == FindingStatus.RESOLVED else None

    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        user_id=current_user.id,
        action="finding_status_changed",
        resource_type="finding",
        resource_id=str(finding.id),
        metadata={"from": previous_status.value, "to": finding.status.value, "repository_id": str(repository.id)},
        request=request,
    )
    return finding

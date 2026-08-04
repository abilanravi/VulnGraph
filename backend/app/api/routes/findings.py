import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.api.routes.repositories import _get_owned_repository
from app.db.models import Finding, User, Vulnerability
from app.schemas.finding import FindingCreate, FindingRead

router = APIRouter(prefix="/repositories/{repository_id}/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
def list_findings(
    repository_id: uuid.UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    repository = _get_owned_repository(repository_id, current_user, db)

    vulnerability = db.query(Vulnerability).filter(Vulnerability.cve == payload.cve).first()
    if vulnerability is None:
        vulnerability = Vulnerability(
            cve=payload.cve, severity=payload.severity, description=payload.description
        )
        db.add(vulnerability)
        db.flush()

    finding = (
        db.query(Finding)
        .filter(Finding.repository_id == repository.id, Finding.vulnerability_id == vulnerability.id)
        .first()
    )
    if finding is None:
        finding = Finding(
            repository_id=repository.id, vulnerability_id=vulnerability.id, status=payload.status
        )
        db.add(finding)
    else:
        finding.status = payload.status

    db.commit()
    db.refresh(finding)
    return finding

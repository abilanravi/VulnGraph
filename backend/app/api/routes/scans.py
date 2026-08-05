import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.api.routes.repositories import _get_owned_repository
from app.db.models import Scan, Scanner, User
from app.schemas.scan import ScanRead, ScanTrigger
from app.services.scan_service import run_scan

router = APIRouter(prefix="/repositories/{repository_id}/scans", tags=["scans"])


def _run_triggered_scan(
    repository_id: uuid.UUID, scanner: Scanner, payload: ScanTrigger, current_user: User, db: Session
) -> Scan:
    repository = _get_owned_repository(repository_id, current_user, db)
    if not os.path.isdir(payload.path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Path not found or not a directory: {payload.path}"
        )
    return run_scan(db, repository, scanner, payload.path)


@router.get("", response_model=list[ScanRead])
def list_scans(
    repository_id: uuid.UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[Scan]:
    repository = _get_owned_repository(repository_id, current_user, db)
    return (
        db.query(Scan)
        .filter(Scan.repository_id == repository.id)
        .order_by(Scan.created_at.desc())
        .all()
    )


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    repository_id: uuid.UUID,
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    repository = _get_owned_repository(repository_id, current_user, db)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.repository_id == repository.id).first()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post("/semgrep", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def trigger_semgrep_scan(
    repository_id: uuid.UUID,
    payload: ScanTrigger,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    return _run_triggered_scan(repository_id, Scanner.SEMGREP, payload, current_user, db)


@router.post("/osv", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def trigger_osv_scan(
    repository_id: uuid.UUID,
    payload: ScanTrigger,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    return _run_triggered_scan(repository_id, Scanner.OSV, payload, current_user, db)

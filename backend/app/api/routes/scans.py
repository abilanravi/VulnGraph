import os
import uuid
from contextlib import contextmanager
from typing import Iterator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db
from app.api.routes.repositories import _get_owned_repository
from app.core.config import settings
from app.core.permissions import require_scan_access
from app.core.rate_limit import user_rate_limit
from app.db.models import Repository, RepositorySource, Scan, Scanner, User
from app.schemas.scan import ScanRead, ScanTrigger
from app.services.audit import record_audit_event
from app.services.repo_fetch import RepositoryFetchError, clone_repository
from app.services.scan_service import run_scan

router = APIRouter(prefix="/repositories/{repository_id}/scans", tags=["scans"])

# Scans invoke external processes (git clone, Semgrep, OSV Scanner) and can be resource-intensive,
# so triggering them is rate-limited per user in addition to being role-gated.
_scan_rate_limit = user_rate_limit("scan_trigger", limit=20, window_seconds=60)


def _resolve_scan_path(path: str) -> str:
    """Validates a user-supplied local scan path.

    Confirms it exists and, when `settings.scan_root_dir` is configured, that the resolved real
    path stays inside that root — closing off path traversal (`..`) or pointing the scanner at
    arbitrary server directories outside the intended scan area. `scan_root_dir` is opt-in (see
    app/core/config.py) since VulnGraph's MVP deployment has one operator scanning their own
    machine; a shared-host deployment should set it.
    """
    resolved = os.path.realpath(path)
    if not os.path.isdir(resolved):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"Path not found or not a directory: {path}"
        )
    if settings.scan_root_dir:
        allowed_root = os.path.realpath(settings.scan_root_dir)
        if os.path.commonpath([resolved, allowed_root]) != allowed_root:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path is outside the allowed scan directory.",
            )
    return resolved


@contextmanager
def _scan_target(repository: Repository, path: str | None) -> Iterator[str]:
    """Resolves the directory to scan: the given local path, or a fresh GitHub clone."""
    if path:
        yield _resolve_scan_path(path)
        return

    if repository.source != RepositorySource.GITHUB or not repository.url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No path provided and this repository has no GitHub URL to clone. "
            "Either supply a path, or add the repository with a GitHub URL.",
        )
    try:
        with clone_repository(repository.url, branch=repository.default_branch) as tmp_dir:
            yield tmp_dir
    except RepositoryFetchError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


def _run_triggered_scan(
    repository_id: uuid.UUID,
    scanner: Scanner,
    payload: ScanTrigger,
    current_user: User,
    db: Session,
    request: Request,
) -> Scan:
    repository = _get_owned_repository(repository_id, current_user, db)
    with _scan_target(repository, payload.path) as target_path:
        scan = run_scan(db, repository, scanner, target_path)
    record_audit_event(
        db,
        user_id=current_user.id,
        action="scan_triggered",
        resource_type="scan",
        resource_id=str(scan.id),
        metadata={"repository_id": str(repository.id), "scanner": scanner.value, "status": scan.status.value},
        request=request,
    )
    return scan


@router.get("", response_model=list[ScanRead])
def list_scans(
    repository_id: uuid.UUID, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)
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
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Scan:
    repository = _get_owned_repository(repository_id, current_user, db)
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.repository_id == repository.id).first()
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post(
    "/semgrep", response_model=ScanRead, status_code=status.HTTP_201_CREATED, dependencies=[Depends(_scan_rate_limit)]
)
def trigger_semgrep_scan(
    repository_id: uuid.UUID,
    payload: ScanTrigger,
    request: Request,
    current_user: User = Depends(require_scan_access),
    db: Session = Depends(get_db),
) -> Scan:
    return _run_triggered_scan(repository_id, Scanner.SEMGREP, payload, current_user, db, request)


@router.post(
    "/osv", response_model=ScanRead, status_code=status.HTTP_201_CREATED, dependencies=[Depends(_scan_rate_limit)]
)
def trigger_osv_scan(
    repository_id: uuid.UUID,
    payload: ScanTrigger,
    request: Request,
    current_user: User = Depends(require_scan_access),
    db: Session = Depends(get_db),
) -> Scan:
    return _run_triggered_scan(repository_id, Scanner.OSV, payload, current_user, db, request)


@router.post(
    "/run", response_model=list[ScanRead], status_code=status.HTTP_201_CREATED, dependencies=[Depends(_scan_rate_limit)]
)
def trigger_full_scan(
    repository_id: uuid.UUID,
    payload: ScanTrigger,
    request: Request,
    current_user: User = Depends(require_scan_access),
    db: Session = Depends(get_db),
) -> list[Scan]:
    """Runs Semgrep and OSV Scanner against the repository in a single pass (one clone, if any)."""
    repository = _get_owned_repository(repository_id, current_user, db)
    with _scan_target(repository, payload.path) as target_path:
        semgrep_scan = run_scan(db, repository, Scanner.SEMGREP, target_path)
        osv_scan = run_scan(db, repository, Scanner.OSV, target_path)
    for scan in (semgrep_scan, osv_scan):
        record_audit_event(
            db,
            user_id=current_user.id,
            action="scan_triggered",
            resource_type="scan",
            resource_id=str(scan.id),
            metadata={"repository_id": str(repository.id), "scanner": scan.scanner.value, "status": scan.status.value},
            request=request,
        )
    return [semgrep_scan, osv_scan]

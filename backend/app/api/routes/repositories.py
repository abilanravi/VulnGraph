import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db
from app.core.permissions import require_scan_access
from app.db.models import Repository, RepositorySource, User, UserRole
from app.schemas.repository import RepositoryCreate, RepositoryRead
from app.services.audit import record_audit_event
from app.services.github import InvalidGitHubUrlError, canonical_clone_url, parse_github_url

router = APIRouter(prefix="/repositories", tags=["repositories"])


@router.get("", response_model=list[RepositoryRead])
def list_repositories(
    current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)
) -> list[Repository]:
    query = db.query(Repository)
    if current_user.role != UserRole.ADMIN:
        query = query.filter(Repository.owner_id == current_user.id)
    return query.order_by(Repository.created_at.desc()).all()


@router.post("", response_model=RepositoryRead, status_code=status.HTTP_201_CREATED)
def create_repository(
    payload: RepositoryCreate,
    request: Request,
    current_user: User = Depends(require_scan_access),
    db: Session = Depends(get_db),
) -> Repository:
    if payload.url:
        try:
            owner, name = parse_github_url(payload.url)
        except InvalidGitHubUrlError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        repository = Repository(
            owner_id=current_user.id,
            name=name,
            owner=owner,
            url=canonical_clone_url(owner, name),
            source=RepositorySource.GITHUB,
        )
    else:
        repository = Repository(
            owner_id=current_user.id, name=payload.name, owner=payload.owner, source=RepositorySource.MANUAL
        )
    db.add(repository)
    db.commit()
    db.refresh(repository)

    record_audit_event(
        db,
        user_id=current_user.id,
        action="repository_imported" if repository.source == RepositorySource.GITHUB else "repository_created",
        resource_type="repository",
        resource_id=str(repository.id),
        metadata={"name": repository.name, "owner": repository.owner, "source": repository.source.value},
        request=request,
    )
    return repository


def _get_owned_repository(repository_id: uuid.UUID, current_user: User, db: Session) -> Repository:
    """Fetches a repository the user is allowed to act on: their own, or any repository if
    they're an ADMIN. Returns 404 (never 403) for a repository owned by someone else, so a
    request can't be used to probe whether a given repository id exists."""
    query = db.query(Repository).filter(Repository.id == repository_id)
    if current_user.role != UserRole.ADMIN:
        query = query.filter(Repository.owner_id == current_user.id)
    repository = query.first()
    if repository is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")
    return repository


@router.get("/{repository_id}", response_model=RepositoryRead)
def get_repository(
    repository_id: uuid.UUID, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)
) -> Repository:
    return _get_owned_repository(repository_id, current_user, db)

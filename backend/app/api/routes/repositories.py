import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.db.models import Repository, User
from app.schemas.repository import RepositoryCreate, RepositoryRead

router = APIRouter(prefix="/repositories", tags=["repositories"])


@router.get("", response_model=list[RepositoryRead])
def list_repositories(
    current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[Repository]:
    return db.query(Repository).filter(Repository.owner_id == current_user.id).order_by(Repository.created_at.desc()).all()


@router.post("", response_model=RepositoryRead, status_code=status.HTTP_201_CREATED)
def create_repository(
    payload: RepositoryCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Repository:
    repository = Repository(
        owner_id=current_user.id, name=payload.name, owner=payload.owner, url=payload.url
    )
    db.add(repository)
    db.commit()
    db.refresh(repository)
    return repository


def _get_owned_repository(repository_id: uuid.UUID, current_user: User, db: Session) -> Repository:
    repository = (
        db.query(Repository)
        .filter(Repository.id == repository_id, Repository.owner_id == current_user.id)
        .first()
    )
    if repository is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")
    return repository


@router.get("/{repository_id}", response_model=RepositoryRead)
def get_repository(
    repository_id: uuid.UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> Repository:
    return _get_owned_repository(repository_id, current_user, db)

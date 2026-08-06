import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.permissions import require_admin
from app.db.models import User
from app.schemas.user import UserActiveUpdate, UserRead, UserRoleUpdate
from app.services.audit import record_audit_event

router = APIRouter(prefix="/users", tags=["users"])


def _get_user_or_404(user_id: uuid.UUID, db: Session) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("", response_model=list[UserRead])
def list_users(current_user: User = Depends(require_admin), db: Session = Depends(get_db)) -> list[User]:
    return db.query(User).order_by(User.created_at.asc()).all()


@router.patch("/{user_id}/role", response_model=UserRead)
def update_user_role(
    user_id: uuid.UUID,
    payload: UserRoleUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> User:
    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot change your own role")
    user = _get_user_or_404(user_id, db)

    previous_role = user.role
    user.role = payload.role
    db.commit()
    db.refresh(user)

    record_audit_event(
        db,
        user_id=current_user.id,
        action="role_changed",
        resource_type="user",
        resource_id=str(user.id),
        metadata={"from": previous_role.value, "to": user.role.value},
        request=request,
    )
    return user


@router.patch("/{user_id}/active", response_model=UserRead)
def update_user_active(
    user_id: uuid.UUID,
    payload: UserActiveUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> User:
    if user_id == current_user.id and not payload.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate your own account")
    user = _get_user_or_404(user_id, db)

    user.is_active = payload.is_active
    db.commit()
    db.refresh(user)

    record_audit_event(
        db,
        user_id=current_user.id,
        action="user_reactivated" if user.is_active else "user_deactivated",
        resource_type="user",
        resource_id=str(user.id),
        request=request,
    )
    return user

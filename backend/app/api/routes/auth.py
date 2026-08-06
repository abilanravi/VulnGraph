from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db
from app.core.rate_limit import rate_limit
from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import User
from app.schemas.user import TokenResponse, UserCreate, UserLogin, UserRead
from app.services.audit import record_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])

# Generous enough for normal use, tight enough to blunt brute-force/enumeration attempts. See
# app/core/rate_limit.py for why this is in-memory rather than a shared store.
_signup_rate_limit = rate_limit("signup", limit=5, window_seconds=60)
_login_rate_limit = rate_limit("login", limit=10, window_seconds=60, by_ip_and_body_field="email")


@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_signup_rate_limit)],
)
def signup(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    # role/is_active intentionally not client-supplied — every new account starts as an active
    # DEVELOPER (see User model defaults); only an admin can change that afterward.
    user = User(email=payload.email, hashed_password=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)

    record_audit_event(db, user_id=user.id, action="signup", resource_type="user", resource_id=str(user.id), request=request)

    return TokenResponse(access_token=create_access_token(str(user.id)))


@router.post("/login", response_model=TokenResponse, dependencies=[Depends(_login_rate_limit)])
def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.email == payload.email).first()
    # Same generic error for "no such user" and "wrong password" so the response never confirms
    # whether an email is registered.
    if user is None or not verify_password(payload.password, user.hashed_password):
        record_audit_event(
            db,
            user_id=user.id if user else None,
            action="login_failed",
            resource_type="user",
            resource_id=str(user.id) if user else None,
            metadata={"email": payload.email},
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_active:
        record_audit_event(
            db, user_id=user.id, action="login_failed", resource_type="user", resource_id=str(user.id),
            metadata={"reason": "deactivated"}, request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    record_audit_event(db, user_id=user.id, action="login_success", resource_type="user", resource_id=str(user.id), request=request)

    return TokenResponse(access_token=create_access_token(str(user.id)))


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_active_user)) -> User:
    return current_user

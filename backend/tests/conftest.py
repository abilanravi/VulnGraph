"""Test fixtures. Uses an in-memory SQLite DB in place of Postgres (unavailable in this
environment) — schema is created directly from the SQLAlchemy models rather than via
Alembic, since migration 0002 relies on Postgres-only DDL (native ENUM widening, USING casts).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.core.rate_limit import reset_rate_limits
from app.db.base import Base
from app.db.models import UserRole
from app.main import app

DEMO_EMAIL = "test@example.com"
DEMO_PASSWORD = "password123"


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    """The rate limiter is a module-level in-memory store (see app/core/rate_limit.py) — reset
    it between tests so one test's login/signup attempts don't 429 the next test."""
    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture()
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    testing_session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = testing_session_local()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def client(db_session):
    def _get_db_override():
        yield db_session

    app.dependency_overrides[get_db] = _get_db_override
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _login_as(client, email: str, password: str) -> TestClient:
    resp = client.post("/api/auth/login", json={"email": email, "password": password})
    token = resp.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


@pytest.fixture()
def auth_client(client):
    client.post("/api/auth/signup", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD})
    return _login_as(client, DEMO_EMAIL, DEMO_PASSWORD)


def make_user(db_session, email: str, password: str, role: UserRole = UserRole.DEVELOPER, is_active: bool = True):
    """Creates a user directly in the DB with a specific role/active flag (signup can't set
    either — role/active are always server-controlled, see app/schemas/user.py)."""
    from app.core.security import hash_password
    from app.db.models import User

    user = User(email=email, hashed_password=hash_password(password), role=role, is_active=is_active)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture()
def admin_client(client, db_session):
    make_user(db_session, "admin@example.com", "password123", role=UserRole.ADMIN)
    return _login_as(client, "admin@example.com", "password123")


@pytest.fixture()
def viewer_client(client, db_session):
    make_user(db_session, "viewer@example.com", "password123", role=UserRole.VIEWER)
    return _login_as(client, "viewer@example.com", "password123")


@pytest.fixture()
def admin_headers(client, db_session):
    """An ADMIN bearer token as a headers dict, *without* mutating `client`'s default headers —
    use this (passed explicitly per-request) in tests that need to act as two different users
    against the same TestClient instance, since `client.headers.update(...)` (as `auth_client`/
    `admin_client`/`viewer_client` do) clobbers whichever identity was set last."""
    make_user(db_session, "admin@example.com", "password123", role=UserRole.ADMIN)
    token = client.post(
        "/api/auth/login", json={"email": "admin@example.com", "password": "password123"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

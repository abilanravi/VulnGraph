from datetime import datetime, timedelta, timezone

from jose import jwt

from app.core.config import settings


def test_missing_token_rejected(client):
    resp = client.get("/api/repositories")
    assert resp.status_code == 401


def test_malformed_token_rejected(client):
    resp = client.get("/api/repositories", headers={"Authorization": "Bearer not-a-real-jwt"})
    assert resp.status_code == 401


def test_token_signed_with_wrong_secret_rejected(client):
    bogus = jwt.encode({"sub": "00000000-0000-0000-0000-000000000000"}, "wrong-secret", algorithm=settings.jwt_algorithm)
    resp = client.get("/api/repositories", headers={"Authorization": f"Bearer {bogus}"})
    assert resp.status_code == 401


def test_expired_token_rejected(client):
    expired = jwt.encode(
        {"sub": "00000000-0000-0000-0000-000000000000", "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    resp = client.get("/api/repositories", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401


def test_token_for_nonexistent_user_rejected(client):
    token = jwt.encode(
        {"sub": "00000000-0000-0000-0000-000000000000", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    resp = client.get("/api/repositories", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_login_error_message_does_not_reveal_account_existence(client):
    client.post("/api/auth/signup", json={"email": "known@example.com", "password": "password123"})

    wrong_password = client.post("/api/auth/login", json={"email": "known@example.com", "password": "wrong"})
    unknown_email = client.post("/api/auth/login", json={"email": "unknown@example.com", "password": "wrong"})

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json()["detail"] == unknown_email.json()["detail"]


def test_password_is_hashed_not_stored_plaintext(client, db_session):
    from app.db.models import User

    client.post("/api/auth/signup", json={"email": "hashme@example.com", "password": "password123"})
    user = db_session.query(User).filter(User.email == "hashme@example.com").first()
    assert user.hashed_password != "password123"
    assert user.hashed_password.startswith("$2b$")

"""IDOR/BOLA-style tests: User A must never reach User B's repositories/scans/findings by
guessing/incrementing an id, and ADMIN must be able to intentionally bypass that isolation."""

import pytest


@pytest.fixture()
def user_a(client):
    client.post("/api/auth/signup", json={"email": "a@example.com", "password": "password123"})
    token = client.post("/api/auth/login", json={"email": "a@example.com", "password": "password123"}).json()[
        "access_token"
    ]
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


def _switch_user(client, email, password="password123"):
    client.post("/api/auth/signup", json={"email": email, "password": password})
    token = client.post("/api/auth/login", json={"email": email, "password": password}).json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


def test_user_cannot_access_other_users_repository(client):
    repo = _switch_user(client, "owner@example.com").post(
        "/api/repositories", json={"name": "webapp", "owner": "acme"}
    ).json()

    other = _switch_user(client, "other@example.com")
    resp = other.get(f"/api/repositories/{repo['id']}")
    assert resp.status_code == 404


def test_user_cannot_access_other_users_findings(client):
    owner = _switch_user(client, "owner2@example.com")
    repo = owner.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()
    owner.post(
        f"/api/repositories/{repo['id']}/findings",
        json={"cve": "CVE-2024-1", "severity": "HIGH", "description": "x"},
    )

    other = _switch_user(client, "other2@example.com")
    resp = other.get(f"/api/repositories/{repo['id']}/findings")
    assert resp.status_code == 404


def test_user_cannot_trigger_scan_on_other_users_repository(client):
    owner = _switch_user(client, "owner3@example.com")
    repo = owner.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()

    other = _switch_user(client, "other3@example.com")
    resp = other.post(f"/api/repositories/{repo['id']}/scans/semgrep", json={"path": "/tmp"})
    assert resp.status_code == 404


def test_user_cannot_update_other_users_finding(client):
    owner = _switch_user(client, "owner4@example.com")
    repo = owner.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()
    finding = owner.post(
        f"/api/repositories/{repo['id']}/findings",
        json={"cve": "CVE-2024-2", "severity": "LOW", "description": "x"},
    ).json()

    other = _switch_user(client, "other4@example.com")
    resp = other.patch(
        f"/api/repositories/{repo['id']}/findings/{finding['id']}", json={"status": "RESOLVED"}
    )
    assert resp.status_code == 404


def test_admin_can_view_other_users_repository(client, db_session):
    from tests.conftest import make_user

    owner = _switch_user(client, "owner5@example.com")
    repo = owner.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()

    from app.db.models import UserRole

    make_user(db_session, "admin5@example.com", "password123", role=UserRole.ADMIN)
    admin = client
    token = admin.post(
        "/api/auth/login", json={"email": "admin5@example.com", "password": "password123"}
    ).json()["access_token"]
    admin.headers.update({"Authorization": f"Bearer {token}"})

    resp = admin.get(f"/api/repositories/{repo['id']}")
    assert resp.status_code == 200
    assert resp.json()["id"] == repo["id"]


def test_admin_sees_all_repositories_in_list(client, db_session):
    from app.db.models import UserRole
    from tests.conftest import make_user

    _switch_user(client, "owner6@example.com").post("/api/repositories", json={"name": "webapp", "owner": "acme"})

    make_user(db_session, "admin6@example.com", "password123", role=UserRole.ADMIN)
    admin = client
    token = admin.post(
        "/api/auth/login", json={"email": "admin6@example.com", "password": "password123"}
    ).json()["access_token"]
    admin.headers.update({"Authorization": f"Bearer {token}"})

    resp = admin.get("/api/repositories")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

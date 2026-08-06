"""RBAC + role-default tests. See app/core/permissions.py for the enforcement itself."""

from tests.conftest import make_user


def test_signup_defaults_to_developer_role(client):
    client.post("/api/auth/signup", json={"email": "dev@example.com", "password": "password123"})
    resp = client.post("/api/auth/login", json={"email": "dev@example.com", "password": "password123"})
    client.headers.update({"Authorization": f"Bearer {resp.json()['access_token']}"})
    me = client.get("/api/auth/me").json()
    assert me["role"] == "DEVELOPER"
    assert me["is_active"] is True


def test_signup_ignores_client_supplied_role(client):
    """`role` isn't a field UserCreate accepts, so a client sending one is simply ignored, not
    honored — this is enforced by the schema shape, not by explicit filtering logic."""
    resp = client.post(
        "/api/auth/signup", json={"email": "sneaky@example.com", "password": "password123", "role": "ADMIN"}
    )
    assert resp.status_code == 201
    login = client.post("/api/auth/login", json={"email": "sneaky@example.com", "password": "password123"})
    client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
    assert client.get("/api/auth/me").json()["role"] == "DEVELOPER"


def test_viewer_cannot_create_repository(viewer_client):
    resp = viewer_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"})
    assert resp.status_code == 403


def test_viewer_cannot_trigger_scan(viewer_client, db_session):
    from app.db.models import Repository, RepositorySource

    repo = Repository(owner_id=_viewer_id(viewer_client, db_session), name="webapp", owner="acme", source=RepositorySource.MANUAL)
    db_session.add(repo)
    db_session.commit()

    resp = viewer_client.post(f"/api/repositories/{repo.id}/scans/semgrep", json={"path": "/tmp"})
    assert resp.status_code == 403


def test_viewer_cannot_update_finding_status(viewer_client, db_session):
    from app.db.models import Finding, FindingStatus, FindingType, Repository, RepositorySource, Scanner

    owner_id = _viewer_id(viewer_client, db_session)
    repo = Repository(owner_id=owner_id, name="webapp", owner="acme", source=RepositorySource.MANUAL)
    db_session.add(repo)
    db_session.flush()
    finding = Finding(
        repository_id=repo.id,
        scanner=Scanner.MANUAL,
        finding_type=FindingType.MANUAL,
        severity="LOW",
        title="x",
        fingerprint="fp1",
        status=FindingStatus.OPEN,
    )
    db_session.add(finding)
    db_session.commit()

    resp = viewer_client.patch(
        f"/api/repositories/{repo.id}/findings/{finding.id}", json={"status": "RESOLVED"}
    )
    assert resp.status_code == 403


def test_viewer_can_still_list_own_repositories(viewer_client, db_session):
    from app.db.models import Repository, RepositorySource

    owner_id = _viewer_id(viewer_client, db_session)
    repo = Repository(owner_id=owner_id, name="webapp", owner="acme", source=RepositorySource.MANUAL)
    db_session.add(repo)
    db_session.commit()

    resp = viewer_client.get("/api/repositories")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_developer_can_create_repository_and_trigger_scan(auth_client):
    resp = auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"})
    assert resp.status_code == 201
    repo_id = resp.json()["id"]

    resp = auth_client.post(f"/api/repositories/{repo_id}/scans/semgrep", json={"path": "/no/such/path"})
    # 400 (invalid path), not 403 — proves the developer *is* authorized to trigger scans.
    assert resp.status_code == 400


def test_admin_can_list_all_users(admin_client):
    resp = admin_client.get("/api/users")
    assert resp.status_code == 200
    assert any(u["email"] == "admin@example.com" for u in resp.json())


def test_non_admin_cannot_list_users(auth_client):
    resp = auth_client.get("/api/users")
    assert resp.status_code == 403


def test_non_admin_cannot_view_audit_logs(auth_client):
    resp = auth_client.get("/api/audit-logs")
    assert resp.status_code == 403


def test_admin_can_change_another_users_role(admin_client, db_session):
    target = make_user(db_session, "target@example.com", "password123")
    resp = admin_client.patch(f"/api/users/{target.id}/role", json={"role": "VIEWER"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "VIEWER"


def test_admin_cannot_change_own_role(admin_client, db_session):
    me = admin_client.get("/api/auth/me").json()
    resp = admin_client.patch(f"/api/users/{me['id']}/role", json={"role": "VIEWER"})
    assert resp.status_code == 400


def test_non_admin_cannot_change_any_role(auth_client, db_session):
    target = make_user(db_session, "target2@example.com", "password123")
    resp = auth_client.patch(f"/api/users/{target.id}/role", json={"role": "ADMIN"})
    assert resp.status_code == 403


def test_admin_cannot_deactivate_own_account(admin_client):
    me = admin_client.get("/api/auth/me").json()
    resp = admin_client.patch(f"/api/users/{me['id']}/active", json={"is_active": False})
    assert resp.status_code == 400


def test_deactivated_user_loses_access_immediately(admin_client, db_session):
    target = make_user(db_session, "deactivate-me@example.com", "password123")
    resp = admin_client.patch(f"/api/users/{target.id}/active", json={"is_active": False})
    assert resp.status_code == 200

    login = admin_client.post(
        "/api/auth/login", json={"email": "deactivate-me@example.com", "password": "password123"}
    )
    assert login.status_code == 401


def test_deactivated_users_existing_token_is_rejected(client, db_session):
    from app.core.security import create_access_token

    user = make_user(db_session, "revoke-me@example.com", "password123")
    token = create_access_token(str(user.id))
    user.is_active = False
    db_session.commit()

    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def _viewer_id(viewer_client, db_session):
    from app.db.models import User

    return db_session.query(User).filter(User.email == "viewer@example.com").first().id

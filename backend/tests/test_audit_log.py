"""Audit log tests. Note: `admin_headers` is passed explicitly per-request rather than via the
`admin_client`/`auth_client` fixtures, because those mutate the shared TestClient's default
headers — using two of them together in one test would have the second clobber the first's
identity for every call made through either name (see conftest.py)."""

from tests.conftest import make_user


def test_login_success_and_failure_generate_audit_events(client, admin_headers):
    client.post("/api/auth/signup", json={"email": "audituser@example.com", "password": "password123"})
    client.post("/api/auth/login", json={"email": "audituser@example.com", "password": "password123"})
    client.post("/api/auth/login", json={"email": "audituser@example.com", "password": "wrong"})

    logs = client.get("/api/audit-logs", headers=admin_headers).json()
    actions = [log["action"] for log in logs]
    assert "login_success" in actions
    assert "login_failed" in actions
    assert "signup" in actions


def test_repository_and_scan_actions_are_audited(auth_client, admin_headers):
    repo = auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()
    auth_client.post(f"/api/repositories/{repo['id']}/scans/semgrep", json={"path": "/no/such/path"})

    logs = auth_client.get("/api/audit-logs", headers=admin_headers).json()
    actions = [log["action"] for log in logs]
    assert "repository_created" in actions
    repo_events = [log for log in logs if log["resource_type"] == "repository" and log["resource_id"] == repo["id"]]
    assert repo_events


def test_finding_status_change_is_audited(auth_client, admin_headers):
    repo = auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()
    finding = auth_client.post(
        f"/api/repositories/{repo['id']}/findings",
        json={"cve": "CVE-2024-9", "severity": "LOW", "description": "x"},
    ).json()
    auth_client.patch(f"/api/repositories/{repo['id']}/findings/{finding['id']}", json={"status": "RESOLVED"})

    logs = auth_client.get("/api/audit-logs", headers=admin_headers).json()
    matches = [log for log in logs if log["action"] == "finding_status_changed" and log["resource_id"] == finding["id"]]
    assert matches
    assert matches[0]["event_metadata"]["to"] == "RESOLVED"


def test_role_and_activation_changes_are_audited(client, admin_headers, db_session):
    target = make_user(db_session, "audited-target@example.com", "password123")
    client.patch(f"/api/users/{target.id}/role", json={"role": "VIEWER"}, headers=admin_headers)
    client.patch(f"/api/users/{target.id}/active", json={"is_active": False}, headers=admin_headers)

    logs = client.get("/api/audit-logs", headers=admin_headers).json()
    actions = [log["action"] for log in logs]
    assert "role_changed" in actions
    assert "user_deactivated" in actions


def test_audit_log_never_contains_password_or_token(client, admin_headers):
    client.post("/api/auth/signup", json={"email": "secretcheck@example.com", "password": "super-secret-pw"})
    resp = client.post("/api/auth/login", json={"email": "secretcheck@example.com", "password": "super-secret-pw"})
    token = resp.json()["access_token"]

    logs = client.get("/api/audit-logs", headers=admin_headers).json()
    dump = str(logs)
    assert "super-secret-pw" not in dump
    assert token not in dump

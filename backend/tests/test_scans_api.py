import pytest


@pytest.fixture()
def repository(auth_client):
    return auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()


def test_trigger_semgrep_scan_rejects_invalid_path(auth_client, repository):
    resp = auth_client.post(
        f"/api/repositories/{repository['id']}/scans/semgrep", json={"path": "/no/such/path"}
    )
    assert resp.status_code == 400


def test_trigger_semgrep_scan_records_failure_when_binary_missing(auth_client, repository, tmp_path):
    """Semgrep isn't installed in this environment, so a scan against a real directory
    should fail gracefully: a FAILED Scan row with an error message, not a 500."""
    resp = auth_client.post(
        f"/api/repositories/{repository['id']}/scans/semgrep", json={"path": str(tmp_path)}
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "FAILED"
    assert body["error_message"]


def test_list_scans_requires_auth(client):
    resp = client.get("/api/repositories/00000000-0000-0000-0000-000000000000/scans")
    assert resp.status_code == 401

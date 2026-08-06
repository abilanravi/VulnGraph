from unittest.mock import patch

import pytest


@pytest.fixture()
def repository(auth_client):
    return auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()


@pytest.fixture()
def github_repository(auth_client):
    return auth_client.post("/api/repositories", json={"url": "https://github.com/octocat/Hello-World"}).json()


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


def test_trigger_scan_without_path_on_manual_repository_rejected(auth_client, repository):
    """A repository with no GitHub URL has nothing to clone, so omitting `path` is an error."""
    resp = auth_client.post(f"/api/repositories/{repository['id']}/scans/semgrep", json={})
    assert resp.status_code == 400


def test_trigger_scan_without_path_on_github_repository_clones(auth_client, github_repository, tmp_path):
    """When no path is given for a GitHub-imported repository, VulnGraph clones it and scans
    that (asserted here by faking the clone so the test doesn't depend on the network or a
    real scanner binary)."""

    def fake_clone(clone_url, branch=None, timeout=120):
        from contextlib import contextmanager

        @contextmanager
        def _cm():
            yield str(tmp_path)

        return _cm()

    with patch("app.api.routes.scans.clone_repository", side_effect=fake_clone):
        resp = auth_client.post(f"/api/repositories/{github_repository['id']}/scans/semgrep", json={})
    assert resp.status_code == 201
    body = resp.json()
    # Semgrep isn't installed in this environment, so the scan fails gracefully post-clone.
    assert body["status"] == "FAILED"


def test_trigger_scan_clone_failure_returns_502(auth_client, github_repository):
    from app.services.repo_fetch import RepositoryFetchError

    with patch("app.api.routes.scans.clone_repository", side_effect=RepositoryFetchError("repository not found")):
        resp = auth_client.post(f"/api/repositories/{github_repository['id']}/scans/semgrep", json={})
    assert resp.status_code == 502


def test_trigger_full_scan_runs_both_scanners_against_one_clone(auth_client, github_repository, tmp_path):
    call_count = {"n": 0}

    def fake_clone(clone_url, branch=None, timeout=120):
        from contextlib import contextmanager

        @contextmanager
        def _cm():
            call_count["n"] += 1
            yield str(tmp_path)

        return _cm()

    with patch("app.api.routes.scans.clone_repository", side_effect=fake_clone):
        resp = auth_client.post(f"/api/repositories/{github_repository['id']}/scans/run", json={})
    assert resp.status_code == 201
    body = resp.json()
    assert len(body) == 2
    assert {scan["scanner"] for scan in body} == {"SEMGREP", "OSV"}
    # One clone shared by both scanner invocations, not one per scanner.
    assert call_count["n"] == 1


def test_list_scans_requires_auth(client):
    resp = client.get("/api/repositories/00000000-0000-0000-0000-000000000000/scans")
    assert resp.status_code == 401

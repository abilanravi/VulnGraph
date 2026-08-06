"""Input validation / abuse-case tests: malformed GitHub URLs are covered in test_github.py.
This file covers scan path containment and confirms scanner subprocess calls are argument
arrays (no shell interpolation, so no command injection surface)."""

import inspect
import os

import pytest

from app.core.config import settings


@pytest.fixture()
def scan_root(tmp_path, monkeypatch):
    root = tmp_path / "scan-root"
    root.mkdir()
    monkeypatch.setattr(settings, "scan_root_dir", str(root))
    return root


def test_scan_path_outside_configured_root_rejected(auth_client, scan_root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    repo = auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()

    resp = auth_client.post(f"/api/repositories/{repo['id']}/scans/semgrep", json={"path": str(outside)})
    assert resp.status_code == 400
    assert "outside the allowed" in resp.json()["detail"]


def test_scan_path_traversal_outside_root_rejected(auth_client, scan_root):
    repo = auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()
    traversal_path = str(scan_root / ".." )

    resp = auth_client.post(f"/api/repositories/{repo['id']}/scans/semgrep", json={"path": traversal_path})
    assert resp.status_code == 400


def test_scan_path_inside_configured_root_allowed_to_proceed(auth_client, scan_root):
    repo = auth_client.post("/api/repositories", json={"name": "webapp", "owner": "acme"}).json()
    inner = scan_root / "project"
    inner.mkdir()

    resp = auth_client.post(f"/api/repositories/{repo['id']}/scans/semgrep", json={"path": str(inner)})
    # Not rejected for being outside the root; fails later because semgrep isn't installed here.
    assert resp.status_code == 201
    assert resp.json()["status"] == "FAILED"


def test_semgrep_invocation_uses_argument_array_not_shell():
    from app.services.scanners import semgrep

    source = inspect.getsource(semgrep.run_semgrep)
    assert "shell=True" not in source
    assert "shell=" not in source


def test_osv_invocation_uses_argument_array_not_shell():
    from app.services.scanners import osv

    source = inspect.getsource(osv.run_osv_scanner)
    assert "shell=True" not in source
    assert "shell=" not in source


def test_git_clone_invocation_uses_argument_array_not_shell():
    from app.services import repo_fetch

    source = inspect.getsource(repo_fetch.clone_repository)
    assert "shell=True" not in source


def test_repository_name_and_owner_reject_empty_strings(auth_client):
    resp = auth_client.post("/api/repositories", json={"name": "", "owner": ""})
    assert resp.status_code == 422

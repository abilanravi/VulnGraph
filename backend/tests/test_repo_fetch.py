"""Tests for app.services.repo_fetch.clone_repository.

Error paths are exercised with a mocked subprocess so they're deterministic and don't depend
on network access (mirrors how test_scans_api.py tests scanner-missing without installing a
scanner). One real clone against a small, stable public repo is included to verify the actual
git integration end-to-end; it requires outbound network access to github.com.
"""

import os
import subprocess
from unittest.mock import patch

import pytest

from app.services.repo_fetch import RepositoryFetchError, clone_repository


def test_clone_repository_missing_git_raises(monkeypatch):
    with patch("app.services.repo_fetch.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(RepositoryFetchError, match="git CLI not found"):
            with clone_repository("https://github.com/acme-corp/webapp.git"):
                pass


def test_clone_repository_timeout_raises():
    with patch(
        "app.services.repo_fetch.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="git", timeout=5),
    ):
        with pytest.raises(RepositoryFetchError, match="timed out"):
            with clone_repository("https://github.com/acme-corp/webapp.git", timeout=5):
                pass


def test_clone_repository_nonzero_exit_raises():
    fake_result = subprocess.CompletedProcess(args=["git"], returncode=128, stdout="", stderr="repository not found")
    with patch("app.services.repo_fetch.subprocess.run", return_value=fake_result):
        with pytest.raises(RepositoryFetchError, match="repository not found"):
            with clone_repository("https://github.com/acme-corp/does-not-exist.git"):
                pass


def test_clone_repository_cleans_up_temp_dir_on_success():
    captured = {}

    def fake_run(command, **kwargs):
        target_dir = command[-1]
        captured["dir"] = target_dir
        os.makedirs(target_dir, exist_ok=True)
        with open(os.path.join(target_dir, "marker.txt"), "w") as fh:
            fh.write("cloned")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    with patch("app.services.repo_fetch.subprocess.run", side_effect=fake_run):
        with clone_repository("https://github.com/acme-corp/webapp.git") as tmp_dir:
            assert os.path.isdir(tmp_dir)
            assert os.path.exists(os.path.join(tmp_dir, "marker.txt"))

    assert not os.path.exists(captured["dir"])


@pytest.mark.network
def test_clone_real_public_repository():
    """Exercises a real `git clone` against a small, stable public GitHub repo."""
    with clone_repository("https://github.com/octocat/Hello-World.git", branch="master", timeout=30) as tmp_dir:
        assert os.path.isdir(tmp_dir)
        assert os.path.exists(os.path.join(tmp_dir, "README"))

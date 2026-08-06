"""Obtains a public GitHub repository locally for scanning via a shallow `git clone`.

The clone lives in a temporary directory for the lifetime of the `with` block and is removed
afterward — VulnGraph does not persist cloned source code. Only public repositories are
supported: git's credential prompt is disabled so a private/missing repo fails fast with a
clear error instead of hanging the scan.
"""

import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from typing import Iterator

DEFAULT_CLONE_TIMEOUT_SECONDS = 120


class RepositoryFetchError(Exception):
    """Raised when a repository cannot be cloned for scanning."""


@contextmanager
def clone_repository(
    clone_url: str, branch: str | None = None, timeout: int = DEFAULT_CLONE_TIMEOUT_SECONDS
) -> Iterator[str]:
    """Shallow-clones `clone_url` into a temp directory, yields its path, then deletes it."""
    tmp_dir = tempfile.mkdtemp(prefix="vulngraph-clone-")
    try:
        command = ["git", "clone", "--depth", "1", "--quiet"]
        if branch:
            command += ["--branch", branch]
        command += [clone_url, tmp_dir]

        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")

        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=env)
        except FileNotFoundError as exc:
            raise RepositoryFetchError("git CLI not found on PATH. Install Git to enable GitHub scanning.") from exc
        except subprocess.TimeoutExpired as exc:
            raise RepositoryFetchError(f"Repository clone timed out after {timeout}s.") from exc

        if proc.returncode != 0:
            raise RepositoryFetchError(
                f"git clone failed for {clone_url}: {proc.stderr.strip() or 'unknown error'}"
            )

        yield tmp_dir
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

"""Builds a stable dedup fingerprint for a finding within a repository.

The fingerprint identifies "the same underlying issue" across repeated scans so that
re-running a scanner updates existing findings instead of creating duplicates. It is
scoped to a single repository (uniqueness is enforced as (repository_id, fingerprint)).
"""

import hashlib
import uuid

from app.db.models import Scanner


def compute_fingerprint(
    repository_id: uuid.UUID,
    scanner: Scanner,
    *,
    rule_id: str | None = None,
    file_path: str | None = None,
    line_start: int | None = None,
    package_name: str | None = None,
    package_version: str | None = None,
    cve: str | None = None,
) -> str:
    if scanner == Scanner.SEMGREP:
        parts = ["semgrep", rule_id or "", file_path or "", str(line_start or "")]
    elif scanner == Scanner.OSV:
        parts = ["osv", package_name or "", package_version or "", cve or rule_id or ""]
    else:
        parts = ["manual", cve or rule_id or ""]

    raw = f"{repository_id}:" + ":".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

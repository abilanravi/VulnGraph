"""Runs Semgrep (SAST) against a local path and normalizes its JSON output.

Requires the `semgrep` CLI to be installed and available on PATH (e.g. `pip install semgrep`).
This module does not implement any scanning logic itself — it only invokes the tool and
converts its results into VulnGraph's normalized finding shape.
"""

import json
import subprocess

from app.db.models import FindingType, Scanner, Severity
from app.services.scanners.base import NormalizedFinding, ScannerExecutionError, ScannerOutputError

DEFAULT_TIMEOUT_SECONDS = 600

_TOP_LEVEL_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def run_semgrep(target_path: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Executes `semgrep --config=auto --json` against `target_path` and returns the parsed JSON."""
    try:
        proc = subprocess.run(
            ["semgrep", "--config=auto", "--json", "--quiet", target_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ScannerExecutionError(
            "Semgrep CLI not found on PATH. Install it with `pip install semgrep`."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerExecutionError(f"Semgrep scan timed out after {timeout}s.") from exc

    if not proc.stdout.strip():
        raise ScannerExecutionError(
            f"Semgrep produced no output (exit code {proc.returncode}): {proc.stderr.strip() or 'no stderr'}"
        )

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerOutputError(f"Could not parse Semgrep JSON output: {exc}") from exc


def _map_severity(metadata_severity: object, top_level_severity: object) -> Severity:
    if metadata_severity:
        candidate = str(metadata_severity).upper()
        if candidate in Severity.__members__:
            return Severity[candidate]
    if top_level_severity:
        mapped = _TOP_LEVEL_SEVERITY_MAP.get(str(top_level_severity).upper())
        if mapped is not None:
            return mapped
    return Severity.MEDIUM


def parse_semgrep_results(raw: dict) -> list[NormalizedFinding]:
    """Converts a parsed Semgrep JSON report into a list of NormalizedFinding."""
    findings: list[NormalizedFinding] = []
    for result in raw.get("results", []):
        extra = result.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        rule_id = result.get("check_id") or "unknown-rule"
        start = result.get("start") or {}

        findings.append(
            NormalizedFinding(
                scanner=Scanner.SEMGREP,
                finding_type=FindingType.SAST,
                severity=_map_severity(metadata.get("severity"), extra.get("severity")),
                title=rule_id,
                description=extra.get("message"),
                file_path=result.get("path"),
                line_start=start.get("line"),
                rule_id=rule_id,
                raw_metadata=result,
            )
        )
    return findings

"""Runs OSV Scanner (SCA) against a local path and normalizes its JSON output.

Requires the `osv-scanner` CLI to be installed and available on PATH (see
https://github.com/google/osv-scanner). This module does not implement any dependency
vulnerability detection itself — it only invokes the tool and converts its results into
VulnGraph's normalized finding shape.
"""

import json
import subprocess

from app.db.models import FindingType, Scanner, Severity
from app.services.scanners.base import NormalizedFinding, ScannerExecutionError, ScannerOutputError

DEFAULT_TIMEOUT_SECONDS = 600

# osv-scanner exits 1 when vulnerabilities are found — that is a *successful* run, not a failure.
_ACCEPTABLE_EXIT_CODES = {0, 1}

_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def run_osv_scanner(target_path: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Executes `osv-scanner --format json -r` against `target_path` and returns the parsed JSON."""
    try:
        proc = subprocess.run(
            ["osv-scanner", "--format", "json", "-r", target_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ScannerExecutionError(
            "osv-scanner CLI not found on PATH. Install it from "
            "https://github.com/google/osv-scanner."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerExecutionError(f"OSV Scanner scan timed out after {timeout}s.") from exc

    if proc.returncode not in _ACCEPTABLE_EXIT_CODES:
        raise ScannerExecutionError(
            f"OSV Scanner exited with code {proc.returncode}: {proc.stderr.strip() or 'no stderr'}"
        )

    if not proc.stdout.strip():
        # No dependencies found / nothing to report.
        return {"results": []}

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ScannerOutputError(f"Could not parse OSV Scanner JSON output: {exc}") from exc


def _extract_cve(vulnerability: dict) -> str | None:
    for alias in vulnerability.get("aliases", []) or []:
        if str(alias).startswith("CVE-"):
            return alias
    vuln_id = vulnerability.get("id", "")
    if str(vuln_id).startswith("CVE-"):
        return vuln_id
    return None


def _map_severity(vulnerability: dict) -> Severity:
    database_specific = vulnerability.get("database_specific") or {}
    candidate = database_specific.get("severity")
    if candidate:
        mapped = _SEVERITY_MAP.get(str(candidate).upper())
        if mapped is not None:
            return mapped
    return Severity.MEDIUM


def parse_osv_results(raw: dict) -> list[NormalizedFinding]:
    """Converts a parsed OSV Scanner JSON report into a list of NormalizedFinding."""
    findings: list[NormalizedFinding] = []
    for result in raw.get("results", []):
        source_path = (result.get("source") or {}).get("path")

        for pkg_entry in result.get("packages", []):
            package = pkg_entry.get("package", {}) or {}
            pkg_name = package.get("name")
            pkg_version = package.get("version")

            for vulnerability in pkg_entry.get("vulnerabilities", []):
                vuln_id = vulnerability.get("id")
                cve = _extract_cve(vulnerability) or vuln_id
                title = vulnerability.get("summary") or vuln_id or "OSV finding"

                findings.append(
                    NormalizedFinding(
                        scanner=Scanner.OSV,
                        finding_type=FindingType.SCA,
                        severity=_map_severity(vulnerability),
                        title=title,
                        description=vulnerability.get("details") or title,
                        file_path=source_path,
                        rule_id=vuln_id,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        cve=cve,
                        raw_metadata=vulnerability,
                    )
                )
    return findings

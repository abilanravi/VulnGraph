"""Orchestrates a scan run: invoke the scanner, parse results, and reconcile findings.

Reconciliation compares the findings produced by this scan against the repository's existing
findings for the same scanner (matched by fingerprint, see app/services/fingerprint.py):

- not previously seen                -> created as a new Finding (OPEN)
- previously seen and still OPEN/IN_PROGRESS -> refreshed in place (unchanged)
- previously seen and RESOLVED        -> reopened (status -> OPEN)
- previously seen and FALSE_POSITIVE  -> left alone (user judgement is not overridden)
- previously OPEN/IN_PROGRESS but not seen in this scan -> marked RESOLVED
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.db.models import Finding, FindingStatus, Repository, Scan, Scanner, ScanStatus
from app.services.fingerprint import compute_fingerprint
from app.services.scanners.base import NormalizedFinding, ScannerExecutionError, ScannerOutputError
from app.services.scanners.osv import parse_osv_results, run_osv_scanner
from app.services.scanners.semgrep import parse_semgrep_results, run_semgrep


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def run_scan(db: Session, repository: Repository, scanner: Scanner, target_path: str) -> Scan:
    """Runs `scanner` against `target_path`, ingests results, and returns the completed Scan."""
    scan = Scan(repository_id=repository.id, scanner=scanner, status=ScanStatus.RUNNING, started_at=_utcnow())
    db.add(scan)
    db.flush()

    try:
        if scanner == Scanner.SEMGREP:
            raw = run_semgrep(target_path)
            parsed = parse_semgrep_results(raw)
        elif scanner == Scanner.OSV:
            raw = run_osv_scanner(target_path)
            parsed = parse_osv_results(raw)
        else:
            raise ValueError(f"Unsupported scanner: {scanner}")
    except (ScannerExecutionError, ScannerOutputError) as exc:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(exc)
        scan.completed_at = _utcnow()
        db.commit()
        db.refresh(scan)
        return scan

    summary = ingest_findings(db, repository, scan, parsed)

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = _utcnow()
    scan.total_findings = summary["total"]
    scan.new_findings = summary["new"]
    scan.resolved_findings = summary["resolved"]
    db.commit()
    db.refresh(scan)
    return scan


def ingest_findings(
    db: Session, repository: Repository, scan: Scan, parsed: list[NormalizedFinding]
) -> dict[str, int]:
    """Creates/updates/resolves Finding rows for one scan's results. Returns count summary."""
    now = _utcnow()
    touched_ids: set[uuid.UUID] = set()
    new_count = 0

    for item in parsed:
        fingerprint = compute_fingerprint(
            repository.id,
            item.scanner,
            rule_id=item.rule_id,
            file_path=item.file_path,
            line_start=item.line_start,
            package_name=item.package_name,
            package_version=item.package_version,
            cve=item.cve,
        )
        existing = (
            db.query(Finding)
            .filter(Finding.repository_id == repository.id, Finding.fingerprint == fingerprint)
            .first()
        )

        if existing is None:
            finding = Finding(
                repository_id=repository.id,
                scan_id=scan.id,
                scanner=item.scanner,
                finding_type=item.finding_type,
                severity=item.severity,
                title=item.title,
                description=item.description,
                file_path=item.file_path,
                line_start=item.line_start,
                rule_id=item.rule_id,
                package_name=item.package_name,
                package_version=item.package_version,
                cve=item.cve,
                fingerprint=fingerprint,
                raw_metadata=item.raw_metadata,
                status=FindingStatus.OPEN,
                detected_at=now,
                last_seen_at=now,
            )
            db.add(finding)
            db.flush()
            new_count += 1
            touched_ids.add(finding.id)
        else:
            existing.scan_id = scan.id
            existing.last_seen_at = now
            existing.severity = item.severity
            existing.title = item.title
            existing.description = item.description
            existing.raw_metadata = item.raw_metadata
            if existing.status == FindingStatus.RESOLVED:
                existing.status = FindingStatus.OPEN
                existing.resolved_at = None
            touched_ids.add(existing.id)

    stale = (
        db.query(Finding)
        .filter(
            Finding.repository_id == repository.id,
            Finding.scanner == scan.scanner,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        )
        .all()
    )
    resolved_count = 0
    for finding in stale:
        if finding.id not in touched_ids:
            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
            resolved_count += 1

    return {"total": len(parsed), "new": new_count, "resolved": resolved_count}

from app.db.models import (
    Finding,
    FindingStatus,
    FindingType,
    Repository,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
    User,
)
from app.services.scan_service import ingest_findings
from app.services.scanners.base import NormalizedFinding


def _make_repository(db_session) -> Repository:
    user = User(email="scan@example.com", hashed_password="x")
    db_session.add(user)
    db_session.flush()
    repo = Repository(owner_id=user.id, name="webapp", owner="acme")
    db_session.add(repo)
    db_session.flush()
    return repo


def _make_scan(db_session, repo: Repository, scanner: Scanner) -> Scan:
    scan = Scan(repository_id=repo.id, scanner=scanner, status=ScanStatus.RUNNING)
    db_session.add(scan)
    db_session.flush()
    return scan


def _semgrep_item(rule_id="rule-1", file_path="a.py", line=10, severity=Severity.HIGH):
    return NormalizedFinding(
        scanner=Scanner.SEMGREP,
        finding_type=FindingType.SAST,
        severity=severity,
        title=rule_id,
        description="desc",
        file_path=file_path,
        line_start=line,
        rule_id=rule_id,
    )


def test_ingest_new_findings_creates_rows(db_session):
    repo = _make_repository(db_session)
    scan = _make_scan(db_session, repo, Scanner.SEMGREP)

    summary = ingest_findings(db_session, repo, scan, [_semgrep_item()])
    db_session.commit()

    assert summary == {"total": 1, "new": 1, "resolved": 0}
    findings = db_session.query(Finding).filter(Finding.repository_id == repo.id).all()
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.OPEN


def test_ingest_existing_finding_is_updated_not_duplicated(db_session):
    repo = _make_repository(db_session)
    scan1 = _make_scan(db_session, repo, Scanner.SEMGREP)
    ingest_findings(db_session, repo, scan1, [_semgrep_item(severity=Severity.HIGH)])
    db_session.commit()

    scan2 = _make_scan(db_session, repo, Scanner.SEMGREP)
    summary = ingest_findings(db_session, repo, scan2, [_semgrep_item(severity=Severity.CRITICAL)])
    db_session.commit()

    assert summary == {"total": 1, "new": 0, "resolved": 0}
    findings = db_session.query(Finding).filter(Finding.repository_id == repo.id).all()
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].scan_id == scan2.id


def test_ingest_missing_finding_is_marked_resolved(db_session):
    repo = _make_repository(db_session)
    scan1 = _make_scan(db_session, repo, Scanner.SEMGREP)
    ingest_findings(
        db_session,
        repo,
        scan1,
        [_semgrep_item(rule_id="rule-1"), _semgrep_item(rule_id="rule-2", file_path="b.py")],
    )
    db_session.commit()

    scan2 = _make_scan(db_session, repo, Scanner.SEMGREP)
    summary = ingest_findings(db_session, repo, scan2, [_semgrep_item(rule_id="rule-1")])
    db_session.commit()

    assert summary["resolved"] == 1
    resolved = db_session.query(Finding).filter(Finding.rule_id == "rule-2").one()
    assert resolved.status == FindingStatus.RESOLVED
    assert resolved.resolved_at is not None


def test_ingest_reopens_resolved_finding_when_it_reappears(db_session):
    repo = _make_repository(db_session)
    scan1 = _make_scan(db_session, repo, Scanner.SEMGREP)
    ingest_findings(db_session, repo, scan1, [_semgrep_item(rule_id="rule-1")])
    db_session.commit()

    scan2 = _make_scan(db_session, repo, Scanner.SEMGREP)
    ingest_findings(db_session, repo, scan2, [])
    db_session.commit()
    finding = db_session.query(Finding).filter(Finding.rule_id == "rule-1").one()
    assert finding.status == FindingStatus.RESOLVED

    scan3 = _make_scan(db_session, repo, Scanner.SEMGREP)
    ingest_findings(db_session, repo, scan3, [_semgrep_item(rule_id="rule-1")])
    db_session.commit()
    db_session.refresh(finding)
    assert finding.status == FindingStatus.OPEN
    assert finding.resolved_at is None


def test_ingest_does_not_reopen_false_positive_finding(db_session):
    repo = _make_repository(db_session)
    scan1 = _make_scan(db_session, repo, Scanner.SEMGREP)
    ingest_findings(db_session, repo, scan1, [_semgrep_item(rule_id="rule-1")])
    db_session.commit()

    finding = db_session.query(Finding).filter(Finding.rule_id == "rule-1").one()
    finding.status = FindingStatus.FALSE_POSITIVE
    db_session.commit()

    scan2 = _make_scan(db_session, repo, Scanner.SEMGREP)
    ingest_findings(db_session, repo, scan2, [_semgrep_item(rule_id="rule-1")])
    db_session.commit()
    db_session.refresh(finding)
    assert finding.status == FindingStatus.FALSE_POSITIVE


def test_ingest_does_not_resolve_findings_from_a_different_scanner(db_session):
    repo = _make_repository(db_session)
    osv_scan = _make_scan(db_session, repo, Scanner.OSV)
    osv_item = NormalizedFinding(
        scanner=Scanner.OSV,
        finding_type=FindingType.SCA,
        severity=Severity.HIGH,
        title="lodash vuln",
        package_name="lodash",
        package_version="4.17.15",
        cve="CVE-2021-23337",
    )
    ingest_findings(db_session, repo, osv_scan, [osv_item])
    db_session.commit()

    semgrep_scan = _make_scan(db_session, repo, Scanner.SEMGREP)
    ingest_findings(db_session, repo, semgrep_scan, [])
    db_session.commit()

    osv_finding = db_session.query(Finding).filter(Finding.scanner == Scanner.OSV).one()
    assert osv_finding.status == FindingStatus.OPEN

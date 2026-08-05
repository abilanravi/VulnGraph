import uuid

from app.db.models import Scanner
from app.services.fingerprint import compute_fingerprint

REPO_ID = uuid.uuid4()


def test_fingerprint_is_stable_for_identical_inputs():
    a = compute_fingerprint(REPO_ID, Scanner.SEMGREP, rule_id="rule-1", file_path="a.py", line_start=10)
    b = compute_fingerprint(REPO_ID, Scanner.SEMGREP, rule_id="rule-1", file_path="a.py", line_start=10)
    assert a == b


def test_fingerprint_differs_by_line():
    a = compute_fingerprint(REPO_ID, Scanner.SEMGREP, rule_id="rule-1", file_path="a.py", line_start=10)
    b = compute_fingerprint(REPO_ID, Scanner.SEMGREP, rule_id="rule-1", file_path="a.py", line_start=11)
    assert a != b


def test_fingerprint_differs_by_scanner():
    semgrep_fp = compute_fingerprint(REPO_ID, Scanner.SEMGREP, rule_id="x", file_path="a.py", line_start=1)
    osv_fp = compute_fingerprint(REPO_ID, Scanner.OSV, rule_id="x", package_name="a.py", package_version="1")
    assert semgrep_fp != osv_fp


def test_fingerprint_scoped_to_repository():
    other_repo = uuid.uuid4()
    a = compute_fingerprint(REPO_ID, Scanner.OSV, package_name="lodash", package_version="4.17.15", cve="CVE-1")
    b = compute_fingerprint(other_repo, Scanner.OSV, package_name="lodash", package_version="4.17.15", cve="CVE-1")
    assert a != b


def test_manual_fingerprint_keyed_by_cve():
    a = compute_fingerprint(REPO_ID, Scanner.MANUAL, cve="CVE-2024-1")
    b = compute_fingerprint(REPO_ID, Scanner.MANUAL, cve="CVE-2024-1")
    c = compute_fingerprint(REPO_ID, Scanner.MANUAL, cve="CVE-2024-2")
    assert a == b
    assert a != c

import pytest

from app.db.models import FindingType, Scanner, Severity
from app.services.scanners.base import ScannerExecutionError
from app.services.scanners.semgrep import parse_semgrep_results, run_semgrep

SAMPLE_SEMGREP_OUTPUT = {
    "results": [
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "app/main.py",
            "start": {"line": 42, "col": 1},
            "end": {"line": 42, "col": 30},
            "extra": {
                "message": "Detected subprocess call with shell=True",
                "severity": "ERROR",
                "metadata": {"severity": "CRITICAL"},
            },
        },
        {
            "check_id": "python.flask.security.audit.debug-enabled",
            "path": "app/config.py",
            "start": {"line": 5, "col": 1},
            "end": {"line": 5, "col": 20},
            "extra": {
                "message": "Flask app run with debug=True",
                "severity": "WARNING",
            },
        },
        {
            "check_id": "generic.secrets.security.detected-generic-secret",
            "path": "app/util.py",
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 10},
            "extra": {"message": "Possible secret", "severity": "INFO"},
        },
    ]
}


def test_parse_semgrep_results_maps_fields():
    findings = parse_semgrep_results(SAMPLE_SEMGREP_OUTPUT)
    assert len(findings) == 3

    first = findings[0]
    assert first.scanner == Scanner.SEMGREP
    assert first.finding_type == FindingType.SAST
    assert first.rule_id == "python.lang.security.audit.dangerous-subprocess-use"
    assert first.file_path == "app/main.py"
    assert first.line_start == 42
    assert first.description == "Detected subprocess call with shell=True"
    # explicit metadata.severity overrides the top-level ERROR/WARNING/INFO severity
    assert first.severity == Severity.CRITICAL


def test_parse_semgrep_results_maps_top_level_severity_when_no_metadata_override():
    findings = parse_semgrep_results(SAMPLE_SEMGREP_OUTPUT)
    assert findings[1].severity == Severity.MEDIUM  # WARNING -> MEDIUM
    assert findings[2].severity == Severity.LOW  # INFO -> LOW


def test_parse_semgrep_results_empty_results():
    assert parse_semgrep_results({"results": []}) == []
    assert parse_semgrep_results({}) == []


def test_run_semgrep_missing_binary_raises_scanner_execution_error(tmp_path):
    with pytest.raises(ScannerExecutionError):
        run_semgrep(str(tmp_path))

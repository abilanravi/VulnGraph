import pytest

from app.db.models import FindingType, Scanner, Severity
from app.services.scanners.base import ScannerExecutionError
from app.services.scanners.osv import parse_osv_results, run_osv_scanner

SAMPLE_OSV_OUTPUT = {
    "results": [
        {
            "source": {"path": "package-lock.json", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-35jh-r3h4-6jhm",
                            "aliases": ["CVE-2021-23337"],
                            "summary": "Command Injection in lodash",
                            "details": "lodash versions prior to 4.17.21 are vulnerable...",
                            "database_specific": {"severity": "HIGH"},
                        }
                    ],
                },
                {
                    "package": {"name": "minimist", "version": "1.2.0", "ecosystem": "npm"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-vh95-rmgr-6w4m",
                            "aliases": [],
                            "summary": "Prototype Pollution in minimist",
                            "database_specific": {"severity": "MODERATE"},
                        }
                    ],
                },
            ],
        }
    ]
}


def test_parse_osv_results_maps_fields():
    findings = parse_osv_results(SAMPLE_OSV_OUTPUT)
    assert len(findings) == 2

    first = findings[0]
    assert first.scanner == Scanner.OSV
    assert first.finding_type == FindingType.SCA
    assert first.package_name == "lodash"
    assert first.package_version == "4.17.15"
    assert first.cve == "CVE-2021-23337"  # preferred over the raw GHSA id
    assert first.rule_id == "GHSA-35jh-r3h4-6jhm"
    assert first.severity == Severity.HIGH
    assert first.file_path == "package-lock.json"


def test_parse_osv_results_maps_moderate_to_medium_and_falls_back_to_ghsa_id():
    findings = parse_osv_results(SAMPLE_OSV_OUTPUT)
    second = findings[1]
    assert second.severity == Severity.MEDIUM  # MODERATE -> MEDIUM
    assert second.cve == "GHSA-vh95-rmgr-6w4m"  # no CVE alias present, falls back to GHSA id


def test_parse_osv_results_no_vulnerabilities():
    assert parse_osv_results({"results": []}) == []
    assert parse_osv_results({}) == []


def test_run_osv_scanner_missing_binary_raises_scanner_execution_error(tmp_path):
    with pytest.raises(ScannerExecutionError):
        run_osv_scanner(str(tmp_path))

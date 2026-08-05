from dataclasses import dataclass, field

from app.db.models import FindingType, Scanner, Severity


class ScannerExecutionError(Exception):
    """Raised when a scanner CLI cannot be run or exits with an unexpected error."""


class ScannerOutputError(Exception):
    """Raised when a scanner's output cannot be parsed as expected."""


@dataclass
class NormalizedFinding:
    """A scanner result converted into VulnGraph's common finding shape.

    This is an intermediate representation produced by scanner-specific parsers,
    consumed by the scan ingestion service to create/update `Finding` rows.
    """

    scanner: Scanner
    finding_type: FindingType
    severity: Severity
    title: str
    description: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    rule_id: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    cve: str | None = None
    raw_metadata: dict = field(default_factory=dict)

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Scanner(str, enum.Enum):
    MANUAL = "MANUAL"
    SEMGREP = "SEMGREP"
    OSV = "OSV"


class FindingType(str, enum.Enum):
    MANUAL = "MANUAL"
    SAST = "SAST"
    SCA = "SCA"


class ScanStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    repositories: Mapped[list["Repository"]] = relationship(back_populates="user")


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_uuid)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # named `user` (not `owner`) to avoid clashing with the `owner` text column (GitHub org/user)
    user: Mapped["User"] = relationship(back_populates="repositories")
    findings: Mapped[list["Finding"]] = relationship(back_populates="repository", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="repository", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_uuid)
    cve: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="severity"), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="vulnerability")


class Scan(Base):
    """A single execution of one scanner (Semgrep or OSV) against a repository."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_uuid)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"), nullable=False)
    scanner: Mapped[Scanner] = mapped_column(Enum(Scanner, name="scanner"), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"), default=ScanStatus.QUEUED, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)
    new_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved_findings: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    repository: Mapped["Repository"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("repository_id", "fingerprint", name="uq_finding_repo_fingerprint"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=_uuid)
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"), nullable=False)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=True)

    scanner: Mapped[Scanner] = mapped_column(Enum(Scanner, name="scanner"), default=Scanner.MANUAL, nullable=False)
    finding_type: Mapped[FindingType] = mapped_column(
        Enum(FindingType, name="finding_type"), default=FindingType.MANUAL, nullable=False
    )
    severity: Mapped[Severity] = mapped_column(Enum(Severity, name="severity"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # SAST (Semgrep) fields
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # SCA (OSV) fields
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    package_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Dedup fingerprint, unique per repository (see app/services/fingerprint.py)
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    raw_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status"), default=FindingStatus.OPEN, nullable=False
    )
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    repository: Mapped["Repository"] = relationship(back_populates="findings")
    vulnerability: Mapped["Vulnerability | None"] = relationship(back_populates="findings")
    scan: Mapped["Scan | None"] = relationship(back_populates="findings")

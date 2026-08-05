"""scan pipeline: scans table, normalized findings, expanded finding lifecycle

Revision ID: 0002_scan_pipeline
Revises: 0001_initial
Create Date: 2026-08-04

"""
import hashlib
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy.dialects import postgresql

revision: str = "0002_scan_pipeline"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

scanner_enum = postgresql.ENUM("MANUAL", "SEMGREP", "OSV", name="scanner")
finding_type_enum = postgresql.ENUM("MANUAL", "SAST", "SCA", name="finding_type")
scan_status_enum = postgresql.ENUM("QUEUED", "RUNNING", "COMPLETED", "FAILED", name="scan_status")

old_finding_status_values = ("OPEN", "RESOLVED", "IGNORED")
new_finding_status_values = ("OPEN", "IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE")


def upgrade() -> None:
    bind = op.get_bind()

    # --- new enum types (created here; referencing columns below create finding_type/scanner
    #     lazily is avoided since both are used on two columns/tables) ---
    scanner_enum.create(bind, checkfirst=True)
    finding_type_enum.create(bind, checkfirst=True)
    scan_status_enum.create(bind, checkfirst=True)

    # --- scans table ---
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("repository_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("scanner", scanner_enum, nullable=False),
        sa.Column("status", scan_status_enum, nullable=False, server_default="QUEUED"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=True),
        sa.Column("new_findings", sa.Integer(), nullable=True),
        sa.Column("resolved_findings", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # --- findings: widen status enum (OPEN/RESOLVED/IGNORED -> OPEN/IN_PROGRESS/RESOLVED/FALSE_POSITIVE) ---
    op.execute("ALTER TABLE findings ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TABLE findings ALTER COLUMN status TYPE text")
    op.execute("UPDATE findings SET status = 'FALSE_POSITIVE' WHERE status = 'IGNORED'")
    op.execute("DROP TYPE finding_status")
    new_status_enum = postgresql.ENUM(*new_finding_status_values, name="finding_status")
    new_status_enum.create(bind, checkfirst=True)
    op.execute("ALTER TABLE findings ALTER COLUMN status TYPE finding_status USING status::finding_status")
    op.execute("ALTER TABLE findings ALTER COLUMN status SET DEFAULT 'OPEN'")

    # --- findings: new normalized-model columns ---
    op.add_column("findings", sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id"), nullable=True))
    op.alter_column("findings", "vulnerability_id", nullable=True)
    op.add_column(
        "findings", sa.Column("scanner", scanner_enum, nullable=False, server_default="MANUAL")
    )
    op.add_column(
        "findings", sa.Column("finding_type", finding_type_enum, nullable=False, server_default="MANUAL")
    )
    op.add_column("findings", sa.Column("title", sa.String(500), nullable=True))
    op.add_column("findings", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("file_path", sa.String(1024), nullable=True))
    op.add_column("findings", sa.Column("line_start", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("rule_id", sa.String(255), nullable=True))
    op.add_column("findings", sa.Column("package_name", sa.String(255), nullable=True))
    op.add_column("findings", sa.Column("package_version", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("cve", sa.String(64), nullable=True))
    op.add_column("findings", sa.Column("fingerprint", sa.String(128), nullable=True))
    op.add_column("findings", sa.Column("raw_metadata", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))

    # --- backfill title/cve/fingerprint for pre-existing (Milestone 2 manual) findings from
    #     their linked vulnerability, using the same fingerprint algorithm as
    #     app/services/fingerprint.py so future manual submissions dedupe against them.
    #     Requires a live connection to fetch rows, so it's skipped when generating an
    #     offline `--sql` script (there each statement below still renders for review). ---
    if not context.is_offline_mode():
        connection = op.get_bind()
        rows = connection.execute(
            sa.text(
                """
                SELECT f.id AS finding_id, f.repository_id AS repository_id, v.cve AS cve, f.detected_at AS detected_at
                FROM findings f
                JOIN vulnerabilities v ON v.id = f.vulnerability_id
                """
            )
        ).fetchall()
        for row in rows:
            fingerprint = hashlib.sha256(f"{row.repository_id}:manual:{row.cve}".encode("utf-8")).hexdigest()
            connection.execute(
                sa.text(
                    "UPDATE findings SET title = :title, cve = :cve, fingerprint = :fingerprint, "
                    "last_seen_at = :last_seen_at WHERE id = :id"
                ),
                {
                    "title": row.cve,
                    "cve": row.cve,
                    "fingerprint": fingerprint,
                    "last_seen_at": row.detected_at,
                    "id": row.finding_id,
                },
            )

    op.alter_column("findings", "title", nullable=False)
    op.alter_column("findings", "fingerprint", nullable=False)
    op.alter_column("findings", "last_seen_at", nullable=False)
    op.alter_column("findings", "scanner", server_default=None)
    op.alter_column("findings", "finding_type", server_default=None)

    op.drop_constraint("uq_finding_repo_vuln", "findings", type_="unique")
    op.create_unique_constraint("uq_finding_repo_fingerprint", "findings", ["repository_id", "fingerprint"])
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])


def downgrade() -> None:
    bind = op.get_bind()

    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_constraint("uq_finding_repo_fingerprint", "findings", type_="unique")
    op.create_unique_constraint("uq_finding_repo_vuln", "findings", ["repository_id", "vulnerability_id"])

    op.drop_column("findings", "resolved_at")
    op.drop_column("findings", "last_seen_at")
    op.drop_column("findings", "raw_metadata")
    op.drop_column("findings", "fingerprint")
    op.drop_column("findings", "cve")
    op.drop_column("findings", "package_version")
    op.drop_column("findings", "package_name")
    op.drop_column("findings", "rule_id")
    op.drop_column("findings", "line_start")
    op.drop_column("findings", "file_path")
    op.drop_column("findings", "description")
    op.drop_column("findings", "title")
    op.drop_column("findings", "finding_type")
    op.drop_column("findings", "scanner")
    op.alter_column("findings", "vulnerability_id", nullable=False)
    op.drop_column("findings", "scan_id")

    op.execute("ALTER TABLE findings ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TABLE findings ALTER COLUMN status TYPE text")
    op.execute("UPDATE findings SET status = 'IGNORED' WHERE status = 'FALSE_POSITIVE'")
    op.execute("UPDATE findings SET status = 'OPEN' WHERE status = 'IN_PROGRESS'")
    op.execute("DROP TYPE finding_status")
    old_status_enum = postgresql.ENUM(*old_finding_status_values, name="finding_status")
    old_status_enum.create(bind, checkfirst=True)
    op.execute("ALTER TABLE findings ALTER COLUMN status TYPE finding_status USING status::finding_status")
    op.execute("ALTER TABLE findings ALTER COLUMN status SET DEFAULT 'OPEN'")

    op.drop_table("scans")

    scan_status_enum.drop(bind, checkfirst=True)
    finding_type_enum.drop(bind, checkfirst=True)
    scanner_enum.drop(bind, checkfirst=True)

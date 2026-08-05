"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-04

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

severity_enum = postgresql.ENUM("LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity")
finding_status_enum = postgresql.ENUM("OPEN", "RESOLVED", "IGNORED", name="finding_status")


def upgrade() -> None:
    # Enum types are created automatically the first (and only) time each is
    # referenced below, by `vulnerabilities.severity` and `findings.status`
    # respectively — do not call `.create()` here or Postgres raises
    # "type already exists".
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "repositories",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("url", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cve", sa.String(64), nullable=False, unique=True),
        sa.Column("severity", severity_enum, nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vulnerabilities_cve", "vulnerabilities", ["cve"])

    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "repository_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("repositories.id"), nullable=False
        ),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id"),
            nullable=False,
        ),
        sa.Column("status", finding_status_enum, nullable=False, server_default="OPEN"),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("repository_id", "vulnerability_id", name="uq_finding_repo_vuln"),
    )


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("vulnerabilities")
    op.drop_table("repositories")
    op.drop_table("users")
    finding_status_enum.drop(op.get_bind(), checkfirst=True)
    severity_enum.drop(op.get_bind(), checkfirst=True)

"""repositories: add source (MANUAL/GITHUB) and default_branch

Revision ID: 0003_github_repository_source
Revises: 0002_scan_pipeline
Create Date: 2026-08-05

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003_github_repository_source"
down_revision: Union[str, None] = "0002_scan_pipeline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

repository_source_enum = postgresql.ENUM("MANUAL", "GITHUB", name="repository_source")


def upgrade() -> None:
    bind = op.get_bind()
    repository_source_enum.create(bind, checkfirst=True)

    op.add_column(
        "repositories",
        sa.Column("source", repository_source_enum, nullable=False, server_default="MANUAL"),
    )
    op.add_column("repositories", sa.Column("default_branch", sa.String(255), nullable=True))

    # Existing rows with a github.com URL were, in practice, GitHub repositories even though
    # the concept of "source" didn't exist yet — backfill so they show up correctly.
    op.execute("UPDATE repositories SET source = 'GITHUB' WHERE url ILIKE 'https://github.com/%'")

    op.alter_column("repositories", "source", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_column("repositories", "default_branch")
    op.drop_column("repositories", "source")
    repository_source_enum.drop(bind, checkfirst=True)

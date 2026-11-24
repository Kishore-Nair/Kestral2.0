"""Create the scans lifecycle table.

Revision ID: 20261123_0001
Revises: None
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261123_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("scan_id", sa.String(length=40), nullable=False),
        sa.Column("repository_url", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(length=150), nullable=False),
        sa.Column("repository_name", sa.String(length=150), nullable=False),
        sa.Column("requested_ref", sa.String(length=150), nullable=True),
        sa.Column("resolved_ref", sa.String(length=150), nullable=True),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False),
        sa.Column("current_stage", sa.String(length=40), nullable=True),
        sa.Column("inventory_path", sa.Text(), nullable=True),
        sa.Column("sbom_path", sa.Text(), nullable=True),
        sa.Column("normalized_path", sa.Text(), nullable=True),
        sa.Column("graph_path", sa.Text(), nullable=True),
        sa.Column("warnings_json", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(length=100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("scan_id"),
    )
    op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scans_status"), table_name="scans")
    op.drop_table("scans")


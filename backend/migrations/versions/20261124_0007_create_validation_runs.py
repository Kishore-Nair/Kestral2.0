"""Create validation_runs for sandbox validation of approved fixes.

Revision ID: 20261124_0007
Revises: 20261124_0006
Create Date: 2026-11-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261124_0007"
down_revision: str | None = "20261124_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "validation_runs",
        sa.Column("validation_id", sa.String(40), primary_key=True),
        sa.Column("scan_id", sa.String(40), nullable=False),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("source_id", sa.String(80), nullable=False),
        sa.Column("finding_id", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("verdict", sa.String(40), nullable=True),
        sa.Column("run_tests", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("change_json", sa.JSON(), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_validation_runs_scan_id", "validation_runs", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_validation_runs_scan_id", table_name="validation_runs")
    op.drop_table("validation_runs")

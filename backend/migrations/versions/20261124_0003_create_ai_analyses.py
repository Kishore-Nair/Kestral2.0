"""Create the ai_analyses table for the optional AI analyst.

Revision ID: 20261124_0003
Revises: 20261124_0002
Create Date: 2026-11-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261124_0003"
down_revision: str | None = "20261124_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_analyses",
        sa.Column("analysis_id", sa.String(40), primary_key=True),
        sa.Column("scan_id", sa.String(40), nullable=False),
        sa.Column("finding_id", sa.String(200), nullable=False),
        sa.Column("commit_sha", sa.String(64), nullable=True),
        sa.Column("cache_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("provider", sa.String(40), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("prompt_version", sa.String(20), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("decision", sa.String(20), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_ai_analyses_scan_id", "ai_analyses", ["scan_id"])
    op.create_index("ix_ai_analyses_cache_key", "ai_analyses", ["cache_key"])


def downgrade() -> None:
    op.drop_index("ix_ai_analyses_cache_key", table_name="ai_analyses")
    op.drop_index("ix_ai_analyses_scan_id", table_name="ai_analyses")
    op.drop_table("ai_analyses")

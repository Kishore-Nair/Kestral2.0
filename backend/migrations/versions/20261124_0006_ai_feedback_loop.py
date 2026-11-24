"""Add human feedback loop and revision tracking to ai_analyses.

Revision ID: 20261124_0006
Revises: 20261124_0005
Create Date: 2026-11-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261124_0006"
down_revision: str | None = "20261124_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("ai_analyses") as batch:
        batch.add_column(sa.Column("parent_analysis_id", sa.String(length=40), nullable=True))
        batch.add_column(
            sa.Column("revision", sa.Integer(), nullable=False, server_default="1")
        )
        batch.add_column(sa.Column("decision_reasons_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("feedback_history_json", sa.JSON(), nullable=True))
        batch.create_index("ix_ai_analyses_parent_analysis_id", ["parent_analysis_id"])


def downgrade() -> None:
    with op.batch_alter_table("ai_analyses") as batch:
        batch.drop_index("ix_ai_analyses_parent_analysis_id")
        batch.drop_column("feedback_history_json")
        batch.drop_column("decision_reasons_json")
        batch.drop_column("revision")
        batch.drop_column("parent_analysis_id")

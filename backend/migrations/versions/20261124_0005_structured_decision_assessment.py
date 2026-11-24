"""Store structured reviewer assessments and generated audit explanations.

Revision ID: 20261124_0005
Revises: 20261124_0004
Create Date: 2026-11-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261124_0005"
down_revision: str | None = "20261124_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Nullable so existing free-text decisions remain valid, immutable records.
    with op.batch_alter_table("remediation_decisions") as batch:
        batch.add_column(sa.Column("assessment_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("note", sa.Text(), nullable=True))
        batch.add_column(sa.Column("explanation_template", sa.String(length=40), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("remediation_decisions") as batch:
        batch.drop_column("explanation_template")
        batch.drop_column("note")
        batch.drop_column("assessment_json")

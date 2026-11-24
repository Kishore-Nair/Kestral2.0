"""Add the findings artifact path for the risk analysis stage.

Revision ID: 20261124_0002
Revises: 20261123_0001
Create Date: 2026-11-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261124_0002"
down_revision: str | None = "20261123_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("findings_path", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "findings_path")

"""Record pull requests opened for validated fixes.

Revision ID: 20261124_0008
Revises: 20261124_0007
Create Date: 2026-11-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261124_0008"
down_revision: str | None = "20261124_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("validation_runs", sa.Column("pull_request_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("validation_runs", "pull_request_json")

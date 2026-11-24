"""Create evidence-bound remediation proposals and decisions.

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
        "remediation_proposals",
        sa.Column("proposal_id", sa.String(length=40), nullable=False),
        sa.Column("scan_id", sa.String(length=40), nullable=False),
        sa.Column("finding_id", sa.String(length=80), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("subject_label", sa.Text(), nullable=False),
        sa.Column("current_value", sa.Text(), nullable=True),
        sa.Column("proposed_value", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("expected_risk_reduction", sa.String(length=20), nullable=False),
        sa.Column("compatibility_impact", sa.String(length=20), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("uncertainty_json", sa.JSON(), nullable=False),
        sa.Column("repository_commit", sa.String(length=64), nullable=False),
        sa.Column("finding_digest", sa.String(length=64), nullable=False),
        sa.Column("proposal_digest", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.scan_id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "status IN ('PENDING','APPROVED','REJECTED','SUPERSEDED')",
            name="ck_remediation_proposal_status",
        ),
        sa.CheckConstraint("version >= 1", name="ck_remediation_proposal_version"),
        sa.PrimaryKeyConstraint("proposal_id"),
        sa.UniqueConstraint(
            "scan_id", "finding_id", "proposal_digest", name="uq_proposal_snapshot"
        ),
    )
    op.create_index("ix_remediation_proposals_scan_id", "remediation_proposals", ["scan_id"])
    op.create_index("ix_remediation_proposals_finding_id", "remediation_proposals", ["finding_id"])
    op.create_table(
        "remediation_decisions",
        sa.Column("decision_id", sa.String(length=40), nullable=False),
        sa.Column("proposal_id", sa.String(length=40), nullable=False),
        sa.Column("decision", sa.String(length=20), nullable=False),
        sa.Column("decided_by", sa.String(length=200), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("factors_json", sa.JSON(), nullable=False),
        sa.Column("conditions", sa.Text(), nullable=True),
        sa.Column("alternative", sa.Text(), nullable=True),
        sa.Column("external_reference", sa.Text(), nullable=True),
        sa.Column("repository_commit", sa.String(length=64), nullable=False),
        sa.Column("finding_digest", sa.String(length=64), nullable=False),
        sa.Column("proposal_digest", sa.String(length=64), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["proposal_id"], ["remediation_proposals.proposal_id"], ondelete="RESTRICT"
        ),
        sa.CheckConstraint(
            "decision IN ('APPROVED','REJECTED')", name="ck_remediation_decision_type"
        ),
        sa.PrimaryKeyConstraint("decision_id"),
        sa.UniqueConstraint("proposal_id"),
    )


def downgrade() -> None:
    op.drop_table("remediation_decisions")
    op.drop_index("ix_remediation_proposals_finding_id", table_name="remediation_proposals")
    op.drop_index("ix_remediation_proposals_scan_id", table_name="remediation_proposals")
    op.drop_table("remediation_proposals")

"""Database tables for scan lifecycle metadata."""

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class Scan(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    repository_url: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(150), nullable=False)
    repository_name: Mapped[str] = mapped_column(String(150), nullable=False)
    requested_ref: Mapped[str | None] = mapped_column(String(150))
    resolved_ref: Mapped[str | None] = mapped_column(String(150))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    current_stage: Mapped[str | None] = mapped_column(String(40))
    inventory_path: Mapped[str | None] = mapped_column(Text)
    sbom_path: Mapped[str | None] = mapped_column(Text)
    normalized_path: Mapped[str | None] = mapped_column(Text)
    graph_path: Mapped[str | None] = mapped_column(Text)
    findings_path: Mapped[str | None] = mapped_column(Text)
    warnings_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    error_code: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))



class AiAnalysisRow(Base):
    """One AI investigation of one finding. Kept apart from scan status and artifacts."""

    __tablename__ = "ai_analyses"

    analysis_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(200), nullable=False)
    parent_analysis_id: Mapped[str | None] = mapped_column(String(40), index=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    cache_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(20), nullable=False)
    result_json: Mapped[dict | None] = mapped_column(JSON)
    error_message: Mapped[str | None] = mapped_column(Text)
    decision: Mapped[str | None] = mapped_column(String(20))
    decision_reasons_json: Mapped[list[str] | None] = mapped_column(JSON)
    decision_note: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    feedback_history_json: Mapped[list[dict] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RemediationProposalRow(Base):
    __tablename__ = "remediation_proposals"
    __table_args__ = (
        UniqueConstraint("scan_id", "finding_id", "proposal_digest", name="uq_proposal_snapshot"),
        CheckConstraint(
            "status IN ('PENDING','APPROVED','REJECTED','SUPERSEDED')",
            name="ck_remediation_proposal_status",
        ),
        CheckConstraint("version >= 1", name="ck_remediation_proposal_version"),
    )

    proposal_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.scan_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    finding_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    subject_label: Mapped[str] = mapped_column(Text, nullable=False)
    current_value: Mapped[str | None] = mapped_column(Text)
    proposed_value: Mapped[str | None] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    expected_risk_reduction: Mapped[str] = mapped_column(String(20), nullable=False)
    compatibility_impact: Mapped[str] = mapped_column(String(20), nullable=False)
    evidence_json: Mapped[list[dict]] = mapped_column(JSON, nullable=False)
    uncertainty_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    repository_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    proposal_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class RemediationDecisionRow(Base):
    __tablename__ = "remediation_decisions"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('APPROVED','REJECTED')", name="ck_remediation_decision_type"
        ),
    )

    decision_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    proposal_id: Mapped[str] = mapped_column(
        ForeignKey("remediation_proposals.proposal_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    )
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    decided_by: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    factors_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    # Structured reviewer selections; NULL only for legacy free-text decisions.
    assessment_json: Mapped[dict[str, str] | None] = mapped_column(JSON)
    note: Mapped[str | None] = mapped_column(Text)
    explanation_template: Mapped[str | None] = mapped_column(String(40))
    conditions: Mapped[str | None] = mapped_column(Text)
    alternative: Mapped[str | None] = mapped_column(Text)
    external_reference: Mapped[str | None] = mapped_column(Text)
    repository_commit: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    proposal_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ValidationRunRow(Base):
    """One sandbox validation of one approved change. Separate from scan status."""

    __tablename__ = "validation_runs"

    validation_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(20), nullable=False)
    source_id: Mapped[str] = mapped_column(String(80), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    verdict: Mapped[str | None] = mapped_column(String(40))
    run_tests: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    change_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    result_json: Mapped[dict | None] = mapped_column(JSON)
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    pull_request_json: Mapped[dict | None] = mapped_column(JSON)

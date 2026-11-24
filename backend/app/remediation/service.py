"""Persistence and atomic decision transitions for remediation proposals."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import RemediationDecisionRow, RemediationProposalRow, Scan
from app.remediation.explanation import generate_explanation
from app.remediation.generator import GeneratedProposal
from app.schemas.findings import FindingsDocument
from app.schemas.inventory import Evidence
from app.schemas.remediation import (
    EXPLANATION_TEMPLATE_VERSION,
    RemediationDecision,
    RemediationDecisionCreate,
    RemediationProposal,
    ReviewAssessment,
)


class ProposalConflict(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def create_proposals(db: Session, scan: Scan, findings: FindingsDocument) -> None:
    """Idempotently persist deterministic proposals for one completed risk result."""
    from app.remediation.generator import generate_proposal

    if not scan.commit_sha:
        raise ValueError("A repository commit is required before creating proposals")
    existing = set(
        db.scalars(
            select(RemediationProposalRow.proposal_id).where(
                RemediationProposalRow.scan_id == scan.scan_id
            )
        ).all()
    )
    for finding in findings.findings:
        generated: GeneratedProposal = generate_proposal(finding, scan.scan_id)
        if generated.proposal_id in existing:
            continue
        db.add(
            RemediationProposalRow(
                proposal_id=generated.proposal_id,
                scan_id=scan.scan_id,
                finding_id=generated.finding_id,
                action=generated.action,
                subject_label=generated.subject_label,
                current_value=generated.current_value,
                proposed_value=generated.proposed_value,
                recommendation=generated.recommendation,
                rationale=generated.rationale,
                expected_risk_reduction=generated.expected_risk_reduction,
                compatibility_impact=generated.compatibility_impact,
                evidence_json=generated.evidence_json,
                uncertainty_json=generated.uncertainty_json,
                repository_commit=scan.commit_sha,
                finding_digest=generated.finding_digest,
                proposal_digest=generated.proposal_digest,
                status="PENDING",
                version=1,
            )
        )
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise


def list_proposal_rows(db: Session, scan_id: str) -> list[RemediationProposalRow]:
    return list(
        db.scalars(
            select(RemediationProposalRow)
            .where(RemediationProposalRow.scan_id == scan_id)
            .order_by(RemediationProposalRow.created_at, RemediationProposalRow.proposal_id)
        ).all()
    )


def load_proposal(db: Session, scan_id: str, proposal_id: str) -> RemediationProposalRow | None:
    return db.scalar(
        select(RemediationProposalRow).where(
            RemediationProposalRow.scan_id == scan_id,
            RemediationProposalRow.proposal_id == proposal_id,
        )
    )


def load_proposal_for_decision(
    db: Session, scan_id: str, proposal_id: str
) -> RemediationProposalRow | None:
    """Lock the proposal so concurrent reviewers cannot both decide it."""
    return db.scalar(
        select(RemediationProposalRow)
        .where(
            RemediationProposalRow.scan_id == scan_id,
            RemediationProposalRow.proposal_id == proposal_id,
        )
        .with_for_update()
    )


def load_decision(db: Session, proposal_id: str) -> RemediationDecisionRow | None:
    return db.scalar(
        select(RemediationDecisionRow).where(
            RemediationDecisionRow.proposal_id == proposal_id
        )
    )


def decide_proposal(
    db: Session,
    scan: Scan,
    row: RemediationProposalRow,
    request: RemediationDecisionCreate,
) -> RemediationDecisionRow:
    if row.status != "PENDING" or load_decision(db, row.proposal_id) is not None:
        raise ProposalConflict("PROPOSAL_ALREADY_DECIDED", "This proposal already has a decision")
    if row.version != request.expected_proposal_version:
        raise ProposalConflict("PROPOSAL_CHANGED", "The proposal changed; refresh before deciding")
    if scan.commit_sha != row.repository_commit:
        raise ProposalConflict(
            "FINDING_NO_LONGER_CURRENT",
            "The repository commit no longer matches the reviewed proposal",
        )

    now = datetime.now(UTC)
    decision = RemediationDecisionRow(
        decision_id="dec_" + uuid.uuid4().hex,
        proposal_id=row.proposal_id,
        decision=request.decision,
        decided_by=request.decided_by,
        reason=generate_explanation(request.decision, request.assessment, row, request.note),
        factors_json=[],
        assessment_json=request.assessment.model_dump(),
        note=request.note,
        explanation_template=EXPLANATION_TEMPLATE_VERSION,
        conditions=None,
        alternative=None,
        external_reference=request.external_reference,
        repository_commit=row.repository_commit,
        finding_digest=row.finding_digest,
        proposal_digest=row.proposal_digest,
        decided_at=now,
    )
    db.add(decision)
    row.status = request.decision
    row.version += 1
    row.updated_at = now
    try:
        db.commit()
        db.refresh(decision)
        db.refresh(row)
    except Exception:
        db.rollback()
        raise
    return decision


def to_decision(row: RemediationDecisionRow) -> RemediationDecision:
    return RemediationDecision(
        decision_id=row.decision_id,
        proposal_id=row.proposal_id,
        decision=row.decision,
        decided_by=row.decided_by,
        reason=row.reason,
        reason_source="GENERATED" if row.assessment_json is not None else "REVIEWER_WRITTEN",
        explanation_template=row.explanation_template,
        assessment=(
            ReviewAssessment.model_validate(row.assessment_json)
            if row.assessment_json is not None
            else None
        ),
        note=row.note,
        factors=row.factors_json,
        conditions=row.conditions,
        alternative=row.alternative,
        external_reference=row.external_reference,
        repository_commit=row.repository_commit,
        finding_digest=row.finding_digest,
        proposal_digest=row.proposal_digest,
        decided_at=row.decided_at,
    )


def to_proposal(db: Session, row: RemediationProposalRow) -> RemediationProposal:
    decision = load_decision(db, row.proposal_id)
    return RemediationProposal(
        proposal_id=row.proposal_id,
        scan_id=row.scan_id,
        finding_id=row.finding_id,
        action=row.action,
        subject_label=row.subject_label,
        current_value=row.current_value,
        proposed_value=row.proposed_value,
        recommendation=row.recommendation,
        rationale=row.rationale,
        expected_risk_reduction=row.expected_risk_reduction,
        compatibility_impact=row.compatibility_impact,
        evidence=[Evidence.model_validate(item) for item in row.evidence_json],
        uncertainty=list(row.uncertainty_json),
        repository_commit=row.repository_commit,
        finding_digest=row.finding_digest,
        proposal_digest=row.proposal_digest,
        status=row.status,
        version=row.version,
        created_at=row.created_at,
        decision=to_decision(decision) if decision else None,
    )

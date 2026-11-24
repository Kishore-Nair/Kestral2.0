from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.models import RemediationProposalRow, Scan
from app.remediation.service import ProposalConflict, decide_proposal, to_proposal
from app.schemas.remediation import RemediationDecisionCreate, ReviewAssessment


@pytest.fixture
def db() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def rows(db: Session) -> tuple[Scan, RemediationProposalRow]:
    scan = Scan(
        scan_id="scan_1",
        repository_url="https://github.com/example/repo",
        owner="example",
        repository_name="repo",
        status="COMPLETED",
        commit_sha="a" * 40,
        warnings_json=[],
    )
    proposal = RemediationProposalRow(
        proposal_id="rem_1",
        scan_id=scan.scan_id,
        finding_id="finding_1",
        action="upgrade",
        subject_label="example@1.0.0",
        current_value="1.0.0",
        proposed_value="1.0.1",
        recommendation="Upgrade example",
        rationale="A fixed version is reported",
        expected_risk_reduction="high",
        compatibility_impact="unknown",
        evidence_json=[{"path": "package-lock.json", "kind": "lockfile", "locator": "example"}],
        uncertainty_json=[],
        repository_commit=scan.commit_sha,
        finding_digest="b" * 64,
        proposal_digest="c" * 64,
        status="PENDING",
        version=1,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db.add_all([scan, proposal])
    db.commit()
    return scan, proposal


ASSESSMENT = ReviewAssessment(
    production_usage="IN_PRODUCTION",
    compatibility="COMPATIBLE",
    test_confidence="HIGH",
    ownership="OWNER_CONFIRMED",
    alternatives="NO_ALTERNATIVE",
    timing="NEXT_RELEASE",
)


def decision(version: int = 1) -> RemediationDecisionCreate:
    return RemediationDecisionCreate(
        decision="APPROVED",
        decided_by="reviewer@example.com",
        assessment=ASSESSMENT,
        note="Run the integration suite before merge.",
        expected_proposal_version=version,
    )


def test_decision_requires_every_assessment_dimension() -> None:
    with pytest.raises(ValidationError):
        RemediationDecisionCreate.model_validate(
            {
                "decision": "APPROVED",
                "decided_by": "reviewer",
                "assessment": {"production_usage": "UNKNOWN"},
                "expected_proposal_version": 1,
            }
        )


def test_free_text_reason_is_no_longer_accepted() -> None:
    with pytest.raises(ValidationError):
        RemediationDecisionCreate.model_validate(
            {
                "decision": "APPROVED",
                "decided_by": "reviewer",
                "reason": "A long hand-written risk assessment.",
                "assessment": ASSESSMENT.model_dump(),
                "expected_proposal_version": 1,
            }
        )


def test_all_unknown_is_valid_and_blank_note_is_dropped() -> None:
    request = RemediationDecisionCreate(
        decision="REJECTED",
        decided_by="reviewer",
        assessment=ReviewAssessment(**dict.fromkeys(ReviewAssessment.model_fields, "UNKNOWN")),
        note="   ",
        expected_proposal_version=1,
    )
    assert request.note is None


def test_note_is_short() -> None:
    with pytest.raises(ValidationError):
        RemediationDecisionCreate(
            decision="APPROVED",
            decided_by="reviewer",
            assessment=ASSESSMENT,
            note="x" * 281,
            expected_proposal_version=1,
        )


def test_decision_is_bound_and_terminal(db: Session) -> None:
    scan, proposal = rows(db)
    saved = decide_proposal(db, scan, proposal, decision())
    value = to_proposal(db, proposal)
    assert saved.reason.startswith("Approved the proposed upgrade of example@1.0.0")
    assert saved.explanation_template == "assessment-v1"
    assert value.status == "APPROVED"
    assert value.version == 2
    assert value.decision is not None
    assert value.decision.repository_commit == scan.commit_sha
    assert value.decision.reason_source == "GENERATED"
    assert value.decision.assessment == ASSESSMENT
    assert value.decision.note == "Run the integration suite before merge."
    assert value.decision.factors == []
    with pytest.raises(ProposalConflict, match="already has a decision"):
        decide_proposal(db, scan, proposal, decision(version=2))


def test_stale_version_is_rejected(db: Session) -> None:
    scan, proposal = rows(db)
    with pytest.raises(ProposalConflict) as caught:
        decide_proposal(db, scan, proposal, decision(version=2))
    assert caught.value.code == "PROPOSAL_CHANGED"

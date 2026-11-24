from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.models import RemediationProposalRow, Scan
from app.remediation.service import ProposalConflict, decide_proposal, to_proposal
from app.schemas.remediation import RemediationDecisionCreate


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


def decision(version: int = 1) -> RemediationDecisionCreate:
    return RemediationDecisionCreate(
        decision="APPROVED",
        decided_by="reviewer@example.com",
        reason="The fixed patch version is supported and the evidence is sufficient.",
        factors=["SECURITY_RISK", "SOURCE_CONFIDENCE"],
        conditions="Run the integration suite before merge.",
        expected_proposal_version=version,
    )


def test_decision_requires_substantive_reason() -> None:
    with pytest.raises(ValidationError):
        RemediationDecisionCreate(
            decision="APPROVED",
            decided_by="reviewer",
            reason="approved",
            factors=["SECURITY_RISK"],
            expected_proposal_version=1,
        )


def test_decision_is_bound_and_terminal(db: Session) -> None:
    scan, proposal = rows(db)
    saved = decide_proposal(db, scan, proposal, decision())
    value = to_proposal(db, proposal)
    assert saved.reason.startswith("The fixed patch")
    assert value.status == "APPROVED"
    assert value.version == 2
    assert value.decision is not None
    assert value.decision.repository_commit == scan.commit_sha
    with pytest.raises(ProposalConflict, match="already has a decision"):
        decide_proposal(db, scan, proposal, decision(version=2))


def test_stale_version_is_rejected(db: Session) -> None:
    scan, proposal = rows(db)
    with pytest.raises(ProposalConflict) as caught:
        decide_proposal(db, scan, proposal, decision(version=2))
    assert caught.value.code == "PROPOSAL_CHANGED"

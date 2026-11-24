from collections.abc import Generator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.models import RemediationProposalRow, Scan
from app.database.session import get_db
from app.main import app


@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with sessions() as db:
            yield db

    now = datetime.now(UTC)
    with sessions() as db:
        scan = Scan(
            scan_id="scan_1",
            repository_url="https://github.com/example/repo",
            owner="example",
            repository_name="repo",
            status="COMPLETED",
            commit_sha="a" * 40,
            warnings_json=[],
            created_at=now,
            finished_at=now,
        )
        proposal = RemediationProposalRow(
            proposal_id="rem_1",
            scan_id="scan_1",
            finding_id="finding_1",
            action="upgrade",
            subject_label="example@1.0.0",
            current_value="1.0.0",
            proposed_value="1.0.1",
            recommendation="Evaluate upgrading example to 1.0.1.",
            rationale="A fixed version is reported.",
            expected_risk_reduction="high",
            compatibility_impact="unknown",
            evidence_json=[
                {"path": "package-lock.json", "kind": "lockfile", "locator": "example"}
            ],
            uncertainty_json=[],
            repository_commit="a" * 40,
            finding_digest="b" * 64,
            proposal_digest="c" * 64,
            status="PENDING",
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add_all([scan, proposal])
        db.commit()

    app.dependency_overrides[get_db] = override_db
    yield TestClient(app)
    app.dependency_overrides.clear()
    engine.dispose()


def test_lists_and_records_explained_decision(client: TestClient) -> None:
    listed = client.get("/api/v1/scans/scan_1/remediations")
    assert listed.status_code == 200
    assert listed.json()["proposals"][0]["status"] == "PENDING"

    decided = client.post(
        "/api/v1/scans/scan_1/remediations/rem_1/decision",
        json={
            "decision": "REJECTED",
            "decided_by": "owner@example.com",
            "reason": "The proposed update breaks an application API used by this service.",
            "factors": ["COMPATIBILITY", "APPLICATION_CONTEXT"],
            "alternative": "Wait for the compatible parent dependency release.",
            "expected_proposal_version": 1,
        },
    )
    assert decided.status_code == 200
    body = decided.json()
    assert body["status"] == "REJECTED"
    assert body["decision"]["reason"].startswith("The proposed update")
    assert body["decision"]["repository_commit"] == "a" * 40

    repeated = client.post(
        "/api/v1/scans/scan_1/remediations/rem_1/decision",
        json={
            "decision": "APPROVED",
            "decided_by": "second@example.com",
            "reason": "A second reviewer should not be able to overwrite the first decision.",
            "factors": ["SECURITY_RISK"],
            "expected_proposal_version": 2,
        },
    )
    assert repeated.status_code == 409
    assert repeated.json()["error"]["code"] == "PROPOSAL_ALREADY_DECIDED"


def test_rejects_missing_reason(client: TestClient) -> None:
    response = client.post(
        "/api/v1/scans/scan_1/remediations/rem_1/decision",
        json={
            "decision": "APPROVED",
            "decided_by": "owner@example.com",
            "reason": "approved",
            "factors": ["SECURITY_RISK"],
            "expected_proposal_version": 1,
        },
    )
    assert response.status_code == 422

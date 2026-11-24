"""AI analyst API with an in-memory database and a scripted provider."""

from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.ai import service
from app.ai.provider import FakeProvider, ProviderError
from app.api.routes import ai as ai_routes
from app.config import settings
from app.database.base import Base
from app.database.models import Scan
from app.database.session import get_db
from app.main import app
from tests.ai.ai_helpers import COMMIT, draft, final_turn, tools_turn, write_scan
from tests.risk.risk_helpers import SCAN_ID

FINDING = "finding:vuln-qs"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with sessions() as session:
            yield session

    root = tmp_path / "scans"
    write_scan(root / SCAN_ID)
    with sessions() as db:
        db.add(
            Scan(
                scan_id=SCAN_ID,
                repository_url="https://github.com/example/demo",
                owner="example",
                repository_name="demo",
                status="COMPLETED",
                commit_sha=COMMIT,
                findings_path=f"{SCAN_ID}/findings.json",
                finished_at=datetime.now(UTC),
            )
        )
        db.commit()
    app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr(settings, "scan_output_root", root)
    monkeypatch.setattr(settings, "ai_enabled", False)
    monkeypatch.setattr(settings, "groq_api_key", None)
    monkeypatch.setattr(settings, "ai_provider", "groq")
    monkeypatch.setattr(settings, "ai_model", None)
    monkeypatch.setattr(ai_routes, "session_factory", sessions)
    yield TestClient(app)
    app.dependency_overrides.clear()
    engine.dispose()


def configure(monkeypatch, turns) -> FakeProvider:
    provider = FakeProvider(list(turns))
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "groq_api_key", SecretStr("test-key-not-real"))
    monkeypatch.setattr(service, "build_provider", lambda _settings: provider)
    return provider


def url(path: str = "") -> str:
    return f"/api/v1/scans/{SCAN_ID}{path}"


def test_unconfigured_ai_leaves_scans_working(client: TestClient) -> None:
    status = client.get("/api/v1/ai/status").json()
    assert status["enabled"] is False and status["configured"] is False
    assert (
        status["model"] == "openai/gpt-oss-120b"
        and status["api_key_env"] == "GROQ_API_KEY"
        and "never sent" in status["data_notice"]
    )
    response = client.post(url(f"/findings/{FINDING}/ai-analysis"))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "AI_NOT_CONFIGURED"
    assert client.get(url()).status_code == 200
    assert client.get(url("/findings")).status_code == 200
    assert client.get(url(f"/findings/{FINDING}/remediation")).json() is None


def test_analysis_runs_caches_and_records_a_decision(client: TestClient, monkeypatch) -> None:
    provider = configure(
        monkeypatch,
        [tools_turn(("get_advisory", {"advisory_id": "CVE-2022-24999"})), final_turn(draft())],
    )
    started = client.post(url(f"/findings/{FINDING}/ai-analysis"))
    assert started.status_code == 202
    body = started.json()
    assert body["status"] == "queued" and body["cached"] is False
    analysis_id = body["analysis_id"]

    done = client.get(url(f"/ai-analysis/{analysis_id}")).json()
    assert done["status"] == "recommendation_ready", done["error"]
    rec = done["recommendation"]
    assert rec["tool_trace"][0]["name"] == "get_advisory"
    assert rec["recommended_remediation"]["fixed_version_verified"] is True
    assert done["stale"] is False
    assert len(provider.calls) == 2

    again = client.post(url(f"/findings/{FINDING}/ai-analysis")).json()
    assert again["analysis_id"] == analysis_id and again["cached"] is True
    assert client.get(url(f"/findings/{FINDING}/remediation")).json()["analysis_id"] == analysis_id

    decided = client.post(
        url(f"/ai-analysis/{analysis_id}/decision"), json={"decision": "approved"}
    )
    assert decided.status_code == 200
    assert decided.json()["decision"]["decision"] == "approved"
    assert decided.json()["status"] == "recommendation_ready"  # approval is not a fix


def test_model_change_marks_recommendation_stale(client: TestClient, monkeypatch) -> None:
    configure(monkeypatch, [final_turn(draft())])
    analysis_id = client.post(url(f"/findings/{FINDING}/ai-analysis")).json()["analysis_id"]
    monkeypatch.setattr(settings, "ai_model", "a-different-model")
    current = client.get(url(f"/ai-analysis/{analysis_id}")).json()
    assert current["stale"] is True
    blocked = client.post(
        url(f"/ai-analysis/{analysis_id}/decision"), json={"decision": "approved"}
    )
    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "RECOMMENDATION_STALE"


def test_errors_are_sanitized(client: TestClient, monkeypatch) -> None:
    configure(monkeypatch, [ProviderError("rate_limit", "AI provider rate limit or quota reached")])
    analysis_id = client.post(url(f"/findings/{FINDING}/ai-analysis")).json()["analysis_id"]
    failed = client.get(url(f"/ai-analysis/{analysis_id}")).json()
    assert failed["status"] == "failed"
    assert failed["error"] == "AI provider rate limit or quota reached"
    assert "test-key-not-real" not in str(failed)
    assert client.post(url("/findings/finding:nope/ai-analysis")).status_code == 404
    assert client.get(url("/ai-analysis/ai_missing")).status_code == 404
    no_rec = client.post(url(f"/ai-analysis/{analysis_id}/decision"), json={"decision": "approved"})
    assert no_rec.status_code == 409


def test_incomplete_scan_is_refused(client: TestClient, monkeypatch) -> None:
    configure(monkeypatch, [])
    running = "scan_" + "1" * 32
    with ai_routes.session_factory() as db:
        db.add(
            Scan(
                scan_id=running,
                repository_url="https://github.com/example/demo",
                owner="example",
                repository_name="demo",
                status="ANALYZING_RISK",
            )
        )
        db.commit()
    response = client.post(f"/api/v1/scans/{running}/findings/{FINDING}/ai-analysis")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "FINDINGS_NOT_READY"


def test_real_provider_is_only_built_when_configured(monkeypatch) -> None:
    monkeypatch.setattr(settings, "ai_enabled", False)
    with pytest.raises(ProviderError) as disabled:
        service.build_provider(settings)
    assert disabled.value.kind == "not_configured"
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(settings, "groq_api_key", None)
    with pytest.raises(ProviderError, match="GROQ_API_KEY is not set"):
        service.build_provider(settings)

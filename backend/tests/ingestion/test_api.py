import json
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import scans as scan_routes
from app.database.base import Base
from app.database.scans import load_scan, record_artifact
from app.database.session import get_db
from app.main import app

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def api_client(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    testing_sessions = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with testing_sessions() as session:
            yield session

    def finish_background(_scan_id: str) -> None:
        scan_routes.scan_capacity.release()

    app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr(scan_routes, "run_reserved_scan", finish_background)
    monkeypatch.setattr(scan_routes.settings, "scan_output_root", tmp_path / "scans")
    client = TestClient(app)
    client.testing_sessions = testing_sessions  # type: ignore[attr-defined]
    yield client
    app.dependency_overrides.clear()
    engine.dispose()


def create_scan(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/example/repository", "ref": "main"},
    )
    assert response.status_code == 202
    return response.json()


def test_health(api_client: TestClient) -> None:
    response = api_client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_invalid_repository_uses_error_contract(api_client: TestClient) -> None:
    response = api_client.post(
        "/api/v1/scans",
        json={"repository_url": "file:///etc/passwd", "ref": None},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REPOSITORY"
    assert response.json()["scan_id"] is None


def test_create_scan_returns_202_and_persists_queued_state(api_client: TestClient) -> None:
    created = create_scan(api_client)
    assert created["status"] == "QUEUED"
    assert created["repository_name"] == "repository"
    assert created["scan_id"].startswith("scan_")

    status = api_client.get(f"/api/v1/scans/{created['scan_id']}")
    assert status.status_code == 200
    assert status.json()["status"] == "QUEUED"
    assert status.json()["current_stage"] is None
    assert status.json()["repository"]["url"] == "https://github.com/example/repository"


def test_unknown_scan_returns_404(api_client: TestClient) -> None:
    scan_id = "scan_" + "0" * 32
    response = api_client.get(f"/api/v1/scans/{scan_id}")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_graph_not_ready_returns_409(api_client: TestClient) -> None:
    created = create_scan(api_client)
    response = api_client.get(f"/api/v1/scans/{created['scan_id']}/graph")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ARTIFACT_NOT_READY"


def test_inventory_artifact_is_validated_and_served(api_client: TestClient) -> None:
    created = create_scan(api_client)
    scan_id = created["scan_id"]
    output = scan_routes.settings.scan_output_root / scan_id
    output.mkdir(parents=True)
    payload = json.loads((FIXTURES / "inventory.json").read_text(encoding="utf-8"))
    payload["scan_id"] = scan_id
    (output / "inventory.json").write_text(json.dumps(payload), encoding="utf-8")
    sessions = api_client.testing_sessions  # type: ignore[attr-defined]
    with sessions() as db:
        row = load_scan(db, scan_id)
        assert row is not None
        record_artifact(db, row, field="inventory_path", filename="inventory.json")

    response = api_client.get(f"/api/v1/scans/{scan_id}/inventory")
    assert response.status_code == 200
    assert response.json()["schema_version"] == "1.0"


def test_busy_scanner_returns_429(
    api_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_routes.scan_capacity, "reserve", lambda: False)
    response = api_client.post(
        "/api/v1/scans",
        json={"repository_url": "https://github.com/example/repository", "ref": None},
    )
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "SCANNER_BUSY"


def test_openapi_publishes_all_team_endpoints(api_client: TestClient) -> None:
    paths = api_client.get("/openapi.json").json()["paths"]
    assert {
        "/api/v1/health",
        "/api/v1/scans",
        "/api/v1/scans/{scan_id}",
        "/api/v1/scans/{scan_id}/inventory",
        "/api/v1/scans/{scan_id}/sbom",
        "/api/v1/scans/{scan_id}/graph",
    } <= paths.keys()

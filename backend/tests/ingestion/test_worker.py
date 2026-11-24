import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database.base import Base
from app.database.scans import create_scan_row, load_scan
from app.ingestion import worker
from app.ingestion.cloner import CheckoutMetadata
from app.ingestion.interfaces import PipelineComponentUnavailable
from app.ingestion.url_validation import ValidatedRepository
from app.schemas.dependency import DependencyDocument
from app.schemas.findings import FindingsDocument, FindingStats
from app.schemas.graph import GraphDocument
from app.schemas.inventory import Inventory
from app.schemas.scan import ScanStatus

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture[ModelT](filename: str, model_type: type[ModelT], scan_id: str) -> ModelT:
    payload = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
    if filename == "graph.json":
        payload["meta"]["scan_id"] = scan_id
    else:
        payload["scan_id"] = scan_id
    return model_type.model_validate(payload)


@pytest.fixture
def worker_context(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(worker, "session_factory", sessions)
    monkeypatch.setattr(worker.settings, "workspace_root", tmp_path / "workspaces")
    monkeypatch.setattr(worker.settings, "scan_output_root", tmp_path / "scans")
    return sessions, tmp_path


def create_row(sessions: sessionmaker, scan_id: str) -> None:
    repository = ValidatedRepository(
        owner="example",
        name="fixture-app",
        canonical_url="https://github.com/example/fixture-app",
        requested_ref="main",
    )
    with sessions() as db:
        create_scan_row(db, scan_id=scan_id, repository=repository)


def install_clone_fakes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_clone(_repository, workspace: Path, _timeout: int) -> Path:
        repo = workspace / "repo"
        repo.mkdir()
        (repo / "package.json").write_text("{}", encoding="utf-8")
        return repo

    monkeypatch.setattr(worker, "clone_public_repo", fake_clone)
    monkeypatch.setattr(
        worker,
        "inspect_checkout",
        lambda *_args, **_kwargs: CheckoutMetadata(
            commit_sha="a" * 40,
            resolved_ref="main",
        ),
    )


def test_worker_happy_path_publishes_all_artifacts(
    worker_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions, tmp_path = worker_context
    scan_id = "scan_" + "3" * 32
    create_row(sessions, scan_id)
    install_clone_fakes(monkeypatch)

    inventory = load_fixture("inventory.json", Inventory, scan_id)
    document = load_fixture("normalized.json", DependencyDocument, scan_id)
    graph = load_fixture("graph.json", GraphDocument, scan_id)
    monkeypatch.setattr(worker, "discover_repository", lambda *_args: inventory)

    def fake_dependency(_repo, _inventory, _scan_id, scan_dir: Path):
        (scan_dir / "sbom.cdx.json").write_text(
            json.dumps({"bomFormat": "CycloneDX", "components": []}),
            encoding="utf-8",
        )
        return document

    monkeypatch.setattr(worker, "generate_dependency_document", fake_dependency)
    monkeypatch.setattr(worker, "build_graph", lambda *_args, **_kwargs: graph)
    findings = FindingsDocument(
        scan_id=scan_id,
        findings=[],
        sources=[],
        stats=FindingStats(
            vulnerabilities=0, vulnerable_packages=0, confirmed_by_both=0, workflow_pins=0,
            components_total=0, components_assessed=0, components_not_assessed=0,
        ),
        partial=False,
        warnings=["risk note"],
    )
    monkeypatch.setattr(worker, "analyze_risk", lambda *_args, **_kwargs: findings)

    worker.run_scan(scan_id)

    with sessions() as db:
        row = load_scan(db, scan_id)
        assert row is not None
        assert row.status == ScanStatus.COMPLETED.value
        assert row.commit_sha == "a" * 40
        assert row.inventory_path == f"{scan_id}/inventory.json"
        assert row.normalized_path == f"{scan_id}/normalized.json"
        assert row.graph_path == f"{scan_id}/graph.json"
        assert row.findings_path == f"{scan_id}/findings.json"
        assert "risk note" in row.warnings_json
    output = tmp_path / "scans" / scan_id
    assert {path.name for path in output.iterdir()} == {
        "inventory.json",
        "normalized.json",
        "sbom.cdx.json",
        "graph.json",
        "findings.json",
    }
    assert not (tmp_path / "workspaces" / scan_id).exists()


def test_worker_failure_is_sanitized_and_stops_pipeline(
    worker_context, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions, _tmp_path = worker_context
    scan_id = "scan_" + "4" * 32
    create_row(sessions, scan_id)
    install_clone_fakes(monkeypatch)
    inventory = load_fixture("inventory.json", Inventory, scan_id)
    monkeypatch.setattr(worker, "discover_repository", lambda *_args: inventory)

    def missing_sbom(*_args, **_kwargs):
        raise PipelineComponentUnavailable("M3 SBOM module is not installed")

    monkeypatch.setattr(worker, "generate_dependency_document", missing_sbom)
    worker.run_scan(scan_id)

    with sessions() as db:
        row = load_scan(db, scan_id)
        assert row is not None
        assert row.status == ScanStatus.FAILED.value
        assert row.current_stage == ScanStatus.GENERATING_SBOM.value
        assert row.error_code == "PIPELINE_COMPONENT_UNAVAILABLE"
        assert row.error_message == "M3 SBOM module is not installed"
        assert row.graph_path is None

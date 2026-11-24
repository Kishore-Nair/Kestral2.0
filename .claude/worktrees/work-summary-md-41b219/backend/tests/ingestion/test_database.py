from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.database.scans import (
    create_scan_row,
    finish_completed,
    load_scan,
    reconcile_interrupted_scans,
    record_artifact,
    set_stage,
)
from app.ingestion.url_validation import ValidatedRepository
from app.schemas.scan import ScanStatus


def make_sessions() -> sessionmaker:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def repository() -> ValidatedRepository:
    return ValidatedRepository(
        owner="example",
        name="repository",
        canonical_url="https://github.com/example/repository",
        requested_ref="main",
    )


def test_scan_lifecycle_persists_each_stage() -> None:
    sessions = make_sessions()
    scan_id = "scan_" + "1" * 32
    with sessions() as db:
        row = create_scan_row(db, scan_id=scan_id, repository=repository())
        for stage in (
            ScanStatus.CLONING,
            ScanStatus.DISCOVERING,
            ScanStatus.GENERATING_SBOM,
            ScanStatus.BUILDING_GRAPH,
        ):
            set_stage(db, row, stage)
            assert row.status == stage.value
        record_artifact(db, row, field="graph_path", filename="graph.json")
        finish_completed(db, row, warnings=["one", "one", "two"])
        assert row.status == ScanStatus.COMPLETED.value
        assert row.current_stage == ScanStatus.BUILDING_GRAPH.value
        assert row.finished_at is not None
        assert row.warnings_json == ["one", "two"]


def test_startup_reconciliation_fails_nonterminal_scans() -> None:
    sessions = make_sessions()
    scan_id = "scan_" + "2" * 32
    with sessions() as db:
        create_scan_row(db, scan_id=scan_id, repository=repository())
        assert reconcile_interrupted_scans(db) == 1
        row = load_scan(db, scan_id)
        assert row is not None
        assert row.status == ScanStatus.FAILED.value
        assert row.error_code == "SCAN_INTERRUPTED"
        assert row.finished_at is not None


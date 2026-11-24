"""Transactional scan lifecycle operations."""

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import PurePosixPath

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.database.models import Scan
from app.ingestion.url_validation import ValidatedRepository
from app.schemas.scan import ScanStatus

PROCESSING_STAGES = (
    ScanStatus.CLONING,
    ScanStatus.DISCOVERING,
    ScanStatus.GENERATING_SBOM,
    ScanStatus.BUILDING_GRAPH,
    ScanStatus.ANALYZING_RISK,
)
NONTERMINAL_STATUSES = (ScanStatus.QUEUED, *PROCESSING_STAGES)
ARTIFACT_FIELDS = {
    "inventory_path",
    "sbom_path",
    "normalized_path",
    "graph_path",
    "findings_path",
}
EXPECTED_PREVIOUS_STATUS = {
    ScanStatus.CLONING: ScanStatus.QUEUED,
    ScanStatus.DISCOVERING: ScanStatus.CLONING,
    ScanStatus.GENERATING_SBOM: ScanStatus.DISCOVERING,
    ScanStatus.BUILDING_GRAPH: ScanStatus.GENERATING_SBOM,
    ScanStatus.ANALYZING_RISK: ScanStatus.BUILDING_GRAPH,
}


class InvalidScanTransition(RuntimeError):
    pass


def _commit(db: Session) -> None:
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise


def create_scan_row(
    db: Session,
    *,
    scan_id: str,
    repository: ValidatedRepository,
) -> Scan:
    row = Scan(
        scan_id=scan_id,
        repository_url=repository.canonical_url,
        owner=repository.owner,
        repository_name=repository.name,
        requested_ref=repository.requested_ref,
        status=ScanStatus.QUEUED.value,
        warnings_json=[],
    )
    db.add(row)
    _commit(db)
    db.refresh(row)
    return row


def load_scan(db: Session, scan_id: str) -> Scan | None:
    return db.get(Scan, scan_id)


def set_stage(db: Session, row: Scan, stage: ScanStatus) -> None:
    if stage not in PROCESSING_STAGES:
        raise InvalidScanTransition(f"{stage} is not a processing stage")
    expected = EXPECTED_PREVIOUS_STATUS[stage]
    if row.status != expected.value:
        raise InvalidScanTransition(
            f"Cannot transition scan from {row.status} to {stage.value}"
        )
    now = datetime.now(UTC)
    if row.started_at is None:
        row.started_at = now
    row.status = stage.value
    row.current_stage = stage.value
    _commit(db)


def record_commit_info(
    db: Session,
    row: Scan,
    *,
    commit_sha: str,
    resolved_ref: str | None,
) -> None:
    row.commit_sha = commit_sha
    row.resolved_ref = resolved_ref
    _commit(db)


def record_artifact(
    db: Session,
    row: Scan,
    *,
    field: str,
    filename: str,
) -> str:
    if field not in ARTIFACT_FIELDS:
        raise ValueError("Unknown artifact field")
    relative = PurePosixPath(row.scan_id, filename)
    if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 2:
        raise ValueError("Artifact path must be a direct child of its scan directory")
    value = relative.as_posix()
    setattr(row, field, value)
    _commit(db)
    return value


def finish_completed(db: Session, row: Scan, warnings: Iterable[str]) -> None:
    if (
        row.status != ScanStatus.ANALYZING_RISK.value
        or not row.graph_path
        or not row.findings_path
    ):
        raise InvalidScanTransition(
            "A scan can complete only after publishing its graph and findings"
        )
    row.status = ScanStatus.COMPLETED.value
    row.finished_at = datetime.now(UTC)
    row.error_code = None
    row.error_message = None
    row.warnings_json = list(dict.fromkeys(warnings))
    _commit(db)


def finish_failed(db: Session, row: Scan, *, code: str, message: str) -> None:
    if row.status in {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value}:
        return
    row.status = ScanStatus.FAILED.value
    row.finished_at = datetime.now(UTC)
    row.error_code = code
    row.error_message = message
    _commit(db)


def reconcile_interrupted_scans(db: Session) -> int:
    now = datetime.now(UTC)
    result = db.execute(
        update(Scan)
        .where(Scan.status.in_([status.value for status in NONTERMINAL_STATUSES]))
        .values(
            status=ScanStatus.FAILED.value,
            finished_at=now,
            error_code="SCAN_INTERRUPTED",
            error_message="The scanner process stopped before this scan completed; resubmit it",
        )
    )
    _commit(db)
    return int(result.rowcount or 0)


def active_scan_count(db: Session) -> int:
    rows = db.scalars(
        select(Scan.scan_id).where(
            Scan.status.in_([status.value for status in NONTERMINAL_STATUSES])
        )
    )
    return len(rows.all())


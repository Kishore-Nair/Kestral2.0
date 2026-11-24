"""Database-backed scan lifecycle and artifact API."""

import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.errors import ApiProblem
from app.config import settings
from app.database.models import Scan
from app.database.scans import active_scan_count, create_scan_row, load_scan
from app.database.session import get_db
from app.ingestion.artifacts import load_validated_json, resolve_artifact_path
from app.ingestion.url_validation import validate_repo_url
from app.ingestion.worker import run_reserved_scan, scan_capacity
from app.schemas.dependency import DependencyDocument
from app.schemas.error import ErrorResponse
from app.schemas.graph import GraphDocument
from app.schemas.inventory import Inventory
from app.schemas.scan import Repository, ScanCreate, ScanCreated, ScanState, ScanStatus

router = APIRouter(tags=["scans"])
DatabaseSession = Annotated[Session, Depends(get_db)]

ERROR_RESPONSES = {
    500: {"model": ErrorResponse, "description": "Unexpected service error"},
    404: {"model": ErrorResponse, "description": "Unknown scan ID"},
    409: {"model": ErrorResponse, "description": "Artifact is not ready"},
    422: {"model": ErrorResponse, "description": "Invalid repository URL or ref"},
    429: {"model": ErrorResponse, "description": "Scanner concurrency limit reached"},
    503: {"model": ErrorResponse, "description": "Scanner service is temporarily unavailable"},
}


def _database_unavailable() -> ApiProblem:
    return ApiProblem(
        status=503,
        code="DATABASE_UNAVAILABLE",
        message="The scan database is temporarily unavailable",
    )


def _require_scan(db: Session, scan_id: str) -> Scan:
    try:
        row = load_scan(db, scan_id)
    except SQLAlchemyError:
        raise _database_unavailable() from None
    if row is None:
        raise ApiProblem(
            status=404,
            code="SCAN_NOT_FOUND",
            message="The requested scan does not exist",
            scan_id=scan_id,
        )
    return row


def _scan_state(row: Scan) -> ScanState:
    return ScanState(
        scan_id=row.scan_id,
        status=ScanStatus(row.status),
        current_stage=ScanStatus(row.current_stage) if row.current_stage else None,
        repository=Repository(
            url=row.repository_url,
            owner=row.owner,
            name=row.repository_name,
            requested_ref=row.requested_ref,
            resolved_ref=row.resolved_ref,
            commit_sha=row.commit_sha,
        ),
        created_at=row.created_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
        error=row.error_message,
        warnings=list(row.warnings_json or []),
    )


def _read_artifact[ModelT: BaseModel](
    db: Session,
    scan_id: str,
    *,
    field: str,
    label: str,
    model_type: type[ModelT],
) -> ModelT:
    row = _require_scan(db, scan_id)
    stored_path = getattr(row, field)
    if stored_path is None:
        raise ApiProblem(
            status=409,
            code="ARTIFACT_NOT_READY",
            message=f"{label} is not available yet",
            scan_id=scan_id,
        )
    try:
        artifact_path = resolve_artifact_path(settings.scan_output_root, stored_path)
        if not artifact_path.is_file():
            raise FileNotFoundError
        artifact = load_validated_json(
            artifact_path,
            model_type,
            max_bytes=settings.max_artifact_size_mb * 1024 * 1024,
        )
        artifact_scan_id = getattr(artifact, "scan_id", None)
        if artifact_scan_id is None and isinstance(artifact, GraphDocument):
            artifact_scan_id = artifact.meta.scan_id
        if artifact_scan_id != scan_id:
            raise ValueError("Artifact scan ID does not match its database row")
        return artifact
    except (OSError, ValueError, ValidationError):
        raise ApiProblem(
            status=503,
            code="ARTIFACT_UNAVAILABLE",
            message=f"{label} could not be loaded",
            scan_id=scan_id,
        ) from None


@router.post(
    "/scans",
    response_model=ScanCreated,
    status_code=202,
    responses=ERROR_RESPONSES,
)
def create_scan(
    body: ScanCreate,
    background_tasks: BackgroundTasks,
    db: DatabaseSession,
) -> ScanCreated:
    try:
        repository = validate_repo_url(body.repository_url, body.ref)
    except ValueError as exc:
        raise ApiProblem(
            status=422,
            code="INVALID_REPOSITORY",
            message=str(exc),
        ) from None

    if not scan_capacity.reserve():
        raise ApiProblem(
            status=429,
            code="SCANNER_BUSY",
            message="The scanner is already processing the maximum number of jobs",
        )

    try:
        if active_scan_count(db) >= settings.max_active_scans:
            raise ApiProblem(
                status=429,
                code="SCANNER_BUSY",
                message="The scanner is already processing the maximum number of jobs",
            )
        scan_id = "scan_" + uuid.uuid4().hex
        create_scan_row(db, scan_id=scan_id, repository=repository)
    except ApiProblem:
        scan_capacity.release()
        raise
    except SQLAlchemyError:
        scan_capacity.release()
        raise _database_unavailable() from None
    except Exception:
        scan_capacity.release()
        raise

    background_tasks.add_task(run_reserved_scan, scan_id)
    return ScanCreated(
        scan_id=scan_id,
        status="QUEUED",
        repository_name=repository.name,
    )


@router.get("/scans/{scan_id}", response_model=ScanState, responses=ERROR_RESPONSES)
def get_scan(scan_id: str, db: DatabaseSession) -> ScanState:
    return _scan_state(_require_scan(db, scan_id))


@router.get(
    "/scans/{scan_id}/inventory",
    response_model=Inventory,
    responses=ERROR_RESPONSES,
)
def get_inventory(scan_id: str, db: DatabaseSession) -> Inventory:
    return _read_artifact(
        db,
        scan_id,
        field="inventory_path",
        label="Inventory",
        model_type=Inventory,
    )


@router.get(
    "/scans/{scan_id}/sbom",
    response_model=DependencyDocument,
    responses=ERROR_RESPONSES,
)
def get_sbom(scan_id: str, db: DatabaseSession) -> DependencyDocument:
    return _read_artifact(
        db,
        scan_id,
        field="normalized_path",
        label="Normalized dependency document",
        model_type=DependencyDocument,
    )


@router.get(
    "/scans/{scan_id}/graph",
    response_model=GraphDocument,
    responses=ERROR_RESPONSES,
)
def get_graph(scan_id: str, db: DatabaseSession) -> GraphDocument:
    return _read_artifact(
        db,
        scan_id,
        field="graph_path",
        label="Graph",
        model_type=GraphDocument,
    )

"""Sandbox validation API: list approved changes, start a validation, read its result."""

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.errors import ApiProblem
from app.api.routes.scans import ERROR_RESPONSES, _database_unavailable, _require_scan
from app.config import settings
from app.database.models import ValidationRunRow
from app.database.session import get_db, session_factory
from app.ingestion.worker import scan_capacity
from app.schemas.scan import ScanStatus
from app.schemas.validation import ValidationOverview, ValidationRun, ValidationStartRequest
from app.validation import service

router = APIRouter(tags=["validation"])
DatabaseSession = Annotated[Session, Depends(get_db)]


def _completed(db: Session, scan_id: str):
    row = _require_scan(db, scan_id)
    if row.status != ScanStatus.COMPLETED.value or not row.findings_path:
        raise ApiProblem(
            status=409,
            code="FINDINGS_NOT_READY",
            message="Validation needs a completed scan with findings",
            scan_id=scan_id,
        )
    return row


@router.get(
    "/scans/{scan_id}/validations", response_model=ValidationOverview, responses=ERROR_RESPONSES
)
def get_validations(scan_id: str, db: DatabaseSession) -> ValidationOverview:
    scan = _completed(db, scan_id)
    try:
        candidates = service.candidates(db, settings, scan)
        runs = [service.to_api(r) for r in service.list_runs(db, scan_id)]
    except SQLAlchemyError:
        raise _database_unavailable() from None
    except (OSError, ValueError):
        raise ApiProblem(
            status=503,
            code="ARTIFACT_UNAVAILABLE",
            message="Scan artifacts could not be loaded",
            scan_id=scan_id,
        ) from None
    return ValidationOverview(
        scan_id=scan_id, sandbox=service.sandbox_info(settings), candidates=candidates, runs=runs
    )


@router.post(
    "/scans/{scan_id}/validations",
    response_model=ValidationRun,
    status_code=202,
    responses=ERROR_RESPONSES,
)
def start_validation(
    scan_id: str,
    body: ValidationStartRequest,
    background_tasks: BackgroundTasks,
    db: DatabaseSession,
) -> ValidationRun:
    scan = _completed(db, scan_id)
    if not scan_capacity.reserve():
        raise ApiProblem(
            status=429,
            code="SCANNER_BUSY",
            message="The scanner is busy; try the validation again shortly",
            scan_id=scan_id,
        )
    try:
        row = service.start(db, settings, scan, body.source_type, body.source_id, body.run_tests)
    except service.ValidationError as exc:
        scan_capacity.release()
        raise ApiProblem(status=409, code=exc.code, message=str(exc), scan_id=scan_id) from None
    except Exception:
        scan_capacity.release()
        raise
    background_tasks.add_task(
        service.run_validation,
        session_factory,
        settings,
        row.validation_id,
        release=scan_capacity.release,
    )
    return service.to_api(row)


@router.get(
    "/scans/{scan_id}/validations/{validation_id}",
    response_model=ValidationRun,
    responses=ERROR_RESPONSES,
)
def get_validation(scan_id: str, validation_id: str, db: DatabaseSession) -> ValidationRun:
    _require_scan(db, scan_id)
    row = db.get(ValidationRunRow, validation_id)
    if row is None or row.scan_id != scan_id:
        raise ApiProblem(
            status=404, code="VALIDATION_NOT_FOUND", message="No such validation", scan_id=scan_id
        )
    return service.to_api(row)

"""Optional AI analyst API. Separate from the scan lifecycle; scans work without it."""

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.ai import service
from app.ai.bundle import BundleError
from app.api.errors import ApiProblem
from app.api.routes.scans import ERROR_RESPONSES, _database_unavailable, _require_scan
from app.config import settings
from app.database.models import AiAnalysisRow
from app.database.session import get_db, session_factory
from app.schemas.ai import AiAnalysis, AiDecisionRequest, AiStatus
from app.schemas.scan import ScanStatus

router = APIRouter(tags=["ai"])
DatabaseSession = Annotated[Session, Depends(get_db)]


def _completed_scan(db: Session, scan_id: str):
    row = _require_scan(db, scan_id)
    if row.status != ScanStatus.COMPLETED.value or not row.findings_path:
        raise ApiProblem(
            status=409,
            code="FINDINGS_NOT_READY",
            message="AI analysis needs a completed scan with findings",
            scan_id=scan_id,
        )
    return row


def _analysis(db: Session, scan_id: str, analysis_id: str) -> AiAnalysisRow:
    try:
        analysis = db.get(AiAnalysisRow, analysis_id)
    except SQLAlchemyError:
        raise _database_unavailable() from None
    if analysis is None or analysis.scan_id != scan_id:
        raise ApiProblem(
            status=404, code="ANALYSIS_NOT_FOUND", message="No such AI analysis", scan_id=scan_id
        )
    return analysis


@router.get("/ai/status", response_model=AiStatus)
def get_ai_status() -> AiStatus:
    return service.ai_status(settings)


@router.post(
    "/scans/{scan_id}/findings/{finding_id}/ai-analysis",
    response_model=AiAnalysis,
    status_code=202,
    responses=ERROR_RESPONSES,
)
def start_ai_analysis(
    scan_id: str,
    finding_id: str,
    background_tasks: BackgroundTasks,
    db: DatabaseSession,
    refresh: Annotated[bool, Query()] = False,
) -> AiAnalysis:
    status = service.ai_status(settings)
    if not status.configured:
        raise ApiProblem(
            status=503,
            code="AI_NOT_CONFIGURED",
            message="AI analysis is not configured on this server",
            scan_id=scan_id,
        )
    row = _completed_scan(db, scan_id)
    try:
        analysis, should_run = service.start_analysis(db, settings, row, finding_id, force=refresh)
    except KeyError:
        raise ApiProblem(
            status=404,
            code="FINDING_NOT_FOUND",
            message="No such finding in this scan",
            scan_id=scan_id,
        ) from None
    except BundleError:
        raise ApiProblem(
            status=503,
            code="ARTIFACT_UNAVAILABLE",
            message="Scan findings could not be loaded",
            scan_id=scan_id,
        ) from None
    except SQLAlchemyError:
        raise _database_unavailable() from None
    if should_run:
        background_tasks.add_task(
            service.run_analysis, session_factory, settings, analysis.analysis_id
        )
    return service.to_api(analysis, analysis.cache_key, cached=not should_run)


@router.get(
    "/scans/{scan_id}/ai-analysis/{analysis_id}",
    response_model=AiAnalysis,
    responses=ERROR_RESPONSES,
)
def get_ai_analysis(scan_id: str, analysis_id: str, db: DatabaseSession) -> AiAnalysis:
    row = _require_scan(db, scan_id)
    analysis = _analysis(db, scan_id, analysis_id)
    return service.to_api(analysis, service.current_key(settings, row, analysis))


@router.get(
    "/scans/{scan_id}/findings/{finding_id}/remediation",
    response_model=AiAnalysis | None,
    responses=ERROR_RESPONSES,
)
def get_remediation(scan_id: str, finding_id: str, db: DatabaseSession) -> AiAnalysis | None:
    row = _require_scan(db, scan_id)
    try:
        analysis = service.latest_for_finding(db, scan_id, finding_id)
    except SQLAlchemyError:
        raise _database_unavailable() from None
    if analysis is None:
        return None
    return service.to_api(analysis, service.current_key(settings, row, analysis))


@router.post(
    "/scans/{scan_id}/ai-analysis/{analysis_id}/decision",
    response_model=AiAnalysis,
    responses=ERROR_RESPONSES,
)
def record_ai_decision(
    scan_id: str,
    analysis_id: str,
    body: AiDecisionRequest,
    background_tasks: BackgroundTasks,
    db: DatabaseSession,
) -> AiAnalysis:
    row = _require_scan(db, scan_id)
    analysis = _analysis(db, scan_id, analysis_id)
    if analysis.result_json is None:
        raise ApiProblem(
            status=409,
            code="NO_RECOMMENDATION",
            message="There is no recommendation to decide on",
            scan_id=scan_id,
        )
    if analysis.decision is not None:
        raise ApiProblem(
            status=409,
            code="ANALYSIS_ALREADY_DECIDED",
            message="This AI proposal revision already has a recorded decision",
            scan_id=scan_id,
        )
    key = service.current_key(settings, row, analysis)
    if key != analysis.cache_key:
        raise ApiProblem(
            status=409,
            code="RECOMMENDATION_STALE",
            message="The recommendation is stale; analyze again",
            scan_id=scan_id,
        )
    wants_revision = body.decision == "changes_requested" or (
        body.decision == "rejected" and body.trigger_revision
    )
    if wants_revision and not service.ai_status(settings).configured:
        raise ApiProblem(
            status=503,
            code="AI_NOT_CONFIGURED",
            message="AI analysis is not configured on this server",
            scan_id=scan_id,
        )
    service.record_decision(db, analysis, body.decision, body.note, list(body.reasons))
    next_id: str | None = None
    if wants_revision:
        try:
            child, should_run = service.start_revision(db, settings, row, analysis)
        except KeyError:
            raise ApiProblem(
                status=404,
                code="FINDING_NOT_FOUND",
                message="No such finding in this scan",
                scan_id=scan_id,
            ) from None
        except BundleError:
            raise ApiProblem(
                status=503,
                code="ARTIFACT_UNAVAILABLE",
                message="Scan findings could not be loaded",
                scan_id=scan_id,
            ) from None
        except SQLAlchemyError:
            raise _database_unavailable() from None
        if should_run:
            background_tasks.add_task(
                service.run_analysis, session_factory, settings, child.analysis_id
            )
        next_id = child.analysis_id
    return service.to_api(analysis, key, next_analysis_id=next_id)


@router.post(
    "/scans/{scan_id}/ai-analysis/{analysis_id}/revise",
    response_model=AiAnalysis,
    status_code=202,
    responses=ERROR_RESPONSES,
)
def revise_ai_analysis(
    scan_id: str,
    analysis_id: str,
    background_tasks: BackgroundTasks,
    db: DatabaseSession,
) -> AiAnalysis:
    """Trigger a new AI revision using the recorded rejection or change-request feedback."""
    if not service.ai_status(settings).configured:
        raise ApiProblem(
            status=503,
            code="AI_NOT_CONFIGURED",
            message="AI analysis is not configured on this server",
            scan_id=scan_id,
        )
    row = _completed_scan(db, scan_id)
    parent = _analysis(db, scan_id, analysis_id)
    if parent.decision not in ("rejected", "changes_requested"):
        raise ApiProblem(
            status=409,
            code="FEEDBACK_REQUIRED",
            message="Request changes or reject with reasons before revising with AI",
            scan_id=scan_id,
        )
    try:
        child, should_run = service.start_revision(db, settings, row, parent)
    except KeyError:
        raise ApiProblem(
            status=404,
            code="FINDING_NOT_FOUND",
            message="No such finding in this scan",
            scan_id=scan_id,
        ) from None
    except BundleError:
        raise ApiProblem(
            status=503,
            code="ARTIFACT_UNAVAILABLE",
            message="Scan findings could not be loaded",
            scan_id=scan_id,
        ) from None
    except SQLAlchemyError:
        raise _database_unavailable() from None
    if should_run:
        background_tasks.add_task(
            service.run_analysis, session_factory, settings, child.analysis_id
        )
    return service.to_api(child, child.cache_key, cached=not should_run)

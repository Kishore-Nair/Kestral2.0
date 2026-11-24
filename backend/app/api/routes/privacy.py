"""Privacy impact API: LINDDUN classes and ENISA severity for a scan's findings."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.errors import ApiProblem
from app.api.routes.scans import ERROR_RESPONSES
from app.api.routes.validation import _completed
from app.config import settings
from app.database.session import get_db
from app.privacy.service import assess
from app.schemas.privacy import DataContext, PrivacyAssessment
from app.validation.service import load_findings

router = APIRouter(tags=["privacy"])
DatabaseSession = Annotated[Session, Depends(get_db)]


@router.get("/scans/{scan_id}/privacy", response_model=PrivacyAssessment, responses=ERROR_RESPONSES)
def get_privacy_impact(
    scan_id: str,
    db: DatabaseSession,
    data_context: Annotated[DataContext | None, Query()] = None,
) -> PrivacyAssessment:
    scan = _completed(db, scan_id)
    try:
        document = load_findings(settings, scan)
    except (OSError, ValueError):
        raise ApiProblem(
            status=503,
            code="ARTIFACT_UNAVAILABLE",
            message="Scan findings could not be loaded",
            scan_id=scan_id,
        ) from None
    return assess(document, data_context or settings.privacy_data_context)

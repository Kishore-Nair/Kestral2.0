"""Evidence-bound remediation proposals and human decision API."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.errors import ApiProblem
from app.database.scans import load_scan
from app.database.session import get_db
from app.remediation.service import (
    ProposalConflict,
    decide_proposal,
    list_proposal_rows,
    load_proposal,
    load_proposal_for_decision,
    to_proposal,
)
from app.schemas.remediation import (
    RemediationDecisionCreate,
    RemediationList,
    RemediationProposal,
)
from app.schemas.scan import ScanStatus

router = APIRouter(tags=["remediation decisions"])
DatabaseSession = Annotated[Session, Depends(get_db)]


def _scan(db: Session, scan_id: str):
    try:
        row = load_scan(db, scan_id)
    except SQLAlchemyError:
        raise ApiProblem(
            status=503, code="DATABASE_UNAVAILABLE", message="The decision database is unavailable"
        ) from None
    if row is None:
        raise ApiProblem(
            status=404,
            code="SCAN_NOT_FOUND",
            message="The requested scan does not exist",
            scan_id=scan_id,
        )
    if row.status != ScanStatus.COMPLETED.value:
        raise ApiProblem(
            status=409,
            code="REMEDIATIONS_NOT_READY",
            message="Remediation proposals are available after a scan completes",
            scan_id=scan_id,
        )
    return row


@router.get("/scans/{scan_id}/remediations", response_model=RemediationList)
def list_remediations(scan_id: str, db: DatabaseSession) -> RemediationList:
    _scan(db, scan_id)
    try:
        proposals = [to_proposal(db, row) for row in list_proposal_rows(db, scan_id)]
    except SQLAlchemyError:
        raise ApiProblem(
            status=503,
            code="DATABASE_UNAVAILABLE",
            message="Remediation proposals could not be loaded",
            scan_id=scan_id,
        ) from None
    return RemediationList(scan_id=scan_id, proposals=proposals)


@router.get(
    "/scans/{scan_id}/remediations/{proposal_id}", response_model=RemediationProposal
)
def get_remediation(scan_id: str, proposal_id: str, db: DatabaseSession) -> RemediationProposal:
    _scan(db, scan_id)
    try:
        row = load_proposal(db, scan_id, proposal_id)
        if row is None:
            raise ApiProblem(
                status=404,
                code="PROPOSAL_NOT_FOUND",
                message="The remediation proposal does not exist",
                scan_id=scan_id,
            )
        return to_proposal(db, row)
    except ApiProblem:
        raise
    except SQLAlchemyError:
        raise ApiProblem(
            status=503,
            code="DATABASE_UNAVAILABLE",
            message="The remediation proposal could not be loaded",
            scan_id=scan_id,
        ) from None


@router.post(
    "/scans/{scan_id}/remediations/{proposal_id}/decision",
    response_model=RemediationProposal,
)
def record_decision(
    scan_id: str,
    proposal_id: str,
    body: RemediationDecisionCreate,
    db: DatabaseSession,
) -> RemediationProposal:
    scan = _scan(db, scan_id)
    try:
        row = load_proposal_for_decision(db, scan_id, proposal_id)
        if row is None:
            raise ApiProblem(
                status=404,
                code="PROPOSAL_NOT_FOUND",
                message="The remediation proposal does not exist",
                scan_id=scan_id,
            )
        decide_proposal(db, scan, row, body)
        return to_proposal(db, row)
    except ProposalConflict as exc:
        raise ApiProblem(status=409, code=exc.code, message=str(exc), scan_id=scan_id) from None
    except ApiProblem:
        raise
    except SQLAlchemyError:
        raise ApiProblem(
            status=503,
            code="DATABASE_UNAVAILABLE",
            message="The remediation decision could not be recorded",
            scan_id=scan_id,
        ) from None

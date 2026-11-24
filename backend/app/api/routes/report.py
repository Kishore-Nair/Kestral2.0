"""Guardian report downloads: JSON (machine-readable) and self-contained HTML (printable)."""

import json
import re
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app.api.errors import ApiProblem
from app.api.routes.scans import ERROR_RESPONSES, _require_scan
from app.config import settings
from app.database.session import get_db
from app.report.builder import build_report
from app.report.render import render_html
from app.schemas.scan import ScanStatus

router = APIRouter(tags=["report"])
DatabaseSession = Annotated[Session, Depends(get_db)]


def _report(db: Session, scan_id: str) -> tuple[dict, str]:
    scan = _require_scan(db, scan_id)
    if scan.status != ScanStatus.COMPLETED.value or not scan.findings_path:
        raise ApiProblem(
            status=409,
            code="FINDINGS_NOT_READY",
            message="The report needs a completed scan with findings",
            scan_id=scan_id,
        )
    try:
        report = build_report(db, settings, scan)
    except (OSError, ValueError):
        raise ApiProblem(
            status=503,
            code="ARTIFACT_UNAVAILABLE",
            message="Scan artifacts could not be loaded for the report",
            scan_id=scan_id,
        ) from None
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{scan.owner}-{scan.repository_name}").strip("-")
    name = f"kestral-guardian-report-{slug}-{(scan.commit_sha or 'unknown')[:7]}"
    return report, name


def _disposition(name: str, download: bool) -> dict[str, str]:
    kind = "attachment" if download else "inline"
    return {"Content-Disposition": f'{kind}; filename="{name}"'}


@router.get("/scans/{scan_id}/report.json", responses=ERROR_RESPONSES)
def report_json(
    scan_id: str, db: DatabaseSession, download: Annotated[bool, Query()] = True
) -> Response:
    report, name = _report(db, scan_id)
    return Response(
        json.dumps(report, indent=2, default=str),
        media_type="application/json",
        headers=_disposition(f"{name}.json", download),
    )


@router.get("/scans/{scan_id}/report.html", response_class=HTMLResponse, responses=ERROR_RESPONSES)
def report_html(
    scan_id: str, db: DatabaseSession, download: Annotated[bool, Query()] = True
) -> HTMLResponse:
    report, name = _report(db, scan_id)
    return HTMLResponse(render_html(report), headers=_disposition(f"{name}.html", download))

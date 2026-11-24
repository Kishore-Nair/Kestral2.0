"""Linear M1 scan worker coordinating the independently owned modules."""

import json
import logging
import subprocess
from dataclasses import dataclass

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.database.scans import (
    finish_completed,
    finish_failed,
    load_scan,
    previous_completed_scan,
    record_artifact,
    record_commit_info,
    set_stage,
)
from app.database.session import session_factory
from app.ingestion.artifacts import save_validated_json, validate_cyclonedx_artifact
from app.ingestion.capacity import ScanCapacity
from app.ingestion.cloner import clone_public_repo, inspect_checkout
from app.ingestion.interfaces import (
    PipelineComponentUnavailable,
    analyze_risk,
    build_graph,
    discover_repository,
    generate_dependency_document,
)
from app.ingestion.url_validation import ValidatedRepository
from app.ingestion.workspace import (
    WorkspaceLimitError,
    allocate_scan_dirs,
    enforce_workspace_limits,
    remove_scan_workspace,
)
from app.remediation.service import create_proposals
from app.risk.changes import Baseline
from app.risk.nvd import NvdClient
from app.schemas.scan import ScanStatus

logger = logging.getLogger(__name__)
scan_capacity = ScanCapacity(settings.max_active_scans)


@dataclass(frozen=True)
class SafeScanError:
    code: str
    message: str


def to_safe_error(error: Exception) -> SafeScanError:
    if isinstance(error, subprocess.TimeoutExpired):
        return SafeScanError("CLONE_TIMEOUT", "Repository cloning exceeded the configured timeout")
    if isinstance(error, subprocess.CalledProcessError):
        return SafeScanError(
            "CLONE_FAILED",
            "Git could not clone or inspect the repository; "
            "verify that it is public and the ref exists",
        )
    if isinstance(error, WorkspaceLimitError):
        return SafeScanError("REPOSITORY_LIMIT_EXCEEDED", str(error))
    if isinstance(error, PipelineComponentUnavailable):
        return SafeScanError("PIPELINE_COMPONENT_UNAVAILABLE", str(error))
    if isinstance(error, (ValidationError, json.JSONDecodeError)):
        return SafeScanError("INVALID_PIPELINE_OUTPUT", "A pipeline stage returned invalid data")
    if isinstance(error, ValueError):
        return SafeScanError("SCAN_VALIDATION_FAILED", str(error))
    return SafeScanError(
        "SCAN_FAILED",
        "The scan failed unexpectedly; inspect restricted server logs using the scan ID",
    )


def _nvd_client() -> NvdClient | None:
    if not settings.nvd_enabled:
        return None
    key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    return NvdClient(
        settings.nvd_cache_root,
        api_key=key,
        timeout=settings.nvd_timeout_seconds,
        cache_days=settings.nvd_cache_days,
    )


def _baseline(db, row, output_root) -> Baseline | None:
    previous = previous_completed_scan(db, row)
    if previous is None:
        return None
    return Baseline(
        scan_id=previous.scan_id,
        directory=output_root / previous.scan_id,
        commit_sha=previous.commit_sha,
        resolved_ref=previous.resolved_ref,
        finished_at=previous.finished_at.isoformat() if previous.finished_at else None,
    )


def _validate_stage_scan_id(actual: str, expected: str, stage: str) -> None:
    if actual != expected:
        raise ValueError(f"{stage} output used a different scan ID")


def run_scan(scan_id: str) -> None:
    allocated = False
    row = None
    max_artifact_bytes = settings.max_artifact_size_mb * 1024 * 1024
    with session_factory() as db:
        try:
            row = load_scan(db, scan_id)
            if row is None:
                logger.error("worker received unknown scan_id=%s", scan_id)
                return

            directories = allocate_scan_dirs(
                scan_id,
                settings.workspace_root,
                settings.scan_output_root,
            )
            allocated = True
            repository = ValidatedRepository(
                owner=row.owner,
                name=row.repository_name,
                canonical_url=row.repository_url,
                requested_ref=row.requested_ref,
            )

            set_stage(db, row, ScanStatus.CLONING)
            repo_dir = clone_public_repo(
                repository,
                directories.workspace,
                settings.git_clone_timeout_seconds,
            )
            enforce_workspace_limits(
                repo_dir,
                max_repository_size_mb=settings.max_repository_size_mb,
                max_file_count=settings.max_file_count,
            )
            metadata = inspect_checkout(
                repo_dir,
                requested_ref=repository.requested_ref,
                timeout=settings.git_clone_timeout_seconds,
            )
            record_commit_info(
                db,
                row,
                commit_sha=metadata.commit_sha,
                resolved_ref=metadata.resolved_ref,
            )

            set_stage(db, row, ScanStatus.DISCOVERING)
            inventory = discover_repository(repo_dir, scan_id)
            _validate_stage_scan_id(inventory.scan_id, scan_id, "Discovery")
            save_validated_json(
                directories.output / "inventory.json",
                inventory,
                max_bytes=max_artifact_bytes,
            )
            record_artifact(
                db,
                row,
                field="inventory_path",
                filename="inventory.json",
            )

            set_stage(db, row, ScanStatus.GENERATING_SBOM)
            document = generate_dependency_document(
                repo_dir,
                inventory,
                scan_id,
                directories.output,
            )
            _validate_stage_scan_id(document.scan_id, scan_id, "Dependency")
            raw_sbom = directories.output / "sbom.cdx.json"
            validate_cyclonedx_artifact(raw_sbom, max_bytes=max_artifact_bytes)
            save_validated_json(
                directories.output / "normalized.json",
                document,
                max_bytes=max_artifact_bytes,
            )
            record_artifact(db, row, field="sbom_path", filename="sbom.cdx.json")
            record_artifact(
                db,
                row,
                field="normalized_path",
                filename="normalized.json",
            )

            set_stage(db, row, ScanStatus.BUILDING_GRAPH)
            graph = build_graph(document, app_name=row.repository_name)
            _validate_stage_scan_id(graph.meta.scan_id, scan_id, "Graph")
            save_validated_json(
                directories.output / "graph.json",
                graph,
                max_bytes=max_artifact_bytes,
            )
            record_artifact(db, row, field="graph_path", filename="graph.json")

            set_stage(db, row, ScanStatus.ANALYZING_RISK)
            findings = analyze_risk(
                repo_dir,
                inventory,
                document,
                scan_id,
                directories.output,
                row.repository_name,
                osv_enabled=settings.osv_enabled,
                grype_enabled=settings.grype_enabled,
                osv_timeout=settings.osv_timeout_seconds,
                grype_timeout=settings.grype_timeout_seconds,
                nvd_client=_nvd_client(),
                nvd_budget=settings.nvd_budget_seconds,
                baseline=_baseline(db, row, directories.output.parent),
                current_commit=metadata.commit_sha,
            )
            _validate_stage_scan_id(findings.scan_id, scan_id, "Risk analysis")
            save_validated_json(
                directories.output / "findings.json",
                findings,
                max_bytes=max_artifact_bytes,
            )
            record_artifact(db, row, field="findings_path", filename="findings.json")
            proposal_warnings: list[str] = []
            try:
                create_proposals(db, row, findings)
            except Exception:
                logger.exception("remediation proposal generation failed: scan_id=%s", scan_id)
                proposal_warnings.append(
                    "Remediation proposals could not be generated; scan evidence remains available"
                )
            finish_completed(
                db,
                row,
                warnings=[
                    *inventory.warnings,
                    *document.warnings,
                    *graph.meta.warnings,
                    *findings.warnings,
                    *proposal_warnings,
                ],
            )
        except Exception as exc:
            safe_error = to_safe_error(exc)
            if row is not None:
                try:
                    finish_failed(
                        db,
                        row,
                        code=safe_error.code,
                        message=safe_error.message,
                    )
                except SQLAlchemyError:
                    logger.exception("could not persist scan failure: scan_id=%s", scan_id)
            logger.exception("scan failed: scan_id=%s code=%s", scan_id, safe_error.code)
        finally:
            if allocated:
                try:
                    remove_scan_workspace(scan_id, settings.workspace_root)
                except OSError:
                    logger.exception("workspace cleanup failed: scan_id=%s", scan_id)


def run_reserved_scan(scan_id: str) -> None:
    try:
        run_scan(scan_id)
    finally:
        scan_capacity.release()

"""Validate an approved fix in an isolated sandbox, then rescan and compare.

Flow: approved change -> fresh clone of the exact scanned commit -> deterministic manifest
patch -> lockfile resolution (npm, scripts disabled) -> project tests before/after inside a
container (when a runtime is available) -> full Kestral rescan of the patched copy ->
before/after comparison -> verdict. The original scan, its artifacts and the upstream
repository are never modified.
"""

import json
import logging
import os
import shutil
import stat
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.database.models import (
    AiAnalysisRow,
    RemediationDecisionRow,
    RemediationProposalRow,
    Scan,
    ValidationRunRow,
)
from app.ingestion.artifacts import save_validated_json
from app.ingestion.url_validation import ValidatedRepository
from app.remediation.generator import generate_proposal
from app.risk.changes import Baseline
from app.schemas.dependency import DependencyDocument
from app.schemas.findings import FindingsDocument
from app.schemas.validation import (
    FileDiff,
    PullRequestInfo,
    SandboxInfo,
    TestRun,
    ValidationCandidate,
    ValidationChange,
    ValidationResult,
    ValidationRun,
    ValidationStep,
)
from app.validation import compare, patching, sandbox

logger = logging.getLogger(__name__)
SUPPORTED_ECOSYSTEMS = {"pypi", "npm"}
PATCH_DIR = "patch"
PR_VERDICTS = {"FIXED"}
SUPPORTED_ACTIONS = {"upgrade", "pin"}


class ValidationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def _scan_dir(settings: Settings, scan: Scan) -> Path:
    return settings.scan_output_root / scan.scan_id


def load_findings(settings: Settings, scan: Scan) -> FindingsDocument:
    return FindingsDocument.model_validate_json(
        (_scan_dir(settings, scan) / "findings.json").read_bytes()
    )


def load_document(settings: Settings, scan: Scan) -> DependencyDocument:
    return DependencyDocument.model_validate_json(
        (_scan_dir(settings, scan) / "normalized.json").read_bytes()
    )


def sandbox_info(settings: Settings) -> SandboxInfo:
    runtime = sandbox.container_runtime(settings.validation_container_runtime)
    notes = []
    if not runtime:
        notes.append(
            "No container runtime (Podman or Docker) is available: project tests are not run. "
            "Kestral never runs scanned code on the host."
        )
    if not sandbox.npm_available():
        notes.append("npm is not installed: npm lockfiles cannot be regenerated")
    if not runtime:
        notes.append("Without a container, uv.lock files cannot be regenerated")
    return SandboxInfo(
        github_configured=bool(settings.github_token),
        container_runtime=runtime,
        tests_enabled=bool(runtime and settings.validation_run_tests),
        npm_available=sandbox.npm_available(),
        notes=notes,
    )


def candidates(db: Session, settings: Settings, scan: Scan) -> list[ValidationCandidate]:
    """Approved changes in this scan, and whether the sandbox can apply them."""
    findings = {f.finding_id: f for f in load_findings(settings, scan).findings}
    components = {c.component_id: c for c in load_document(settings, scan).components}
    out: list[ValidationCandidate] = []

    proposals = db.scalars(
        select(RemediationProposalRow).where(
            RemediationProposalRow.scan_id == scan.scan_id,
            RemediationProposalRow.status == "APPROVED",
        )
    ).all()
    for proposal in proposals:
        decision = db.scalars(
            select(RemediationDecisionRow).where(
                RemediationDecisionRow.proposal_id == proposal.proposal_id
            )
        ).first()
        finding = findings.get(proposal.finding_id)
        component = components.get(finding.subject_id or "") if finding else None
        reason = None
        generated = generate_proposal(finding, scan.scan_id) if finding else None
        if (
            decision is None
            or decision.decision != "APPROVED"
            or not decision.decided_by
            or generated is None
            or decision.repository_commit != scan.commit_sha
            or proposal.repository_commit != scan.commit_sha
            or decision.proposal_digest != proposal.proposal_digest
            or decision.finding_digest != proposal.finding_digest
            or generated.proposal_digest != proposal.proposal_digest
            or generated.finding_digest != proposal.finding_digest
            or generated.proposed_value != proposal.proposed_value
            or generated.action != proposal.action
        ):
            reason = "Human approval is absent or does not match the current proposal and evidence"
        elif proposal.action not in SUPPORTED_ACTIONS or not proposal.proposed_value:
            reason = "Only approved version upgrades with one target version can be applied"
        elif component is None:
            reason = "The finding's package is not in this scan's inventory"
        elif component.ecosystem not in SUPPORTED_ECOSYSTEMS:
            reason = f"No sandbox patcher for {component.ecosystem}"
        out.append(
            ValidationCandidate(
                source_type="remediation",
                source_id=proposal.proposal_id,
                finding_id=proposal.finding_id,
                title=proposal.recommendation,
                package=proposal.subject_label,
                ecosystem=component.ecosystem if component else None,
                from_version=component.version if component else proposal.current_value,
                to_version=proposal.proposed_value,
                approved_by=decision.decided_by if decision else None,
                approved_at=decision.decided_at if decision else None,
                supported=reason is None,
                reason=reason,
            )
        )

    analyses = db.scalars(
        select(AiAnalysisRow).where(
            AiAnalysisRow.scan_id == scan.scan_id,
            AiAnalysisRow.decision == "approved",
            AiAnalysisRow.result_json.is_not(None),
        )
    ).all()
    for analysis in analyses:
        rec = analysis.result_json or {}
        rem = rec.get("recommended_remediation") or {}
        component = components.get(rem.get("target_component_id") or "")
        reason = None
        if rem.get("type") not in ("upgrade", "override", "pin_source") or not rem.get(
            "target_version"
        ):
            reason = "Only approved version changes with a target version can be applied"
        elif component is None:
            reason = "The recommendation's target package is not in this scan"
        elif component.ecosystem not in SUPPORTED_ECOSYSTEMS:
            reason = f"No sandbox patcher for {component.ecosystem}"
        out.append(
            ValidationCandidate(
                source_type="ai",
                source_id=analysis.analysis_id,
                finding_id=analysis.finding_id,
                title=str(rec.get("title") or "AI recommendation"),
                package=component.name if component else str(rem.get("target_component_id")),
                ecosystem=component.ecosystem if component else None,
                from_version=component.version if component else None,
                to_version=rem.get("target_version"),
                approved_by="reviewer (AI proposal)",
                approved_at=analysis.decided_at,
                supported=reason is None,
                reason=reason,
            )
        )
    return out


def resolve_change(
    db: Session, settings: Settings, scan: Scan, source_type: str, source_id: str
) -> ValidationChange:
    match = next(
        (
            c
            for c in candidates(db, settings, scan)
            if c.source_type == source_type and c.source_id == source_id
        ),
        None,
    )
    if match is None:
        raise ValidationError("NOT_APPROVED", "No approved change with that ID in this scan")
    if not match.supported:
        raise ValidationError("UNSUPPORTED_CHANGE", match.reason or "Unsupported change")
    findings = {f.finding_id: f for f in load_findings(settings, scan).findings}
    components = {c.component_id: c for c in load_document(settings, scan).components}
    finding = findings[match.finding_id]
    if source_type == "ai":
        analysis = db.get(AiAnalysisRow, source_id)
        component_id = (analysis.result_json or {})["recommended_remediation"][
            "target_component_id"
        ]
    else:
        component_id = finding.subject_id
    component = components[component_id]
    return ValidationChange(
        source_type=match.source_type,
        source_id=match.source_id,
        finding_id=match.finding_id,
        component_id=component.component_id,
        package=component.name,
        ecosystem=component.ecosystem,
        project_path=component.project_path,
        from_version=component.version,
        to_version=str(match.to_version),
        approved_by=match.approved_by,
        approved_at=match.approved_at,
    )


def start(
    db: Session, settings: Settings, scan: Scan, source_type: str, source_id: str, run_tests: bool
) -> ValidationRunRow:
    change = resolve_change(db, settings, scan, source_type, source_id)
    row = ValidationRunRow(
        validation_id=f"val_{uuid.uuid4().hex}",
        scan_id=scan.scan_id,
        source_type=change.source_type,
        source_id=change.source_id,
        finding_id=change.finding_id,
        status="queued",
        run_tests=run_tests,
        change_json=change.model_dump(mode="json"),
    )
    db.add(row)
    db.commit()
    return row


def save_patch(repo: Path, original: dict[str, str | None], target: Path) -> list[str]:
    """Keep the exact patched files (the sandbox is deleted) so a PR carries the tested bytes."""
    saved = []
    for rel, before in sorted(original.items()):
        path = repo / rel
        after = path.read_text(encoding="utf-8") if path.is_file() else None
        if after is None or after == before:
            continue
        destination = (target / rel).resolve()
        destination.relative_to(target.resolve())
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(after, encoding="utf-8")
        saved.append(rel)
    (target.parent / "patch.json").write_text(json.dumps({"files": saved}), encoding="utf-8")
    return saved


def patch_files(settings: Settings, row: ValidationRunRow) -> dict[str, str]:
    """{repo-relative path: patched content} saved by a completed validation."""
    base = settings.scan_output_root / row.scan_id / "validations" / row.validation_id
    try:
        listed = json.loads((base / "patch.json").read_text(encoding="utf-8"))["files"]
    except (OSError, ValueError, KeyError):
        return {}
    out = {}
    root = (base / PATCH_DIR).resolve()
    for rel in listed:
        path = (root / rel).resolve()
        path.relative_to(root)
        out[rel] = path.read_text(encoding="utf-8")
    return out


def to_api(row: ValidationRunRow, settings: Settings | None = None) -> ValidationRun:
    progress = []
    if settings:
        progress_file = (
            settings.scan_output_root
            / row.scan_id
            / "validations"
            / row.validation_id
            / "progress.json"
        )
        if progress_file.is_file():
            progress = [
                ValidationStep.model_validate(s) for s in json.loads(progress_file.read_text())
            ]
    return ValidationRun(
        validation_id=row.validation_id,
        scan_id=row.scan_id,
        status=row.status,
        change=ValidationChange.model_validate(row.change_json),
        error=row.error_message,
        created_at=row.created_at,
        finished_at=row.finished_at,
        result=ValidationResult.model_validate(row.result_json) if row.result_json else None,
        pull_request=PullRequestInfo.model_validate(row.pull_request_json)
        if row.pull_request_json
        else None,
        patch_available=bool(settings and patch_files(settings, row)),
        progress=progress,
    )


def list_runs(db: Session, scan_id: str) -> list[ValidationRunRow]:
    return list(
        db.scalars(
            select(ValidationRunRow)
            .where(ValidationRunRow.scan_id == scan_id)
            .order_by(ValidationRunRow.created_at.desc())
        ).all()
    )


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


class _Steps:
    def __init__(self) -> None:
        self.items: list[ValidationStep] = []
        self.progress_path: Path | None = None

    def add(self, step_id: str, label: str, status: str, detail: str, started: float) -> None:
        self.items.append(
            ValidationStep(
                id=step_id,
                label=label,
                status=status,
                detail=detail[:1500],
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        )
        if self.progress_path:
            temporary = self.progress_path.with_suffix(".tmp")
            temporary.write_text(
                json.dumps([s.model_dump(mode="json") for s in self.items]), encoding="utf-8"
            )
            temporary.replace(self.progress_path)


def _pipeline():
    from app.ingestion.interfaces import (
        analyze_risk,
        build_graph,
        discover_repository,
        generate_dependency_document,
    )
    from app.ingestion.worker import _nvd_client

    return discover_repository, generate_dependency_document, build_graph, analyze_risk, _nvd_client


def execute(
    settings: Settings,
    scan: Scan,
    change: ValidationChange,
    validation_id: str,
    run_tests: bool,
    *,
    checkout: Callable = sandbox.checkout_commit,
    pipeline: Callable = _pipeline,
    runtime_probe: Callable = sandbox.container_runtime,
    test_runner: Callable = sandbox.run_tests_in_container,
    lock_regenerator: Callable = sandbox.regenerate_npm_lock,
    uv_lock_regenerator: Callable = sandbox.regenerate_uv_lock_in_container,
) -> ValidationResult:
    steps = _Steps()
    diffs: list[FileDiff] = []
    tests: list[TestRun] = []
    residual: list[str] = []
    before = load_findings(settings, scan)
    before_doc = load_document(settings, scan)
    target = next(f for f in before.findings if f.finding_id == change.finding_id)
    workspace = (settings.workspace_root / validation_id).resolve()
    output = (_scan_dir(settings, scan) / "validations" / validation_id).resolve()
    workspace.mkdir(parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=False)
    steps.progress_path = output / "progress.json"

    def failed(reason: str) -> ValidationResult:
        return ValidationResult(
            verdict="FAILED",
            verdict_reason=reason,
            tests_status="not_run",
            tests_detail="Validation stopped before tests",
            sandbox_commit=scan.commit_sha,
            steps=steps.items,
            diffs=diffs,
            tests=tests,
            comparison=None,
            rescan_artifacts=None,
            residual_risks=[target.title],
        )

    try:
        # 1. Isolated copy of the exact scanned commit
        t = time.monotonic()
        repository = ValidatedRepository(
            owner=scan.owner,
            name=scan.repository_name,
            canonical_url=scan.repository_url,
            requested_ref=scan.requested_ref,
        )
        try:
            repo = checkout(
                repository, workspace, scan.commit_sha, settings.git_clone_timeout_seconds
            )
        except Exception as exc:  # noqa: BLE001 - reported as a failed step
            steps.add("sandbox", "Isolated checkout of the scanned commit", "failed", str(exc), t)
            return failed("The sandbox checkout failed")
        steps.add(
            "sandbox",
            "Isolated checkout of the scanned commit",
            "passed",
            f"Fresh clone at {str(scan.commit_sha)[:12]} in a separate workspace; the original "
            "scan and repository are untouched",
            t,
        )
        project = patching.project_dir(repo, change.project_path)
        baseline_copy = workspace / "baseline-project"
        container = runtime_probe(settings.validation_container_runtime)
        runtime = container if run_tests else None
        plan = sandbox.test_plan(change.ecosystem, project) if runtime else None
        if plan:
            shutil.copytree(project, baseline_copy, symlinks=True)

        # 2. Deterministic patch
        t = time.monotonic()
        manifests = [
            p.relative_to(repo).as_posix()
            for p in (
                *project.glob("requirements*.txt"),
                project / "pyproject.toml",
                project / "package.json",
                project / "package-lock.json",
                project / "npm-shrinkwrap.json",
                project / "uv.lock",
                project / "poetry.lock",
            )
            if p.is_file()
        ]
        original = patching.snapshot(repo, manifests)
        try:
            patch = patching.apply_change(
                repo,
                ecosystem=change.ecosystem,
                project_path=change.project_path,
                package=change.package,
                new_version=change.to_version,
                direct=target.directness == "direct",
                dev=target.scope == "dev",
            )
        except patching.PatchError as exc:
            steps.add("patch", "Apply the approved change", "failed", str(exc), t)
            return failed(str(exc))
        if not patch.edits and not patch.lockfiles:
            steps.add(
                "patch",
                "Apply the approved change",
                "failed",
                "No manifest in the component's project declares this package, and there is no "
                "lockfile to update",
                t,
            )
            return failed("The change could not be expressed in the project's manifests")
        detail = "; ".join(patch.edits) or "Manifest ranges already allow the version"
        if patch.unchanged:
            detail += " (unchanged: " + "; ".join(patch.unchanged) + ")"
        steps.add("patch", "Apply the approved change", "passed", detail, t)

        # 3. Lockfile resolution. If the lockfile decides the installed version and cannot be
        # updated, the change was never applied: stop instead of rescanning the old lock.
        t = time.monotonic()
        lock_failure: str | None = None
        if change.ecosystem == "npm" and patch.lockfiles:
            try:
                command = lock_regenerator(project, settings.validation_lock_timeout_seconds)
                steps.add(
                    "lockfile",
                    "Regenerate the lockfile",
                    "passed",
                    f"`{command}`: resolved from the public registry; no packages installed "
                    "and no scripts run",
                    t,
                )
            except sandbox.SandboxError as exc:
                lock_failure = str(exc)
        elif change.ecosystem == "pypi" and any(x.endswith("uv.lock") for x in patch.lockfiles):
            if not container:
                lock_failure = (
                    "uv.lock decides the installed version and can only be regenerated inside a "
                    "container; no Podman or Docker runtime is available"
                )
            else:
                try:
                    command = uv_lock_regenerator(
                        container,
                        project,
                        change.package,
                        change.to_version,
                        settings.validation_lock_timeout_seconds,
                    )
                    steps.add(
                        "lockfile",
                        "Regenerate the lockfile",
                        "passed",
                        f"`{command}`: resolved inside the container; only the new uv.lock "
                        "was copied back",
                        t,
                    )
                except sandbox.SandboxError as exc:
                    lock_failure = str(exc)
        elif patch.lockfiles:
            lock_failure = (
                f"{', '.join(patch.lockfiles)} decides the installed version and Kestral cannot "
                "regenerate this lockfile type"
            )
        else:
            steps.add(
                "lockfile",
                "Regenerate the lockfile",
                "skipped",
                "No lockfile in this project; the manifest pin is what installs",
                t,
            )
        if lock_failure:
            steps.add("lockfile", "Regenerate the lockfile", "failed", lock_failure, t)
            diffs = [FileDiff(**d) for d in patching.unified_diffs(repo, original)]
            for step_id, label in (
                ("tests", "Build and run project tests"),
                ("rescan", "Rescan the patched copy"),
            ):
                steps.add(step_id, label, "skipped", "Skipped: the change could not be applied", t)
            return failed(
                "The change could not be applied because the lockfile could not be updated; "
                "the fix was not tested"
            )
        diffs = [FileDiff(**d) for d in patching.unified_diffs(repo, original)]
        save_patch(repo, original, output / PATCH_DIR)

        # 4. Project tests in a container, before and after
        t = time.monotonic()
        if not run_tests:
            tests = [_not_run("patched", "Tests were not requested for this validation")]
            steps.add("tests", "Build and run project tests", "skipped", "Not requested", t)
        elif not runtime:
            reason = (
                "No container runtime (Podman or Docker) is available; Kestral never runs the "
                "scanned project's code on the host"
            )
            tests = [_not_run("patched", reason)]
            steps.add("tests", "Build and run project tests", "not_run", reason, t)
        elif plan is None:
            reason = "No install/test recipe for this project layout"
            tests = [_not_run("patched", reason)]
            steps.add("tests", "Build and run project tests", "not_run", reason, t)
        else:
            timeout = settings.validation_test_timeout_seconds
            for phase, directory in (("baseline", baseline_copy), ("patched", project)):
                outcome = test_runner(runtime, plan, directory, timeout)
                steps.add(
                    f"tests-{phase}",
                    f"{phase.capitalize()} build and tests",
                    "passed" if outcome["status"] == "passed" else "warning",
                    f"{outcome['status']}; {plan.description}",
                    t,
                )
                tests.append(
                    TestRun(
                        phase=phase,
                        runtime=runtime,
                        image=plan.image,
                        command=plan.description,
                        **outcome,
                    )
                )
            status, detail = compare.tests_outcome(tests)
            step_status = {"passed": "passed", "regression": "failed", "no_tests": "warning"}.get(
                status, "warning"
            )
            steps.add(
                "tests",
                "Build and run project tests",
                step_status,
                f"{detail} ({runtime}, {plan.image})",
                t,
            )

        # 5. Rescan the patched copy with the full pipeline
        t = time.monotonic()
        discover, generate, build_graph, analyze, nvd_client = pipeline()
        inventory = discover(repo, validation_id)
        document = generate(repo, inventory, validation_id, output)
        graph = build_graph(document, scan.repository_name)
        after = analyze(
            repo,
            inventory,
            document,
            validation_id,
            output,
            scan.repository_name,
            osv_enabled=settings.osv_enabled,
            grype_enabled=settings.grype_enabled,
            osv_timeout=settings.osv_timeout_seconds,
            grype_timeout=settings.grype_timeout_seconds,
            nvd_client=nvd_client(),
            nvd_budget=settings.nvd_budget_seconds,
            baseline=Baseline(
                scan_id=scan.scan_id,
                directory=_scan_dir(settings, scan),
                commit_sha=scan.commit_sha,
                resolved_ref=scan.resolved_ref,
                finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
            ),
            current_commit=f"{scan.commit_sha}+kestral-patch" if scan.commit_sha else None,
        )
        limit = settings.max_artifact_size_mb * 1024 * 1024
        for name, artifact in (
            ("inventory.json", inventory),
            ("normalized.json", document),
            ("graph.json", graph),
            ("findings.json", after),
        ):
            save_validated_json(output / name, artifact, max_bytes=limit)
        steps.add(
            "rescan",
            "Rescan the patched copy",
            "passed",
            "Discovery, SBOM and graph regenerated. Source coverage: "
            + ", ".join(f"{s.name}: {s.status}" for s in after.sources)
            + f"; {after.stats.vulnerabilities} vulnerabilities, "
            f"{after.stats.suspicious} suspicious",
            t,
        )

        # 6. Compare and decide
        t = time.monotonic()
        comparison = compare.compare_findings(before, before_doc, after, document, target)
        tests_status, tests_detail = compare.tests_outcome(tests)
        verdict, reason = compare.verdict(comparison, tests_status)
        steps.add(
            "compare",
            "Compare before and after",
            "passed" if verdict == "FIXED" else "warning" if verdict != "NOT_FIXED" else "failed",
            f"Target {'resolved' if comparison.target_resolved else 'still present'}; "
            f"{len(comparison.resolved)} resolved, {len(comparison.introduced)} introduced, "
            f"{len(comparison.introduced_suspicious)} new suspicious",
            t,
        )
        for ref in comparison.target_remaining:
            residual.append(f"Still present: {ref.title}")
        lock_step = next((x for x in steps.items if x.id == "lockfile"), None)
        if lock_step and "fresh lock" in lock_step.detail:
            others = [
                item
                for item in comparison.changed_packages
                if not item.lower().startswith(f"{change.package.lower()} ")
            ]
            if others:
                residual.append(
                    "The original lockfile was unreadable, so a fresh lock was resolved; it also "
                    f"changed {len(others)} other package(s): " + "; ".join(others[:6])
                )
        same_package = {target.subject_label.rsplit("@", 1)[0].lower()}
        after_projects = {c.component_id: c.project_path for c in document.components}
        for finding in after.findings:
            if (
                finding.kind == "vulnerability"
                and finding.subject_label.rsplit("@", 1)[0].lower() in same_package
                and after_projects.get(finding.subject_id or "") == change.project_path
                and finding.finding_id not in {r.finding_id for r in comparison.target_remaining}
            ):
                residual.append(f"Other advisory on {finding.subject_label}: {finding.title}")
        for ref in comparison.introduced:
            residual.append(f"Introduced: {ref.title} ({ref.package})")
        if tests_status in ("not_run", "no_tests", "error"):
            residual.append(f"Project tests: {tests_detail}")
        residual.append("Not reachability-checked: runtime use of the package was not analysed")
        return ValidationResult(
            verdict=verdict,
            verdict_reason=reason,
            tests_status=tests_status,
            tests_detail=tests_detail,
            sandbox_commit=scan.commit_sha,
            steps=steps.items,
            diffs=diffs,
            tests=tests,
            comparison=comparison,
            rescan_artifacts=f"{scan.scan_id}/validations/{validation_id}",
            residual_risks=list(dict.fromkeys(residual))[:40],
        )
    finally:
        def remove_readonly(function, path, error):
            if not isinstance(error, PermissionError):
                raise error
            os.chmod(path, stat.S_IWRITE)
            function(path)

        # Windows Git object files can be read-only. Never silently report success
        # when a disposable checkout could not actually be removed.
        workspace.relative_to(settings.workspace_root.resolve())
        shutil.rmtree(workspace, onexc=remove_readonly)


def _not_run(phase: str, reason: str) -> TestRun:
    return TestRun(
        phase=phase,
        status="not_run",
        runtime=None,
        image=None,
        command=None,
        exit_code=None,
        duration_s=None,
        output_tail=reason,
    )


def run_validation(
    session_factory: Callable[[], Session],
    settings: Settings,
    validation_id: str,
    *,
    release: Callable[[], None] | None = None,
    **overrides,
) -> None:
    try:
        with session_factory() as db:
            row = db.get(ValidationRunRow, validation_id)
            if row is None:
                return
            scan = db.get(Scan, row.scan_id)
            row.status = "running"
            db.commit()
            try:
                change = resolve_change(db, settings, scan, row.source_type, row.source_id)
                if change.model_dump(mode="json") != row.change_json:
                    raise ValidationError("APPROVAL_CHANGED", "Approval changed after queuing")
                result = execute(settings, scan, change, validation_id, row.run_tests, **overrides)
                row.result_json = result.model_dump(mode="json")
                row.verdict = result.verdict
                row.status = "completed"
            except Exception as exc:  # noqa: BLE001 - recorded, never raised to the API
                logger.exception("validation failed: %s", validation_id)
                row.status = "failed"
                row.error_message = f"Validation failed: {type(exc).__name__}: {str(exc)[:300]}"
            row.finished_at = datetime.now(UTC)
            db.commit()
    finally:
        if release:
            release()

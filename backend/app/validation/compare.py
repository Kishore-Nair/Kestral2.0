"""Compare findings before and after a sandbox fix, and decide a verdict."""

from app.schemas.dependency import DependencyDocument
from app.schemas.findings import Finding, FindingsDocument
from app.schemas.validation import Comparison, FindingRef, TestRun

HIGH_BANDS = {"critical", "high"}
# Notes produced by comparing with the previous scan; a validation expects these.
CHANGE_NOTES = {"new_dependency", "unexpected_dependency", "version_downgrade", "lockfile_drift"}


def _project_of(document: DependencyDocument, finding: Finding) -> str | None:
    component = next((c for c in document.components if c.component_id == finding.subject_id), None)
    return component.project_path if component else None


def _package(finding: Finding) -> str:
    return finding.subject_label.rsplit("@", 1)[0].lower()


def _level(finding: Finding) -> str | None:
    if finding.priority:
        return finding.priority.band
    return finding.risk_level


def _ref(finding: Finding) -> FindingRef:
    return FindingRef(
        finding_id=finding.finding_id,
        kind=finding.kind,
        title=finding.title,
        package=finding.subject_label,
        advisory_ids=finding.advisory_ids,
        level=_level(finding),
    )


def _vuln_key(document: DependencyDocument, finding: Finding) -> tuple[str, str | None]:
    return (_package(finding), _project_of(document, finding))


def _same_vulnerability(
    a: Finding, a_doc: DependencyDocument, b: Finding, b_doc: DependencyDocument
) -> bool:
    return _vuln_key(a_doc, a) == _vuln_key(b_doc, b) and bool(
        set(a.advisory_ids) & set(b.advisory_ids)
    )


def counts(doc: FindingsDocument) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "suspicious": 0, "workflow_pins": 0}
    for finding in doc.findings:
        if finding.kind == "vulnerability" and finding.priority:
            out[finding.priority.band] += 1
        elif finding.kind == "suspicious" and finding.category not in CHANGE_NOTES:
            out["suspicious"] += 1
        elif finding.kind == "workflow_pin":
            out["workflow_pins"] += 1
    return out


def compare_findings(
    before: FindingsDocument,
    before_doc: DependencyDocument,
    after: FindingsDocument,
    after_doc: DependencyDocument,
    target: Finding,
) -> Comparison:
    before_v = [f for f in before.findings if f.kind == "vulnerability"]
    after_v = [f for f in after.findings if f.kind == "vulnerability"]
    before_projects = {c.component_id: c.project_path for c in before_doc.components}
    after_projects = {c.component_id: c.project_path for c in after_doc.components}

    def key(finding, projects):
        return (_package(finding), projects.get(finding.subject_id))

    def index(findings, projects):
        result = {}
        for finding in findings:
            result.setdefault(key(finding, projects), set()).update(finding.advisory_ids)
        return result

    before_ids = index(before_v, before_projects)
    after_ids = index(after_v, after_projects)
    remaining = [
        f
        for f in after_v
        if key(f, after_projects) == key(target, before_projects)
        and set(f.advisory_ids) & set(target.advisory_ids)
    ]
    resolved = [
        f
        for f in before_v
        if not set(f.advisory_ids) & after_ids.get(key(f, before_projects), set())
    ]
    introduced = [
        g
        for g in after_v
        if not set(g.advisory_ids) & before_ids.get(key(g, after_projects), set())
    ]
    before_s = {(f.category, f.subject_label) for f in before.findings if f.kind == "suspicious"}
    introduced_s = [
        f
        for f in after.findings
        if f.kind == "suspicious"
        and (f.category, f.subject_label) not in before_s
        and f.category not in CHANGE_NOTES
    ]
    changes = after.changes
    package_changes = dict(changes.totals) if changes else {}
    changed = []
    if changes:
        for item in (*changes.upgraded, *changes.downgraded, *changes.added, *changes.removed)[:40]:
            before_v_text = ",".join(item.from_versions) or "∅"
            after_v_text = ",".join(item.to_versions) or "∅"
            changed.append(
                f"{item.name} ({item.project_path or '.'}): {before_v_text} → {after_v_text}"
            )
    required_sources = {s.name for s in target.sources if s.name in {"OSV", "Grype"}}
    completed_sources = {s.name for s in after.sources if s.status == "ok"}
    target_components = [
        c
        for c in after_doc.components
        if c.name.lower() == _package(target) and c.project_path == _project_of(before_doc, target)
    ]
    target_kind_ok = (
        target.kind == "vulnerability"
        and bool(required_sources)
        and required_sources <= completed_sources
        and bool(target_components)
        and all(c.resolved and c.version and c.purl for c in target_components)
    )
    # A missing scanner or partial query is not evidence of vulnerability removal.
    if not target_kind_ok:
        resolved = []
    return Comparison(
        target_resolved=(not remaining) if target_kind_ok else None,
        target_remaining=[_ref(f) for f in remaining],
        resolved=[_ref(f) for f in resolved],
        introduced=[_ref(f) for f in introduced],
        introduced_suspicious=[_ref(f) for f in introduced_s],
        before_counts=counts(before),
        after_counts=counts(after),
        package_changes=package_changes,
        changed_packages=changed,
    )


def tests_outcome(runs: list[TestRun]) -> tuple[str, str]:
    by_phase = {r.phase: r for r in runs}
    patched, baseline = by_phase.get("patched"), by_phase.get("baseline")
    if patched is None or patched.status == "not_run":
        reason = patched.output_tail if patched else "Tests were not requested"
        return "not_run", reason
    if patched.status == "no_tests":
        return "no_tests", "No test suite was found for the changed project"
    if patched.status == "error":
        return "error", "Dependencies could not be installed or the test command failed to start"
    if patched.status == "passed":
        return "passed", "The project's tests pass in the container after the change"
    if baseline is not None and baseline.status == "failed":
        return (
            "failed_before_and_after",
            "Tests fail both before and after the change (pre-existing failures)",
        )
    return "regression", "Tests passed before the change and fail after it"


def verdict(comparison: Comparison, tests_status: str) -> tuple[str, str]:
    if comparison.target_resolved is None:
        return "FAILED", "Target remediation could not be established by comparison"
    if comparison.target_resolved is False:
        return "NOT_FIXED", "The rescan still reports the original vulnerability"
    new_high = [r for r in comparison.introduced if r.level in HIGH_BANDS]
    new_high_s = [r for r in comparison.introduced_suspicious if r.level == "high"]
    if new_high or new_high_s:
        names = ", ".join(sorted({r.package for r in [*new_high, *new_high_s]}))
        return "FIXED_WITH_NEW_RISK", f"Target fixed, but the change introduced high risk: {names}"
    if tests_status == "regression":
        return "FIXED_TESTS_FAILED", "Target fixed, but the project's tests regressed"
    resolved = "The rescan no longer reports the original vulnerability"
    if tests_status == "passed":
        return "FIXED", f"{resolved}; the project's tests pass in the container"
    detail = tests_status.replace("_", " ")
    return "FAILED", f"{resolved}; validation incomplete: project tests {detail}"

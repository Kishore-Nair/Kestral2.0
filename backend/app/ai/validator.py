"""Deterministic checks on an AI draft before it is shown. The model cannot change the outcome.

Checks identity, evidence references, claim support, fixed-version verification against
saved OSV records, manifest ranges, and dependency paths against ``graph.json``.
"""

from dataclasses import dataclass

import networkx as nx

from app.ai import versions
from app.ai.bundle import EvidenceStore, ScanBundle
from app.ai.tools import check_version
from app.schemas.ai import (
    AiDraft,
    Claim,
    Compatibility,
    Remediation,
    ValidationCheck,
    ValidationResult,
)
from app.schemas.findings import Finding

POST_CHANGE_NOTE = "No change has been applied; lockfile resolution, tests and rescan have not run"


@dataclass
class Validated:
    remediation: Remediation
    compatibility: Compatibility
    claims: list[Claim]
    result: ValidationResult
    status_note: str | None


def _at_or_after(ecosystem: str, candidate: str, fixed: str) -> bool:
    c = versions.compare(ecosystem, candidate, fixed)
    return c is not None and c >= 0


def _path_in_graph_json(bundle: ScanBundle, node_ids: list[str]) -> bool:
    return all(bundle.has_edge(a, b) for a, b in zip(node_ids, node_ids[1:], strict=False))


def validate(
    bundle: ScanBundle, finding: Finding, draft: AiDraft, store: EvidenceStore
) -> Validated:
    checks: list[ValidationCheck] = []
    blocking: list[str] = []
    warnings: list[str] = [POST_CHANGE_NOTE]
    known = store.ids()

    def add(check_id: str, status: str, detail: str) -> None:
        checks.append(ValidationCheck(id=check_id, status=status, detail=detail))
        if status == "failed":
            blocking.append(detail)

    # Identity ---------------------------------------------------------------
    same = (
        bundle.finding(finding.finding_id) is finding
        or bundle.finding(finding.finding_id) == finding
    )
    add(
        "finding_identity",
        "passed" if same and bundle.findings.scan_id == bundle.scan_id else "failed",
        f"Finding {finding.finding_id} belongs to scan {bundle.scan_id}",
    )

    # Evidence references ------------------------------------------------------
    rem = draft.recommended_remediation
    cited = {*rem.evidence_refs, *(r for c in draft.claims for r in c.evidence_refs)}
    unknown = sorted(cited - known)
    add(
        "evidence_references",
        "failed" if unknown else "passed",
        f"Unknown evidence IDs cited: {', '.join(unknown)}"
        if unknown
        else f"All {len(cited)} cited evidence IDs exist",
    )

    claims: list[Claim] = []
    downgraded = 0
    for claim in draft.claims:
        refs = claim.evidence_refs
        if any(r not in known for r in refs):
            status = "rejected"
        elif claim.kind == "verified_fact" and refs:
            status = "verified"
        else:
            status = "unverified"
            downgraded += claim.kind == "verified_fact"
        claims.append(Claim(**claim.model_dump(), verification_status=status))
    add(
        "claim_support",
        "warning" if downgraded else "passed",
        f"{downgraded} claim(s) stated as fact without evidence were marked unverified"
        if downgraded
        else "Every claim stated as fact cites existing evidence",
    )

    # Paths cited through evidence must exist in graph.json, in dependency direction ----------
    bad_paths = []
    for evidence_id in cited & known:
        item = store.get(evidence_id)
        if item and item.kind == "dependency-path":
            key = store.key(evidence_id) or ""
            node_ids = key.removeprefix("path:").split(">")
            if not _path_in_graph_json(bundle, node_ids):
                bad_paths.append(evidence_id)
    add(
        "graph_paths",
        "failed" if bad_paths else "passed",
        f"Cited paths not found in graph.json: {', '.join(bad_paths)}"
        if bad_paths
        else "Cited dependency paths exist in graph.json (from_id depends on to_id)",
    )

    # Target component ------------------------------------------------------------
    subject = bundle.component(finding.subject_id or "")
    target = bundle.component(rem.target_component_id) if rem.target_component_id else None
    if rem.target_component_id and target is None:
        add(
            "target_component",
            "failed",
            f"Target component {rem.target_component_id} is not in this scan",
        )
    elif target is not None and subject is not None and target.component_id != subject.component_id:
        graph = bundle.graph
        reaches = (
            target.component_id in graph
            and subject.component_id in graph
            and nx.has_path(graph, target.component_id, subject.component_id)
        )
        add(
            "target_component",
            "passed"
            if reaches and rem.type in ("upgrade_parent", "override", "replace", "remove")
            else "failed",
            f"{target.name} "
            + ("depends (directly or transitively) on " if reaches else "does not depend on ")
            + subject.name,
        )
    else:
        add(
            "target_component",
            "passed",
            "Remediation targets the finding's own component"
            if target
            else "No component targeted",
        )

    # Version checks --------------------------------------------------------------
    fixed_verified = False
    source = url = None
    manifest_status, manifest_detail = "not_checked", "No candidate version proposed"
    component = target or subject
    if rem.target_version and component is None:
        add("candidate_version", "failed", "A version was proposed but no component is identified")
    elif rem.target_version and component is not None:
        facts = check_version(bundle, finding, component, rem.target_version)
        if facts["valid"] is False:
            add(
                "candidate_version",
                "failed",
                f"{rem.target_version} is not a valid {component.ecosystem} version",
            )
        elif facts["valid"] is None:
            add(
                "candidate_version",
                "not_run",
                f"No version rules for ecosystem {component.ecosystem}",
            )
        else:
            add(
                "candidate_version",
                "passed",
                f"{rem.target_version} parses as a {component.ecosystem} version",
            )
            if facts["newer_than_installed"] is False:
                add(
                    "not_a_downgrade",
                    "warning",
                    f"{rem.target_version} is not newer than installed {component.version}",
                )

        relevant = finding.kind == "vulnerability" and component is subject
        advisories = facts["advisories"] if relevant else []
        affected = [a for a in advisories if a["candidate_affected"] is True]
        undecided = [a for a in advisories if a["candidate_affected"] is None]
        if not relevant:
            add(
                "fixed_version_verified",
                "not_run",
                "Fixed-version verification applies to the vulnerable package itself",
            )
        elif affected:
            add(
                "fixed_version_verified",
                "failed",
                f"{rem.target_version} is still inside the affected range of "
                + ", ".join(a["advisory"] for a in affected),
            )
        elif not advisories or undecided:
            add(
                "fixed_version_verified",
                "not_run",
                "No saved OSV record could decide whether this version is affected",
            )
        else:
            listed = {v for a in advisories for v in a["fixed_versions"]} | set(
                finding.fixed_versions
            )
            at_or_after_fix = any(
                _at_or_after(component.ecosystem, rem.target_version, v) for v in listed
            )
            fixed_verified = at_or_after_fix
            ids = [a["advisory"] for a in advisories]
            source = "OSV " + ", ".join(ids)
            url = f"https://osv.dev/vulnerability/{ids[0]}"
            add(
                "fixed_version_verified",
                "passed" if fixed_verified else "warning",
                f"{rem.target_version} is outside the affected ranges of {', '.join(ids)}"
                + ("" if fixed_verified else " but is not at or after a listed fixed version"),
            )

        ranges = facts["manifest_ranges"]
        if not ranges:
            manifest_status, manifest_detail = (
                "not_checked",
                "No manifest declaration recorded for this package",
            )
            add("manifest_constraint", "not_run", manifest_detail)
        elif any(m["accepts"] is False for m in ranges):
            rejected = [f"{m['manifest']} {m['range']!r}" for m in ranges if m["accepts"] is False]
            manifest_status = "rejects"
            manifest_detail = f"Declared range must change: {', '.join(rejected)}"
            add("manifest_constraint", "warning", manifest_detail)
        elif all(m["accepts"] is True for m in ranges):
            manifest_status = "accepts"
            manifest_detail = (
                ", ".join(f"{m['manifest']} {m['range']!r}" for m in ranges) + " accepts it"
            )
            add("manifest_constraint", "passed", manifest_detail)
        else:
            manifest_detail = "Declared range could not be evaluated"
            add("manifest_constraint", "not_run", manifest_detail)
    else:
        add("fixed_version_verified", "not_run", "No candidate version proposed")

    add(
        "lockfile_resolution_after_change",
        "not_run",
        "Requires an approved change and lockfile regeneration",
    )
    add("tests", "not_run", "Kestral does not build or run the scanned project")

    status_note = None
    if draft.status == "recommendation_ready" and rem.type == "upgrade" and not fixed_verified:
        status_note = "Upgrade target is not a verified fixed version; needs human review"
        warnings.append(status_note)

    overall = (
        "failed"
        if blocking
        else ("partial" if any(c.status in ("not_run", "warning") for c in checks) else "passed")
    )
    return Validated(
        remediation=Remediation(
            **rem.model_dump(),
            fixed_version_verified=fixed_verified,
            version_source=source,
            version_source_url=url,
        ),
        compatibility=Compatibility(
            **draft.compatibility.model_dump(),
            manifest_status=manifest_status,
            manifest_detail=manifest_detail,
        ),
        claims=claims,
        result=ValidationResult(
            status=overall, checks=checks, blocking_issues=blocking, warnings=warnings
        ),
        status_note=status_note,
    )

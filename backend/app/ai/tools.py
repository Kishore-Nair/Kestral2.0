"""Registered read-only tools the AI analyst may call.

Rules enforced here, independent of any prompt:
- Tools take stable IDs only, never file paths or URLs. Every ID must belong to the
  selected scan, and advisory/finding IDs to the selected finding.
- Only two tools reach the network (OSV and the package registry), at fixed hosts,
  with a timeout and a response-size cap.
- Nothing here writes, executes or installs anything.
"""

import json
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.ai import versions
from app.ai.bundle import EvidenceStore, ScanBundle, clip
from app.graph.impact import package_impact
from app.risk.osv import OsvError, query_osv
from app.risk.targets import canonical_purl
from app.schemas.findings import Finding

MAX_RESULT_CHARS = 12_000
MAX_HTTP_BYTES = 20 * 1024 * 1024
USER_AGENT = "kestral-ai-analyst"
ALLOWED_HOSTS = {"registry.npmjs.org", "pypi.org", "api.osv.dev"}

FetchJson = Callable[[str, dict[str, str], int], Any]


class ToolInputError(ValueError):
    """Arguments failed validation; the message is shown to the model."""


def fetch_json(url: str, headers: dict[str, str], timeout: int) -> Any:
    host = urllib.parse.urlsplit(url).hostname
    if host not in ALLOWED_HOSTS or not url.startswith("https://"):
        raise ToolInputError("Host not allowed")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - allowlisted
        body = response.read(MAX_HTTP_BYTES + 1)
    if len(body) > MAX_HTTP_BYTES:
        raise ToolInputError("Response too large")
    return json.loads(body)


@dataclass
class ToolContext:
    bundle: ScanBundle
    finding: Finding
    store: EvidenceStore
    external_timeout: int = 15
    fetch: FetchJson = fetch_json
    osv_query: Callable[..., Any] = query_osv
    metadata: dict[str, dict] = field(default_factory=dict)


@dataclass
class ToolOutcome:
    result: dict
    evidence_ids: list[str]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    properties: dict[str, dict]
    handler: Callable[[ToolContext, dict], ToolOutcome]
    external: bool = False

    def schema(self) -> dict:
        """Provider-neutral spec; each provider adapter converts it to its wire format."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.properties,
                "required": list(self.properties),
                "additionalProperties": False,
            },
        }


ID = {"type": "string", "maxLength": 200}


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


def _component(ctx: ToolContext, args: dict):
    component_id = args.get("component_id")
    component = ctx.bundle.component(component_id) if isinstance(component_id, str) else None
    if component is None:
        raise ToolInputError("Unknown component_id for this scan")
    return component


def _own_finding(ctx: ToolContext, args: dict) -> Finding:
    if args.get("finding_id") != ctx.finding.finding_id:
        raise ToolInputError("Only the selected finding can be read")
    return ctx.finding


def _finding_advisories(finding: Finding) -> set[str]:
    return {*finding.advisory_ids, *(c.id for c in finding.cves)}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _scan_status(ctx: ToolContext, _args: dict) -> ToolOutcome:
    doc = ctx.bundle.findings
    runs = [
        {"source": r.name, "status": r.status, "message": r.message, "retrieved_at": r.retrieved_at}
        for r in doc.sources
    ]
    result = {
        "scan_id": ctx.bundle.scan_id,
        "commit_sha": ctx.bundle.commit_sha,
        "repository": ctx.bundle.repository_url,
        "partial": doc.partial,
        "sources": runs,
        "warnings": [clip(w, 200) for w in doc.warnings[:10]],
        "stats": doc.stats.model_dump(),
    }
    summary = f"Scan {ctx.bundle.scan_id} partial={doc.partial}; sources: " + ", ".join(
        f"{r['source']}={r['status']}" for r in runs
    )
    return ToolOutcome(
        result, [ctx.store.add("scan-status", "scan-status", "findings.json", summary)]
    )


def finding_summary(finding: Finding) -> dict:
    return {
        "finding_id": finding.finding_id,
        "kind": finding.kind,
        "category": finding.category,
        "title": clip(finding.title, 300),
        "subject_id": finding.subject_id,
        "subject_label": finding.subject_label,
        "advisory_ids": finding.advisory_ids,
        "sources": [
            {"name": s.name, "record_id": s.record_id, "severity": s.severity}
            for s in finding.sources
        ],
        "fixed_versions": finding.fixed_versions,
        "scope": finding.scope,
        "directness": finding.directness,
        "cvss": finding.cvss.model_dump(
            include={"version", "vector", "base_score", "severity", "source"}
        )
        if finding.cvss
        else None,
        "epss": finding.epss.model_dump(include={"probability", "percentile"})
        if finding.epss
        else None,
        "priority": {"score": finding.priority.score, "band": finding.priority.band}
        if finding.priority
        else None,
        "risk_level": finding.risk_level,
        "risk_reason": finding.risk_reason,
        "cwes": [c.id for c in finding.cwes],
        "uncertainty": finding.uncertainty,
    }


def _get_finding(ctx: ToolContext, args: dict) -> ToolOutcome:
    finding = _own_finding(ctx, args)
    ids = [
        ctx.store.add(
            f"finding-evidence:{i}",
            e.kind,
            e.path,
            f"{e.path} · {e.locator}",
        )
        for i, e in enumerate(finding.evidence)
    ]
    return ToolOutcome({"finding": finding_summary(finding), "evidence_ids": ids}, ids)


def _get_component(ctx: ToolContext, args: dict) -> ToolOutcome:
    c = _component(ctx, args)
    result = {
        "component_id": c.component_id,
        "name": c.name,
        "version": c.version,
        "ecosystem": c.ecosystem,
        "purl": c.purl,
        "scope": c.scope,
        "project_path": c.project_path,
        "install_path": c.install_path,
        "resolved": c.resolved,
    }
    summary = f"Component {c.name}@{c.version} ({c.ecosystem}), scope {c.scope}, purl {c.purl}"
    return ToolOutcome(
        result,
        [ctx.store.add(f"component:{c.component_id}", "component", "normalized.json", summary)],
    )


def _component_evidence(ctx: ToolContext, args: dict) -> ToolOutcome:
    c = _component(ctx, args)
    ids, records = [], []
    for e in c.evidence[:10]:
        ids.append(
            ctx.store.add(
                f"cev:{c.component_id}:{e.path}:{e.locator}",
                e.kind,
                e.path,
                f"{e.path} · {e.locator}",
            )
        )
        records.append({"path": e.path, "kind": e.kind, "locator": e.locator})
    declared = ctx.bundle.declared_ranges(c)
    for path, section, spec in declared:
        ids.append(
            ctx.store.add(
                f"decl:{path}:{section}:{c.name}",
                "manifest-declaration",
                path,
                f"{path} [{section}] declares {c.name} {spec!r}",
            )
        )
    return ToolOutcome(
        {
            "evidence": records,
            "declared_ranges": [{"manifest": p, "section": s, "range": r} for p, s, r in declared],
            "declarations_recorded": bool((ctx.bundle.snapshot or {}).get("declarations")),
        },
        ids,
    )


def _dependency_paths(ctx: ToolContext, args: dict) -> ToolOutcome:
    c = _component(ctx, args)
    graph = ctx.bundle.graph
    if c.component_id not in graph:
        return ToolOutcome({"paths": [], "directness": "unknown"}, [])
    impact = package_impact(graph, c.component_id, limit=5)
    label = lambda n: str(graph.nodes[n].get("label") or n)  # noqa: E731
    ids = []
    paths = []
    for path in impact.paths:
        text = " → ".join(label(n) for n in path)
        ids.append(
            ctx.store.add(
                f"path:{'>'.join(path)}",
                "dependency-path",
                "graph.json",
                f"Dependency path: {text}",
            )
        )
        paths.append({"node_ids": path, "labels": [label(n) for n in path]})
    return ToolOutcome(
        {
            "direction": "each node depends on the next",
            "directness": impact.directness,
            "paths": paths,
            "affected_projects": impact.affected_projects,
            "dependent_packages": impact.dependent_packages,
        },
        ids,
    )


def _reverse_dependencies(ctx: ToolContext, args: dict) -> ToolOutcome:
    c = _component(ctx, args)
    graph = ctx.bundle.graph
    if c.component_id not in graph:
        return ToolOutcome({"dependents": [], "total": 0}, [])
    parents = sorted(
        p
        for p in graph.predecessors(c.component_id)
        if graph.edges[p, c.component_id].get("type") == "DEPENDS_ON"
    )
    listed = [{"node_id": p, "label": graph.nodes[p].get("label")} for p in parents[:25]]
    summary = f"{c.name} is required directly by: " + ", ".join(str(x["label"]) for x in listed)
    return ToolOutcome(
        {"dependents": listed, "total": len(parents)},
        [ctx.store.add(f"rdeps:{c.component_id}", "reverse-dependencies", "graph.json", summary)],
    )


def _advisory_view(record: dict, component) -> dict:
    eco, name = (component.ecosystem, component.name) if component else (None, None)
    affected = []
    for a in record.get("affected") or []:
        package = a.get("package") or {}
        if name and str(package.get("name", "")).lower() != name.lower():
            continue
        affected.append(
            {
                "package": package,
                "ranges": a.get("ranges"),
                "versions": (a.get("versions") or [])[:20],
            }
        )
    return {
        "id": record.get("id"),
        "aliases": record.get("aliases"),
        "summary": clip(str(record.get("summary") or ""), 300),
        "details": clip(str(record.get("details") or ""), 1500),
        "affected": affected[:5],
        "fixed_versions": versions.osv_fixed_versions(record, eco, name) if eco else [],
        "references": [r.get("url") for r in (record.get("references") or [])[:5]],
        "published": record.get("published"),
        "modified": record.get("modified"),
    }


def _get_advisory(ctx: ToolContext, args: dict) -> ToolOutcome:
    advisory_id = args.get("advisory_id")
    if advisory_id not in _finding_advisories(ctx.finding):
        raise ToolInputError("advisory_id must be one of the selected finding's advisory IDs")
    component = ctx.bundle.component(ctx.finding.subject_id or "")
    result: dict[str, Any] = {}
    ids = []
    record = ctx.bundle.osv_record(advisory_id)
    if record:
        view = _advisory_view(record, component)
        result["osv"] = view
        fixed = ", ".join(view["fixed_versions"]) or "none listed"
        ids.append(
            ctx.store.add(
                f"osv:{record.get('id')}",
                "advisory",
                f"OSV {record.get('id')} (osv.json)",
                f"OSV {record.get('id')}: {view['summary']} "
                f"Fixed versions for this package: {fixed}",
            )
        )
    if str(advisory_id).startswith("CVE-"):
        cve = ctx.bundle.nvd_record(advisory_id)
        if cve:
            text = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
            )
            result["nvd"] = {
                "id": advisory_id,
                "status": cve.get("vulnStatus"),
                "description": clip(text, 1500),
            }
            ids.append(
                ctx.store.add(
                    f"nvd:{advisory_id}",
                    "advisory",
                    f"NVD {advisory_id} (nvd.json)",
                    f"NVD {advisory_id}: {text}",
                )
            )
    if not result:
        result["note"] = "No saved advisory record for this ID in the scan"
    return ToolOutcome(result, ids)


def _lookup_advisory(ctx: ToolContext, args: dict) -> ToolOutcome:
    c = _component(ctx, args)
    purl = canonical_purl(c.purl) if c.purl else None
    if not purl:
        raise ToolInputError("Component has no exact package URL to look up")
    try:
        result = ctx.osv_query([purl], timeout=ctx.external_timeout)
    except OsvError as exc:
        return ToolOutcome({"error": str(exc)}, [])
    ids_found = sorted(result.matches.get(purl, []))
    fixed = {
        advisory: versions.osv_fixed_versions(result.records.get(advisory, {}), c.ecosystem, c.name)
        for advisory in ids_found
    }
    summary = f"Live OSV lookup for {purl}: {len(ids_found)} advisories " + "; ".join(
        f"{a} fixed in {', '.join(v) or 'none listed'}" for a, v in fixed.items()
    )
    return ToolOutcome(
        {"purl": purl, "retrieved_at": result.retrieved_at, "advisories": fixed},
        [
            ctx.store.add(
                f"osv-live:{purl}", "advisory-lookup", "api.osv.dev (live)", summary, external=True
            )
        ],
    )


def _package_metadata(ctx: ToolContext, args: dict) -> ToolOutcome:
    c = _component(ctx, args)
    timeout = ctx.external_timeout
    if c.ecosystem == "npm":
        url = "https://registry.npmjs.org/" + urllib.parse.quote(c.name, safe="@")
        data = ctx.fetch(url, {"Accept": "application/vnd.npm.install-v1+json"}, timeout)
        all_versions = list((data.get("versions") or {}).keys())
        latest = (data.get("dist-tags") or {}).get("latest")
        deprecated = {
            v: clip(str(meta.get("deprecated")), 200)
            for v, meta in (data.get("versions") or {}).items()
            if isinstance(meta, dict) and meta.get("deprecated")
        }
        source = "registry.npmjs.org"
    elif c.ecosystem == "pypi":
        url = f"https://pypi.org/pypi/{urllib.parse.quote(c.name)}/json"
        data = ctx.fetch(url, {"Accept": "application/json"}, timeout)
        releases = data.get("releases") or {}
        all_versions = list(releases.keys())
        latest = (data.get("info") or {}).get("version")
        deprecated = {
            v: "yanked: " + clip(str(files[0].get("yanked_reason") or ""), 150)
            for v, files in releases.items()
            if files and all(f.get("yanked") for f in files)
        }
        source = "pypi.org"
    else:
        raise ToolInputError(f"No package registry adapter for ecosystem {c.ecosystem!r}")
    ordered = versions.sort_versions(c.ecosystem, all_versions)
    newer = [
        v for v in ordered if c.version and (versions.compare(c.ecosystem, v, c.version) or 0) > 0
    ]
    ctx.metadata[c.component_id] = {"versions": set(all_versions)}
    result = {
        "package": c.name,
        "installed": c.version,
        "latest": latest,
        "versions_total": len(all_versions),
        "newer_versions": newer[-30:],
        "newer_versions_total": len(newer),
        "installed_deprecated_or_yanked": deprecated.get(c.version or ""),
        "deprecated_or_yanked_newer": {v: deprecated[v] for v in newer if v in deprecated},
    }
    summary = f"{source}: {c.name} latest {latest}; {len(newer)} versions newer than {c.version}"
    return ToolOutcome(
        result,
        [
            ctx.store.add(
                f"meta:{c.component_id}",
                "package-metadata",
                f"{source} (live)",
                summary,
                external=True,
            )
        ],
    )


def check_version(bundle: ScanBundle, finding: Finding, component, version: str) -> dict:
    """Deterministic facts about a candidate version (shared with the validator)."""
    eco = component.ecosystem
    valid = versions.valid(eco, version)
    advisories = []
    seen: set[str] = set()
    for advisory in sorted(_finding_advisories(finding)):
        record = bundle.osv_record(advisory)
        if record is None or record.get("id") in seen:
            continue
        seen.add(record.get("id"))
        advisories.append(
            {
                "advisory": record.get("id"),
                "candidate_affected": versions.osv_affected(record, eco, component.name, version),
                "installed_affected": versions.osv_affected(
                    record, eco, component.name, component.version or ""
                ),
                "fixed_versions": versions.osv_fixed_versions(record, eco, component.name),
            }
        )
    manifests = [
        {
            "manifest": path,
            "section": section,
            "range": spec,
            "accepts": versions.satisfies(eco, spec, version),
        }
        for path, section, spec in bundle.declared_ranges(component)
    ]
    newer = versions.compare(eco, version, component.version) if component.version else None
    return {
        "component_id": component.component_id,
        "ecosystem": eco,
        "installed": component.version,
        "candidate": version,
        "valid": valid,
        "newer_than_installed": None if newer is None else newer > 0,
        "listed_as_fixed_by_finding": version in finding.fixed_versions,
        "advisories": advisories,
        "manifest_ranges": manifests,
    }


def _check_candidate(ctx: ToolContext, args: dict) -> ToolOutcome:
    c = _component(ctx, args)
    version = args.get("version")
    if not isinstance(version, str) or not version or len(version) > 100:
        raise ToolInputError("version must be a short string")
    facts = check_version(ctx.bundle, ctx.finding, c, version)
    known = ctx.metadata.get(c.component_id)
    facts["published_in_registry"] = (version in known["versions"]) if known else None
    affected = [a["candidate_affected"] for a in facts["advisories"]]
    manifest = [m["accepts"] for m in facts["manifest_ranges"]]
    summary = (
        f"Version check {c.name} {version}: valid={facts['valid']}, "
        f"affected by advisories={affected or 'no saved OSV record'}, "
        f"manifest accepts={manifest or 'no recorded declaration'}"
    )
    return ToolOutcome(
        facts,
        [
            ctx.store.add(
                f"check:{c.component_id}:{version}",
                "version-check",
                "Kestral version logic",
                summary,
            )
        ],
    )


def _change_evidence(ctx: ToolContext, args: dict) -> ToolOutcome:
    finding = _own_finding(ctx, args)
    changes = ctx.bundle.changes
    ids = [
        ctx.store.add(f"finding-evidence:{i}", e.kind, e.path, f"{e.path} · {e.locator}")
        for i, e in enumerate(finding.evidence)
    ]
    if not changes:
        return ToolOutcome({"comparison": None, "note": "No earlier scan was compared"}, ids)
    result = {
        "baseline_scan_id": changes.get("baseline_scan_id"),
        "baseline_commit": changes.get("baseline_commit"),
        "current_commit": changes.get("current_commit"),
        "totals": changes.get("totals"),
        "files_changed": (changes.get("files_changed") or [])[:30],
        "caveats": changes.get("caveats") or [],
        "comparison_is_real_history": True,
    }
    ids.append(
        ctx.store.add(
            "changes",
            "scan-diff",
            "changes.json",
            f"Compared with {result['baseline_scan_id']} ({str(result['baseline_commit'])[:12]}): "
            f"{result['totals']}; files changed: "
            + ", ".join(f"{f['path']} ({f['change']})" for f in result["files_changed"][:10]),
        )
    )
    return ToolOutcome(result, ids)


POLICY = {
    "allowed_strategies": [
        "upgrade",
        "upgrade_parent",
        "override",
        "remove",
        "replace",
        "config_mitigation",
        "pin_source",
        "compensating_control",
        "manual_review",
    ],
    "rules": [
        "A fixed version must come from a trusted advisory; otherwise say no verified fix.",
        "Never hand-edit lockfiles; regenerate them with the package manager after approval.",
        "Never invent commit SHAs or image digests; tell the user how to obtain them.",
        "Removal needs evidence or user confirmation that the package is unused.",
        "Every change needs human approval; nothing is applied automatically.",
        "Kestral does not install, build or run the scanned project.",
    ],
}


def _project_policy(ctx: ToolContext, _args: dict) -> ToolOutcome:
    return ToolOutcome(
        POLICY,
        [
            ctx.store.add(
                "policy", "policy", "Kestral remediation policy", "; ".join(POLICY["rules"])
            )
        ],
    )


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in [
        Tool(
            "get_scan_status",
            "Scan identity, which sources ran or failed, coverage and warnings.",
            {},
            _scan_status,
        ),
        Tool(
            "get_finding",
            "The selected finding as recorded by the scanners, with its evidence.",
            {"finding_id": ID},
            _get_finding,
        ),
        Tool(
            "get_component",
            "One package from this scan's normalized inventory.",
            {"component_id": ID},
            _get_component,
        ),
        Tool(
            "get_component_evidence",
            "Lockfile/SBOM evidence for a package and the version ranges its manifests declare.",
            {"component_id": ID},
            _component_evidence,
        ),
        Tool(
            "get_dependency_paths",
            "Verified paths from each project to the package (each node depends on the next).",
            {"component_id": ID},
            _dependency_paths,
        ),
        Tool(
            "get_reverse_dependencies",
            "Packages that directly require this package (max 25).",
            {"component_id": ID},
            _reverse_dependencies,
        ),
        Tool(
            "get_advisory",
            "Saved OSV/NVD record for one of the selected finding's advisory IDs: "
            "affected ranges, fixed versions, description.",
            {"advisory_id": ID},
            _get_advisory,
        ),
        Tool(
            "lookup_advisory",
            "Live OSV query for the package's exact version "
            "(network; counts toward the external limit).",
            {"component_id": ID},
            _lookup_advisory,
            external=True,
        ),
        Tool(
            "get_package_metadata",
            "Live npm/PyPI metadata: published versions newer than installed, "
            "latest, deprecated or yanked (network).",
            {"component_id": ID},
            _package_metadata,
            external=True,
        ),
        Tool(
            "check_candidate_version",
            "Deterministic check of a candidate version: valid syntax, inside or "
            "outside each advisory's affected range, accepted by declared manifest ranges.",
            {"component_id": ID, "version": {"type": "string", "maxLength": 100}},
            _check_candidate,
        ),
        Tool(
            "get_change_evidence",
            "Before/after comparison with the previous scan, for change findings.",
            {"finding_id": ID},
            _change_evidence,
        ),
        Tool(
            "get_project_policy",
            "Kestral's remediation policy and allowed strategies.",
            {},
            _project_policy,
        ),
    ]
}


def run_tool(ctx: ToolContext, name: str, args: dict) -> tuple[ToolOutcome, int]:
    tool = TOOLS[name]
    started = time.monotonic()
    outcome = tool.handler(ctx, args)
    return outcome, int((time.monotonic() - started) * 1000)


def render_result(outcome: ToolOutcome, limit: int = MAX_RESULT_CHARS) -> str:
    """Tool output as quoted, untrusted data for the model, size-capped."""
    payload = json.dumps(outcome.result, default=str, ensure_ascii=False)
    if len(payload) > limit:
        payload = payload[:limit] + "…(truncated)"
    cite = ", ".join(outcome.evidence_ids) or "none"
    return (
        f"Evidence IDs you may cite from this result: {cite}\n"
        "<tool_data>\n" + clip(payload, limit + 20) + "\n</tool_data>"
    )

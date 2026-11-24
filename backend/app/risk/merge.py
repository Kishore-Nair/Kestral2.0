"""Merge OSV and Grype results into one finding per package and advisory.

The two sources name the same issue differently (GHSA, CVE, PYSEC...). Their own
alias lists are joined, so one advisory group becomes one finding that says which
sources reported it. Severity is kept per source, never recomputed.
"""

import networkx as nx

from app.graph.impact import package_impact
from app.graph.serialization import stable_id
from app.risk.grype import GrypeResult
from app.risk.osv import OsvResult
from app.risk.targets import Targets, canonical_purl
from app.schemas.dependency import DependencyComponent
from app.schemas.findings import Finding, FindingSource
from app.schemas.inventory import Evidence

OSV_FILE = "osv.json"
GRYPE_FILE = "grype.json"
NOT_REACHABILITY_CHECKED = "Not reachability-checked: the vulnerable code may never be called"


class _Aliases:
    """Union-find over advisory IDs."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, ids: list[str]) -> None:
        roots = [self.find(i) for i in ids]
        for other in roots[1:]:
            self.parent[self.find(other)] = self.find(roots[0])


def _primary_id(ids: set[str]) -> str:
    rank = {"GHSA": 0, "CVE": 1}
    return min(ids, key=lambda i: (rank.get(i.split("-", 1)[0], 2), i))


def _osv_fixed_versions(record: dict, purl: str) -> list[str]:
    target = canonical_purl(purl, with_version=False)
    name = target.rsplit("/", 1)[-1] if target else ""
    fixed: set[str] = set()
    for affected in record.get("affected") or []:
        package = affected.get("package") or {}
        package_purl = canonical_purl(package.get("purl"), with_version=False)
        if package_purl != target and (package.get("name") or "").lower() != name.lower():
            continue
        for range_ in affected.get("ranges") or []:
            for event in range_.get("events") or []:
                if event.get("fixed"):
                    fixed.add(event["fixed"])
    return sorted(fixed)


def _osv_source(record: dict) -> FindingSource:
    vuln_id = record["id"]
    return FindingSource(
        name="OSV",
        record_id=vuln_id,
        url=f"https://osv.dev/vulnerability/{vuln_id}",
        severity=(record.get("database_specific") or {}).get("severity"),
        cvss_vectors=sorted(
            s["score"]
            for s in record.get("severity") or []
            if str(s.get("type", "")).startswith("CVSS")
        ),
    )


def _grype_source(match: dict) -> FindingSource:
    vuln = match.get("vulnerability") or {}
    details = match.get("matchDetails") or []
    return FindingSource(
        name="Grype",
        record_id=vuln.get("id", ""),
        url=vuln.get("dataSource"),
        severity=vuln.get("severity"),
        cvss_vectors=sorted({c["vector"] for c in vuln.get("cvss") or [] if c.get("vector")}),
        match_type=details[0].get("type") if details else None,
    )


def _from_syft_only(component: DependencyComponent) -> bool:
    return all(e.kind == "syft-sbom" for e in component.evidence)


def vulnerability_findings(
    targets: Targets,
    graph: nx.DiGraph,
    osv: OsvResult | None,
    grype: GrypeResult | None,
) -> list[Finding]:
    aliases = _Aliases()
    # per canonical PURL: advisory id -> (osv records, grype matches)
    osv_by_purl: dict[str, list[dict]] = {}
    grype_by_purl: dict[str, list[dict]] = {}

    if osv is not None:
        for purl, ids in osv.matches.items():
            for vuln_id in ids:
                record = osv.records.get(vuln_id)
                if record is None or record.get("withdrawn"):
                    continue
                aliases.union([vuln_id, *(record.get("aliases") or [])])
                osv_by_purl.setdefault(purl, []).append(record)
    if grype is not None:
        for match in grype.matches:
            purl = canonical_purl((match.get("artifact") or {}).get("purl"))
            vuln_id = (match.get("vulnerability") or {}).get("id")
            if purl not in targets.by_purl or not vuln_id:
                continue
            related = [r["id"] for r in match.get("relatedVulnerabilities") or [] if r.get("id")]
            aliases.union([vuln_id, *related])
            grype_by_purl.setdefault(purl, []).append(match)

    findings: list[Finding] = []
    for purl in sorted(set(osv_by_purl) | set(grype_by_purl)):
        groups: dict[str, dict] = {}
        for record in osv_by_purl.get(purl, []):
            group = groups.setdefault(
                aliases.find(record["id"]), {"ids": set(), "osv": [], "grype": []}
            )
            group["ids"].update([record["id"], *(record.get("aliases") or [])])
            group["osv"].append(record)
        for match in grype_by_purl.get(purl, []):
            vuln = match["vulnerability"]
            group = groups.setdefault(
                aliases.find(vuln["id"]), {"ids": set(), "osv": [], "grype": []}
            )
            group["ids"].update(
                [vuln["id"], *(r["id"] for r in match.get("relatedVulnerabilities") or [])]
            )
            group["grype"].append(match)

        for group in groups.values():
            for component in targets.by_purl[purl]:
                findings.append(_vulnerability_finding(component, purl, group, graph, osv, grype))
    findings.sort(key=lambda f: (f.subject_label, f.advisory_ids[0], f.subject_id or ""))
    return findings


def _vulnerability_finding(
    component: DependencyComponent,
    purl: str,
    group: dict,
    graph: nx.DiGraph,
    osv: OsvResult | None,
    grype: GrypeResult | None,
) -> Finding:
    ids: set[str] = group["ids"]
    primary = _primary_id(ids)
    sources = [_osv_source(r) for r in sorted(group["osv"], key=lambda r: r["id"])]
    sources += [_grype_source(m) for m in group["grype"]]
    sources.sort(key=lambda s: (s.name, s.record_id))
    # Collapse duplicate Grype rows for the same record.
    sources = list({(s.name, s.record_id): s for s in sources}.values())

    fixed: set[str] = set()
    for record in group["osv"]:
        fixed.update(_osv_fixed_versions(record, purl))
    for match in group["grype"]:
        fixed.update(((match["vulnerability"].get("fix") or {}).get("versions")) or [])

    summary = next((r.get("summary") for r in group["osv"] if r.get("summary")), None) or next(
        (
            m["vulnerability"].get("description")
            for m in group["grype"]
            if m["vulnerability"].get("description")
        ),
        None,
    )
    evidence = list(component.evidence)
    evidence += [Evidence(path=OSV_FILE, kind="osv-record", locator=r["id"]) for r in group["osv"]]
    evidence += [
        Evidence(path=GRYPE_FILE, kind="grype-match", locator=m["vulnerability"]["id"])
        for m in group["grype"]
    ]
    evidence = list({(e.path, e.kind, e.locator): e for e in evidence}.values())

    uncertainty: list[str] = []
    names = {s.name for s in sources}
    if names == {"OSV"}:
        uncertainty.append(
            "Reported by OSV only; Grype found no match"
            if grype is not None
            else "Reported by OSV only; Grype did not run"
        )
    elif names == {"Grype"}:
        uncertainty.append(
            "Reported by Grype only; OSV found no match"
            if osv is not None
            else "Reported by Grype only; OSV did not run"
        )
    for source in sources:
        if source.match_type and source.match_type != "exact-direct-match":
            uncertainty.append(
                f"Grype matched by {source.match_type}; this may be a false positive"
            )
    if _from_syft_only(component):
        uncertainty.append("Version comes from Syft's SBOM, not a lockfile")

    impact = (
        package_impact(graph, component.component_id) if component.component_id in graph else None
    )
    if impact is not None and impact.directness == "unknown":
        uncertainty.append("No proven dependency path from any project to this package")
    uncertainty.append(NOT_REACHABILITY_CHECKED)

    return Finding(
        finding_id=stable_id("finding", "vulnerability", component.component_id, primary),
        kind="vulnerability",
        title=f"{primary}: {summary}" if summary else primary,
        subject_id=component.component_id,
        subject_label=f"{component.name}@{component.version}",
        advisory_ids=[primary, *sorted(ids - {primary})],
        sources=sources,
        fixed_versions=sorted(fixed),
        evidence=evidence,
        scope=component.scope,
        directness=impact.directness if impact else "unknown",
        dependency_paths=impact.paths if impact else [],
        affected_projects=impact.affected_projects if impact else [],
        dependent_packages=impact.dependent_packages if impact else None,
        uncertainty=uncertainty,
    )

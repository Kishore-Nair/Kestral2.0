"""Turn M3's normalized dependency document into the M4 graph.

Pure and deterministic: no filesystem, network or database I/O. Edges come only from
M3 relationships; nothing is linked because names, versions or PURLs look related.
"""

import networkx as nx

from app.graph.anomalies import cycle_warning, cyclic_components, malformed_evidence_elements
from app.graph.serialization import stable_id, to_graph_document
from app.graph.traversal import assign_depths
from app.schemas.dependency import DependencyDocument, DependencyRelationship, UnresolvedTarget
from app.schemas.graph import GraphDocument

APP_ID = "app:root"


class GraphValidationError(ValueError):
    """The normalized document cannot be turned into a truthful graph."""


def build_graph(document: DependencyDocument, app_name: str) -> GraphDocument:
    """Pure deterministic transformation. No filesystem, network or database I/O."""
    warnings: list[str] = []
    graph = make_networkx_graph(document, app_name, warnings)
    assign_depths(graph)

    cycles = cyclic_components(graph)
    if warning := cycle_warning(len(cycles)):
        warnings.append(warning)

    malformed = malformed_evidence_elements(graph)
    if malformed:
        shown = ", ".join(malformed[:5]) + (" ..." if len(malformed) > 5 else "")
        warnings.append(
            f"{len(malformed)} graph element(s) carry evidence paths that are not "
            f"repo-relative POSIX paths: {shown}"
        )

    merged_warnings = list(dict.fromkeys([*document.warnings, *warnings]))
    return to_graph_document(
        graph,
        scan_id=document.scan_id,
        partial=document.partial or bool(malformed),
        warnings=merged_warnings,
        cycles=len(cycles),
    )


def make_networkx_graph(
    document: DependencyDocument, app_name: str, warnings: list[str] | None = None
) -> nx.DiGraph:
    """Nodes first (app, projects, packages), then validated relationships."""
    warnings = warnings if warnings is not None else []
    graph = nx.DiGraph()
    graph.add_node(
        APP_ID, id=APP_ID, label=app_name, type="application",
        directness="not_applicable", depth=None,
    )

    for root in document.roots:
        _require_new_id(graph, root.root_id, "root")
        graph.add_node(
            root.root_id, id=root.root_id, label=f"{root.name} ({root.ecosystem})",
            type="project", project_path=root.path, directness="not_applicable", depth=0,
        )
        graph.add_edge(APP_ID, root.root_id, type="CONTAINS")

    for c in document.components:
        _require_new_id(graph, c.component_id, "component")
        graph.add_node(
            c.component_id, id=c.component_id, type="package", label=c.name, name=c.name,
            version=c.version, ecosystem=c.ecosystem, purl=c.purl,
            project_path=c.project_path, install_path=c.install_path,
            evidence=[e.model_dump() for e in c.evidence], directness="unknown", depth=None,
        )

    seen: dict[str, DependencyRelationship] = {}
    for rel in document.relationships:
        previous = seen.get(rel.relationship_id)
        if previous is not None:
            if previous == rel:
                warnings.append(f"Duplicate relationship {rel.relationship_id} ignored")
                continue
            raise GraphValidationError(
                f"Conflicting relationships share id {rel.relationship_id}"
            )
        seen[rel.relationship_id] = rel
        add_validated_relationship(graph, rel)

    return graph


def add_validated_relationship(graph: nx.DiGraph, rel: DependencyRelationship) -> None:
    """Add one DEPENDS_ON edge; never creates implicit nodes or guesses a target."""
    rid = rel.relationship_id
    if rel.from_id not in graph:
        raise GraphValidationError(f"Unknown dependency source {rel.from_id} in {rid}")
    if graph.nodes[rel.from_id]["type"] not in ("project", "package"):
        raise GraphValidationError(
            f"Only projects and packages may declare dependencies ({rel.from_id} in {rid})"
        )

    evidence = [e.model_dump() for e in rel.evidence]
    if rel.resolution_status == "resolved":
        target = rel.to_id
        if target not in graph or graph.nodes[target]["type"] != "package":
            raise GraphValidationError(f"{rid} points to unknown component {target}")
    else:
        target = _add_unresolved_node(graph, rel.from_id, rel.unresolved_target, rel, evidence)

    if graph.has_edge(rel.from_id, target):
        edge = graph.edges[rel.from_id, target]
        if edge["resolution_status"] != rel.resolution_status:
            raise GraphValidationError(
                f"{rid} disagrees with an earlier relationship on resolution status"
            )
        edge["evidence"] = _merge_evidence(edge["evidence"], evidence)
    else:
        graph.add_edge(
            rel.from_id, target, type="DEPENDS_ON", resolution_status=rel.resolution_status,
            evidence=_merge_evidence([], evidence),
        )


def _add_unresolved_node(
    graph: nx.DiGraph,
    from_id: str,
    target: UnresolvedTarget,
    rel: DependencyRelationship,
    evidence: list[dict],
) -> str:
    locators = sorted(_evidence_key(e) for e in evidence)
    node_id = stable_id(
        "unresolved", from_id, target.name, target.specifier, target.ecosystem, locators
    )
    if node_id in graph:
        data = graph.nodes[node_id]
        if data["type"] != "unresolved":
            raise GraphValidationError(f"ID collision on unresolved placeholder {node_id}")
        if data["resolution_status"] != rel.resolution_status:
            raise GraphValidationError(
                f"{rel.relationship_id} disagrees with an earlier declaration on resolution status"
            )
    else:
        graph.add_node(
            node_id, id=node_id, type="unresolved",
            label=f"{target.name} {target.specifier}".strip(),
            unresolved_target=target.model_dump(), resolution_status=rel.resolution_status,
            evidence=[], directness="unknown", depth=None,
        )
    graph.nodes[node_id]["evidence"] = _merge_evidence(graph.nodes[node_id]["evidence"], evidence)
    return node_id


def _require_new_id(graph: nx.DiGraph, node_id: str, kind: str) -> None:
    if node_id == APP_ID:
        raise GraphValidationError(f"{kind} id may not be {APP_ID}")
    if node_id in graph:
        raise GraphValidationError(f"Duplicate {kind} id: {node_id}")


def _evidence_key(item: dict) -> tuple[str, str, str]:
    return (item["path"], item["kind"], item["locator"])


def _merge_evidence(existing: list[dict], new: list[dict]) -> list[dict]:
    """Union of evidence items, de-duplicated and sorted so input order doesn't matter."""
    merged = {_evidence_key(e): e for e in [*existing, *new]}
    return [dict(merged[k]) for k in sorted(merged)]

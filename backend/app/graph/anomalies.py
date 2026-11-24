"""Cyclic strongly connected components and evidence-path checks."""

import re

import networkx as nx

from app.graph.traversal import depends_on_view

SYFT_SBOM_PATH = "sbom.cdx.json"


def cyclic_components(graph: nx.DiGraph) -> list[list[str]]:
    """SCCs with more than one node, or a single node with a self-loop (no cycle enumeration)."""
    view = depends_on_view(graph)
    cyclic = [
        sorted(component)
        for component in nx.strongly_connected_components(view)
        if len(component) > 1 or any(view.has_edge(n, n) for n in component)
    ]
    return sorted(cyclic)


def cycle_warning(count: int) -> str | None:
    if count == 0:
        return None
    noun = "component" if count == 1 else "components"
    return f"Dependency graph contains {count} cyclic {noun}"


def is_valid_evidence(item: dict) -> bool:
    """Lockfile/manifest paths are repo-relative POSIX; syft-sbom points at sbom.cdx.json."""
    path = item["path"]
    if item["kind"] == "syft-sbom":
        return path == SYFT_SBOM_PATH
    if not path or path.startswith("/") or "\\" in path or "://" in path:
        return False
    if re.match(r"^[A-Za-z]:", path):
        return False
    return ".." not in path.split("/")


def malformed_evidence_elements(graph: nx.DiGraph) -> list[str]:
    """IDs of nodes/edges carrying evidence that breaks the path rules (sorted)."""
    bad = {
        node
        for node, data in graph.nodes(data=True)
        if not all(is_valid_evidence(e) for e in data.get("evidence", []))
    }
    bad |= {
        f"{u} -> {v}"
        for u, v, data in graph.edges(data=True)
        if not all(is_valid_evidence(e) for e in data.get("evidence", []))
    }
    return sorted(bad)

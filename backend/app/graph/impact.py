"""Explain how a package enters the application and what depends on it.

Used by risk analysis to attach a proven dependency path and blast radius to a
finding. Only DEPENDS_ON edges count; a package with no path from any project
gets no path (never an invented one).
"""

from dataclasses import dataclass

import networkx as nx

from app.graph.traversal import _require, dependency_depths, depends_on_view, reverse_dependents


@dataclass(frozen=True)
class Impact:
    paths: list[list[str]]
    directness: str  # direct | transitive | unknown
    affected_projects: list[str]
    dependent_packages: int


def dependency_paths(graph: nx.DiGraph, package_id: str, limit: int = 3) -> list[list[str]]:
    """Shortest project -> ... -> package chains, one per reachable project, shortest first."""
    _require(graph, package_id)
    if limit < 1:
        return []
    view = depends_on_view(graph)
    projects = sorted(n for n, d in graph.nodes(data=True) if d["type"] == "project")
    paths = []
    for project in projects:
        try:
            paths.append(nx.shortest_path(view, project, package_id))
        except nx.NetworkXNoPath:
            continue
    paths.sort(key=lambda path: (len(path), path))
    return paths[:limit]


def package_impact(graph: nx.DiGraph, package_id: str, limit: int = 3) -> Impact:
    """Paths, directness and blast radius for one package node."""
    _require(graph, package_id)
    depth = dependency_depths(graph).get(package_id)
    directness = "unknown" if depth is None else "direct" if depth == 1 else "transitive"
    dependents = reverse_dependents(graph, package_id)
    return Impact(
        paths=dependency_paths(graph, package_id, limit),
        directness=directness,
        affected_projects=sorted(n for n in dependents if graph.nodes[n]["type"] == "project"),
        dependent_packages=sum(1 for n in dependents if graph.nodes[n]["type"] == "package"),
    )

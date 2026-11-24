"""Depth, directness and dependency queries over the DEPENDS_ON edges.

Arrows go depender -> dependency: successors are what a node depends on,
predecessors are the nodes that depend on it. CONTAINS edges never count as dependencies.
"""

from collections import deque

import networkx as nx

DEPENDS_ON = "DEPENDS_ON"


def depends_on_view(graph: nx.DiGraph) -> nx.DiGraph:
    """Read-only view of the graph without CONTAINS edges."""
    return nx.subgraph_view(graph, filter_edge=lambda u, v: graph.edges[u, v]["type"] == DEPENDS_ON)


def dependency_depths(graph: nx.DiGraph) -> dict[str, int]:
    """Shortest number of DEPENDS_ON edges from any project root (projects are 0)."""
    roots = sorted(n for n, d in graph.nodes(data=True) if d["type"] == "project")
    depth: dict[str, int] = {root: 0 for root in roots}
    queue = deque(roots)
    while queue:
        src = queue.popleft()
        for dst in sorted(graph.successors(src)):
            if graph.edges[src, dst]["type"] != DEPENDS_ON:
                continue
            proposed = depth[src] + 1
            if dst not in depth or proposed < depth[dst]:
                depth[dst] = proposed
                queue.append(dst)
    return depth


def assign_depths(graph: nx.DiGraph) -> None:
    """Write depth/directness onto package and unresolved nodes; unreachable stays unknown."""
    depths = dependency_depths(graph)
    for node, data in graph.nodes(data=True):
        if data["type"] not in ("package", "unresolved"):
            continue
        depth = depths.get(node)
        data["depth"] = depth
        if depth is None:
            data["directness"] = "unknown"
        else:
            data["directness"] = "direct" if depth == 1 else "transitive"


def _require(graph: nx.DiGraph, node_id: str) -> None:
    if node_id not in graph:
        raise ValueError(f"Unknown graph node: {node_id}")


def direct_dependencies(graph: nx.DiGraph, root_id: str) -> set[str]:
    _require(graph, root_id)
    return set(depends_on_view(graph).successors(root_id))


def transitive_dependencies(graph: nx.DiGraph, root_id: str) -> set[str]:
    """Everything reachable from root_id that it does not declare directly."""
    _require(graph, root_id)
    view = depends_on_view(graph)
    return nx.descendants(view, root_id) - set(view.successors(root_id)) - {root_id}


def reverse_dependents(graph: nx.DiGraph, package_id: str) -> set[str]:
    """Projects and packages that depend on package_id, directly or through other packages."""
    _require(graph, package_id)
    return {
        n
        for n in nx.ancestors(depends_on_view(graph), package_id)
        if graph.nodes[n]["type"] in ("project", "package")
    }


def shortest_dependency_path(graph: nx.DiGraph, root_id: str, package_id: str) -> list[str] | None:
    _require(graph, root_id)
    _require(graph, package_id)
    try:
        return nx.shortest_path(depends_on_view(graph), root_id, package_id)
    except nx.NetworkXNoPath:
        return None

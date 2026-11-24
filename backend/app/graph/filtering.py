"""Pure in-memory selected-node subgraph helper for focused UI views."""

from collections.abc import Iterable

import networkx as nx


def neighborhood(graph: nx.DiGraph, selected_ids: Iterable[str], hops: int = 2) -> nx.DiGraph:
    """Selected nodes plus everything within `hops` edges in either direction.

    Returns a copy; edges between kept nodes are preserved and nothing is added.
    """
    if hops < 0:
        raise ValueError("hops must be >= 0")
    selected = set(selected_ids)
    missing = sorted(selected - set(graph))
    if missing:
        raise ValueError(f"Unknown graph node(s): {', '.join(missing)}")
    undirected = graph.to_undirected(as_view=True)
    keep = set(selected)
    frontier = set(selected)
    for _ in range(hops):
        frontier = {n for f in frontier for n in undirected.neighbors(f)} - keep
        if not frontier:
            break
        keep |= frontier
    return graph.subgraph(keep).copy()

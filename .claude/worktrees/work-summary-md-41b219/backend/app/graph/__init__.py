"""M4 dependency graph engine: normalized document -> Cytoscape graph."""

from app.graph.builder import GraphValidationError, build_graph, make_networkx_graph
from app.graph.filtering import neighborhood
from app.graph.traversal import (
    dependency_depths,
    direct_dependencies,
    reverse_dependents,
    shortest_dependency_path,
    transitive_dependencies,
)

__all__ = [
    "GraphValidationError",
    "build_graph",
    "dependency_depths",
    "direct_dependencies",
    "make_networkx_graph",
    "neighborhood",
    "reverse_dependents",
    "shortest_dependency_path",
    "transitive_dependencies",
]

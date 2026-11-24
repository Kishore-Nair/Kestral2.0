"""M4 dependency graph engine: normalized document -> Cytoscape graph."""

from app.graph.builder import GraphValidationError, build_graph, make_networkx_graph
from app.graph.filtering import neighborhood
from app.graph.impact import Impact, dependency_paths, package_impact
from app.graph.traversal import (
    dependency_depths,
    direct_dependencies,
    reverse_dependents,
    shortest_dependency_path,
    transitive_dependencies,
)

__all__ = [
    "GraphValidationError",
    "Impact",
    "build_graph",
    "dependency_depths",
    "dependency_paths",
    "direct_dependencies",
    "make_networkx_graph",
    "neighborhood",
    "package_impact",
    "reverse_dependents",
    "shortest_dependency_path",
    "transitive_dependencies",
]

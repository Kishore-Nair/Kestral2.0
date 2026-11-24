"""Cytoscape export with stable IDs and JSON-stable ordering."""

import hashlib
import json

import networkx as nx

from app.schemas.graph import GraphDocument

NODE_FIELDS = {
    "application": ("id", "label", "type", "directness", "depth"),
    "project": ("id", "label", "type", "directness", "depth", "project_path"),
    "package": (
        "id", "label", "type", "directness", "depth", "name", "version", "ecosystem", "purl",
        "project_path", "install_path", "evidence",
    ),
    "unresolved": (
        "id", "label", "type", "directness", "depth", "unresolved_target", "resolution_status",
        "evidence",
    ),
}
OPTIONAL_NODE_FIELDS = {"project_path", "install_path"}  # package nodes: only when known


def stable_id(prefix: str, *parts: object) -> str:
    """Deterministic ID from structured parts (JSON-encoded so parts can't run together)."""
    encoded = json.dumps(parts, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(encoded).hexdigest()[:16]}"


def _node_data(data: dict) -> dict:
    out = {}
    for field in NODE_FIELDS[data["type"]]:
        value = data.get(field)
        if data["type"] == "package" and field in OPTIONAL_NODE_FIELDS and value is None:
            continue
        out[field] = [dict(e) for e in value] if field == "evidence" else value
    return out


def to_graph_document(
    graph: nx.DiGraph, *, scan_id: str, partial: bool, warnings: list[str], cycles: int
) -> GraphDocument:
    nodes = [
        {"data": _node_data(data)}
        for _, data in sorted(graph.nodes(data=True), key=lambda item: (item[1]["type"], item[0]))
    ]
    edges = []
    for source, target, data in sorted(
        graph.edges(data=True), key=lambda item: (item[2]["type"], item[0], item[1])
    ):
        edge = {
            "id": stable_id("edge", data["type"], source, target),
            "source": source,
            "target": target,
            "type": data["type"],
        }
        if data["type"] == "DEPENDS_ON":
            edge["resolution_status"] = data["resolution_status"]
            edge["evidence"] = [dict(e) for e in data["evidence"]]
        edges.append({"data": edge})

    element_ids = [n["data"]["id"] for n in nodes] + [e["data"]["id"] for e in edges]
    if len(element_ids) != len(set(element_ids)):
        raise ValueError("Graph export produced duplicate Cytoscape element IDs")

    types = [data["type"] for _, data in graph.nodes(data=True)]
    package_depths = [
        data["depth"]
        for _, data in graph.nodes(data=True)
        if data["type"] == "package" and data["depth"] is not None
    ]
    stats = {
        "applications": types.count("application"),
        "projects": types.count("project"),
        "packages": types.count("package"),
        "unresolved": types.count("unresolved"),
        "depends_on_edges": sum(1 for e in edges if e["data"]["type"] == "DEPENDS_ON"),
        "max_depth": max(package_depths, default=0),
        "cycles": cycles,
    }
    return GraphDocument.model_validate(
        {
            "meta": {
                "schema_version": "1.0",
                "scan_id": scan_id,
                "partial": partial,
                "stats": stats,
                "warnings": warnings,
            },
            "nodes": nodes,
            "edges": edges,
        }
    )

"""Shared helpers for M4 graph tests (unique module name to avoid clashing with other suites)."""

import json
from pathlib import Path

from app.graph import build_graph
from app.schemas.dependency import DependencyDocument

FIXTURES = Path(__file__).parent / "fixtures"
APP_NAME = "demo-app"


def load_payload(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def build(payload: dict, app_name: str = APP_NAME) -> dict:
    document = DependencyDocument.model_validate(payload)
    return build_graph(document, app_name).model_dump(mode="json")


def nodes_by_id(graph: dict) -> dict[str, dict]:
    return {n["data"]["id"]: n["data"] for n in graph["nodes"]}


def edge_pairs(graph: dict, edge_type: str = "DEPENDS_ON") -> set[tuple[str, str]]:
    return {
        (e["data"]["source"], e["data"]["target"])
        for e in graph["edges"]
        if e["data"]["type"] == edge_type
    }


def evidence(path: str, kind: str, locator: str) -> dict:
    return {"path": path, "kind": kind, "locator": locator}


def component(component_id: str, name: str, version: str | None = "1.0.0", **extra) -> dict:
    item = {
        "component_id": component_id, "name": name, "version": version, "ecosystem": "npm",
        "purl": f"pkg:npm/{name}@{version}" if version else None,
        "install_path": f"node_modules/{name}", "project_path": "", "scope": "runtime",
        "licenses": [], "hashes": [],
        "evidence": [evidence("package-lock.json", "lockfile", f"packages.node_modules/{name}")],
        "resolved": version is not None,
    }
    item.update(extra)
    return item


def relationship(rid: str, src: str, dst: str | None, locator: str | None = None, **extra) -> dict:
    item = {
        "relationship_id": rid, "from_id": src, "to_id": dst, "unresolved_target": None,
        "resolution_status": "resolved", "type": "DEPENDS_ON",
        "evidence": [evidence("package-lock.json", "lockfile", locator or f"{src}->{dst}")],
    }
    item.update(extra)
    return item

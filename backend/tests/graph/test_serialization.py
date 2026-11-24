import json
import os
from pathlib import Path

import pytest
from graph_helpers import FIXTURES, build, load_payload

from app.schemas.graph import GraphDocument

EXPECTED = FIXTURES / "expected"
NAMES = ["chain", "cycle", "diamond", "empty", "multi_project", "two_versions", "unresolved"]
M1_FIXTURES = Path(__file__).parents[1] / "ingestion" / "fixtures"


@pytest.mark.parametrize("name", NAMES)
def test_matches_golden_output(name):
    """Golden files were reviewed by hand; regenerate with UPDATE_GOLDEN=1 only after review."""
    actual = build(load_payload(name))
    path = EXPECTED / f"{name}.graph.json"
    if os.environ.get("UPDATE_GOLDEN") == "1":
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(actual, indent=2) + "\n", encoding="utf-8")
    assert actual == json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", NAMES)
def test_invariants(name):
    graph = build(load_payload(name))
    GraphDocument.model_validate(graph)
    node_ids = [n["data"]["id"] for n in graph["nodes"]]
    edge_ids = [e["data"]["id"] for e in graph["edges"]]
    assert len(node_ids) == len(set(node_ids))
    assert len(node_ids + edge_ids) == len(set(node_ids + edge_ids))
    assert all(
        e["data"]["source"] in node_ids and e["data"]["target"] in node_ids
        for e in graph["edges"]
    )
    assert node_ids[0] == "app:root"


@pytest.mark.parametrize("name", NAMES)
def test_sorted_output(name):
    graph = build(load_payload(name))
    node_keys = [(n["data"]["type"], n["data"]["id"]) for n in graph["nodes"]]
    edge_keys = [(e["data"]["type"], e["data"]["source"], e["data"]["target"])
                 for e in graph["edges"]]
    assert node_keys == sorted(node_keys)
    assert edge_keys == sorted(edge_keys)


@pytest.mark.parametrize("name", NAMES)
def test_input_order_does_not_change_output(name):
    payload = load_payload(name)
    shuffled = dict(payload)
    for key in ("roots", "components", "relationships"):
        shuffled[key] = list(reversed(payload[key]))
    assert build(shuffled) == build(payload)


def test_stats_match_nodes_and_edges():
    graph = build(load_payload("unresolved"))
    stats = graph["meta"]["stats"]
    types = [n["data"]["type"] for n in graph["nodes"]]
    assert stats["applications"] == types.count("application")
    assert stats["projects"] == types.count("project")
    assert stats["packages"] == types.count("package")
    assert stats["unresolved"] == types.count("unresolved")
    assert stats["depends_on_edges"] == sum(
        1 for e in graph["edges"] if e["data"]["type"] == "DEPENDS_ON"
    )


def test_empty_collections_are_lists_not_null():
    graph = build(load_payload("empty"))
    assert graph["edges"] == []
    assert graph["meta"]["warnings"] == []


def test_m1_readme_fixture_produces_the_readme_graph_shape():
    """Same graph as M1's README graph.json, except: edge IDs are our stable hashes, and package
    nodes add the optional project_path/install_path from M3 (the README sample omits them)."""
    actual = build(json.loads((M1_FIXTURES / "normalized.json").read_text(encoding="utf-8")),
                   app_name="fixture-app")
    expected = GraphDocument.model_validate(
        json.loads((M1_FIXTURES / "graph.json").read_text(encoding="utf-8"))
    ).model_dump(mode="json")

    def comparable_nodes(graph):
        optional = {"project_path", "install_path"}
        return sorted(
            ({k: v for k, v in n["data"].items()
              if not (n["data"]["type"] == "package" and k in optional)} for n in graph["nodes"]),
            key=lambda d: d["id"],
        )

    def strip_edge_ids(graph):
        return [{k: v for k, v in e["data"].items() if k != "id"} for e in graph["edges"]]

    assert actual["meta"] == expected["meta"]
    assert comparable_nodes(actual) == comparable_nodes(expected)
    assert strip_edge_ids(actual) == strip_edge_ids(expected)
    express = next(n["data"] for n in actual["nodes"] if n["data"]["id"] == "cmp:1a2b3c")
    assert (express["project_path"], express["install_path"]) == ("", "node_modules/express")

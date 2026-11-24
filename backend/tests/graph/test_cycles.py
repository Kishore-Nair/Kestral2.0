from graph_helpers import build, component, nodes_by_id, relationship

from app.graph import make_networkx_graph
from app.graph.anomalies import cyclic_components
from app.schemas.dependency import DependencyDocument


def test_cycle_terminates_and_is_counted(fixture_payload):
    graph = build(fixture_payload("cycle"))
    assert graph["meta"]["stats"]["cycles"] == 1
    assert "Dependency graph contains 1 cyclic component" in graph["meta"]["warnings"]
    nodes = nodes_by_id(graph)
    assert (nodes["cmp:alpha"]["depth"], nodes["cmp:beta"]["depth"]) == (1, 2)


def test_cycle_members_are_reported(fixture_payload):
    graph = make_networkx_graph(DependencyDocument.model_validate(fixture_payload("cycle")), "x")
    assert cyclic_components(graph) == [["cmp:alpha", "cmp:beta"]]


def test_self_loop_counts_as_cycle(fixture_payload):
    payload = fixture_payload("chain")
    payload["relationships"].append(relationship("rel:gamma-gamma", "cmp:gamma", "cmp:gamma"))
    assert build(payload)["meta"]["stats"]["cycles"] == 1


def test_two_separate_cycles(fixture_payload):
    payload = fixture_payload("cycle")
    payload["components"] += [component("cmp:x", "x"), component("cmp:y", "y")]
    payload["relationships"] += [
        relationship("rel:x-y", "cmp:x", "cmp:y"),
        relationship("rel:y-x", "cmp:y", "cmp:x"),
    ]
    graph = build(payload)
    assert graph["meta"]["stats"]["cycles"] == 2
    assert "Dependency graph contains 2 cyclic components" in graph["meta"]["warnings"]


def test_acyclic_graphs_have_no_cycle_warning(fixture_payload):
    for name in ("chain", "diamond", "two_versions", "multi_project", "empty"):
        graph = build(fixture_payload(name))
        assert graph["meta"]["stats"]["cycles"] == 0
        assert not any("cyclic" in w for w in graph["meta"]["warnings"])


def test_cycle_output_is_repeatable(fixture_payload):
    assert build(fixture_payload("cycle")) == build(fixture_payload("cycle"))

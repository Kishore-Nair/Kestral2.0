import pytest
from graph_helpers import relationship

from app.graph import (
    direct_dependencies,
    make_networkx_graph,
    neighborhood,
    reverse_dependents,
    shortest_dependency_path,
    transitive_dependencies,
)
from app.schemas.dependency import DependencyDocument


def _graph(payload: dict):
    return make_networkx_graph(DependencyDocument.model_validate(payload), "demo-app")


def test_direct_and_transitive_dependencies(fixture_payload):
    g = _graph(fixture_payload("chain"))
    assert direct_dependencies(g, "root:demo") == {"cmp:alpha"}
    assert transitive_dependencies(g, "root:demo") == {"cmp:beta", "cmp:gamma"}
    assert direct_dependencies(g, "cmp:gamma") == set()


def test_contains_edges_are_not_dependencies(fixture_payload):
    g = _graph(fixture_payload("chain"))
    assert direct_dependencies(g, "app:root") == set()
    assert "app:root" not in reverse_dependents(g, "cmp:alpha")


def test_transitive_excludes_packages_also_declared_directly(fixture_payload):
    payload = fixture_payload("chain")
    payload["relationships"].append(relationship("rel:demo-gamma", "root:demo", "cmp:gamma"))
    g = _graph(payload)
    assert transitive_dependencies(g, "root:demo") == {"cmp:beta"}


def test_reverse_dependents(fixture_payload):
    g = _graph(fixture_payload("diamond"))
    assert reverse_dependents(g, "cmp:gamma") == {"cmp:alpha", "cmp:beta", "root:demo"}
    assert reverse_dependents(g, "cmp:alpha") == {"root:demo"}


def test_shortest_path_uses_depends_on_only(fixture_payload):
    g = _graph(fixture_payload("chain"))
    assert shortest_dependency_path(g, "root:demo", "cmp:gamma") == [
        "root:demo", "cmp:alpha", "cmp:beta", "cmp:gamma",
    ]
    assert shortest_dependency_path(g, "app:root", "cmp:alpha") is None
    assert shortest_dependency_path(g, "cmp:gamma", "cmp:alpha") is None


def test_queries_terminate_on_cycles(fixture_payload):
    g = _graph(fixture_payload("cycle"))
    assert transitive_dependencies(g, "root:demo") == {"cmp:beta"}
    assert reverse_dependents(g, "cmp:alpha") == {"cmp:beta", "root:demo"}


def test_unknown_node_raises(fixture_payload):
    g = _graph(fixture_payload("chain"))
    with pytest.raises(ValueError, match="Unknown graph node"):
        direct_dependencies(g, "cmp:nope")


def test_neighborhood(fixture_payload):
    g = _graph(fixture_payload("chain"))
    assert set(neighborhood(g, {"cmp:beta"}, hops=1)) == {"cmp:alpha", "cmp:beta", "cmp:gamma"}
    assert set(neighborhood(g, {"cmp:beta"}, hops=0)) == {"cmp:beta"}
    sub = neighborhood(g, {"cmp:alpha"}, hops=1)
    assert set(sub.edges) == {("root:demo", "cmp:alpha"), ("cmp:alpha", "cmp:beta")}
    assert set(g) == {"app:root", "root:demo", "cmp:alpha", "cmp:beta", "cmp:gamma"}  # untouched


def test_neighborhood_rejects_bad_input(fixture_payload):
    g = _graph(fixture_payload("chain"))
    with pytest.raises(ValueError):
        neighborhood(g, {"cmp:nope"})
    with pytest.raises(ValueError):
        neighborhood(g, {"cmp:alpha"}, hops=-1)

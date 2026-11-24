import pytest
from graph_helpers import APP_NAME, component, load_payload

from app.graph import dependency_paths, make_networkx_graph, package_impact
from app.schemas.dependency import DependencyDocument


def nx_graph(payload: dict):
    return make_networkx_graph(DependencyDocument.model_validate(payload), APP_NAME)


def test_chain_path_and_transitive_impact(fixture_payload) -> None:
    graph = nx_graph(fixture_payload("chain"))
    impact = package_impact(graph, "cmp:gamma")
    assert impact.paths == [["root:demo", "cmp:alpha", "cmp:beta", "cmp:gamma"]]
    assert impact.directness == "transitive"
    assert impact.affected_projects == ["root:demo"]
    assert impact.dependent_packages == 2


def test_diamond_returns_one_shortest_path_per_project(fixture_payload) -> None:
    graph = nx_graph(fixture_payload("diamond"))
    paths = dependency_paths(graph, "cmp:gamma")
    assert len(paths) == 1
    assert paths[0][0] == "root:demo" and paths[0][-1] == "cmp:gamma" and len(paths[0]) == 3
    assert package_impact(graph, "cmp:gamma").dependent_packages == 2


def test_direct_dependency(fixture_payload) -> None:
    impact = package_impact(nx_graph(fixture_payload("chain")), "cmp:alpha")
    assert impact.directness == "direct"
    assert impact.paths == [["root:demo", "cmp:alpha"]]
    assert impact.dependent_packages == 0


def test_multi_project_only_reports_projects_that_reach_the_package(fixture_payload) -> None:
    graph = nx_graph(fixture_payload("multi_project"))
    assert package_impact(graph, "cmp:beta").affected_projects == ["root:api"]
    assert dependency_paths(graph, "cmp:beta") == [["root:api", "cmp:beta"]]


def test_orphan_package_gets_no_invented_path(fixture_payload) -> None:
    payload = fixture_payload("chain")
    payload["components"].append(component("cmp:orphan", "orphan"))
    impact = package_impact(nx_graph(payload), "cmp:orphan")
    assert impact.paths == []
    assert impact.directness == "unknown"
    assert impact.affected_projects == []


def test_cycle_terminates(fixture_payload) -> None:
    impact = package_impact(nx_graph(fixture_payload("cycle")), "cmp:beta")
    assert impact.paths == [["root:demo", "cmp:alpha", "cmp:beta"]]
    assert impact.directness == "transitive"


def test_limit_and_unknown_node() -> None:
    graph = nx_graph(load_payload("multi_project"))
    assert dependency_paths(graph, "cmp:alpha", limit=0) == []
    with pytest.raises(ValueError, match="Unknown graph node"):
        package_impact(graph, "cmp:missing")

from graph_helpers import build, component, edge_pairs, evidence, nodes_by_id, relationship


def _depths(graph: dict) -> dict[str, tuple]:
    return {i: (d["depth"], d["directness"]) for i, d in nodes_by_id(graph).items()}


def test_chain_depths(fixture_payload):
    graph = build(fixture_payload("chain"))
    depths = _depths(graph)
    assert depths["root:demo"] == (0, "not_applicable")
    assert depths["cmp:alpha"] == (1, "direct")
    assert depths["cmp:beta"] == (2, "transitive")
    assert depths["cmp:gamma"] == (3, "transitive")
    assert depths["app:root"] == (None, "not_applicable")
    assert graph["meta"]["stats"]["max_depth"] == 3


def test_diamond_shared_package_is_one_node_with_two_parents(fixture_payload):
    graph = build(fixture_payload("diamond"))
    assert sum(1 for n in graph["nodes"] if n["data"].get("name") == "gamma") == 1
    parents = {s for s, t in edge_pairs(graph) if t == "cmp:gamma"}
    assert parents == {"cmp:alpha", "cmp:beta"}
    assert _depths(graph)["cmp:gamma"] == (2, "transitive")


def test_root_direct_and_transitive_uses_minimum_depth(fixture_payload):
    payload = fixture_payload("chain")
    payload["relationships"].append(
        relationship("rel:demo-gamma", "root:demo", "cmp:gamma", "packages[''].dependencies.gamma")
    )
    assert _depths(build(payload))["cmp:gamma"] == (1, "direct")


def test_syft_only_orphan_is_visible_but_unknown(fixture_payload):
    payload = fixture_payload("chain")
    payload["components"].append(
        component("cmp:syft-only", "delta",
                  evidence=[evidence("sbom.cdx.json", "syft-sbom", "components[bom-ref=delta]")])
    )
    graph = build(payload)
    assert _depths(graph)["cmp:syft-only"] == (None, "unknown")
    assert not any("cmp:syft-only" in pair for pair in edge_pairs(graph))


def test_orphan_subtree_is_not_called_transitive(fixture_payload):
    payload = fixture_payload("chain")
    payload["components"] += [component("cmp:x", "x"), component("cmp:y", "y")]
    payload["relationships"].append(relationship("rel:x-y", "cmp:x", "cmp:y"))
    depths = _depths(build(payload))
    assert depths["cmp:x"] == (None, "unknown")
    assert depths["cmp:y"] == (None, "unknown")


def test_empty_document(fixture_payload):
    graph = build(fixture_payload("empty"))
    assert [n["data"]["id"] for n in graph["nodes"]] == ["app:root"]
    assert graph["edges"] == []
    assert graph["meta"]["stats"] == {
        "applications": 1, "projects": 0, "packages": 0, "unresolved": 0,
        "depends_on_edges": 0, "max_depth": 0, "cycles": 0,
    }


def test_multi_project_one_application_two_projects(fixture_payload):
    graph = build(fixture_payload("multi_project"))
    assert edge_pairs(graph, "CONTAINS") == {("app:root", "root:web"), ("app:root", "root:api")}
    assert edge_pairs(graph) == {("root:web", "cmp:alpha"), ("root:api", "cmp:beta")}
    depths = _depths(graph)
    assert depths["cmp:alpha"] == (1, "direct")
    assert depths["cmp:beta"] == (1, "direct")
    assert nodes_by_id(graph)["root:web"]["project_path"] == "web"

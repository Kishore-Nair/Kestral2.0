from graph_helpers import build, edge_pairs, nodes_by_id, relationship

from app.graph.serialization import stable_id


def test_same_package_version_in_two_install_paths_stays_two_nodes(fixture_payload):
    graph = build(fixture_payload("two_versions"))
    nodes = nodes_by_id(graph)
    gammas = [n for n in nodes.values() if n.get("name") == "gamma"]
    assert len(gammas) == 2
    assert {n["purl"] for n in gammas} == {"pkg:npm/gamma@1.0.0"}  # same PURL, not merged
    assert {n["install_path"] for n in gammas} == {
        "node_modules/gamma", "node_modules/alpha/node_modules/gamma",
    }
    assert edge_pairs(graph) >= {
        ("cmp:alpha", "cmp:gamma-nested"), ("cmp:beta", "cmp:gamma-root"),
    }


def test_m3_ids_are_used_unchanged(fixture_payload):
    nodes = nodes_by_id(build(fixture_payload("chain")))
    assert {"root:demo", "cmp:alpha", "cmp:beta", "cmp:gamma"} <= set(nodes)


def test_edge_ids_are_stable_hashes_of_type_source_target(fixture_payload):
    graph = build(fixture_payload("chain"))
    for e in graph["edges"]:
        d = e["data"]
        assert d["id"] == stable_id("edge", d["type"], d["source"], d["target"])


def test_ids_do_not_depend_on_scan_id(fixture_payload):
    first = fixture_payload("unresolved")
    second = fixture_payload("unresolved")
    second["scan_id"] = "scan_00000000000000000000000000000000"
    a, b = build(first), build(second)
    assert [n["data"]["id"] for n in a["nodes"]] == [n["data"]["id"] for n in b["nodes"]]
    assert [e["data"]["id"] for e in a["edges"]] == [e["data"]["id"] for e in b["edges"]]


def test_unresolved_placeholder_differs_per_parent_declaration(fixture_payload):
    payload = fixture_payload("chain")
    target = {"name": "requests", "specifier": ">=2", "ecosystem": "npm"}
    for rid, src in (("rel:u1", "cmp:alpha"), ("rel:u2", "cmp:beta")):
        payload["relationships"].append(
            relationship(rid, src, None, resolution_status="unresolved",
                         unresolved_target=target)
        )
    placeholders = [n for n in build(payload)["nodes"] if n["data"]["type"] == "unresolved"]
    assert len(placeholders) == 2


def test_stable_id_is_unambiguous():
    assert stable_id("x", "a|b", "c") != stable_id("x", "a", "b|c")
    assert stable_id("x", "a") == stable_id("x", "a")

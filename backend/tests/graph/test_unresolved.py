from graph_helpers import build, component, edge_pairs, evidence, nodes_by_id, relationship


def _placeholder(graph: dict) -> dict:
    (node,) = [n["data"] for n in graph["nodes"] if n["data"]["type"] == "unresolved"]
    return node


def test_unresolved_declaration_becomes_placeholder(fixture_payload):
    graph = build(fixture_payload("unresolved"))
    node = _placeholder(graph)
    assert node["id"].startswith("unresolved:")
    assert node["label"] == "requests >=2"
    assert node["unresolved_target"] == {
        "name": "requests", "specifier": ">=2", "ecosystem": "pypi",
    }
    assert node["resolution_status"] == "unresolved"
    assert node["evidence"] == [evidence("requirements.txt", "manifest", "line:2")]
    assert node["depth"] == 1
    assert node["directness"] == "direct"

    (edge,) = [e["data"] for e in graph["edges"] if e["data"]["target"] == node["id"]]
    assert edge["source"] == "root:py"
    assert edge["resolution_status"] == "unresolved"
    assert graph["meta"]["stats"]["unresolved"] == 1


def test_unresolved_target_is_never_mapped_to_a_same_named_package(fixture_payload):
    payload = fixture_payload("unresolved")
    payload["components"].append(
        component("cmp:requests", "requests", "2.31.0", ecosystem="pypi",
                  purl="pkg:pypi/requests@2.31.0")
    )
    graph = build(payload)
    assert ("root:py", "cmp:requests") not in edge_pairs(graph)
    requests_pkg = nodes_by_id(graph)["cmp:requests"]
    assert requests_pkg["depth"] is None
    assert requests_pkg["directness"] == "unknown"
    assert _placeholder(graph)["unresolved_target"]["name"] == "requests"


def test_ambiguous_status_is_preserved(fixture_payload):
    payload = fixture_payload("unresolved")
    payload["relationships"][1]["resolution_status"] = "ambiguous"
    graph = build(payload)
    node = _placeholder(graph)
    assert node["resolution_status"] == "ambiguous"
    (edge,) = [e["data"] for e in graph["edges"] if e["data"]["target"] == node["id"]]
    assert edge["resolution_status"] == "ambiguous"


def test_unresolved_under_unreachable_parent_is_unknown(fixture_payload):
    payload = fixture_payload("unresolved")
    payload["components"].append(component("cmp:orphan", "orphan"))
    payload["relationships"].append(
        relationship("rel:orphan-x", "cmp:orphan", None, resolution_status="unresolved",
                     unresolved_target={"name": "x", "specifier": "*", "ecosystem": "npm"})
    )
    graph = build(payload)
    orphan_child = [n["data"] for n in graph["nodes"]
                    if n["data"]["type"] == "unresolved" and n["data"]["label"] == "x *"]
    assert orphan_child[0]["depth"] is None
    assert orphan_child[0]["directness"] == "unknown"


def test_transitive_unresolved_has_declaration_depth(fixture_payload):
    payload = fixture_payload("chain")
    payload["relationships"].append(
        relationship("rel:beta-x", "cmp:beta", None, resolution_status="unresolved",
                     unresolved_target={"name": "x", "specifier": "^1", "ecosystem": "npm"})
    )
    node = _placeholder(build(payload))
    assert node["depth"] == 3
    assert node["directness"] == "transitive"


def test_unresolved_does_not_count_toward_max_depth(fixture_payload):
    payload = fixture_payload("chain")
    payload["relationships"].append(
        relationship("rel:gamma-x", "cmp:gamma", None, resolution_status="unresolved",
                     unresolved_target={"name": "x", "specifier": "^1", "ecosystem": "npm"})
    )
    assert build(payload)["meta"]["stats"]["max_depth"] == 3

import pytest
from graph_helpers import build, component, edge_pairs, evidence, nodes_by_id, relationship

from app.graph import GraphValidationError, make_networkx_graph
from app.schemas.dependency import DependencyDocument


def test_chain_has_exact_edges(fixture_payload):
    graph = build(fixture_payload("chain"))
    assert edge_pairs(graph, "CONTAINS") == {("app:root", "root:demo")}
    assert edge_pairs(graph) == {
        ("root:demo", "cmp:alpha"),
        ("cmp:alpha", "cmp:beta"),
        ("cmp:beta", "cmp:gamma"),
    }


def test_contains_edges_carry_no_dependency_fields(fixture_payload):
    graph = build(fixture_payload("chain"))
    contains = [e["data"] for e in graph["edges"] if e["data"]["type"] == "CONTAINS"]
    assert contains and all(set(e) == {"id", "source", "target", "type"} for e in contains)


def test_application_and_project_nodes(fixture_payload):
    nodes = nodes_by_id(build(fixture_payload("chain"), app_name="my-repo"))
    assert nodes["app:root"] == {
        "id": "app:root", "label": "my-repo", "type": "application",
        "directness": "not_applicable", "depth": None,
    }
    assert nodes["root:demo"]["label"] == "demo-app (npm)"
    assert nodes["root:demo"]["project_path"] == ""


def test_package_node_keeps_m3_fields(fixture_payload):
    alpha = nodes_by_id(build(fixture_payload("chain")))["cmp:alpha"]
    assert alpha["name"] == "alpha"
    assert alpha["version"] == "1.0.0"
    assert alpha["purl"] == "pkg:npm/alpha@1.0.0"
    assert alpha["install_path"] == "node_modules/alpha"
    assert alpha["evidence"] == [
        evidence("package-lock.json", "lockfile", "packages.node_modules/alpha")
    ]


def test_no_implicit_networkx_nodes(fixture_payload):
    graph = make_networkx_graph(DependencyDocument.model_validate(fixture_payload("diamond")), "x")
    assert all("type" in data for _, data in graph.nodes(data=True))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda p: p["roots"].append(dict(p["roots"][0])), "Duplicate root id"),
        (lambda p: p["components"].append(dict(p["components"][0])), "Duplicate component id"),
        (lambda p: p["components"].append(component("root:demo", "clash")), "Duplicate component"),
        (lambda p: p["components"].append(component("app:root", "clash")), "may not be app:root"),
        (lambda p: p["roots"][0].update(root_id="app:root"), "may not be app:root"),
        (lambda p: p["relationships"].append(relationship("rel:x", "cmp:nope", "cmp:alpha")),
         "Unknown dependency source"),
        (lambda p: p["relationships"].append(relationship("rel:x", "app:root", "cmp:alpha")),
         "Only projects and packages"),
        (lambda p: p["relationships"].append(relationship("rel:x", "cmp:alpha", "cmp:missing")),
         "unknown component"),
        (lambda p: p["relationships"].append(relationship("rel:x", "cmp:alpha", "root:demo")),
         "unknown component"),
    ],
)
def test_invalid_documents_are_rejected(fixture_payload, mutate, message):
    payload = fixture_payload("chain")
    mutate(payload)
    with pytest.raises(GraphValidationError, match=message):
        build(payload)


def test_conflicting_duplicate_relationship_id_is_rejected(fixture_payload):
    payload = fixture_payload("chain")
    payload["relationships"].append(relationship("rel:demo-alpha", "root:demo", "cmp:beta"))
    with pytest.raises(GraphValidationError, match="Conflicting relationships"):
        build(payload)


def test_exact_duplicate_relationship_is_ignored_with_warning(fixture_payload):
    payload = fixture_payload("chain")
    payload["relationships"].append(dict(payload["relationships"][0]))
    graph = build(payload)
    assert graph["meta"]["stats"]["depends_on_edges"] == 3
    assert "Duplicate relationship rel:demo-alpha ignored" in graph["meta"]["warnings"]


def test_same_pair_from_two_relationships_merges_evidence(fixture_payload):
    payload = fixture_payload("chain")
    payload["relationships"].append(
        relationship("rel:demo-alpha-2", "root:demo", "cmp:alpha", locator="dependencies.alpha",
                     evidence=[evidence("package.json", "manifest", "dependencies.alpha")])
    )
    graph = build(payload)
    edges = [e["data"] for e in graph["edges"]
             if (e["data"]["source"], e["data"]["target"]) == ("root:demo", "cmp:alpha")]
    assert len(edges) == 1
    assert edges[0]["evidence"] == [
        evidence("package-lock.json", "lockfile", "packages[''].dependencies.alpha"),
        evidence("package.json", "manifest", "dependencies.alpha"),
    ]


def test_input_partial_and_warnings_pass_through(fixture_payload):
    payload = fixture_payload("chain")
    payload["partial"] = True
    payload["warnings"] = ["lockfile truncated"]
    graph = build(payload)
    assert graph["meta"]["partial"] is True
    assert graph["meta"]["warnings"] == ["lockfile truncated"]


def test_malformed_evidence_path_keeps_node_and_marks_partial(fixture_payload):
    payload = fixture_payload("chain")
    payload["components"][0]["evidence"] = [
        evidence("/home/user/repo/package-lock.json", "lockfile", "x")
    ]
    graph = build(payload)
    assert "cmp:alpha" in nodes_by_id(graph)
    assert graph["meta"]["partial"] is True
    assert any("cmp:alpha" in w and "repo-relative" in w for w in graph["meta"]["warnings"])


@pytest.mark.parametrize(
    ("path", "kind"),
    [("../escape.json", "lockfile"), ("C:/repo/package.json", "manifest"),
     ("https://example.com/x", "manifest"), ("dir\\file", "manifest"),
     ("other.cdx.json", "syft-sbom")],
)
def test_evidence_path_rules(fixture_payload, path, kind):
    payload = fixture_payload("chain")
    payload["relationships"][0]["evidence"] = [evidence(path, kind, "x")]
    assert build(payload)["meta"]["partial"] is True


def test_syft_sbom_evidence_is_valid(fixture_payload):
    payload = fixture_payload("chain")
    payload["components"].append(
        component("cmp:delta", "delta",
                  evidence=[evidence("sbom.cdx.json", "syft-sbom", "components[bom-ref=delta]")])
    )
    graph = build(payload)
    assert graph["meta"]["partial"] is False
    assert graph["meta"]["warnings"] == []

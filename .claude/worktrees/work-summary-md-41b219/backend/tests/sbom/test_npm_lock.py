import json

import pytest

from app.sbom.normalization import finalize
from app.sbom.npm_lock import (
    extract_npm_project,
    find_lockfile,
    is_valid_npm_name,
    name_from_location,
    npm_candidate_locations,
)

from .helpers import FIXTURES, SCAN_ID, edges, labels


def doc_for(repo, manifest="package.json", lock="package-lock.json"):
    return finalize(extract_npm_project(repo, manifest, lock), SCAN_ID)


# ---------------------------------------------------------------- lookup order


@pytest.mark.parametrize(
    ("parent", "expected"),
    [
        ("", ["node_modules/x"]),
        ("node_modules/a", ["node_modules/a/node_modules/x", "node_modules/x"]),
        (
            "node_modules/a/node_modules/b",
            [
                "node_modules/a/node_modules/b/node_modules/x",
                "node_modules/a/node_modules/x",
                "node_modules/x",
            ],
        ),
        (
            "node_modules/@s/a/node_modules/b",
            [
                "node_modules/@s/a/node_modules/b/node_modules/x",
                "node_modules/@s/a/node_modules/x",
                "node_modules/x",
            ],
        ),
        (
            "packages/lib",
            ["packages/lib/node_modules/x", "packages/node_modules/x", "node_modules/x"],
        ),
    ],
)
def test_candidate_order_is_nearest_first(parent, expected):
    assert npm_candidate_locations(parent, "x") == expected


def test_scoped_dependency_candidates():
    assert npm_candidate_locations("node_modules/a", "@scope/pkg") == [
        "node_modules/a/node_modules/@scope/pkg",
        "node_modules/@scope/pkg",
    ]


@pytest.mark.parametrize("bad", ["../evil", "a/b/c", "", "@scope", "x y", "/abs", "..", "UP/../x"])
def test_invalid_names_are_rejected_before_interpolation(bad):
    assert not is_valid_npm_name(bad)
    with pytest.raises(ValueError):
        npm_candidate_locations("", bad)


@pytest.mark.parametrize(
    ("location", "name"),
    [
        ("node_modules/a", "a"),
        ("node_modules/@s/a", "@s/a"),
        ("node_modules/a/node_modules/@s/b", "@s/b"),
        ("packages/lib", None),
        ("node_modules/a/extra/dir", None),
    ],
)
def test_name_from_location(location, name):
    assert name_from_location(location) == name


def test_lockfile_pairing_is_same_directory_only():
    locks = [
        "package-lock.json",
        "web/package-lock.json",
        "api/npm-shrinkwrap.json",
        "api/package-lock.json",
    ]
    assert find_lockfile("package.json", locks) == "package-lock.json"
    assert find_lockfile("web/package.json", locks) == "web/package-lock.json"
    assert (
        find_lockfile("api/package.json", locks) == "api/npm-shrinkwrap.json"
    )  # npm prefers shrinkwrap
    assert find_lockfile("web/sub/package.json", locks) is None  # never borrow a parent lock


# ---------------------------------------------------------------- fixtures

SIMPLE_EDGES = {
    ("ROOT:package.json", "alpha@1.0.0[node_modules/alpha]", "resolved"),
    ("ROOT:package.json", "devtool@0.5.1[node_modules/devtool]", "resolved"),
    ("alpha@1.0.0[node_modules/alpha]", "beta@2.0.0[node_modules/beta]", "resolved"),
    (
        "alpha@1.0.0[node_modules/alpha]",
        "nested@3.0.0[node_modules/alpha/node_modules/nested]",
        "resolved",
    ),
}


@pytest.mark.parametrize("fixture", ["npm_v3_simple", "npm_v2"])
def test_direct_and_transitive_edges_exactly_grounded(fixture):
    document = doc_for(FIXTURES / fixture)
    assert edges(document) == SIMPLE_EDGES
    assert document.partial is False
    assert [r.name for r in document.roots] == ["demo-app"]
    assert len(document.components) == 4


def test_component_fields_from_lockfile():
    document = doc_for(FIXTURES / "npm_v3_simple")
    by_name = {c.name: c for c in document.components}
    alpha = by_name["alpha"]
    assert alpha.purl == "pkg:npm/alpha@1.0.0"
    assert alpha.install_path == "node_modules/alpha"
    assert alpha.scope == "runtime"
    assert [lic.model_dump() for lic in alpha.licenses] == [
        {"id": "MIT", "name": None, "url": None}
    ]
    assert alpha.hashes[0].alg == "SHA-512" and len(alpha.hashes[0].content) == 128
    assert [e.model_dump() for e in alpha.evidence] == [
        {"path": "package-lock.json", "kind": "lockfile", "locator": "packages.node_modules/alpha"}
    ]
    assert by_name["devtool"].scope == "dev"  # root devDependency is not labelled runtime


def test_edges_carry_manifest_and_lock_evidence():
    document = doc_for(FIXTURES / "npm_v3_simple")
    names = labels(document)
    root_edge = next(
        r
        for r in document.relationships
        if names[r.to_id].startswith("alpha") and r.from_id.startswith("root:")
    )
    assert {(e.path, e.locator) for e in root_edge.evidence} == {
        ("package.json", "dependencies.alpha"),
        ("package-lock.json", "packages[''].dependencies.alpha"),
    }
    nested_edge = next(r for r in document.relationships if names[r.to_id].startswith("nested"))
    assert nested_edge.evidence[0].locator == "packages.node_modules/alpha.dependencies.nested"


def test_duplicate_installs_get_distinct_ids_and_correct_parents():
    document = doc_for(FIXTURES / "npm_duplicate")
    shared = [c for c in document.components if c.name == "shared"]
    assert len(shared) == 2
    assert len({c.component_id for c in shared}) == 2
    assert shared[0].purl != shared[1].purl
    assert edges(document) == {
        ("ROOT:package.json", "a@1.0.0[node_modules/a]", "resolved"),
        ("ROOT:package.json", "b@1.0.0[node_modules/b]", "resolved"),
        ("ROOT:package.json", "c@1.0.0[node_modules/c]", "resolved"),
        # multiple parents -> one instance, two incoming edges
        ("a@1.0.0[node_modules/a]", "shared@1.0.0[node_modules/shared]", "resolved"),
        ("c@1.0.0[node_modules/c]", "shared@1.0.0[node_modules/shared]", "resolved"),
        # nested copy wins over the hoisted one
        ("b@1.0.0[node_modules/b]", "shared@2.0.0[node_modules/b/node_modules/shared]", "resolved"),
        (
            "b@1.0.0[node_modules/b]",
            "@scope/util@1.2.0[node_modules/b/node_modules/@scope/util]",
            "resolved",
        ),
        # scoped nested package walks up to its parent's node_modules first
        (
            "@scope/util@1.2.0[node_modules/b/node_modules/@scope/util]",
            "shared@2.0.0[node_modules/b/node_modules/shared]",
            "resolved",
        ),
    }


def test_ambiguity_alias_missing_workspace_and_peers():
    document = doc_for(FIXTURES / "npm_ambiguity")
    assert edges(document) == {
        ("ROOT:package.json", "real-pkg@1.4.0[node_modules/good-alias]", "resolved"),
        ("ROOT:package.json", "?bad-alias", "unresolved"),  # alias target not verified
        ("ROOT:package.json", "?ghost", "unresolved"),  # missing lock entry
        ("ROOT:package.json", "?local-lib", "unresolved"),  # workspace link
        ("ROOT:package.json", "?fsevents", "unresolved"),  # optional, not installed
    }
    assert document.partial is True
    ghost = next(
        r
        for r in document.relationships
        if r.unresolved_target and r.unresolved_target.name == "ghost"
    )
    assert ghost.to_id is None
    assert ghost.unresolved_target.model_dump() == {
        "name": "ghost",
        "specifier": "^9.0.0",
        "ecosystem": "npm",
    }
    assert any("workspace/link" in w for w in document.warnings)
    assert any("peerDependencies" in w for w in document.warnings)
    # no component invented for anything unresolved
    assert {c.name for c in document.components} == {"real-pkg", "something-else"}


def test_missing_lockfile_keeps_declarations_unresolved(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "dependencies": {"a": "^1"}}))
    document = finalize(extract_npm_project(tmp_path, "package.json", None), SCAN_ID)
    assert edges(document) == {("ROOT:package.json", "?a", "unresolved")}
    assert document.components == []
    assert document.partial is True


@pytest.mark.parametrize(
    "lock",
    [
        {"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0"}}},
        {"lockfileVersion": 3},
        {"lockfileVersion": 3, "packages": []},
    ],
)
def test_unsupported_or_malformed_lock_is_partial_not_guessed(tmp_path, lock):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "dependencies": {"a": "1.0.0"}})
    )
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    document = doc_for(tmp_path)
    assert document.components == []
    assert edges(document) == {("ROOT:package.json", "?a", "unresolved")}
    assert document.partial is True and document.warnings


def test_broken_json_lock_is_reported(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    (tmp_path / "package-lock.json").write_text("{nope")
    document = doc_for(tmp_path)
    assert document.partial is True
    assert any("could not be read" in w for w in document.warnings)


def test_oversized_lock_is_rejected(tmp_path, monkeypatch):
    from app.sbom import npm_lock

    monkeypatch.setattr(npm_lock, "MAX_LOCKFILE_BYTES", 10)
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {}}))
    assert doc_for(tmp_path).partial is True


def test_unsafe_lock_keys_are_skipped(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "../outside/node_modules/a": {"version": "1.0.0"},
            "node_modules/ok": {"version": "1.0.0"},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    document = doc_for(tmp_path)
    assert [c.install_path for c in document.components] == ["node_modules/ok"]
    assert any("unsafe" in w for w in document.warnings)


def test_monorepo_subproject_paths_are_lockfile_relative(tmp_path):
    web = tmp_path / "web"
    web.mkdir()
    (web / "package.json").write_text(json.dumps({"name": "web", "dependencies": {"a": "1.0.0"}}))
    (web / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"a": "1.0.0"}},
                    "node_modules/a": {"version": "1.0.0"},
                },
            }
        )
    )
    document = doc_for(tmp_path, "web/package.json", "web/package-lock.json")
    (root,) = document.roots
    (component,) = document.components
    assert (root.path, root.manifest_path) == ("web", "web/package.json")
    assert (component.project_path, component.install_path) == ("web", "node_modules/a")
    assert component.evidence[0].path == "web/package-lock.json"


def test_entry_without_version_is_unresolved_component_without_purl(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "dependencies": {"a": "*"}}))
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {"dependencies": {"a": "*"}}, "node_modules/a": {}},
            }
        )
    )
    (component,) = doc_for(tmp_path).components
    assert component.version is None and component.purl is None and component.resolved is False

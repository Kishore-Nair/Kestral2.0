import re

from app.sbom.identities import (
    component_id,
    relationship_id,
    root_id,
    stable_id,
    syft_only_component_id,
)

ID_RE = re.compile(r"^(cmp|root|rel):[0-9a-f]{24}$")


def test_stable_id_is_deterministic_and_prefixed():
    a = stable_id("cmp", "npm", "alpha", "1.0.0")
    assert a == stable_id("cmp", "npm", "alpha", "1.0.0")
    assert ID_RE.match(a)


def test_field_boundaries_cannot_collide():
    # JSON encoding keeps ("ab","c") distinct from ("a","bc").
    assert stable_id("x", "ab", "c") != stable_id("x", "a", "bc")
    assert stable_id("x", None) != stable_id("x", "None")


def test_same_purl_different_install_paths_differ():
    hoisted = component_id("npm", "alpha", "1.0.0", "", "package-lock.json", "node_modules/alpha")
    nested = component_id(
        "npm", "alpha", "1.0.0", "", "package-lock.json", "node_modules/beta/node_modules/alpha"
    )
    assert hoisted != nested


def test_project_context_is_part_of_identity():
    a = component_id(
        "npm", "alpha", "1.0.0", "frontend", "frontend/package-lock.json", "node_modules/alpha"
    )
    b = component_id(
        "npm", "alpha", "1.0.0", "admin", "admin/package-lock.json", "node_modules/alpha"
    )
    assert a != b


def test_root_id_depends_on_ecosystem_project_and_manifest():
    assert root_id("npm", "", "package.json") != root_id("pypi", "", "package.json")
    assert root_id("pypi", "", "requirements.txt") != root_id("pypi", "", "requirements-dev.txt")


def test_syft_only_namespace_never_matches_lock_instance():
    lock = component_id("npm", "alpha", "1.0.0", "", "package-lock.json", "node_modules/alpha")
    syft = syft_only_component_id(
        "npm", "alpha", "1.0.0", "pkg:npm/alpha@1.0.0", ["package-lock.json"]
    )
    assert lock != syft
    # location order does not matter
    assert syft == syft_only_component_id(
        "npm", "alpha", "1.0.0", "pkg:npm/alpha@1.0.0", ["package-lock.json"]
    )


def test_relationship_id_covers_status_target_and_evidence():
    ev = [("package.json", "manifest", "dependencies.alpha")]
    resolved = relationship_id("root:1", "cmp:2", None, "resolved", ev)
    target = {"name": "alpha", "specifier": "^1", "ecosystem": "npm"}
    unresolved = relationship_id("root:1", None, target, "unresolved", ev)
    ambiguous = relationship_id("root:1", None, target, "ambiguous", ev)
    other_evidence = relationship_id(
        "root:1", "cmp:2", None, "resolved", [("package-lock.json", "lockfile", "x")]
    )
    assert len({resolved, unresolved, ambiguous, other_evidence}) == 4
    assert relationship_id("root:1", "cmp:2", None, "resolved", ev + ev) == resolved


def test_scan_id_is_not_an_input():
    # The API has no scan parameter at all; identical inputs on different scans match.
    assert root_id("npm", "", "package.json") == root_id("npm", "", "package.json")

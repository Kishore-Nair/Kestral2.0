import json
import shutil
from pathlib import Path

import pytest

from app.sbom import build_document, generate_dependency_document, pipeline
from app.sbom.normalization import DocumentIntegrityError, check_integrity
from app.sbom.syft_runner import SBOM_FILENAME, SyftExecutionError, SyftTimeoutError
from app.schemas.dependency import DependencyDocument

from .helpers import FIXTURES, SCAN_ID, edges, labels, make_inventory

HANDOFF = FIXTURES / "handoff"
SIMPLE = FIXTURES / "npm_v3_simple"


def lib(name, version, ref=None, ecosystem="npm", locations=("/package-lock.json",), **extra):
    purl = f"pkg:{ecosystem}/{name}@{version}" if version else None
    component = {
        "type": "library",
        "bom-ref": ref or f"{purl}?id={name}",
        "name": name,
        "version": version,
        "purl": purl,
        "properties": [
            {"name": f"syft:location:{i}:path", "value": loc} for i, loc in enumerate(locations)
        ],
    }
    component.update(extra)
    return component


def sbom(components, dependencies=()):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": list(components),
        "dependencies": list(dependencies),
    }


def build(repo, sbom_data, scan_id=SCAN_ID):
    return build_document(repo, make_inventory(repo, scan_id), scan_id, sbom_data)


# ---------------------------------------------------------------- reconciliation


def test_single_match_enriches_lock_instance_without_new_nodes():
    data = sbom(
        [
            lib(
                "alpha",
                "1.0.0",
                licenses=[{"license": {"id": "Apache-2.0"}}],
                hashes=[{"alg": "SHA-1", "content": "aa"}],
            )
        ]
    )
    document = build(SIMPLE, data)
    alpha = next(c for c in document.components if c.name == "alpha")
    assert [lic.id for lic in alpha.licenses] == ["MIT", "Apache-2.0"]  # "MIT" not duplicated
    assert ("SHA-1", "aa") in {(h.alg, h.content) for h in alpha.hashes}
    assert {"path": "sbom.cdx.json", "kind": "syft-sbom", "locator": "components[0]"} in [
        e.model_dump() for e in alpha.evidence
    ]
    assert len(document.components) == 4
    assert any("coverage discrepancy: 3" in w for w in document.warnings)


def test_syft_one_purl_two_lock_paths_does_not_collapse(tmp_path):
    shutil.copytree(FIXTURES / "npm_duplicate", tmp_path / "repo")
    repo = tmp_path / "repo"
    lock = json.loads((repo / "package-lock.json").read_text())
    lock["packages"]["node_modules/b/node_modules/shared"]["version"] = (
        "1.0.0"  # same version twice
    )
    (repo / "package-lock.json").write_text(json.dumps(lock))
    data = sbom(
        [
            lib(
                "shared",
                "1.0.0",
                hashes=[{"alg": "SHA-1", "content": "bb"}],
                licenses=[{"license": {"id": "MIT"}}],
            )
        ]
    )
    document = build(repo, data)
    shared = [c for c in document.components if c.name == "shared"]
    assert len(shared) == 2 and len({c.component_id for c in shared}) == 2
    for component in shared:
        assert [lic.id for lic in component.licenses] == ["MIT"]  # shared fact: on both
        assert component.hashes == []  # instance-specific fact: not guessed
        assert any(e.kind == "syft-sbom" for e in component.evidence)


def test_syft_only_components_live_in_unknown_namespace():
    action = lib(
        "actions/checkout", "v4", ecosystem="github", locations=("/.github/workflows/ci.yml",)
    )
    action["purl"] = "pkg:github/actions/checkout@v4"
    document = build(SIMPLE, sbom([action]))
    checkout = next(c for c in document.components if c.name == "actions/checkout")
    assert checkout.ecosystem == "github-actions"
    assert checkout.scope == "unknown" and checkout.install_path is None
    assert checkout.project_path == ".github/workflows"
    assert checkout.evidence[0].model_dump() == {
        "path": "sbom.cdx.json",
        "kind": "syft-sbom",
        "locator": "components[0]",
    }
    assert not [r for r in document.relationships if checkout.component_id in (r.from_id, r.to_id)]
    assert document.partial is True


def test_syft_without_location_is_not_merged_by_name_alone():
    document = build(SIMPLE, sbom([lib("alpha", "1.0.0", locations=())]))
    alphas = [c for c in document.components if c.name == "alpha"]
    assert len(alphas) == 2  # lock instance + separate Syft-only record


def test_project_itself_is_not_a_dependency_component():
    document = build(SIMPLE, sbom([lib("demo-app", "1.0.0")]))
    assert "demo-app" not in {c.name for c in document.components}


def test_lockfile_edges_win_over_syft_dependency_claims():
    # Real Syft links alpha to every 'beta' by name; the lock proves only one.
    data = sbom(
        [
            lib("alpha", "1.0.0", ref="a"),
            lib("beta", "2.0.0", ref="b"),
            lib("nested", "3.0.0", ref="n"),
        ],
        [{"ref": "a", "dependsOn": ["b", "n"]}, {"ref": "b", "dependsOn": ["n"]}],
    )
    document = build(SIMPLE, data)
    names = labels(document)
    assert (
        "beta@2.0.0[node_modules/beta]",
        "nested@3.0.0[node_modules/alpha/node_modules/nested]",
        "resolved",
    ) not in edges(document)
    assert all(e.kind != "syft-sbom" for r in document.relationships for e in r.evidence)
    assert any("authoritative" in w for w in document.warnings)
    assert len(names) == 5


def test_syft_edges_used_only_between_syft_only_components():
    x = lib("x", "1.0.0", ref="x", locations=("/vendor/x.json",))
    y = lib("y", "1.0.0", ref="y", locations=("/vendor/y.json",))
    data = sbom([x, y], [{"ref": "x", "dependsOn": ["y", "unknown-ref"]}])
    document = build(SIMPLE, data)
    assert ("x@1.0.0[vendor]", "y@1.0.0[vendor]", "resolved") in edges(document)
    rel = next(r for r in document.relationships if r.evidence[0].kind == "syft-sbom")
    assert rel.evidence[0].locator == "dependencies[0].dependsOn[0]"


def test_syft_edge_to_ambiguous_target_is_kept_ambiguous(tmp_path):
    shutil.copytree(FIXTURES / "npm_duplicate", tmp_path / "repo")
    repo = tmp_path / "repo"
    lock = json.loads((repo / "package-lock.json").read_text())
    lock["packages"]["node_modules/b/node_modules/shared"]["version"] = "1.0.0"
    (repo / "package-lock.json").write_text(json.dumps(lock))
    tool = lib("tool", "1.0.0", ref="t", locations=("/tools/x.json",))
    data = sbom([tool, lib("shared", "1.0.0", ref="s")], [{"ref": "t", "dependsOn": ["s"]}])
    document = build(repo, data)
    rel = next(r for r in document.relationships if r.evidence[0].kind == "syft-sbom")
    assert rel.resolution_status == "ambiguous" and rel.to_id is None
    assert rel.unresolved_target.model_dump() == {
        "name": "shared",
        "specifier": "1.0.0",
        "ecosystem": "npm",
    }


def test_duplicate_bom_refs_are_not_mapped():
    data = sbom(
        [
            lib("x", "1.0.0", ref="dup", locations=("/a",)),
            lib("y", "1.0.0", ref="dup", locations=("/b",)),
        ],
        [{"ref": "dup", "dependsOn": ["dup"]}],
    )
    document = build(SIMPLE, data)
    assert all(e.kind != "syft-sbom" for r in document.relationships for e in r.evidence)


# ---------------------------------------------------------------- whole pipeline


def test_monorepo_inventory_with_unsupported_files(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(SIMPLE, repo / "web")
    shutil.copytree(FIXTURES / "python_uv", repo / "api")
    (repo / "go.mod").write_text("module x\n")
    (repo / "orphan").mkdir()
    (repo / "orphan" / "package-lock.json").write_text("{}")
    inventory = make_inventory(repo).model_copy(update={"partial": True})
    inventory.manifests.append(
        type(inventory.manifests[0])(path="go.mod", kind="go.mod", ecosystem="go")
    )
    document = build_document(repo, inventory, SCAN_ID, None)
    assert sorted((r.manifest_path, r.ecosystem) for r in document.roots) == [
        ("api/pyproject.toml", "pypi"),
        ("web/package.json", "npm"),
    ]
    assert ("ROOT:web/package.json", "alpha@1.0.0[node_modules/alpha]", "resolved") in edges(
        document
    )
    assert ("ROOT:api/pyproject.toml", "httpx@0.27.0[api]", "resolved") in edges(document)
    text = "\n".join(document.warnings)
    assert "inventory is partial" in text
    assert "go.mod: go.mod manifests are not supported" in text
    assert "orphan/package-lock.json: no package.json" in text


def test_unsafe_inventory_paths_are_ignored(tmp_path):
    inventory = make_inventory(SIMPLE)
    entry = type(inventory.manifests[0])
    inventory.manifests.append(
        entry(path="../../etc/package.json", kind="package.json", ecosystem="npm")
    )
    inventory.manifests.append(
        entry(path="/abs/package.json", kind="package.json", ecosystem="npm")
    )
    document = build_document(SIMPLE, inventory, SCAN_ID, None)
    assert len(document.roots) == 1
    assert sum("unsafe manifest path" in w for w in document.warnings) == 1  # deduplicated


def test_same_fixture_twice_is_byte_identical_except_scan_id():
    first = build(SIMPLE, None, "scan_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").model_dump(mode="json")
    second = build(SIMPLE, None, "scan_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").model_dump(mode="json")
    assert first.pop("scan_id") != second.pop("scan_id")
    assert json.dumps(first, sort_keys=False) == json.dumps(second, sort_keys=False)


def test_records_are_sorted_for_repeatability():
    document = build(FIXTURES / "npm_duplicate", None)
    for items, key in (
        (document.roots, "root_id"),
        (document.components, "component_id"),
        (document.relationships, "relationship_id"),
    ):
        ids = [getattr(i, key) for i in items]
        assert ids == sorted(ids)


@pytest.mark.parametrize(
    "fixture",
    [
        "npm_v3_simple",
        "npm_v2",
        "npm_duplicate",
        "npm_ambiguity",
        "python_requirements",
        "python_poetry",
        "python_uv",
    ],
)
def test_every_fixture_satisfies_invariants_and_has_real_evidence(fixture):
    repo = FIXTURES / fixture
    document = build(repo, None)
    payload = document.model_dump(mode="json")
    check_integrity(payload)
    DependencyDocument.model_validate(payload)
    for item in [e for c in document.components for e in c.evidence] + [
        e for r in document.relationships for e in r.evidence
    ]:
        assert (repo / item.path).is_file(), f"evidence points at missing file {item.path}"
    if any(r.resolution_status != "resolved" for r in document.relationships):
        assert document.partial is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["relationships"][0].update(to_id="cmp:doesnotexist"),
        lambda d: d["relationships"][0].update(from_id="cmp:doesnotexist"),
        lambda d: d["relationships"][0].update(resolution_status="unresolved"),
        lambda d: d["components"][0].update(evidence=[]),
        lambda d: d["components"].append(dict(d["components"][0])),
        lambda d: d["components"][0]["evidence"][0].update(path="/etc/passwd"),
        lambda d: d["roots"][0].update(root_id="root:" + SCAN_ID),
    ],
)
def test_integrity_checker_rejects_violations(mutate):
    payload = build(SIMPLE, None).model_dump(mode="json")
    mutate(payload)
    with pytest.raises(DocumentIntegrityError):
        check_integrity(payload)


def test_readme_example_validates_against_contract():
    readme_example = {
        "schema_version": "1.0",
        "scan_id": SCAN_ID,
        "roots": [
            {
                "root_id": "root:6d7e",
                "name": "fixture-app",
                "path": "",
                "manifest_path": "package.json",
                "ecosystem": "npm",
            }
        ],
        "components": [
            {
                "component_id": "cmp:1a2b3c",
                "name": "express",
                "version": "4.18.2",
                "ecosystem": "npm",
                "purl": "pkg:npm/express@4.18.2",
                "install_path": "node_modules/express",
                "project_path": "",
                "scope": "runtime",
                "licenses": [],
                "hashes": [],
                "evidence": [
                    {
                        "path": "package-lock.json",
                        "kind": "lockfile",
                        "locator": "packages.node_modules/express",
                    }
                ],
                "resolved": True,
            }
        ],
        "relationships": [
            {
                "relationship_id": "rel:9a8b7c",
                "from_id": "root:6d7e",
                "to_id": "cmp:1a2b3c",
                "unresolved_target": None,
                "resolution_status": "resolved",
                "type": "DEPENDS_ON",
                "evidence": [
                    {
                        "path": "package-lock.json",
                        "kind": "lockfile",
                        "locator": "packages[''].dependencies.express",
                    }
                ],
            }
        ],
        "partial": False,
        "warnings": [],
    }
    DependencyDocument.model_validate(readme_example)
    check_integrity(readme_example)


# ---------------------------------------------------------------- Syft boundary


def test_generate_writes_sbom_and_returns_document(tmp_path, monkeypatch):
    def fake_run_syft(repo_dir, scan_dir, timeout):
        scan_dir.mkdir(parents=True, exist_ok=True)
        data = sbom([lib("alpha", "1.0.0")])
        (scan_dir / SBOM_FILENAME).write_text(json.dumps(data))
        return data

    monkeypatch.setattr(pipeline, "run_syft", fake_run_syft)
    scan_dir = tmp_path / "scan"
    document = generate_dependency_document(SIMPLE, make_inventory(SIMPLE), SCAN_ID, scan_dir)
    assert (scan_dir / SBOM_FILENAME).is_file()
    assert document.schema_version == "1.0" and document.scan_id == SCAN_ID
    assert sorted(p.name for p in scan_dir.iterdir()) == [SBOM_FILENAME]  # no normalized.json


@pytest.mark.parametrize(
    "error", [SyftTimeoutError("Syft timed out"), SyftExecutionError("exit 1")]
)
def test_syft_failure_propagates_as_typed_error(tmp_path, monkeypatch, error):
    def failing(*args, **kwargs):
        raise error

    monkeypatch.setattr(pipeline, "run_syft", failing)
    with pytest.raises(type(error)):
        generate_dependency_document(SIMPLE, make_inventory(SIMPLE), SCAN_ID, tmp_path / "scan")
    assert not (tmp_path / "scan" / SBOM_FILENAME).exists()


@pytest.mark.skipif(shutil.which("syft") is None, reason="syft not installed")
def test_real_syft_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(SIMPLE, repo)
    scan_dir = tmp_path / "scans" / "scan_1"
    document = generate_dependency_document(
        repo, make_inventory(repo), SCAN_ID, scan_dir, syft_timeout=120
    )
    raw = json.loads((scan_dir / SBOM_FILENAME).read_text())
    assert raw["bomFormat"] == "CycloneDX"
    # Graph edges come from the lockfile, exactly; Syft only adds evidence.
    assert edges(document) == {
        ("ROOT:package.json", "alpha@1.0.0[node_modules/alpha]", "resolved"),
        ("ROOT:package.json", "devtool@0.5.1[node_modules/devtool]", "resolved"),
        ("alpha@1.0.0[node_modules/alpha]", "beta@2.0.0[node_modules/beta]", "resolved"),
        (
            "alpha@1.0.0[node_modules/alpha]",
            "nested@3.0.0[node_modules/alpha/node_modules/nested]",
            "resolved",
        ),
    }
    alpha = next(c for c in document.components if c.name == "alpha")
    assert {e.kind for e in alpha.evidence} == {"lockfile", "syft-sbom"}
    check_integrity(document.model_dump(mode="json"))


# ---------------------------------------------------------------- handoff golden


def test_handoff_golden_normalized_document():
    """Frozen real Syft output + fixture repo -> exactly the committed normalized.json."""
    raw = json.loads((HANDOFF / "sbom.cdx.json").read_text())
    expected = json.loads((HANDOFF / "normalized.json").read_text())
    document = build(SIMPLE, raw)
    assert document.model_dump(mode="json") == expected


def test_handoff_golden_is_self_consistent():
    expected = json.loads((HANDOFF / "normalized.json").read_text())
    check_integrity(expected)
    assert Path(HANDOFF / "README.md").is_file()

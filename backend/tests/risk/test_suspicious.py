"""Suspicious-change detectors and the scan-to-scan diff (all inputs local, no network)."""

import json
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.database.models import Scan
from app.database.scans import previous_completed_scan
from app.graph.builder import make_networkx_graph
from app.risk.analyzer import analyze_risk
from app.risk.changes import Baseline, change_findings, compare
from app.risk.suspicious import (
    _Index,
    container_findings,
    escalate,
    lookalike,
    npm_lockfile_findings,
    package_json_findings,
    requirements_findings,
    suspicious_findings,
    typosquat_findings,
    uv_lock_findings,
)
from app.schemas.inventory import FileEntry, Inventory
from tests.risk.risk_helpers import SCAN_ID, comp, document, rel

LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo"},
        "node_modules/esbuild": {
            "version": "0.20.0",
            "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
            "integrity": "sha512-abc",
            "hasInstallScript": True,
        },
        "node_modules/grunt-if": {
            "version": "0.2.0",
            "resolved": "https://github.com/someone/grunt-if/tarball/master",
            "integrity": "sha1-xyz",
            "dev": True,
        },
        "node_modules/plain": {"version": "1.0.0", "resolved": "http://example.test/plain.tgz"},
        "node_modules/fsevents/node_modules/abbrev": {"version": "1.1.1", "inBundle": True},
        "node_modules/local": {"resolved": "../local", "link": True},
    },
}


def graph_doc():
    return document(
        [
            comp("cmp:esbuild", "esbuild", "0.20.0"),
            comp("cmp:grunt-if", "grunt-if", "0.2.0", scope="dev"),
            comp("cmp:plain", "plain", "1.0.0"),
            comp("cmp:expresss", "expresss", "1.0.0"),
        ],
        [
            rel("r1", "root:demo", "cmp:esbuild"),
            rel("r2", "root:demo", "cmp:grunt-if"),
            rel("r3", "cmp:esbuild", "cmp:plain"),
        ],
    )


def by_category(findings):
    return {(f.category, f.subject_label): f for f in findings}


def test_npm_lockfile_flags_scripts_sources_and_missing_integrity() -> None:
    doc = graph_doc()
    graph = make_networkx_graph(doc, "demo")
    findings, warnings = npm_lockfile_findings(
        "package-lock.json", json.dumps(LOCK), _Index.build(doc), graph
    )
    found = by_category(findings)
    assert warnings == []
    assert set(found) == {
        ("install_script", "esbuild@0.20.0"),
        ("untrusted_source", "grunt-if@0.2.0"),
        ("untrusted_source", "plain@1.0.0"),
        ("missing_integrity", "plain@1.0.0"),
    }
    script = found[("install_script", "esbuild@0.20.0")]
    assert script.subject_id == "cmp:esbuild"
    assert script.directness == "direct"
    assert script.risk_level == "medium"
    assert script.evidence[0].locator == "packages.node_modules/esbuild hasInstallScript"
    git = found[("untrusted_source", "grunt-if@0.2.0")]
    assert git.risk_level == "high" and "branch 'master'" in (git.risk_reason or "")
    plain = found[("untrusted_source", "plain@1.0.0")]
    assert plain.risk_level == "high" and plain.directness == "transitive"
    assert plain.dependency_paths == [["root:demo", "cmp:esbuild", "cmp:plain"]]


def test_npm_lockfile_v1_and_bad_json() -> None:
    v1 = {
        "dependencies": {
            "a": {"version": "1.0.0", "resolved": "git+https://github.com/x/a.git#" + "a" * 40},
        }
    }
    findings, _ = npm_lockfile_findings("package-lock.json", json.dumps(v1), _Index(), None)
    assert [(f.category, f.risk_level) for f in findings] == [
        ("untrusted_source", "medium"),
        ("missing_integrity", "medium"),
    ]
    assert npm_lockfile_findings("package-lock.json", "{", _Index(), None)[1] == [
        "package-lock.json is not valid JSON and was not checked for suspicious entries"
    ]


def test_uv_lock_and_requirements_sources() -> None:
    uv = """
[[package]]
name = "flask"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "forked"
version = "0.1.0"
source = { git = "https://github.com/x/forked?branch=main" }

[[package]]
name = "internal"
version = "2.0.0"
source = { registry = "https://pkgs.example.test/simple" }

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
"""
    findings, _ = uv_lock_findings("uv.lock", uv, _Index(), None)
    assert [(f.subject_label, f.risk_level) for f in findings] == [
        ("forked@0.1.0", "high"),
        ("internal@2.0.0", "medium"),
    ]
    reqs = requirements_findings(
        "requirements.txt",
        "# comment\nflask==3.0\n--extra-index-url https://pkgs.example.test/simple\n"
        "--index-url https://pypi.org/simple\n"
        "mylib @ git+https://github.com/x/mylib@main\n",
    )
    assert [(f.title, f.risk_level) for f in reqs] == [
        ("Extra package index https://pkgs.example.test/simple", "high"),
        ("Requirement installed from git+https://github.com/x/mylib@main", "high"),
    ]
    assert reqs[0].evidence[0].locator.startswith("line 3: --extra-index-url")


def test_package_json_loose_specifiers() -> None:
    text = json.dumps(
        {"dependencies": {"a": "^1.0.0", "b": "latest"}, "devDependencies": {"c": "*"}}, indent=2
    )
    findings = package_json_findings("package.json", text, _Index(), None)
    assert [(f.subject_label, f.risk_level) for f in findings] == [("b", "medium"), ("c", "low")]
    assert findings[0].evidence[0].locator == 'line 4: dependencies.b: "latest"'


def test_container_images() -> None:
    dockerfile = (
        "FROM node:20 AS build\nFROM build\nFROM scratch\n# FROM ignored\n"
        "FROM alpine@sha256:" + "a" * 64 + "\nFROM --platform=linux/amd64 ubuntu\n"
        "FROM $BASE\n"
    )
    findings = container_findings("Dockerfile", dockerfile)
    assert [(f.subject_label, f.risk_level) for f in findings] == [
        ("node:20", "medium"),
        ("ubuntu", "high"),
        ("$BASE", "low"),
    ]
    compose = container_findings(
        "docker-compose.yml", "services:\n  db:\n    image: mongo:latest\n"
    )
    assert compose[0].title == "mongo:latest: service image not pinned by digest"
    assert compose[0].evidence[0].locator == "line 3: image: mongo:latest"


def test_typosquat_lookalikes_use_real_popular_lists() -> None:
    assert lookalike("npm", "expresss") == ("express", lookalike("npm", "expresss")[1])
    assert lookalike("npm", "lodsah")[0] == "lodash"  # adjacent swap
    assert lookalike("pypi", "reqeusts")[0] == "requests"
    assert lookalike("npm", "express") is None  # the real package
    assert lookalike("npm", "prompt") is None  # established, though close to 'prompts'
    assert lookalike("npm", "@acme/expresss") is None  # scoped
    assert lookalike("npm", "abc") is None  # too short to judge
    assert lookalike("maven", "expresss") is None
    doc = graph_doc()
    findings = typosquat_findings(doc, make_networkx_graph(doc, "demo"))
    assert [f.subject_label for f in findings] == ["expresss@1.0.0"]
    assert findings[0].evidence[1].path == "popular_npm.txt"
    assert "express" in findings[0].evidence[1].locator


def test_escalate_stacks_signals_on_one_package() -> None:
    doc = graph_doc()
    lock = json.loads(json.dumps(LOCK))
    lock["packages"]["node_modules/expresss"] = {
        "version": "1.0.0",
        "resolved": "https://registry.npmjs.org/expresss/-/expresss-1.0.0.tgz",
        "integrity": "sha512-q",
        "hasInstallScript": True,
    }
    graph = make_networkx_graph(doc, "demo")
    findings, _ = npm_lockfile_findings(
        "package-lock.json", json.dumps(lock), _Index.build(doc), graph
    )
    raised = by_category(escalate([*findings, *typosquat_findings(doc, graph)]))
    script = raised[("install_script", "expresss@1.0.0")]
    assert script.risk_level == "high"
    assert "also flagged for typosquat" in (script.risk_reason or "")
    assert raised[("typosquat", "expresss@1.0.0")].risk_level == "high"
    assert raised[("install_script", "esbuild@0.20.0")].risk_level == "medium"  # alone


def make_inventory(**files) -> Inventory:
    return Inventory(
        scan_id=SCAN_ID,
        languages=[],
        manifests=files.get("manifests", []),
        lockfiles=files.get("lockfiles", []),
        dockerfiles=files.get("dockerfiles", []),
        ci_files=[],
        iac_files=[],
        existing_sboms=[],
        source_directories=[],
        file_count=1,
        partial=False,
        warnings=[],
    )


def test_suspicious_findings_reads_repo_files_safely(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM node\n", encoding="utf-8")
    (tmp_path / "package.json").symlink_to(tmp_path / "Dockerfile")
    inventory = make_inventory(
        lockfiles=[FileEntry(path="package-lock.json", kind="package-lock.json", ecosystem="npm")],
        manifests=[FileEntry(path="package.json", kind="package.json", ecosystem="npm")],
        dockerfiles=["Dockerfile"],
    )
    findings, warnings, checked = suspicious_findings(tmp_path, inventory, graph_doc(), None)
    assert checked == 2
    assert warnings == ["package.json could not be read safely and was not checked"]
    assert {f.category for f in findings} == {
        "install_script",
        "untrusted_source",
        "missing_integrity",
        "unpinned_image",
        "typosquat",
    }


def baseline_doc():
    return document(
        [
            comp("cmp:esbuild-old", "esbuild", "0.21.0"),
            comp("cmp:grunt-if", "grunt-if", "0.2.0"),
            comp("cmp:gone", "left-pad", "1.3.0"),
        ],
        [],
    )


BASE = Baseline("scan_" + "1" * 32, Path("/nowhere"), "a" * 40, "main", "2026-11-23T00:00:00")


def test_compare_lists_added_removed_and_downgraded() -> None:
    summary = compare(
        graph_doc(),
        baseline_doc(),
        BASE,
        "b" * 40,
        {"package.json": "1", "package-lock.json": "2"},
        {"package.json": "1", "package-lock.json": "OLD", "Dockerfile": "x"},
    )
    assert [c.name for c in summary.added] == ["expresss", "plain"]
    assert [c.name for c in summary.removed] == ["left-pad"]
    assert [(c.name, c.from_versions, c.to_versions) for c in summary.downgraded] == [
        ("esbuild", ["0.21.0"], ["0.20.0"])
    ]
    assert summary.totals["upgraded"] == 0
    assert [(f.path, f.change) for f in summary.files_changed] == [
        ("Dockerfile", "removed"),
        ("package-lock.json", "modified"),
    ]
    assert not summary.same_commit


def test_change_findings_explain_unexpected_and_drift() -> None:
    doc = graph_doc()
    inventory = make_inventory(
        lockfiles=[FileEntry(path="package-lock.json", kind="package-lock.json", ecosystem="npm")],
        manifests=[FileEntry(path="package.json", kind="package.json", ecosystem="npm")],
    )
    summary = compare(
        doc,
        baseline_doc(),
        BASE,
        "b" * 40,
        {"package.json": "1", "package-lock.json": "2"},
        {"package.json": "1", "package-lock.json": "OLD"},
    )
    findings = by_category(
        change_findings(summary, doc, inventory, make_networkx_graph(doc, "demo"))
    )
    assert set(found_key for found_key in findings) == {
        ("unexpected_dependency", "expresss@1.0.0"),
        ("unexpected_dependency", "plain@1.0.0"),
        ("version_downgrade", "esbuild 0.21.0 → 0.20.0"),
        ("lockfile_drift", "package-lock.json"),
    }
    plain = findings[("unexpected_dependency", "plain@1.0.0")]
    assert plain.subject_id == "cmp:plain" and plain.directness == "transitive"
    assert plain.evidence[-1].path == "changes.json"

    # Manifest changed too: new packages are expected, so only low-risk notes, no drift.
    summary = compare(
        doc, baseline_doc(), BASE, None, {"package.json": "NEW"}, {"package.json": "1"}
    )
    kinds = {f.category for f in change_findings(summary, doc, inventory, None)}
    assert kinds == {"new_dependency", "version_downgrade"}


def test_analyzer_compares_with_baseline_scan(tmp_path: Path) -> None:
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    (base_dir / "normalized.json").write_text(baseline_doc().model_dump_json(), encoding="utf-8")
    (base_dir / "supply_chain.json").write_text(json.dumps({"files": {}}), encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    result = analyze_risk(
        tmp_path / "repo",
        make_inventory(),
        graph_doc(),
        SCAN_ID,
        out,
        "demo",
        osv_enabled=False,
        grype_enabled=False,
        baseline=Baseline("scan_" + "1" * 32, base_dir, "a" * 40, "main", None),
        current_commit="a" * 40,
    )
    assert result.changes is not None and result.changes.same_commit
    diff = next(s for s in result.sources if s.name == "scan-diff")
    assert diff.status == "ok" and diff.raw_output == "changes.json"
    assert "2 added, 1 removed, 0 upgraded, 1 downgraded" in (diff.message or "")
    assert result.stats.suspicious == len([f for f in result.findings if f.kind == "suspicious"])
    assert {p.name for p in out.iterdir()} == {"changes.json", "supply_chain.json"}

    missing = analyze_risk(
        tmp_path / "repo",
        make_inventory(),
        graph_doc(),
        SCAN_ID,
        out,
        "demo",
        osv_enabled=False,
        grype_enabled=False,
        baseline=Baseline("scan_" + "2" * 32, tmp_path / "nope", None, None, None),
    )
    assert next(s for s in missing.sources if s.name == "scan-diff").status == "failed"
    assert missing.partial


def test_previous_completed_scan_picks_latest_same_repository() -> None:
    from datetime import UTC, datetime

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()

    def scan(sid, url, status, day, normalized="x"):
        db.add(
            Scan(
                scan_id=sid,
                repository_url=url,
                owner="o",
                repository_name="r",
                status=status,
                normalized_path=normalized,
                finished_at=datetime(2026, 11, day, tzinfo=UTC),
            )
        )

    scan("s1", "https://github.com/o/r", "COMPLETED", 1)
    scan("s2", "https://github.com/o/r", "COMPLETED", 3)
    scan("s3", "https://github.com/o/r", "FAILED", 4)
    scan("s4", "https://github.com/o/other", "COMPLETED", 5)
    scan("cur", "https://github.com/o/r", "ANALYZING_RISK", 6)
    db.commit()
    current = db.get(Scan, "cur")
    assert previous_completed_scan(db, current).scan_id == "s2"


def test_compare_excludes_packages_from_an_extraction_gap() -> None:
    # The earlier scan extracted nothing from package-lock.json (e.g. unsupported v1 lockfile).
    empty = document([], [])
    files = {"package.json": "1", "package-lock.json": "2"}
    summary = compare(graph_doc(), empty, BASE, None, files, {**files, "package-lock.json": "1"})
    assert summary.added == [] and summary.totals["excluded"] == 4
    assert summary.extraction_gaps == ["package-lock.json"]
    assert "no packages were extracted from it in the earlier scan" in summary.caveats[0]

    # The lockfile itself is new: its packages are a real addition, not a gap.
    summary = compare(graph_doc(), empty, BASE, None, files, {"package.json": "1"})
    assert len(summary.added) == 4 and summary.extraction_gaps == []


def test_plain_http_with_integrity_is_medium_and_v1_locator_is_nested() -> None:
    v1 = {
        "dependencies": {
            "npm": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/npm/-/npm-1.0.0.tgz",
                "integrity": "sha1-a",
                "dependencies": {
                    "nan": {
                        "version": "1.0.0",
                        "resolved": "http://registry.npmjs.org/nan/-/nan-1.0.0.tgz",
                        "integrity": "sha1-b",
                    }
                },
            }
        }
    }
    [finding], _ = npm_lockfile_findings("package-lock.json", json.dumps(v1), _Index(), None)
    assert finding.risk_level == "medium"
    assert finding.evidence[0].locator.startswith("dependencies.npm.dependencies.nan resolved=http")

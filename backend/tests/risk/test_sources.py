import json
import subprocess
from pathlib import Path

import pytest
from risk_helpers import SCAN_ID, demo_document, grype_match, osv_record

from app.risk import analyze_risk
from app.risk import grype as grype_module
from app.risk.grype import GrypeError, GrypeResult, run_grype
from app.risk.osv import BATCH_SIZE, OsvError, OsvResult, query_osv
from app.risk.workflows import workflow_findings
from app.schemas.inventory import Inventory

LODASH = "pkg:npm/lodash@4.17.15"


# ---------- OSV ----------


def test_osv_batches_and_fetches_each_record_once() -> None:
    purls = [f"pkg:npm/p{i}@1.0.0" for i in range(BATCH_SIZE + 3)]
    posts, gets = [], []

    def post(url, payload, timeout):
        posts.append(len(payload["queries"]))
        return {
            "results": [
                {"vulns": [{"id": "GHSA-1"}]}
                if q["package"]["purl"] in ("pkg:npm/p0@1.0.0", "pkg:npm/p1@1.0.0")
                else {}
                for q in payload["queries"]
            ]
        }

    def get(url, timeout):
        gets.append(url)
        return osv_record("GHSA-1", "p0", [])

    result = query_osv(purls, post_json=post, get_json=get)
    assert posts == [BATCH_SIZE, 3]
    assert gets == ["https://api.osv.dev/v1/vulns/GHSA-1"]
    assert result.matches == {"pkg:npm/p0@1.0.0": ["GHSA-1"], "pkg:npm/p1@1.0.0": ["GHSA-1"]}
    assert set(result.raw()) == {"source", "retrieved_at", "matches", "records"}


def test_osv_network_failure_raises_safe_error() -> None:
    def post(*_):
        raise OSError("connection refused to 10.0.0.1")

    with pytest.raises(OsvError, match="OSV query failed: OSError"):
        query_osv([LODASH], post_json=post)


def test_osv_bad_shape_and_missing_record_are_reported() -> None:
    with pytest.raises(OsvError, match="unexpected batch"):
        query_osv([LODASH], post_json=lambda *_: {"results": []})

    def get(*_):
        raise TimeoutError

    result = query_osv(
        [LODASH],
        post_json=lambda *_: {"results": [{"vulns": [{"id": "GHSA-1"}], "next_page_token": "x"}]},
        get_json=get,
    )
    assert result.records == {}
    assert "OSV record GHSA-1 could not be fetched" in result.warnings
    assert f"OSV results for {LODASH} were truncated" in result.warnings


# ---------- Grype ----------


def fake_grype(monkeypatch, stdout: str, returncode: int = 0):
    calls = []
    monkeypatch.setattr(grype_module.shutil, "which", lambda _: "/usr/bin/grype")

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        purl_file = Path(command[1].removeprefix("purl:"))
        assert purl_file.read_text(encoding="utf-8") == f"{LODASH}\n"
        return subprocess.CompletedProcess(command, returncode, stdout, "/secret/host/path")

    return calls, runner


def grype_stdout() -> str:
    return json.dumps(
        {
            "matches": [grype_match("GHSA-1", LODASH, ["CVE-1"])],
            "descriptor": {
                "name": "grype",
                "version": "0.122.1",
                "timestamp": "t",
                "configuration": {"secret": "x"},
                "db": {
                    "status": {
                        "built": "2026-11-23T06:28:32Z",
                        "path": "/Users/me/db",
                        "valid": True,
                        "schemaVersion": "v6",
                        "from": "https://grype.anchore.io/x",
                    }
                },
            },
        }
    )


def test_grype_runs_offline_with_safe_environment(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "do-not-leak")
    calls, runner = fake_grype(monkeypatch, grype_stdout())
    result = run_grype([LODASH], tmp_path, runner=runner)
    command, kwargs = calls[0]
    assert command[0] == "/usr/bin/grype" and command[2:] == ["-o", "json", "-q"]
    assert kwargs["shell"] is False
    assert kwargs["env"]["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert "GITHUB_TOKEN" not in kwargs["env"]
    assert result.tool_version == "0.122.1"
    assert result.database_built == "2026-11-23T06:28:32Z"
    assert "configuration" not in result.raw["descriptor"]
    assert "path" not in result.raw["descriptor"]["db"]
    assert not list(tmp_path.iterdir())  # PURL input file cleaned up


def test_grype_failures_are_safe(monkeypatch, tmp_path: Path) -> None:
    _, runner = fake_grype(monkeypatch, "", returncode=1)
    with pytest.raises(GrypeError, match="exit code 1") as error:
        run_grype([LODASH], tmp_path, runner=runner)
    assert "/secret" not in str(error.value)

    _, runner = fake_grype(monkeypatch, "not json")
    with pytest.raises(GrypeError, match="not valid JSON"):
        run_grype([LODASH], tmp_path, runner=runner)

    monkeypatch.setattr(grype_module.shutil, "which", lambda _: None)
    with pytest.raises(GrypeError, match="not installed"):
        run_grype([LODASH], tmp_path)


# ---------- workflow pins ----------

WORKFLOW = """\
name: ci
on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: "someone/tool@main"   # branch
      - uses: owner/pinned@0123456789abcdef0123456789abcdef01234567
      - uses: ./local-action
      # - uses: commented/out@v1
      - uses: docker://alpine:3.20
      - uses: docker://alpine@sha256:abc
      - uses: noref/action
"""


def test_workflow_pin_detector(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(WORKFLOW, encoding="utf-8")
    findings, warnings = workflow_findings(tmp_path, [".github/workflows/ci.yml", "Jenkinsfile"])
    assert warnings == []
    assert [(f.subject_label, f.evidence[0].locator) for f in findings] == [
        ("actions/checkout", "line 6: uses: actions/checkout@v4"),
        ("someone/tool", "line 7: uses: someone/tool@main"),
        ("docker://alpine:3.20", "line 11: uses: docker://alpine:3.20"),
        ("noref/action", "line 13: uses: noref/action"),
    ]
    assert findings[0].title == "actions/checkout: Pinned to mutable ref 'v4'"
    assert "First-party GitHub action: lower risk, but still mutable" in findings[0].uncertainty
    assert findings[0].sources[0].record_id == ".github/workflows/ci.yml:6"
    assert findings[3].title.endswith("uses the action's default branch")


def test_workflow_symlink_or_missing_file_is_skipped_with_warning(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    outside = tmp_path.parent / "outside.yml"
    outside.write_text("- uses: a/b@v1\n", encoding="utf-8")
    (workflows / "link.yml").symlink_to(outside)
    findings, warnings = workflow_findings(
        tmp_path, [".github/workflows/link.yml", ".github/workflows/missing.yml"]
    )
    assert findings == []
    assert len(warnings) == 2


# ---------- analyzer ----------


def inventory(ci_files: list[str]) -> Inventory:
    return Inventory(
        scan_id=SCAN_ID,
        languages=[],
        manifests=[],
        lockfiles=[],
        dockerfiles=[],
        ci_files=ci_files,
        iac_files=[],
        existing_sboms=[],
        source_directories=[],
        file_count=1,
        partial=False,
        warnings=[],
    )


def fake_osv(purls, timeout):
    return OsvResult(
        retrieved_at="2026-11-24T00:00:00+00:00",
        matches={LODASH: ["GHSA-1"]},
        records={"GHSA-1": osv_record("GHSA-1", "lodash", ["CVE-1"])},
    )


def fake_grype_run(purls, scan_dir, timeout):
    return GrypeResult(
        tool_version="0.122.1",
        database_built="2026-11-23",
        matches=[grype_match("CVE-1", LODASH, ["GHSA-1"])],
        raw={"matches": []},
    )


def test_analyzer_combines_sources_and_writes_evidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("- uses: a/b@v1\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    result = analyze_risk(
        repo,
        inventory([".github/workflows/ci.yml"]),
        demo_document(),
        SCAN_ID,
        out,
        "demo",
        osv_query=fake_osv,
        grype_run=fake_grype_run,
    )
    assert result.stats.model_dump() == {
        "vulnerabilities": 2,
        "vulnerable_packages": 2,
        "confirmed_by_both": 2,
        "workflow_pins": 1,
        "components_total": 6,
        "components_assessed": 4,
        "components_not_assessed": 2,
        "cves_linked": 0,
        "nvd_scored": 0,
        "suspicious": 0,
    }
    assert [(s.name, s.status) for s in result.sources] == [
        ("OSV", "ok"),
        ("Grype", "ok"),
        ("NVD", "skipped"),
        ("workflow-scan", "ok"),
        ("supply-chain-scan", "ok"),
        ("scan-diff", "skipped"),
    ]
    assert {p.name for p in out.iterdir()} == {"osv.json", "grype.json", "supply_chain.json"}
    assert result.partial  # two packages could not be assessed
    assert "2 package(s) not assessed: no exact version or unsupported ecosystem" in result.warnings


def test_one_source_failing_keeps_the_other(tmp_path: Path) -> None:
    def broken_osv(purls, timeout):
        raise OsvError("OSV query failed: URLError")

    result = analyze_risk(
        tmp_path,
        inventory([]),
        demo_document(),
        SCAN_ID,
        tmp_path,
        "demo",
        osv_query=broken_osv,
        grype_run=fake_grype_run,
    )
    assert result.sources[0].status == "failed"
    assert result.stats.vulnerabilities == 2
    assert result.stats.confirmed_by_both == 0
    assert "OSV unavailable: OSV query failed: URLError" in result.warnings
    assert result.partial


def test_no_source_means_not_assessed_never_clean(tmp_path: Path) -> None:
    def broken_grype(purls, scan_dir, timeout):
        raise GrypeError("Grype is not installed or not on PATH")

    result = analyze_risk(
        tmp_path,
        inventory([]),
        demo_document(),
        SCAN_ID,
        tmp_path,
        "demo",
        osv_enabled=False,
        grype_run=broken_grype,
    )
    assert [s.status for s in result.sources[:2]] == ["skipped", "failed"]
    assert result.stats.components_assessed == 0
    assert result.stats.components_not_assessed == 6
    assert "Vulnerabilities not assessed: no vulnerability source was available" in result.warnings
    assert result.partial

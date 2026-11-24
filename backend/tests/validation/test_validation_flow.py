"""Sandbox validation end to end with fakes: no network, no git, no container, no real scan."""

import json
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import validation as validation_routes
from app.config import settings
from app.database.base import Base
from app.database.models import (
    RemediationDecisionRow,
    RemediationProposalRow,
    Scan,
    ValidationRunRow,
)
from app.database.session import get_db
from app.graph import build_graph
from app.main import app
from app.remediation.generator import generate_proposal
from app.schemas.findings import FindingsDocument, FindingStats, SourceRun
from app.schemas.inventory import Inventory
from app.schemas.validation import ValidationChange
from app.validation import compare, service
from app.validation.sandbox import TestPlan
from tests.ai.ai_helpers import COMMIT, findings_document, write_scan
from tests.risk.risk_helpers import SCAN_ID, comp, document, rel

FINDING = "finding:vuln-qs"
PROPOSAL = "rem_" + "a" * 32


def make_scan() -> Scan:
    return Scan(
        scan_id=SCAN_ID,
        repository_url="https://github.com/example/demo",
        owner="example",
        repository_name="demo",
        requested_ref=None,
        resolved_ref="main",
        commit_sha=COMMIT,
        status="COMPLETED",
        findings_path=f"{SCAN_ID}/findings.json",
        created_at=datetime(2026, 11, 24, tzinfo=UTC),
        finished_at=datetime(2026, 11, 24, tzinfo=UTC),
    )


def fake_checkout(repository, workspace: Path, commit, timeout):
    repo = workspace / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.0.0"}}, indent=2) + "\n"
    )
    (repo / "package-lock.json").write_text('{"lockfileVersion": 3}\n')
    return repo


def after_document():
    return document(
        [comp("cmp:express", "express", "4.0.0"), comp("cmp:qs2", "qs", "6.2.4")],
        [rel("r1", "root:demo", "cmp:express"), rel("r2", "cmp:express", "cmp:qs2")],
    )


def fake_pipeline(after_findings: FindingsDocument | None = None):
    def discover(repo, scan_id):
        return Inventory(
            scan_id=scan_id,
            languages=[],
            manifests=[],
            lockfiles=[],
            dockerfiles=[],
            ci_files=[],
            iac_files=[],
            existing_sboms=[],
            source_directories=[],
            file_count=2,
            partial=False,
            warnings=[],
        )

    def generate(repo, inventory, scan_id, out):
        doc = after_document()
        return doc.model_copy(update={"scan_id": scan_id})

    def graph(doc, name):
        return build_graph(doc, name)

    def analyze(repo, inventory, doc, scan_id, out, name, **kwargs):
        assert kwargs["baseline"].scan_id == SCAN_ID  # compared against the original scan
        base = after_findings or FindingsDocument(
            scan_id=scan_id,
            findings=[],
            sources=[SourceRun(name="OSV", status="ok", queried=2)],
            partial=False,
            warnings=[],
            stats=FindingStats(
                vulnerabilities=0,
                vulnerable_packages=0,
                confirmed_by_both=0,
                workflow_pins=0,
                components_total=2,
                components_assessed=2,
                components_not_assessed=0,
            ),
        )
        return base.model_copy(
            update={
                "scan_id": scan_id,
                "sources": base.sources or [SourceRun(name="OSV", status="ok", queried=2)],
            }
        )

    return lambda: (discover, generate, graph, analyze, lambda: None)


CHANGE = ValidationChange(
    source_type="remediation",
    source_id=PROPOSAL,
    finding_id=FINDING,
    component_id="cmp:qs",
    package="qs",
    ecosystem="npm",
    project_path="",
    from_version="6.0.0",
    to_version="6.2.4",
    approved_by="reviewer",
    approved_at=datetime(2026, 11, 24, tzinfo=UTC),
)


@pytest.fixture
def roots(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(settings, "scan_output_root", tmp_path / "scans")
    monkeypatch.setattr(settings, "workspace_root", tmp_path / "ws")
    write_scan(tmp_path / "scans" / SCAN_ID)
    return tmp_path


def test_fix_unverified_without_container(roots: Path) -> None:
    original = (roots / "scans" / SCAN_ID / "findings.json").read_bytes()
    result = service.execute(
        settings,
        make_scan(),
        CHANGE,
        "val_" + "1" * 32,
        True,
        checkout=fake_checkout,
        pipeline=fake_pipeline(),
        runtime_probe=lambda _p: None,
        lock_regenerator=lambda project, timeout: "install --package-lock-only --ignore-scripts",
    )
    assert result.verdict == "FAILED", result.verdict_reason
    assert result.tests_status == "not_run" and "never runs" in result.tests_detail
    steps = {s.id: s.status for s in result.steps}
    assert steps == {
        "sandbox": "passed",
        "patch": "passed",
        "lockfile": "passed",
        "tests": "not_run",
        "rescan": "passed",
        "compare": "warning",
    }
    assert [d.path for d in result.diffs] == ["package.json"]
    assert '"qs": "6.2.4"' in result.diffs[0].diff  # transitive: npm overrides
    assert result.comparison.target_resolved is True and len(result.comparison.resolved) == 1
    out = roots / "scans" / SCAN_ID / "validations" / ("val_" + "1" * 32)
    assert {p.name for p in out.iterdir()} >= {
        "findings.json",
        "normalized.json",
        "graph.json",
        "inventory.json",
    }
    assert (roots / "scans" / SCAN_ID / "findings.json").read_bytes() == original  # untouched
    assert not (roots / "ws" / ("val_" + "1" * 32)).exists()  # sandbox cleaned up


def test_tests_run_before_and_after_in_container(roots: Path) -> None:
    calls = []

    def runner(runtime, plan, directory, timeout):
        calls.append((runtime, plan.image, directory.name))
        return {"status": "passed", "exit_code": 0, "duration_s": 1.0, "output_tail": "3 passed"}

    result = service.execute(
        settings,
        make_scan(),
        CHANGE,
        "val_" + "2" * 32,
        True,
        checkout=fake_checkout,
        pipeline=fake_pipeline(),
        runtime_probe=lambda _p: "podman",
        test_runner=runner,
        lock_regenerator=lambda p, t: "npm install --package-lock-only",
    )
    assert [c[2] for c in calls] == ["baseline-project", "repo"]
    assert calls[0][1] == "docker.io/library/node:22-slim"
    assert result.tests_status == "passed" and result.verdict == "FIXED"
    assert "tests pass in the container" in result.verdict_reason


def test_not_fixed_and_regression_verdicts(roots: Path) -> None:
    still = findings_document()  # the vulnerable qs finding is still reported after the patch
    still.findings[0] = still.findings[0].model_copy(update={"subject_id": "cmp:qs2"})
    result = service.execute(
        settings,
        make_scan(),
        CHANGE,
        "val_" + "3" * 32,
        False,
        checkout=fake_checkout,
        pipeline=fake_pipeline(still),
        runtime_probe=lambda _p: None,
        lock_regenerator=lambda p, t: "npm",
    )
    assert result.verdict == "NOT_FIXED"
    assert any("Still present" in r for r in result.residual_risks)

    from app.schemas.validation import TestRun

    def run(phase, status):
        return TestRun(
            phase=phase,
            status=status,
            runtime="podman",
            image="i",
            command="c",
            exit_code=0,
            duration_s=1,
            output_tail="",
        )

    assert (
        compare.tests_outcome([run("baseline", "passed"), run("patched", "failed")])[0]
        == "regression"
    )
    assert (
        compare.tests_outcome([run("baseline", "failed"), run("patched", "failed")])[0]
        == "failed_before_and_after"
    )
    assert compare.tests_outcome([run("patched", "no_tests")])[0] == "no_tests"


def test_failed_checkout_and_patch_are_reported(roots: Path) -> None:
    def broken(*_a):
        raise RuntimeError("network down")

    result = service.execute(
        settings,
        make_scan(),
        CHANGE,
        "val_" + "4" * 32,
        False,
        checkout=broken,
        pipeline=fake_pipeline(),
        runtime_probe=lambda _p: None,
    )
    assert result.verdict == "FAILED" and result.steps[0].status == "failed"

    def empty_checkout(repository, workspace, commit, timeout):
        repo = workspace / "repo"
        repo.mkdir()
        return repo

    result = service.execute(
        settings,
        make_scan(),
        CHANGE,
        "val_" + "5" * 32,
        False,
        checkout=empty_checkout,
        pipeline=fake_pipeline(),
        runtime_probe=lambda _p: None,
    )
    assert result.verdict == "FAILED" and "package.json" in result.verdict_reason


def test_python_test_plan(tmp_path: Path) -> None:
    from app.validation.sandbox import test_plan

    (tmp_path / "requirements.txt").write_text("flask==3.0\n")
    (tmp_path / "tests").mkdir()
    plan = test_plan("pypi", tmp_path)
    assert isinstance(plan, TestPlan) and plan.image.endswith("python:3.12-slim")
    assert "pip install -q -r requirements.txt" in plan.script and "pytest" in plan.script
    assert test_plan("maven", tmp_path) is None


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


@pytest.fixture
def client(roots: Path, monkeypatch) -> Generator[TestClient, None, None]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    def override() -> Generator[Session, None, None]:
        with sessions() as s:
            yield s

    with sessions() as db:
        db.add(make_scan())
        generated = generate_proposal(findings_document().findings[0], SCAN_ID)
        db.add(
            RemediationProposalRow(
                proposal_id=PROPOSAL,
                scan_id=SCAN_ID,
                finding_id=FINDING,
                action="upgrade",
                subject_label="qs@6.0.0",
                current_value="6.0.0",
                proposed_value="6.2.4",
                recommendation="Evaluate upgrading qs@6.0.0 to fixed version 6.2.4.",
                rationale="r",
                expected_risk_reduction="high",
                compatibility_impact="unknown",
                evidence_json=[{"path": "package-lock.json", "kind": "lockfile", "locator": "x"}],
                uncertainty_json=[],
                repository_commit=COMMIT,
                finding_digest=generated.finding_digest,
                proposal_digest=generated.proposal_digest,
                status="APPROVED",
                version=1,
            )
        )
        db.add(
            RemediationDecisionRow(
                decision_id="dec_1",
                proposal_id=PROPOSAL,
                decision="APPROVED",
                decided_by="Asha (security)",
                reason="approved",
                factors_json=[],
                repository_commit=COMMIT,
                finding_digest=generated.finding_digest,
                proposal_digest=generated.proposal_digest,
            )
        )
        db.commit()
    app.dependency_overrides[get_db] = override
    started = []
    monkeypatch.setattr(
        validation_routes.service,
        "run_validation",
        lambda *a, **k: (started.append(a[2]), k["release"]()),
    )
    monkeypatch.setattr(
        validation_routes.service,
        "sandbox_info",
        lambda s: service.SandboxInfo(
            container_runtime=None, tests_enabled=False, npm_available=True, notes=[]
        ),
    )
    c = TestClient(app)
    c.sessions, c.started = sessions, started  # type: ignore[attr-defined]
    yield c
    app.dependency_overrides.clear()
    engine.dispose()


def test_overview_start_and_get(client: TestClient) -> None:
    base = f"/api/v1/scans/{SCAN_ID}/validations"
    overview = client.get(base).json()
    [candidate] = overview["candidates"]
    assert candidate["supported"] and candidate["to_version"] == "6.2.4"
    assert candidate["approved_by"] == "Asha (security)"

    started = client.post(base, json={"source_type": "remediation", "source_id": PROPOSAL})
    assert started.status_code == 202
    run = started.json()
    assert run["status"] == "queued" and run["change"]["package"] == "qs"
    assert client.started == [run["validation_id"]]
    assert (
        client.get(f"{base}/{run['validation_id']}").json()["validation_id"] == run["validation_id"]
    )

    refused = client.post(base, json={"source_type": "remediation", "source_id": "rem_unknown"})
    assert refused.status_code == 409 and refused.json()["error"]["code"] == "NOT_APPROVED"
    assert client.get(f"{base}/val_missing").status_code == 404


def test_busy_scanner_refuses_validation(client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(validation_routes.scan_capacity, "reserve", lambda: False)
    response = client.post(
        f"/api/v1/scans/{SCAN_ID}/validations",
        json={"source_type": "remediation", "source_id": PROPOSAL},
    )
    assert response.status_code == 429


def test_report_downloads(client: TestClient) -> None:
    with client.sessions() as db:  # type: ignore[attr-defined]
        db.add(
            ValidationRunRow(
                validation_id="val_" + "9" * 32,
                scan_id=SCAN_ID,
                source_type="remediation",
                source_id=PROPOSAL,
                finding_id=FINDING,
                status="completed",
                verdict="FIXED",
                run_tests=False,
                change_json=CHANGE.model_dump(mode="json"),
                result_json={
                    "verdict": "FIXED",
                    "verdict_reason": "The rescan no longer reports it <script>alert(1)</script>",
                    "tests_status": "not_run",
                    "tests_detail": "No container",
                    "sandbox_commit": COMMIT,
                    "steps": [],
                    "diffs": [],
                    "tests": [],
                    "comparison": None,
                    "rescan_artifacts": None,
                    "residual_risks": [],
                },
                finished_at=datetime(2026, 11, 24, 1, tzinfo=UTC),
            )
        )
        db.commit()
    html = client.get(f"/api/v1/scans/{SCAN_ID}/report.html")
    assert html.status_code == 200
    assert (
        html.headers["content-disposition"]
        == 'attachment; filename="kestral-guardian-report-example-demo-ccccccc.html"'
    )
    body = html.text
    assert "Kestral Guardian Report" in body and "data:image/jpeg;base64," in body
    assert "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body  # escaped
    assert "Fix verified" in body and "Responsible AI" in body and "Asha (security)" in body

    data = client.get(f"/api/v1/scans/{SCAN_ID}/report.json?download=false")
    assert data.headers["content-disposition"].startswith("inline")
    report = data.json()
    assert report["schema"] == "kestral-guardian-report/1.0"
    assert report["summary"]["validations"] == {"FIXED": 1}
    states = {r["finding_id"]: r["state"] for r in report["remaining_risks"]}
    assert states[FINDING].startswith("Fix verified in sandbox")
    assert report["inventory"]["components"][0]["name"] == "express"
    assert any(e["event"].startswith("Sandbox validation FIXED") for e in report["audit_trail"])


def test_uv_lock_is_relocked_in_the_container(roots: Path) -> None:
    py_change = CHANGE.model_copy(
        update={"ecosystem": "pypi", "package": "qs", "to_version": "6.2.4"}
    )
    relocked = []

    def checkout(repository, workspace, commit, timeout):
        repo = workspace / "repo"
        repo.mkdir()
        (repo / "pyproject.toml").write_text('[project]\nname = "d"\ndependencies = ["qs>=6.0"]\n')
        (repo / "uv.lock").write_text("version = 1\n")
        return repo

    def uv(runtime, project, package, version, timeout):
        relocked.append((runtime, package, version))
        (project / "uv.lock").write_text("version = 1\n# qs 6.2.4\n")
        return f"uv lock --upgrade-package {package}=={version} (in {runtime} container)"

    result = service.execute(
        settings,
        make_scan(),
        py_change,
        "val_" + "6" * 32,
        False,
        checkout=checkout,
        pipeline=fake_pipeline(),
        runtime_probe=lambda _p: "podman",
        uv_lock_regenerator=uv,
    )
    assert relocked == [("podman", "qs", "6.2.4")]
    steps = {s.id: s for s in result.steps}
    assert (
        steps["lockfile"].status == "passed" and "only the new uv.lock" in steps["lockfile"].detail
    )
    assert [d.path for d in result.diffs] == ["uv.lock"]
    assert (
        steps["tests"].status == "skipped"
    )  # tests not requested, container still used for the lock


def _py_checkout(lock: str = "version = 1\n"):
    def checkout(repository, workspace, commit, timeout):
        repo = workspace / "repo"
        repo.mkdir()
        (repo / "pyproject.toml").write_text('[project]\nname = "d"\ndependencies = ["qs>=6.0"]\n')
        (repo / "uv.lock").write_text(lock)
        return repo

    return checkout


def test_lockfile_failure_stops_with_a_clear_failed_verdict(roots: Path) -> None:
    from app.validation.sandbox import SandboxError

    py_change = CHANGE.model_copy(update={"ecosystem": "pypi", "to_version": "6.2.4"})

    def broken_uv(*_a):
        raise SandboxError("uv could not re-lock: error: No solution found")

    def must_not_rescan():
        raise AssertionError("a change that was never applied must not be rescanned")

    result = service.execute(
        settings,
        make_scan(),
        py_change,
        "val_" + "7" * 32,
        True,
        checkout=_py_checkout(),
        pipeline=must_not_rescan,
        runtime_probe=lambda _p: "podman",
        uv_lock_regenerator=broken_uv,
        test_runner=lambda *a: (_ for _ in ()).throw(AssertionError("no tests either")),
    )
    assert result.verdict == "FAILED"
    assert "could not be applied" in result.verdict_reason and "not tested" in result.verdict_reason
    steps = {s.id: (s.status, s.detail) for s in result.steps}
    assert steps["lockfile"] == ("failed", "uv could not re-lock: error: No solution found")
    assert steps["tests"][0] == "skipped" and steps["rescan"][0] == "skipped"


def test_no_container_means_uv_lock_cannot_be_validated(roots: Path) -> None:
    py_change = CHANGE.model_copy(update={"ecosystem": "pypi", "to_version": "6.2.4"})
    result = service.execute(
        settings,
        make_scan(),
        py_change,
        "val_" + "8" * 32,
        True,
        checkout=_py_checkout(),
        pipeline=fake_pipeline(),
        runtime_probe=lambda _p: None,
    )
    assert result.verdict == "FAILED"
    assert "only be regenerated inside a container" in result.steps[2].detail


def test_fresh_lock_note_is_reported(roots: Path) -> None:
    py_change = CHANGE.model_copy(update={"ecosystem": "pypi", "to_version": "6.2.4"})

    def uv(runtime, project, package, version, timeout):
        (project / "uv.lock").write_text("version = 1\n# fresh\n")
        return (
            f"uv lock --upgrade-package {package}=={version} (in {runtime} container); "
            "the existing "
            "uv.lock could not be read, so a fresh lock was resolved from pyproject.toml"
        )

    from app.schemas.findings import ChangeSummary, PackageChange

    def moved(name, old, new):
        return PackageChange(
            ecosystem="pypi", name=name, project_path="", from_versions=[old], to_versions=[new]
        )

    changes = ChangeSummary(
        baseline_scan_id=SCAN_ID,
        baseline_commit=COMMIT,
        baseline_ref=None,
        baseline_finished_at=None,
        current_commit=None,
        same_commit=False,
        added=[],
        removed=[],
        upgraded=[moved("qs", "6.0.0", "6.2.4"), moved("httpx", "0.27.0", "0.28.1")],
        downgraded=[],
        other_changes=[],
        totals={"added": 0, "removed": 0, "upgraded": 2, "downgraded": 0},
        files_compared=True,
        files_changed=[],
        truncated=False,
    )
    after = FindingsDocument(
        scan_id="x",
        findings=[],
        sources=[],
        partial=False,
        warnings=[],
        changes=changes,
        stats=FindingStats(
            vulnerabilities=0,
            vulnerable_packages=0,
            confirmed_by_both=0,
            workflow_pins=0,
            components_total=2,
            components_assessed=2,
            components_not_assessed=0,
        ),
    )
    result = service.execute(
        settings,
        make_scan(),
        py_change,
        "val_" + "a" * 32,
        False,
        checkout=_py_checkout("broken"),
        pipeline=fake_pipeline(after),
        runtime_probe=lambda _p: "podman",
        uv_lock_regenerator=uv,
    )
    assert result.verdict == "FAILED"
    assert "fresh lock was resolved" in next(s.detail for s in result.steps if s.id == "lockfile")
    # The rescan moved qs (the target) and httpx; only httpx belongs in the note.
    note = next(
        r for r in result.residual_risks if r.startswith("The original lockfile was unreadable")
    )
    assert "httpx (.): 0.27.0 → 0.28.1" in note and "qs (" not in note.split(":", 1)[1]


def test_start_runtime_endpoint(client: TestClient, monkeypatch) -> None:
    from app.validation import sandbox

    monkeypatch.setattr(
        validation_routes.sandbox, "start_runtime", lambda: "Podman machine started"
    )
    ok = client.post("/api/v1/sandbox/runtime/start")
    assert ok.status_code == 200 and "container_runtime" in ok.json()

    def missing():
        raise sandbox.SandboxError("No container runtime is installed. Install Podman")

    monkeypatch.setattr(validation_routes.sandbox, "start_runtime", missing)
    refused = client.post("/api/v1/sandbox/runtime/start")
    assert refused.status_code == 503 and refused.json()["error"]["code"] == "RUNTIME_UNAVAILABLE"

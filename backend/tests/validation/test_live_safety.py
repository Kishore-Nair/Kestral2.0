"""Offline negative tests for the live runner; subprocesses and scanners are fakes."""

import json
import subprocess
from unittest.mock import patch

import pytest

from app.database.models import RemediationDecisionRow, RemediationProposalRow
from app.schemas.findings import SourceRun
from app.validation import compare, service
from app.validation.profiles import nodegoat_script
from app.validation.sandbox import TestPlan, run_tests_in_container
from tests.ai.ai_helpers import findings_document, scan_document
from tests.risk.risk_helpers import SCAN_ID
from tests.validation.test_validation_flow import (  # noqa: F401
    PROPOSAL,
    after_document,
    client,
    fake_pipeline,
    make_scan,
    roots,
)


@pytest.mark.parametrize("tamper", ["missing", "digest", "version", "commit"])
def test_approval_must_match_current_evidence(client, tamper):  # noqa: F811
    with client.sessions() as db:
        decision = db.get(RemediationDecisionRow, "dec_1")
        if tamper == "missing":
            db.delete(decision)
        elif tamper == "digest":
            decision.proposal_digest = "0" * 64
        elif tamper == "commit":
            decision.repository_commit = "0" * 40
        else:
            db.get(RemediationProposalRow, PROPOSAL).proposed_value = "99.0.0"
        db.commit()
    response = client.post(
        f"/api/v1/scans/{SCAN_ID}/validations",
        json={"source_type": "remediation", "source_id": PROPOSAL},
    )
    assert response.status_code == 409
    assert not client.started


@pytest.mark.parametrize("status", ["failed", "skipped"])
def test_missing_scanner_never_resolves_target(status):
    before = findings_document()
    after = before.model_copy(
        update={
            "findings": [],
            "sources": [SourceRun(name="OSV", status=status)],
        }
    )
    result = compare.compare_findings(
        before, scan_document(), after, after_document(), before.findings[0]
    )
    assert result.target_resolved is None
    assert result.resolved == []
    assert compare.verdict(result, "passed")[0] == "FAILED"


def test_unknown_project_cannot_select_nodegoat_profile(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"owasp-nodejs-goat"}')
    assert nodegoat_script(tmp_path) is None


@pytest.mark.parametrize("fail_stage", [None, "install", "test", "timeout"])
def test_staged_runner_isolates_execution_and_cleans_resources(tmp_path, fail_stage):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "run":
            offline = "--network=none" in argv
            if fail_stage == "timeout":
                raise subprocess.TimeoutExpired(argv, 1)
            failed = (fail_stage == "install" and not offline) or (fail_stage == "test" and offline)
            return subprocess.CompletedProcess(argv, int(failed), "stage output", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    with (
        patch("app.validation.sandbox.shutil.which", return_value="docker"),
        patch("app.validation.sandbox.subprocess.run", side_effect=run),
    ):
        result = run_tests_in_container(
            "docker", TestPlan("node:22-slim", "test", "reviewed", "install"), tmp_path, 10
        )
    executions = [a for a in calls if a[1] == "run"]
    assert "--read-only" in executions[0] and "--cap-drop=ALL" in executions[0]
    if len(executions) == 2:
        assert "--network=none" in executions[1]
        assert not any(":/src:" in a for a in executions[1])
    assert calls[-2][1:3] == ["rm", "--force"]
    assert calls[-1][1:4] == ["volume", "rm", "--force"]
    assert result["status"] == (
        "passed" if fail_stage is None else "failed" if fail_stage == "test" else "error"
    )


def test_progress_is_saved_as_validated_steps(tmp_path):
    steps = service._Steps()
    steps.progress_path = tmp_path / "progress.json"
    steps.add("sandbox", "Checkout", "passed", "Exact commit", 0)
    saved = json.loads(steps.progress_path.read_text())
    assert saved[0]["id"] == "sandbox"
    assert not steps.progress_path.with_suffix(".tmp").exists()

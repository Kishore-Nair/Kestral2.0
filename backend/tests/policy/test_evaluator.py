"""Synthetic findings and mocked OPA subprocess results."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.policy import evaluator
from app.provenance.local import OperationError


@pytest.fixture
def evidence():
    findings = {
        "schema_version": "1.0", "scan_id": "test", "partial": False,
        "findings": [], "sources": [{"name": "workflow-scan", "status": "ok"}],
        "stats": dict.fromkeys((
            "vulnerabilities", "vulnerable_packages", "confirmed_by_both", "workflow_pins",
            "components_total", "components_assessed", "components_not_assessed",
        ), 0),
        "warnings": [],
    }
    provenance = {
        "schema_version": "1.0", "scan_id": "test", "timestamp": datetime.now(UTC).isoformat(),
        "assessment_status": "not_assessed", "artifacts": [], "warnings": [],
        "tool_version": None,
    }
    return findings, provenance


def encode(document):
    return json.dumps(document).encode()


def test_build_input(evidence):
    findings, provenance = evidence
    data = evaluator.build_input("test", encode(findings), encode(provenance), True)
    assert data == {
        "schema_version": "1.0", "strict": True, "findings_partial": False, "findings": [],
        "assessment": "not_assessed", "artifacts": [],
    }


def test_missing_source_marks_findings_incomplete(evidence):
    findings, provenance = evidence
    findings["sources"] = []
    data = evaluator.build_input("test", encode(findings), encode(provenance), False)
    assert data["findings_partial"] is True


@pytest.mark.parametrize("missing", ["findings", "schema_version", "partial"])
def test_missing_finding_fields_rejected(evidence, missing):
    findings, provenance = evidence
    del findings[missing]
    with pytest.raises(OperationError, match="required fields"):
        evaluator.build_input("test", encode(findings), encode(provenance), False)


def test_scan_mismatch(evidence):
    findings, provenance = evidence
    provenance["scan_id"] = "different"
    with pytest.raises(OperationError, match="scan ID"):
        evaluator.build_input("test", encode(findings), encode(provenance), False)


@pytest.mark.parametrize("output", [
    b"not JSON", b"{}", b'{"result":[]}',
    b'{"result":[{"expressions":[{"value":{"decision":"ALLOW","violations":[{}]}}]}]}',
    b'{"result":[{"expressions":[{"value":{"decision":"BLOCK","violations":[]}}]}]}',
])
def test_invalid_opa_output_fails_closed(output):
    with pytest.raises(OperationError, match="undefined or invalid"):
        evaluator.parse_result(output)


@pytest.mark.parametrize("failure", ["missing", "timeout", "invalid"])
def test_mocked_tool_error(tmp_path, monkeypatch, failure):
    def unavailable(*_):
        raise OperationError("opa unavailable")

    def mock_run(_executable, args, _stage):
        if args == ["version"]:
            return 0, b"Version: 1.22.4\n"
        if failure == "timeout":
            raise OperationError("Tool execution timed out")
        return 0, b"{}"

    if failure == "missing":
        monkeypatch.setattr(evaluator, "tool_path", unavailable)
    else:
        monkeypatch.setattr(evaluator, "tool_path", lambda *_: Path("/mock/opa"))
        monkeypatch.setattr(evaluator, "run_tool", mock_run)
    result = evaluator.evaluate("test", tmp_path, {})
    assert result.evaluation_status == "error" and result.decision is None
    assert result.warnings and result.policy_hash

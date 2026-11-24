"""Agent loop, tools and validator with a scripted provider (no live LLM, no network)."""

import hashlib
import json
from pathlib import Path

import pytest

from app.ai.agent import FINISH_SAME_CALL, SYSTEM_PROMPT, AgentLimits, run_agent
from app.ai.bundle import EvidenceStore, redact
from app.ai.provider import FakeProvider, ProviderError
from app.ai.tools import TOOLS, ToolContext
from app.risk.osv import OsvResult
from tests.ai.ai_helpers import EXPRESS, QS, draft, final_turn, load, tools_turn, write_scan

LIMITS = AgentLimits()


@pytest.fixture
def bundle(tmp_path: Path):
    return load(write_scan(tmp_path / "scan"))


def vuln(bundle):
    return bundle.finding("finding:vuln-qs")


def run(bundle, turns, finding=None, limits=LIMITS, **kwargs):
    provider = FakeProvider(list(turns))
    result = run_agent(bundle, finding or vuln(bundle), provider, limits, **kwargs)
    return result, provider


def test_happy_path_selects_tools_and_validates(bundle) -> None:
    result, provider = run(
        bundle,
        [
            tools_turn(("get_advisory", {"advisory_id": "CVE-2022-24999"})),
            tools_turn(
                ("check_candidate_version", {"component_id": QS, "version": "6.2.4"}),
                ("get_dependency_paths", {"component_id": QS}),
            ),
            final_turn(
                draft(
                    claims=[
                        {
                            "claim": "6.2.4 is fixed",
                            "kind": "verified_fact",
                            "evidence_refs": ["ev-4", "ev-5"],
                        },
                        {
                            "claim": "qs arrives via express",
                            "kind": "verified_fact",
                            "evidence_refs": ["ev-6"],
                        },
                        {
                            "claim": "Low breaking risk",
                            "kind": "model_interpretation",
                            "evidence_refs": [],
                        },
                    ]
                )
            ),
        ],
    )
    rec = result.recommendation
    assert result.status == "recommendation_ready", result.error
    assert [(t.name, t.status) for t in rec.tool_trace] == [
        ("get_advisory", "ok"),
        ("check_candidate_version", "ok"),
        ("get_dependency_paths", "ok"),
    ]
    assert rec.recommended_remediation.fixed_version_verified is True
    assert rec.recommended_remediation.version_source == "OSV GHSA-test-qs00-0001"
    assert rec.compatibility.manifest_status == "rejects"  # qs is declared "~6.0.0"
    assert "~6.0.0" in rec.compatibility.manifest_detail
    checks = {c.id: c.status for c in rec.validation.checks}
    assert checks["fixed_version_verified"] == "passed"
    assert checks["graph_paths"] == "passed"
    assert checks["tests"] == "not_run" and checks["lockfile_resolution_after_change"] == "not_run"
    assert rec.validation.status == "partial"
    assert [c.verification_status for c in rec.claims] == ["verified", "verified", "unverified"]
    # Identity and original finding come from canonical data, not the model.
    assert rec.scan_id == bundle.scan_id and rec.commit_sha == bundle.commit_sha
    assert rec.original_finding.severity == "HIGH" and rec.original_finding.fixed_versions == [
        "6.2.4"
    ]
    assert rec.human_approval_required is True and rec.patch.available is False
    assert rec.model_metadata.input_tokens == 400  # 100 + 100 + 200
    # Each tool result is handed back as quoted data with its citable IDs.
    second_call_messages = provider.calls[1]["messages"]
    assert "<tool_data>" in second_call_messages[-1]["content"][0]["content"]


def test_tool_budget_is_enforced_in_code(bundle) -> None:
    six = [("get_component", {"component_id": QS})] * 7
    result, _ = run(bundle, [tools_turn(*six), final_turn(draft())])
    statuses = [t.status for t in result.trace]
    assert statuses == ["ok"] * 5 + ["budget_exhausted"] * 2
    assert result.recommendation.stop_reason == "tool budget exhausted"

    result, _ = run(bundle, [tools_turn(*six), tools_turn(*six[:1]), final_turn(draft())])
    assert result.status == "insufficient_evidence"
    assert result.recommendation is None


def test_external_budget_and_network_failure(bundle) -> None:
    def failing_fetch(url, headers, timeout):
        raise TimeoutError

    def context(b, f, store):
        osv = lambda purls, timeout: OsvResult("2026-11-24", {purls[0]: ["X"]}, {"X": {}})  # noqa: E731
        return ToolContext(b, f, store, fetch=failing_fetch, osv_query=osv)

    calls = [
        ("lookup_advisory", {"component_id": QS}),
        ("get_package_metadata", {"component_id": QS}),
        ("get_package_metadata", {"component_id": QS}),
    ]
    result, _ = run(bundle, [tools_turn(*calls), final_turn(draft())], tool_context=context)
    assert [(t.name, t.status) for t in result.trace] == [
        ("lookup_advisory", "ok"),
        ("get_package_metadata", "error"),
        ("get_package_metadata", "budget_exhausted"),
    ]
    assert result.trace[0].external and result.recommendation.evidence[-1].external


def test_unregistered_tools_and_out_of_scope_ids_are_rejected(bundle) -> None:
    calls = [
        ("run_shell", {"cmd": "cat /etc/passwd"}),
        ("get_component", {"component_id": "../../../etc/passwd"}),
        ("get_finding", {"finding_id": "finding:script-express"}),
        ("get_advisory", {"advisory_id": "CVE-1999-0001"}),
        ("get_component", {"component_id": QS, "extra": "x"}),
    ]
    result, _ = run(bundle, [tools_turn(*calls), final_turn(draft())])
    assert [(t.status, t.message) for t in result.trace] == [
        ("rejected", "Not a registered tool"),
        ("error", "Unknown component_id for this scan"),
        ("error", "Only the selected finding can be read"),
        ("error", "advisory_id must be one of the selected finding's advisory IDs"),
        ("rejected", "Invalid arguments"),
    ]


def test_no_execution_or_write_tools_exist() -> None:
    assert set(TOOLS) == {
        "get_scan_status",
        "get_finding",
        "get_component",
        "get_component_evidence",
        "get_dependency_paths",
        "get_reverse_dependencies",
        "get_advisory",
        "lookup_advisory",
        "get_package_metadata",
        "check_candidate_version",
        "get_change_evidence",
        "get_project_policy",
    }
    for tool in TOOLS.values():
        assert all(
            p in {"component_id", "finding_id", "advisory_id", "version"} for p in tool.properties
        )
        assert tool.schema()["input_schema"]["additionalProperties"] is False


def test_invented_evidence_ids_fail_validation(bundle) -> None:
    payload = draft(claims=[{"claim": "x", "kind": "verified_fact", "evidence_refs": ["ev-99"]}])
    result, _ = run(bundle, [final_turn(payload)])
    assert result.status == "validation_failed"
    rec = result.recommendation
    assert rec.claims[0].verification_status == "rejected"
    assert "ev-99" in rec.validation.blocking_issues[0]


def test_candidate_inside_affected_range_fails(bundle) -> None:
    result, _ = run(bundle, [final_turn(draft(remediation={"target_version": "6.1.0"}))])
    assert result.status == "validation_failed"
    assert result.recommendation.recommended_remediation.fixed_version_verified is False
    assert "still inside the affected range" in result.recommendation.validation.blocking_issues[0]


def test_unverified_upgrade_is_downgraded_to_review(bundle) -> None:
    # 7.0.0 is outside the range but the model cannot mark it verified; upgrade gets reviewed.
    result, _ = run(bundle, [final_turn(draft(remediation={"target_version": "not.semver"}))])
    assert result.status == "validation_failed"
    result, _ = run(
        bundle,
        [final_turn(draft(remediation={"target_component_id": None, "target_version": None}))],
    )
    assert result.status == "needs_human_review"
    assert result.recommendation.recommended_remediation.fixed_version_verified is False


def test_parent_upgrade_must_depend_on_the_vulnerable_package(bundle) -> None:
    ok = draft(
        remediation={
            "type": "upgrade_parent",
            "target_component_id": EXPRESS,
            "target_version": None,
        }
    )
    result, _ = run(bundle, [final_turn(ok)])
    checks = {c.id: c for c in result.recommendation.validation.checks}
    assert checks["target_component"].status == "passed"

    script = bundle.finding("finding:script-express")
    bad = draft(
        remediation={"type": "upgrade_parent", "target_component_id": QS, "target_version": None}
    )
    result, _ = run(bundle, [final_turn(bad)], finding=script)
    assert result.status == "validation_failed"
    assert "does not depend on" in result.recommendation.validation.blocking_issues[0]


def test_invalid_json_gets_one_repair_then_fails(bundle) -> None:
    result, provider = run(bundle, [final_turn("{not json"), final_turn(draft())])
    assert result.status == "recommendation_ready"
    assert "failed validation" in provider.calls[1]["messages"][-1]["content"]

    oversized = draft(title="x" * 500)
    result, _ = run(bundle, [final_turn(oversized), final_turn(oversized)])
    assert result.status == "failed" and result.error == "The model returned an invalid response"


def test_provider_failures_are_reported_not_hidden(bundle) -> None:
    result, _ = run(bundle, [ProviderError("timeout", "AI provider timed out")])
    assert (result.status, result.error) == ("failed", "AI provider timed out")
    result, _ = run(bundle, [ProviderError("not_configured", "ANTHROPIC_API_KEY is not set")])
    assert result.status == "ai_unavailable"


def test_wall_clock_limit(bundle) -> None:
    ticks = iter([0, 0, 1000])
    result, _ = run(
        bundle,
        [tools_turn(("get_component", {"component_id": QS})), final_turn(draft())],
        limits=AgentLimits(wall_clock_seconds=10),
        clock=lambda: next(ticks),
    )
    assert result.status == "failed" and "time limit" in result.error


def test_untrusted_text_stays_quoted_data_and_secrets_are_redacted(bundle) -> None:
    result, provider = run(
        bundle,
        [tools_turn(("get_advisory", {"advisory_id": "GHSA-test-qs00-0001"})), final_turn(draft())],
    )
    first = provider.calls[0]
    context = first["messages"][0]["content"]
    assert context.startswith("<scan_context>")
    assert "IGNORE PREVIOUS INSTRUCTIONS" in context  # passed as data, inside the delimiters
    assert "sk-abcdefghijklmnopqrstuvwx" not in context and "[REDACTED]" in context
    assert first["system"] == SYSTEM_PROMPT.format(budget=5, external=2, finish=FINISH_SAME_CALL)
    tool_result = provider.calls[1]["messages"][-1]["content"][0]["content"]
    assert "<tool_data>" in tool_result and "IGNORE ALL PREVIOUS INSTRUCTIONS" in tool_result
    # The injected text changed nothing: identity and status come from code.
    assert result.recommendation.finding_id == "finding:vuln-qs"
    assert redact("token: abc123 and ghp_" + "a" * 30) == "[REDACTED] and [REDACTED]"


def test_canonical_artifacts_are_unchanged(tmp_path: Path) -> None:
    scan_dir = write_scan(tmp_path / "scan")
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in scan_dir.iterdir()}
    bundle = load(scan_dir)
    run(
        bundle,
        [
            tools_turn(
                *[
                    (n, {"component_id": QS})
                    for n in ("get_component", "get_component_evidence", "get_reverse_dependencies")
                ]
            ),
            final_turn(draft()),
        ],
    )
    after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in scan_dir.iterdir()}
    assert before == after


def test_change_evidence_and_policy_tools(bundle) -> None:
    script = bundle.finding("finding:script-express")
    store = EvidenceStore()
    ctx = ToolContext(bundle, script, store)
    outcome = TOOLS["get_change_evidence"].handler(ctx, {"finding_id": script.finding_id})
    assert outcome.result["comparison"] is None  # no earlier scan was compared: said, not invented
    policy = TOOLS["get_project_policy"].handler(ctx, {})
    assert "manual_review" in policy.result["allowed_strategies"]
    evidence = TOOLS["get_component_evidence"].handler(ctx, {"component_id": EXPRESS})
    assert evidence.result["declared_ranges"] == [
        {"manifest": "package.json", "section": "dependencies", "range": "^4.0.0"}
    ]
    assert json.dumps(evidence.result)  # serializable


def test_package_metadata_uses_allowlisted_registry(bundle) -> None:
    seen = []

    def fetch(url, headers, timeout):
        seen.append(url)
        return {
            "dist-tags": {"latest": "6.13.0"},
            "versions": {"6.0.0": {}, "6.2.4": {}, "6.13.0": {"deprecated": "use x"}},
        }

    ctx = ToolContext(bundle, vuln(bundle), EvidenceStore(), fetch=fetch)
    outcome = TOOLS["get_package_metadata"].handler(ctx, {"component_id": QS})
    assert seen == ["https://registry.npmjs.org/qs"]
    assert outcome.result["newer_versions"] == ["6.2.4", "6.13.0"]
    assert outcome.result["deprecated_or_yanked_newer"] == {"6.13.0": "use x"}
    check = TOOLS["check_candidate_version"].handler(ctx, {"component_id": QS, "version": "6.2.4"})
    assert check.result["published_in_registry"] is True


def test_manifest_ranges_come_from_the_components_own_project(tmp_path: Path) -> None:
    scan_dir = write_scan(tmp_path / "scan")
    snapshot = json.loads((scan_dir / "supply_chain.json").read_text())
    snapshot["declarations"]["examples/app/package.json"] = {
        "ecosystem": "npm",
        "sections": {"dependencies": {"qs": "^7.0.0"}},
    }
    (scan_dir / "supply_chain.json").write_text(json.dumps(snapshot))
    bundle = load(scan_dir)
    qs = bundle.component(QS)  # project_path "" (repository root)
    assert bundle.declared_ranges(qs) == [("package.json", "dependencies", "~6.0.0")]

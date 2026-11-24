import { afterEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import AiAnalysisPanel from "@/components/risk/AiAnalysisPanel";
import type { AiApi } from "@/services/aiApi";
import type { AiAnalysis, AiRecommendation, AiStatus } from "@/types/ai";

// Test data only: shapes match the backend contract; not output from a real model.
const STATUS: AiStatus = {
  enabled: true, configured: true, provider: "xai", api_key_env: "XAI_API_KEY", model: "grok-4.7",
  prompt_version: "1.0", tool_budget: 5, data_notice: "Sends this finding's evidence to the provider.",
};

const REC: AiRecommendation = {
  schema_version: "1.0", scan_id: "scan_test", finding_id: "finding:test", commit_sha: "c".repeat(40),
  status: "recommendation_ready", title: "Upgrade qs to 6.2.4", summary: "qs 6.0.0 is affected.",
  why_it_matters: "It is a transitive runtime dependency.",
  original_finding: {
    finding_id: "finding:test", kind: "vulnerability", title: "qs prototype pollution", advisory_ids: ["GHSA-test"],
    component_id: "cmp:qs", package: "qs", ecosystem: "npm", installed_version: "6.0.0", severity: "HIGH",
    severity_source: "OSV", cvss_base_score: null, priority_score: null, priority_band: null, risk_level: null,
    fixed_versions: ["6.2.4"],
  },
  recommended_remediation: {
    type: "upgrade", target_component_id: "cmp:qs", target_version: "6.2.4", steps: ["Update in an isolated copy"],
    evidence_refs: ["ev-4"], fixed_version_verified: true, version_source: "OSV GHSA-test",
    version_source_url: "https://osv.dev/vulnerability/GHSA-test",
  },
  alternatives: [],
  compatibility: {
    breaking_change_risk: "low", notes: [], required_checks: [], manifest_status: "rejects",
    manifest_detail: "Declared range must change: package.json '~6.0.0'",
  },
  risks_and_tradeoffs: [], validation_plan: ["Rescan after the change"], residual_risk: [],
  claims: [
    { claim: "6.2.4 is fixed", kind: "verified_fact", evidence_refs: ["ev-4"], verification_status: "verified" },
    { claim: "Probably safe", kind: "model_interpretation", evidence_refs: [], verification_status: "unverified" },
  ],
  unknowns: ["Whether the vulnerable function is called"], confidence: "medium",
  evidence: [{ id: "ev-4", kind: "advisory", source: "OSV GHSA-test (osv.json)", summary: "Fixed in 6.2.4", external: false }],
  human_approval_required: true, patch: { available: false, diff: null, files_affected: [] },
  tool_trace: [{
    index: 1, name: "get_advisory", arguments: { advisory_id: "GHSA-test" }, status: "ok", external: false,
    evidence_ids: ["ev-4"], duration_ms: 3, message: null,
  }],
  stop_reason: "model finished",
  validation: {
    status: "partial",
    checks: [
      { id: "fixed_version_verified", status: "passed", detail: "6.2.4 is outside the affected range" },
      { id: "tests", status: "not_run", detail: "Kestral does not run the project" },
    ],
    blocking_issues: [], warnings: ["No change has been applied"],
  },
  model_metadata: { provider: "xai", model: "grok-4.7", prompt_version: "1.0", effort: "medium", input_tokens: 10, output_tokens: 5 },
};

function analysis(over: Partial<AiAnalysis> = {}): AiAnalysis {
  return {
    analysis_id: "ai_1", scan_id: "scan_test", finding_id: "finding:test", revision: 1, parent_analysis_id: null,
    status: "recommendation_ready", stale: false, cached: false, error: null, created_at: "2026-11-24T00:00:00Z",
    finished_at: null, recommendation: REC, decision: null, feedback_history: [], next_analysis_id: null, ...over,
  };
}

function fakeClient(over: Partial<AiApi> = {}): AiApi {
  return {
    getStatus: vi.fn(async () => STATUS),
    getRemediation: vi.fn(async () => null),
    start: vi.fn(async () => analysis()),
    get: vi.fn(async () => analysis()),
    decide: vi.fn(async (_scanId, _id, body) =>
      analysis({
        decision: {
          decision: body.decision,
          reasons: body.reasons ?? [],
          note: body.note ?? null,
          decided_at: "2026-11-24T00:00:00Z",
        },
      }),
    ),
    revise: vi.fn(async () => analysis({ analysis_id: "ai_2", revision: 2, parent_analysis_id: "ai_1" })),
    ...over,
  };
}

afterEach(() => vi.useRealTimers());

describe("AiAnalysisPanel", () => {
  it("explains that AI is not configured and offers no action", () => {
    const client = fakeClient();
    render(<AiAnalysisPanel scanId="scan_test" findingId="finding:test" status={{ ...STATUS, enabled: false, configured: false }} client={client} />);
    expect(screen.getByText(/not configured on this server/)).toHaveTextContent("XAI_API_KEY");
    expect(screen.getByText(/Scanning and findings work without it/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Analyze with Kestral AI/ })).toBeNull();
    expect(client.getRemediation).not.toHaveBeenCalled();
  });

  it("runs an analysis, shows the proposal as unapplied and records a decision", async () => {
    const client = fakeClient();
    render(<AiAnalysisPanel scanId="scan_test" findingId="finding:test" status={STATUS} client={client} />);
    fireEvent.click(screen.getByRole("button", { name: /Analyze with Kestral AI/ }));
    expect(await screen.findByText("Proposal ready (not applied)")).toBeInTheDocument();
    expect(client.start).toHaveBeenCalledWith("scan_test", "finding:test", false);
    expect(screen.getByText(/Fixed version confirmed by OSV GHSA-test/)).toBeInTheDocument();
    expect(screen.getByText(/Declared range must change/)).toBeInTheDocument();
    expect(screen.getByText("Investigation trace (1 tool call)")).toBeInTheDocument();
    expect(screen.getByText("Deterministic validation: partial")).toBeInTheDocument();
    expect(screen.getByText("unverified")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Approve proposal" }));
    const confirmApprove = screen.getByRole("button", { name: /Confirm approval & record feedback/ });
    expect(confirmApprove).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Verified safe upgrade"));
    fireEvent.change(screen.getByLabelText(/Approval feedback/), {
      target: { value: "Patch version is verified and compatible with our runtime." },
    });
    expect(confirmApprove).toBeEnabled();
    fireEvent.click(confirmApprove);

    expect(await screen.findByText(/No change has been applied, tested or rescanned/)).toBeInTheDocument();
    expect(client.decide).toHaveBeenCalledWith("scan_test", "ai_1", {
      decision: "approved",
      reasons: ["VERIFIED_SAFE_UPGRADE"],
      note: "Patch version is verified and compatible with our runtime.",
    });
  });

  it("marks a stale analysis and blocks decisions on it", async () => {
    const client = fakeClient({ getRemediation: vi.fn(async () => analysis({ stale: true })) });
    render(<AiAnalysisPanel scanId="scan_test" findingId="finding:test" status={STATUS} client={client} />);
    expect(await screen.findByText("Stale")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve proposal" })).toBeDisabled();
    expect(screen.getByRole("button", { name: /Analyze with Kestral AI/ })).toBeInTheDocument();
  });

  it("polls a running analysis until it finishes", async () => {
    vi.useFakeTimers();
    const client = fakeClient({
      start: vi.fn(async () => analysis({ status: "running", recommendation: null })),
      get: vi.fn(async () => analysis()),
    });
    render(<AiAnalysisPanel scanId="scan_test" findingId="finding:test" status={STATUS} client={client} />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /Analyze with Kestral AI/ }));
    });
    expect(screen.getByText(/Investigating with up to 5 read-only tool calls/)).toBeInTheDocument();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100);
    });
    vi.useRealTimers();
    await waitFor(() => expect(screen.getByText("Proposal ready (not applied)")).toBeInTheDocument());
    expect(client.get).toHaveBeenCalledWith("scan_test", "ai_1");
  });

  it("shows a failed analysis honestly", async () => {
    const client = fakeClient({
      getRemediation: vi.fn(async () => analysis({ status: "failed", recommendation: null, error: "AI provider timed out" })),
    });
    render(<AiAnalysisPanel scanId="scan_test" findingId="finding:test" status={STATUS} client={client} />);
    expect(await screen.findByText("AI provider timed out")).toBeInTheDocument();
    expect(screen.getByText("Analysis failed")).toBeInTheDocument();
  });

  it("supports asking for changes, feeding back into rev 2, and approving the revised fix", async () => {
    const rev2 = analysis({
      analysis_id: "ai_2",
      revision: 2,
      parent_analysis_id: "ai_1",
      feedback_history: [
        {
          analysis_id: "ai_1",
          revision: 1,
          decision: "changes_requested",
          reasons: ["WRONG_STRATEGY"],
          note: "Use a parent upgrade instead of a direct override.",
          previous_strategy: "upgrade",
          previous_target_version: "6.2.4",
          previous_title: "Upgrade qs to 6.2.4",
          decided_at: "2026-11-24T00:05:00Z",
        },
      ],
    });
    const client = fakeClient({
      getRemediation: vi.fn(async () => analysis()),
      decide: vi.fn(async (_scanId, analysisId, body) => {
        if (analysisId === "ai_1") {
          return analysis({
            decision: { decision: body.decision, reasons: body.reasons ?? [], note: body.note ?? null, decided_at: "2026-11-24T00:05:00Z" },
            next_analysis_id: "ai_2",
          });
        }
        return { ...rev2, decision: { decision: "approved" as const, reasons: [], note: null, decided_at: "2026-11-24T00:06:00Z" } };
      }),
      get: vi.fn(async () => rev2),
    });

    render(<AiAnalysisPanel scanId="scan_test" findingId="finding:test" status={STATUS} client={client} />);
    expect(await screen.findByText("Proposal ready (not applied)")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Ask for changes" }));
    const sendBtn = screen.getByRole("button", { name: /Send feedback & revise fix/ });
    expect(sendBtn).toBeDisabled();

    fireEvent.click(screen.getByLabelText("Wrong strategy"));
    fireEvent.change(screen.getByLabelText(/What changes should Kestral AI make/), {
      target: { value: "Use a parent upgrade instead of a direct override." },
    });
    expect(sendBtn).toBeEnabled();
    fireEvent.click(sendBtn);

    expect(await screen.findByText("Rev 2")).toBeInTheDocument();
    expect(screen.getByText(/Feedback loop history \(1 prior round\)/)).toBeInTheDocument();
    expect(screen.getByText("Use a parent upgrade instead of a direct override.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Approve proposal" }));
    fireEvent.click(screen.getByLabelText("Verified safe upgrade"));
    fireEvent.change(screen.getByLabelText(/Approval feedback/), {
      target: { value: "Revised parent upgrade looks clean and safe to proceed." },
    });
    fireEvent.click(screen.getByRole("button", { name: /Confirm approval & record feedback/ }));
    expect(await screen.findByText(/You approved this proposal \(Rev 2\)/)).toBeInTheDocument();
  });

  it("requires structured reasons and explanation to reject, and allows revising afterward", async () => {
    const rev2 = analysis({ analysis_id: "ai_2", revision: 2, parent_analysis_id: "ai_1" });
    const client = fakeClient({
      getRemediation: vi.fn(async () => analysis()),
      revise: vi.fn(async () => rev2),
    });

    render(<AiAnalysisPanel scanId="scan_test" findingId="finding:test" status={STATUS} client={client} />);
    expect(await screen.findByText("Proposal ready (not applied)")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    const rejectOnly = screen.getByRole("button", { name: "Reject proposal" });
    expect(rejectOnly).toBeDisabled();

    fireEvent.change(screen.getByLabelText(/Why are you rejecting this proposal/), {
      target: { value: "This upgrade breaks our serialization behavior in prod." },
    });
    // Still disabled until at least one structured reason is checked.
    expect(rejectOnly).toBeDisabled();

    fireEvent.click(screen.getByLabelText("Breaking change"));
    expect(rejectOnly).toBeEnabled();
    fireEvent.click(rejectOnly);

    expect(await screen.findByText(/You rejected this proposal/)).toBeInTheDocument();
    expect(screen.getByText(/Reasons: Breaking change/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Revise with AI using this feedback/ }));
    expect(await screen.findByText("Rev 2")).toBeInTheDocument();
    expect(client.revise).toHaveBeenCalledWith("scan_test", "ai_1");
  });
});

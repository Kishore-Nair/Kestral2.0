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
    analysis_id: "ai_1", scan_id: "scan_test", finding_id: "finding:test", status: "recommendation_ready",
    stale: false, cached: false, error: null, created_at: "2026-11-24T00:00:00Z", finished_at: null,
    recommendation: REC, decision: null, ...over,
  };
}

function fakeClient(over: Partial<AiApi> = {}): AiApi {
  return {
    getStatus: vi.fn(async () => STATUS),
    getRemediation: vi.fn(async () => null),
    start: vi.fn(async () => analysis()),
    get: vi.fn(async () => analysis()),
    decide: vi.fn(async () => analysis({ decision: { decision: "approved", note: null, decided_at: "2026-11-24T00:00:00Z" } })),
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
    expect(await screen.findByText(/No change has been applied, tested or rescanned/)).toBeInTheDocument();
    expect(client.decide).toHaveBeenCalledWith("scan_test", "ai_1", "approved");
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
});

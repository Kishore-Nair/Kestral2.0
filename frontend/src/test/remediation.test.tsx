import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import RemediationPanel from "@/components/remediation/RemediationPanel";
import type { ScanApi } from "@/services/api";
import type { RemediationProposal } from "@/types/remediation";

const proposal: RemediationProposal = {
  proposal_id: "rem_1", scan_id: "scan_1", finding_id: "finding_1", action: "upgrade",
  subject_label: "example@1.0.0", current_value: "1.0.0", proposed_value: "1.0.1",
  recommendation: "Evaluate upgrading example to 1.0.1.", rationale: "A fixed version is reported.",
  expected_risk_reduction: "high", compatibility_impact: "unknown",
  evidence: [{ path: "package-lock.json", kind: "lockfile", locator: "example" }], uncertainty: [],
  repository_commit: "a".repeat(40), finding_digest: "b".repeat(64), proposal_digest: "c".repeat(64),
  status: "PENDING", version: 1, created_at: "2026-11-24T00:00:00Z", decision: null,
};

function service(): ScanApi {
  return {
    createScan: vi.fn(), getScan: vi.fn(), getInventory: vi.fn(), getSbom: vi.fn(),
    getGraph: vi.fn(), getFindings: vi.fn(),
    getRemediations: vi.fn(async () => ({ schema_version: "1.0", scan_id: "scan_1", proposals: [proposal] })),
    decideRemediation: vi.fn(async (_id, _proposal, body) => {
      const decisionBody = {
        decision: body.decision, decided_by: body.decided_by, reason: body.reason,
        factors: body.factors, conditions: body.conditions, alternative: body.alternative,
        external_reference: body.external_reference,
      };
      return {
        ...proposal, status: body.decision, version: 2,
        decision: { ...decisionBody, decision_id: "dec_1", proposal_id: "rem_1", repository_commit: proposal.repository_commit,
          finding_digest: proposal.finding_digest, proposal_digest: proposal.proposal_digest, decided_at: "2026-11-24T01:00:00Z" },
      };
    }),
  };
}

describe("RemediationPanel", () => {
  it("requires reviewer reasoning and records an evidence-bound decision", async () => {
    const api = service();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<RemediationPanel scanId="scan_1" service={api} />);
    expect(await screen.findByText(/Evaluate upgrading/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve remediation" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Reviewer identity"), { target: { value: "alice@example.com" } });
    fireEvent.click(screen.getByLabelText("Security risk"));
    fireEvent.change(screen.getByLabelText("Reasoning (required)"), { target: { value: "The patch is supported and removes the verified runtime vulnerability." } });
    fireEvent.click(screen.getByRole("button", { name: "Approve remediation" }));
    await waitFor(() => expect(api.decideRemediation).toHaveBeenCalled());
    expect(await screen.findByText(/Reason:/)).toBeInTheDocument();
  });
});

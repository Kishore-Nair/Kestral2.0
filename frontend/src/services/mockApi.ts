// Offline sample adapter: same signatures as `api`, static fixtures from src/mocks.
// Every getScan call advances one stage, so progress is deterministic (no random delays).
import type { ScanState, ScanStatus } from "@/types/api";
import type { ScanApi } from "@/services/api";
import scanFixture from "@/mocks/scan.json";
import inventoryFixture from "@/mocks/inventory.json";
import sbomFixture from "@/mocks/sbom.json";
import graphFixture from "@/mocks/graph.json";
import findingsFixture from "@/mocks/findings.json";
import type { FindingsDocument } from "@/types/findings";
import type { Inventory } from "@/types/api";
import type { DependencyDocument } from "@/types/sbom";
import type { GraphDocument } from "@/types/graph";
import type { RemediationDecisionCreate, RemediationList, RemediationProposal } from "@/types/remediation";

const STAGES: ScanStatus[] = [
  "QUEUED", "CLONING", "DISCOVERING", "GENERATING_SBOM", "BUILDING_GRAPH", "ANALYZING_RISK",
  "COMPLETED",
];

const completed = scanFixture as ScanState;
const polls = new Map<string, number>();
const mockDecisions = new Map<string, RemediationProposal>();

function stateAt(id: string, step: number): ScanState {
  const status = STAGES[Math.min(step, STAGES.length - 1)];
  const done = status === "COMPLETED";
  return {
    ...completed,
    scan_id: id,
    status,
    current_stage: status === "QUEUED" ? null : done ? "ANALYZING_RISK" : status,
    started_at: status === "QUEUED" ? null : completed.started_at,
    finished_at: done ? completed.finished_at : null,
    repository: {
      ...completed.repository,
      commit_sha: step >= 2 ? completed.repository.commit_sha : null,
    },
    warnings: done ? completed.warnings : [],
  };
}

function withId<T extends object>(fixture: T, id: string): T {
  return { ...fixture, scan_id: id };
}

export function resetMockApi() {
  polls.clear();
  mockDecisions.clear();
}

function sampleProposal(id: string): RemediationProposal {
  const sampleFinding = (findingsFixture as FindingsDocument).findings[0];
  const subject = sampleFinding?.subject_label ?? "sample-package@1.0.0";
  return mockDecisions.get("rem_sample") ?? {
    proposal_id: "rem_sample", scan_id: id, finding_id: sampleFinding?.finding_id ?? "finding_sample",
    action: "upgrade", subject_label: subject,
    current_value: subject.includes("@") ? subject.slice(subject.lastIndexOf("@") + 1) : null,
    proposed_value: sampleFinding?.fixed_versions[0] ?? null,
    recommendation: `Evaluate upgrading to the reported fixed version ${sampleFinding?.fixed_versions[0] ?? "after review"}.`,
    rationale: "A vulnerability source reports a fixed version and a proven dependency path.",
    expected_risk_reduction: "high", compatibility_impact: "unknown",
    evidence: sampleFinding?.evidence ?? [{ path: "package-lock.json", kind: "lockfile", locator: "sample" }],
    uncertainty: ["Compatibility still requires validation."],
    repository_commit: completed.repository.commit_sha ?? "0".repeat(40), finding_digest: "a".repeat(64), proposal_digest: "b".repeat(64),
    status: "PENDING", version: 1, created_at: completed.finished_at ?? new Date().toISOString(), decision: null,
  };
}

export const mockApi: ScanApi = {
  createScan: async () => {
    const id = completed.scan_id;
    polls.set(id, 0);
    return { scan_id: id, status: "QUEUED", repository_name: completed.repository.name };
  },
  getScan: async (id) => {
    const step = polls.get(id) ?? STAGES.length - 1;
    polls.set(id, step + 1);
    return stateAt(id, step);
  },
  getInventory: async (id) => withId(inventoryFixture as Inventory, id),
  getSbom: async (id) => withId(sbomFixture as DependencyDocument, id),
  getGraph: async (id) => {
    const graph = graphFixture as GraphDocument;
    return { ...graph, meta: { ...graph.meta, scan_id: id } };
  },
  getFindings: async (id) => withId(findingsFixture as FindingsDocument, id),
  getRemediations: async (id): Promise<RemediationList> => ({ schema_version: "1.0", scan_id: id, proposals: [sampleProposal(id)] }),
  decideRemediation: async (id, proposalId, body: RemediationDecisionCreate) => {
    const proposal = sampleProposal(id);
    const decisionBody = {
      decision: body.decision, decided_by: body.decided_by, reason: body.reason,
      factors: body.factors, conditions: body.conditions, alternative: body.alternative,
      external_reference: body.external_reference,
    };
    const decided: RemediationProposal = {
      ...proposal, status: body.decision, version: proposal.version + 1,
      decision: {
        ...decisionBody, decision_id: "dec_sample", proposal_id: proposalId,
        repository_commit: proposal.repository_commit, finding_digest: proposal.finding_digest,
        proposal_digest: proposal.proposal_digest, decided_at: new Date().toISOString(),
      },
    };
    mockDecisions.set(proposalId, decided);
    return decided;
  },
};

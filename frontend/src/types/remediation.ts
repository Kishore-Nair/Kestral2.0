import type { Evidence } from "@/types/graph";

export type RemediationAction = "upgrade" | "replace" | "remove" | "pin" | "mitigate" | "block" | "security_review";
export type ProposalStatus = "PENDING" | "APPROVED" | "REJECTED" | "SUPERSEDED";
export type DecisionType = "APPROVED" | "REJECTED";
export type DecisionFactor =
  | "SECURITY_RISK" | "EXPLOITABILITY" | "DEPENDENCY_PATH" | "APPLICATION_CONTEXT"
  | "COMPATIBILITY" | "BUSINESS_IMPACT" | "TEST_EVIDENCE" | "SOURCE_CONFIDENCE"
  | "INCOMPLETE_EVIDENCE" | "LICENSE_OR_POLICY" | "OPERATIONAL_RISK"
  | "ROLLBACK_READINESS" | "ALTERNATIVE_AVAILABLE" | "OTHER";

export interface RemediationDecisionCreate {
  decision: DecisionType;
  decided_by: string;
  reason: string;
  factors: DecisionFactor[];
  conditions: string | null;
  alternative: string | null;
  external_reference: string | null;
  expected_proposal_version: number;
}

export interface RemediationDecision extends Omit<RemediationDecisionCreate, "expected_proposal_version"> {
  decision_id: string;
  proposal_id: string;
  repository_commit: string;
  finding_digest: string;
  proposal_digest: string;
  decided_at: string;
}

export interface RemediationProposal {
  proposal_id: string;
  scan_id: string;
  finding_id: string;
  action: RemediationAction;
  subject_label: string;
  current_value: string | null;
  proposed_value: string | null;
  recommendation: string;
  rationale: string;
  expected_risk_reduction: "high" | "medium" | "low" | "unknown";
  compatibility_impact: "high" | "medium" | "low" | "unknown";
  evidence: Evidence[];
  uncertainty: string[];
  repository_commit: string;
  finding_digest: string;
  proposal_digest: string;
  status: ProposalStatus;
  version: number;
  created_at: string;
  decision: RemediationDecision | null;
}

export interface RemediationList {
  schema_version: "1.0";
  scan_id: string;
  proposals: RemediationProposal[];
}

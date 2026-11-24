// Mirrors backend app/schemas/ai.py (optional AI analyst, schema 1.0).

export type AnalysisStatus =
  | "queued" | "running" | "recommendation_ready" | "needs_human_review"
  | "insufficient_evidence" | "no_verified_fix" | "ai_unavailable" | "validation_failed" | "failed";

export type ClaimKind = "verified_fact" | "model_interpretation" | "recommendation" | "unknown";

export interface AiStatus {
  enabled: boolean;
  configured: boolean;
  provider: string;
  api_key_env: string;
  model: string;
  prompt_version: string;
  tool_budget: number;
  data_notice: string;
}

export interface EvidenceItem { id: string; kind: string; source: string; summary: string; external: boolean }

export interface ToolCall {
  index: number;
  name: string;
  arguments: Record<string, unknown>;
  status: "ok" | "error" | "rejected" | "budget_exhausted";
  external: boolean;
  evidence_ids: string[];
  duration_ms: number;
  message: string | null;
}

export interface ValidationCheck { id: string; status: "passed" | "failed" | "not_run" | "warning"; detail: string }

export interface ValidationResult {
  status: "passed" | "partial" | "failed";
  checks: ValidationCheck[];
  blocking_issues: string[];
  warnings: string[];
}

export interface Remediation {
  type: string;
  target_component_id: string | null;
  target_version: string | null;
  steps: string[];
  evidence_refs: string[];
  fixed_version_verified: boolean;
  version_source: string | null;
  version_source_url: string | null;
}

export interface Claim { claim: string; kind: ClaimKind; evidence_refs: string[]; verification_status: "verified" | "unverified" | "rejected" }

export interface AiRecommendation {
  schema_version: "1.0";
  scan_id: string;
  finding_id: string;
  commit_sha: string | null;
  status: AnalysisStatus;
  title: string;
  summary: string;
  why_it_matters: string;
  original_finding: {
    finding_id: string; kind: string; title: string; advisory_ids: string[]; component_id: string | null;
    package: string; ecosystem: string | null; installed_version: string | null; severity: string | null;
    severity_source: string | null; cvss_base_score: number | null; priority_score: number | null;
    priority_band: string | null; risk_level: string | null; fixed_versions: string[];
  };
  recommended_remediation: Remediation;
  alternatives: Array<{ type: string; description: string; tradeoffs: string }>;
  compatibility: {
    breaking_change_risk: "low" | "medium" | "high" | "unknown";
    notes: string[];
    required_checks: string[];
    manifest_status: "accepts" | "rejects" | "not_checked";
    manifest_detail: string;
  };
  risks_and_tradeoffs: string[];
  validation_plan: string[];
  residual_risk: string[];
  claims: Claim[];
  unknowns: string[];
  confidence: "low" | "medium" | "high";
  evidence: EvidenceItem[];
  human_approval_required: true;
  patch: { available: false; diff: null; files_affected: string[] };
  tool_trace: ToolCall[];
  stop_reason: string;
  validation: ValidationResult;
  model_metadata: { provider: string; model: string; prompt_version: string; effort: string | null; input_tokens: number; output_tokens: number };
}

export interface AiAnalysis {
  analysis_id: string;
  scan_id: string;
  finding_id: string;
  status: AnalysisStatus;
  stale: boolean;
  cached: boolean;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  recommendation: AiRecommendation | null;
  decision: { decision: "approved" | "rejected"; note: string | null; decided_at: string } | null;
}

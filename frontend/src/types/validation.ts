// Mirrors backend app/schemas/validation.py (sandbox validation of approved fixes, 1.0).

export type SourceType = "remediation" | "ai";
export type StepStatus = "passed" | "failed" | "warning" | "not_run" | "skipped";
export type Verdict =
  | "FIXED" | "FIXED_WITH_NEW_RISK" | "FIXED_TESTS_FAILED" | "NOT_FIXED" | "FAILED" | "UNSUPPORTED";
export type TestsStatus = "passed" | "regression" | "failed_before_and_after" | "no_tests" | "not_run" | "error";

export interface ValidationChange {
  source_type: SourceType;
  source_id: string;
  finding_id: string;
  component_id: string;
  package: string;
  ecosystem: string;
  project_path: string;
  from_version: string | null;
  to_version: string;
  approved_by: string | null;
  approved_at: string | null;
}

export interface ValidationCandidate {
  source_type: SourceType;
  source_id: string;
  finding_id: string;
  title: string;
  package: string;
  ecosystem: string | null;
  from_version: string | null;
  to_version: string | null;
  approved_by: string | null;
  approved_at: string | null;
  supported: boolean;
  reason: string | null;
}

export interface ValidationStep { id: string; label: string; status: StepStatus; detail: string; duration_ms: number }
export interface FileDiff { path: string; lines_added: number; lines_removed: number; diff: string; truncated: boolean }
export interface TestRun {
  phase: "baseline" | "patched";
  status: "passed" | "failed" | "no_tests" | "error" | "not_run";
  runtime: string | null;
  image: string | null;
  command: string | null;
  exit_code: number | null;
  duration_s: number | null;
  output_tail: string;
}
export interface FindingRef { finding_id: string; kind: string; title: string; package: string; advisory_ids: string[]; level: string | null }
export interface Comparison {
  target_resolved: boolean | null;
  target_remaining: FindingRef[];
  resolved: FindingRef[];
  introduced: FindingRef[];
  introduced_suspicious: FindingRef[];
  before_counts: Record<string, number>;
  after_counts: Record<string, number>;
  package_changes: Record<string, number>;
  changed_packages: string[];
}
export interface ValidationResult {
  verdict: Verdict;
  verdict_reason: string;
  tests_status: TestsStatus;
  tests_detail: string;
  sandbox_commit: string | null;
  steps: ValidationStep[];
  diffs: FileDiff[];
  tests: TestRun[];
  comparison: Comparison | null;
  rescan_artifacts: string | null;
  residual_risks: string[];
}
export interface ValidationRun {
  schema_version: "1.0";
  validation_id: string;
  scan_id: string;
  status: "queued" | "running" | "completed" | "failed";
  change: ValidationChange;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  result: ValidationResult | null;
}
export interface SandboxInfo { container_runtime: string | null; tests_enabled: boolean; npm_available: boolean; notes: string[] }
export interface ValidationOverview {
  schema_version: "1.0";
  scan_id: string;
  sandbox: SandboxInfo;
  candidates: ValidationCandidate[];
  runs: ValidationRun[];
}

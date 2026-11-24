// Mirrors backend app/schemas/findings.py (findings.json v1.0, Phase 1B risk analysis).
import type { Evidence } from "@/types/graph";

export type FindingKind = "vulnerability" | "workflow_pin" | "suspicious";
export type SourceName = "OSV" | "Grype" | "NVD" | "workflow-scan" | "supply-chain-scan" | "scan-diff";
export type RiskLevel = "high" | "medium" | "low";

export interface FindingSource {
  name: SourceName;
  record_id: string;
  url: string | null;
  severity: string | null;
  cvss_vectors: string[];
  match_type: string | null;
}

export interface CveRef {
  id: string;
  url: string;
  looked_up: boolean;
  in_nvd: boolean;
  nvd_status: string | null;
  published: string | null;
  last_modified: string | null;
  description: string | null;
}

export interface CweRef {
  id: string;
  url: string | null;
  sources: string[];
}

export interface CvssScore {
  version: string;
  vector: string;
  base_score: number | null;
  severity: string | null;
  source: string;
  source_type: string | null;
  cve_id: string | null;
  computed: boolean;
  published_score: number | null;
  matches_published: boolean | null;
}

export interface EpssScore {
  cve_id: string;
  probability: number;
  percentile: number;
  date: string | null;
  source: string;
}

export interface PriorityFactor {
  name: string;
  value: string;
  weight: number;
  points: number;
}

export interface Priority {
  score: number;
  band: "critical" | "high" | "medium" | "low";
  factors: PriorityFactor[];
  method: string;
}

export interface Finding {
  finding_id: string;
  kind: FindingKind;
  title: string;
  subject_id: string | null;
  subject_label: string;
  advisory_ids: string[];
  sources: FindingSource[];
  fixed_versions: string[];
  evidence: Evidence[];
  scope: string | null;
  directness: "direct" | "transitive" | "unknown" | null;
  dependency_paths: string[][];
  affected_projects: string[];
  dependent_packages: number | null;
  uncertainty: string[];
  // Added by NVD/CVSS enrichment; absent on findings from older scans.
  cves?: CveRef[];
  cwes?: CweRef[];
  cvss?: CvssScore | null;
  epss?: EpssScore | null;
  priority?: Priority | null;
  // Non-CVE (suspicious) findings: anomaly category and rule-based initial risk level.
  category?: string | null;
  risk_level?: RiskLevel | null;
  risk_reason?: string | null;
}

export interface SourceRun {
  name: SourceName;
  status: "ok" | "failed" | "skipped";
  tool_version: string | null;
  database_built: string | null;
  retrieved_at: string | null;
  queried: number;
  raw_output: string | null;
  message: string | null;
}

export interface FindingStats {
  vulnerabilities: number;
  vulnerable_packages: number;
  confirmed_by_both: number;
  workflow_pins: number;
  components_total: number;
  components_assessed: number;
  components_not_assessed: number;
  cves_linked?: number;
  nvd_scored?: number;
  suspicious?: number;
}

export interface PackageChange {
  ecosystem: string;
  name: string;
  project_path: string;
  from_versions: string[];
  to_versions: string[];
  component_id: string | null;
}

export interface ChangeSummary {
  baseline_scan_id: string;
  baseline_commit: string | null;
  baseline_ref: string | null;
  baseline_finished_at: string | null;
  current_commit: string | null;
  same_commit: boolean;
  added: PackageChange[];
  removed: PackageChange[];
  upgraded: PackageChange[];
  downgraded: PackageChange[];
  other_changes: PackageChange[];
  totals: Record<string, number>;
  files_compared: boolean;
  files_changed: Array<{ path: string; change: "added" | "removed" | "modified" }>;
  truncated: boolean;
  extraction_gaps?: string[];
  caveats?: string[];
}

export interface FindingsDocument {
  schema_version: "1.0";
  scan_id: string;
  findings: Finding[];
  sources: SourceRun[];
  stats: FindingStats;
  partial: boolean;
  warnings: string[];
  changes?: ChangeSummary | null;
}

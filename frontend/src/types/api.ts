// Mirrors README.md "Canonical contracts" v1.0. Do not rename fields.

export type ScanStatus =
  | "QUEUED" | "CLONING" | "DISCOVERING" | "GENERATING_SBOM"
  | "BUILDING_GRAPH" | "ANALYZING_RISK" | "COMPLETED" | "FAILED";

export const TERMINAL_STATUSES: readonly ScanStatus[] = ["COMPLETED", "FAILED"];

export const PIPELINE_STAGES: readonly ScanStatus[] = [
  "QUEUED", "CLONING", "DISCOVERING", "GENERATING_SBOM", "BUILDING_GRAPH", "ANALYZING_RISK",
  "COMPLETED",
];

export interface ScanCreate {
  repository_url: string;
  ref?: string | null;
}
export interface ScanCreated {
  scan_id: string;
  status: "QUEUED";
  repository_name: string;
}
export interface ScanState {
  schema_version: "1.0";
  scan_id: string;
  status: ScanStatus;
  current_stage: ScanStatus | null;
  repository: {
    url: string; owner: string; name: string;
    requested_ref: string | null; resolved_ref: string | null;
    commit_sha: string | null;
  };
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  warnings: string[];
}
export interface ArtifactEntry {
  path: string; kind: string; ecosystem: string;
}
export interface Inventory {
  schema_version: "1.0"; scan_id: string;
  languages: Array<{ name: string; file_count: number }>;
  manifests: ArtifactEntry[]; lockfiles: ArtifactEntry[];
  dockerfiles: string[]; ci_files: string[]; iac_files: string[];
  existing_sboms: string[]; source_directories: string[];
  file_count: number; partial: boolean; warnings: string[];
}
export interface ApiError {
  error: { code: string; message: string; details: Record<string, unknown> };
  scan_id: string | null;
}

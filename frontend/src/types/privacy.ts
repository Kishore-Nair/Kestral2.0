// Mirrors backend app/schemas/privacy.py (schema 1.0).

export type DataContext = "simple" | "behavioural" | "financial" | "sensitive";
export type PrivacyBand = "low" | "medium" | "high" | "very_high";
export type MappingStatus =
  | "mapped"
  | "no_cwe"
  | "cwe_excluded"
  | "cwe_has_no_category"
  | "category_has_no_linddun"
  | "cwe_not_in_dataset";

export interface LinddunMapping {
  cwe_id: string;
  status: MappingStatus;
  linddun: string[];
  inherited: string[];
  override: boolean;
  rationale: string | null;
  mitre_categories: string[];
  nvd_cves: number;
  source: string | null;
}

export interface EnisaFactor {
  name: string;
  value: number;
  basis: string;
}

export interface PrivacyImpact {
  finding_id: string;
  title: string;
  subject_label: string;
  advisory_ids: string[];
  status: MappingStatus;
  linddun: string[];
  mappings: LinddunMapping[];
  score: number | null;
  band: PrivacyBand | null;
  dpc: number;
  ei: number | null;
  cb: number | null;
  factors: EnisaFactor[];
  uncertainty: string[];
  security_priority: number | null;
}

export interface DataContextOption {
  value: DataContext;
  label: string;
  dpc: number;
  examples: string;
}

export interface PrivacyDataset {
  dataset_file: string;
  dataset_sha256: string;
  dataset_rows: number;
  dataset_labelled_rows: number;
  built_at: string;
  cwes: number;
  cwes_mapped: number;
  cwes_from_chain: number;
  label_rule: string;
}

export interface PrivacySummary {
  assessed: number;
  mapped: number;
  unmapped: number;
  by_band: Record<string, number>;
  by_linddun: Record<string, number>;
  unmapped_reasons: Record<string, number>;
  max_score: number | null;
  max_band: PrivacyBand | null;
}

export interface PrivacyAssessment {
  schema_version: "1.0";
  scan_id: string;
  data_context: DataContext;
  dpc: number;
  data_contexts: DataContextOption[];
  method: string;
  dataset: PrivacyDataset;
  summary: PrivacySummary;
  impacts: PrivacyImpact[];
  caveats: string[];
}

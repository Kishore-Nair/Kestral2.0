// Mirrors README.md normalized.json (DependencyDocument) contract v1.0.
// GET /scans/{id}/sbom returns this normalized document, not raw CycloneDX.
import type { Evidence, UnresolvedTarget } from "@/types/graph";

export type Ecosystem = "npm" | "pypi" | string;
export type ComponentScope = "runtime" | "dev" | "optional" | "unknown";

export interface DependencyRoot {
  root_id: string;
  name: string;
  path: string;
  manifest_path: string;
  ecosystem: Ecosystem;
}
/** At least one of id or name is present. */
export interface License {
  id: string | null;
  name: string | null;
  url: string | null;
}
export interface ComponentHash {
  alg: string;
  content: string;
}
export interface DependencyComponent {
  component_id: string;
  name: string;
  version: string | null;
  ecosystem: Ecosystem;
  purl: string | null;
  install_path: string | null;
  project_path: string;
  scope: ComponentScope;
  licenses: License[];
  hashes: ComponentHash[];
  evidence: Evidence[];
  resolved: boolean;
}
export interface DependencyRelationship {
  relationship_id: string;
  from_id: string;
  to_id: string | null;
  unresolved_target: UnresolvedTarget | null;
  resolution_status: "resolved" | "unresolved" | "ambiguous";
  type: "DEPENDS_ON";
  evidence: Evidence[];
}
export interface DependencyDocument {
  schema_version: "1.0";
  scan_id: string;
  roots: DependencyRoot[];
  components: DependencyComponent[];
  relationships: DependencyRelationship[];
  partial: boolean;
  warnings: string[];
}

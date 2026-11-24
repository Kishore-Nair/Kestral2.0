// Mirrors README.md graph.json contract v1.0 (Member 4 -> Member 5).

export type NodeKind = "application" | "project" | "package" | "unresolved";
export type Directness = "direct" | "transitive" | "unknown" | "not_applicable";
export interface Evidence { path: string; kind: string; locator: string }
export interface UnresolvedTarget { name: string; specifier: string; ecosystem: string }
export interface GraphNodeData {
  id: string; label: string; type: NodeKind; directness: Directness;
  depth: number | null;
  // package-only fields (unresolved nodes carry ecosystem in unresolved_target)
  name?: string; version?: string | null; ecosystem?: string;
  purl?: string | null; project_path?: string; install_path?: string | null;
  evidence?: Evidence[];
  // optional unresolved target metadata; do not assume a package was resolved
  unresolved_target?: UnresolvedTarget;
  resolution_status?: "unresolved" | "ambiguous";
}
export interface GraphEdgeData {
  id: string; source: string; target: string;
  type: "CONTAINS" | "DEPENDS_ON";
  resolution_status?: "resolved" | "unresolved" | "ambiguous";
  evidence?: Evidence[];
}
export interface GraphStats {
  applications: number; projects: number; packages: number;
  unresolved: number; depends_on_edges: number;
  max_depth: number; cycles: number;
}
export interface GraphDocument {
  meta: {
    schema_version: "1.0"; scan_id: string; partial: boolean;
    stats: GraphStats;
    warnings: string[];
  };
  nodes: Array<{ data: GraphNodeData }>;
  edges: Array<{ data: GraphEdgeData }>;
}

// Pure graph helpers: search, filtering, neighborhood limiting and payload validation.
// None of these mutate the original GraphDocument.
import type { GraphDocument, GraphEdgeData, GraphNodeData } from "@/types/graph";

export type DirectnessFilter = "all" | "direct" | "transitive" | "unresolved";
export type EcosystemBucket = "npm" | "pypi" | "other";

export const ECOSYSTEM_BUCKETS: readonly EcosystemBucket[] = ["npm", "pypi", "other"];
export const LARGE_GRAPH_LIMIT = 400;

type Node = { data: GraphNodeData };
type Edge = { data: GraphEdgeData };

export interface GraphView {
  nodes: Node[];
  edges: Edge[];
  totalNodes: number;
  hiddenByFilter: number;
  hiddenByLimit: number;
}

/** Label for display: name@version when known, never "@undefined". */
export function nodeDisplayLabel(data: GraphNodeData): string {
  if (data.type === "package" && data.name) {
    return data.version ? `${data.name}@${data.version}` : data.name;
  }
  if (data.type === "unresolved" && data.unresolved_target) {
    const { name, specifier } = data.unresolved_target;
    return specifier ? `${name} ${specifier}` : name;
  }
  return data.label || data.id;
}

export function isContextNode(data: GraphNodeData): boolean {
  return data.type === "application" || data.type === "project";
}

/** Packages carry `ecosystem`; unresolved nodes carry it inside `unresolved_target`. */
export function nodeEcosystem(data: GraphNodeData): string | undefined {
  return data.ecosystem ?? data.unresolved_target?.ecosystem;
}

export function ecosystemBucket(ecosystem: string | undefined): EcosystemBucket {
  const eco = (ecosystem ?? "").toLowerCase();
  if (eco === "npm") return "npm";
  if (eco === "pypi" || eco === "python" || eco === "pip") return "pypi";
  return "other";
}

/** Case-insensitive match on name, PURL, version and label. Deterministic order. */
export function searchNodes(graph: GraphDocument, query: string): GraphNodeData[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return graph.nodes
    .map((n) => n.data)
    .filter((d) => d.type === "package" || d.type === "unresolved")
    .filter((d) =>
      [d.name, d.purl, d.version, d.label, d.unresolved_target?.name]
        .some((field) => typeof field === "string" && field.toLowerCase().includes(q)),
    )
    .sort((a, b) =>
      nodeDisplayLabel(a).localeCompare(nodeDisplayLabel(b)) || a.id.localeCompare(b.id),
    );
}

function matchesDirectness(data: GraphNodeData, filter: DirectnessFilter): boolean {
  switch (filter) {
    case "all":
      return true;
    case "direct":
      return data.type === "package" && data.directness === "direct";
    case "transitive":
      return data.type === "package" && data.directness === "transitive";
    case "unresolved":
      return data.type === "unresolved";
  }
}

/** Keep edges only when both endpoints are visible (no dangling edges). */
function edgesBetween(edges: Edge[], visible: Set<string>): Edge[] {
  return edges.filter((e) => visible.has(e.data.source) && visible.has(e.data.target));
}

export function filterGraph(
  graph: GraphDocument,
  filter: DirectnessFilter,
  ecosystems: ReadonlySet<EcosystemBucket> = new Set(ECOSYSTEM_BUCKETS),
): GraphView {
  const nodes = graph.nodes.filter(({ data }) =>
    isContextNode(data) ||
    (matchesDirectness(data, filter) && ecosystems.has(ecosystemBucket(nodeEcosystem(data)))),
  );
  const visible = new Set(nodes.map((n) => n.data.id));
  return {
    nodes,
    edges: edgesBetween(graph.edges, visible),
    totalNodes: graph.nodes.length,
    hiddenByFilter: graph.nodes.length - nodes.length,
    hiddenByLimit: 0,
  };
}

/**
 * For large graphs, show a breadth-first neighborhood (from `focusId` or the
 * application/project roots) of at most `limit` nodes. Unseen nodes still exist.
 */
export function limitView(view: GraphView, limit: number, focusId?: string | null): GraphView {
  if (view.nodes.length <= limit) return view;
  const byId = new Map(view.nodes.map((n) => [n.data.id, n]));
  const adjacency = new Map<string, string[]>();
  for (const { data } of view.edges) {
    adjacency.set(data.source, [...(adjacency.get(data.source) ?? []), data.target]);
    adjacency.set(data.target, [...(adjacency.get(data.target) ?? []), data.source]);
  }
  const seeds = focusId && byId.has(focusId)
    ? [focusId]
    : view.nodes.filter((n) => isContextNode(n.data)).map((n) => n.data.id);
  const kept = new Set<string>();
  const queue = [...seeds];
  while (queue.length && kept.size < limit) {
    const id = queue.shift()!;
    if (kept.has(id)) continue;
    kept.add(id);
    for (const next of adjacency.get(id) ?? []) if (!kept.has(next)) queue.push(next);
  }
  // Disconnected remainder: fill in deterministic order so the cap is honored.
  for (const n of view.nodes) {
    if (kept.size >= limit) break;
    kept.add(n.data.id);
  }
  const nodes = view.nodes.filter((n) => kept.has(n.data.id));
  return {
    ...view,
    nodes,
    edges: edgesBetween(view.edges, kept),
    hiddenByLimit: view.nodes.length - nodes.length,
  };
}

/** Returns a list of problems; an empty list means the payload is renderable. */
export function validateGraph(payload: unknown): string[] {
  const problems: string[] = [];
  const g = payload as Partial<GraphDocument> | null;
  if (!g || typeof g !== "object") return ["Graph response is not a JSON object."];
  if (!g.meta || typeof g.meta !== "object") problems.push("Missing graph meta.");
  else if (!g.meta.stats) problems.push("Missing graph meta.stats.");
  if (!Array.isArray(g.nodes)) problems.push("Graph nodes is not an array.");
  if (!Array.isArray(g.edges)) problems.push("Graph edges is not an array.");
  if (problems.length) return problems;
  const ids = new Set<string>();
  for (const n of g.nodes!) {
    if (!n?.data?.id) problems.push("A node is missing data.id.");
    else if (ids.has(n.data.id)) problems.push(`Duplicate node id ${n.data.id}.`);
    else ids.add(n.data.id);
  }
  const edgeIds = new Set<string>();
  for (const e of g.edges!) {
    if (!e?.data?.id) problems.push("An edge is missing data.id.");
    else if (edgeIds.has(e.data.id)) problems.push(`Duplicate edge id ${e.data.id}.`);
    else edgeIds.add(e.data.id);
  }
  return problems;
}

/** Edges whose endpoints are missing; reported as a contract issue, not rendered. */
export function danglingEdges(graph: GraphDocument): GraphEdgeData[] {
  const ids = new Set(graph.nodes.map((n) => n.data.id));
  return graph.edges.map((e) => e.data).filter((e) => !ids.has(e.source) || !ids.has(e.target));
}

export function countByDirectness(graph: GraphDocument) {
  const counts = { all: 0, direct: 0, transitive: 0, unresolved: 0 };
  for (const { data } of graph.nodes) {
    if (isContextNode(data)) continue;
    counts.all += 1;
    if (data.type === "unresolved") counts.unresolved += 1;
    else if (data.directness === "direct") counts.direct += 1;
    else if (data.directness === "transitive") counts.transitive += 1;
  }
  return counts;
}

export function countByEcosystem(graph: GraphDocument): Record<EcosystemBucket, number> {
  const counts: Record<EcosystemBucket, number> = { npm: 0, pypi: 0, other: 0 };
  for (const { data } of graph.nodes) {
    if (isContextNode(data)) continue;
    counts[ecosystemBucket(nodeEcosystem(data))] += 1;
  }
  return counts;
}

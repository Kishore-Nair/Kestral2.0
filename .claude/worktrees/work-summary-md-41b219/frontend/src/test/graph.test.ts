import { describe, expect, it } from "vitest";
import graphFixture from "@/mocks/graph.json";
import type { GraphDocument } from "@/types/graph";
import {
  danglingEdges,
  filterGraph,
  limitView,
  nodeDisplayLabel,
  searchNodes,
  validateGraph,
} from "@/lib/graph";

const graph = graphFixture as GraphDocument;

function assertNoDanglingEdges(view: ReturnType<typeof filterGraph>) {
  const ids = new Set(view.nodes.map((n) => n.data.id));
  for (const e of view.edges) {
    expect(ids.has(e.data.source)).toBe(true);
    expect(ids.has(e.data.target)).toBe(true);
  }
}

describe("graph fixture", () => {
  it("contains expected, typed node and edge IDs", () => {
    expect(validateGraph(graph)).toEqual([]);
    expect(graph.nodes.map((n) => n.data.id)).toEqual(expect.arrayContaining([
      "app:root", "root:6d7e", "root:py01", "cmp:1a2b3c", "cmp:4d5e6f", "unresolved:f1a5",
    ]));
    expect(graph.edges.map((e) => e.data.id)).toEqual(expect.arrayContaining(["edge:app-root", "edge:9a8b7c"]));
    const allowed = ["application", "project", "package", "unresolved"];
    for (const n of graph.nodes) expect(allowed).toContain(n.data.type);
    expect(danglingEdges(graph)).toEqual([]);
  });

  it("unresolved nodes carry target, status and evidence", () => {
    const unresolved = graph.nodes.filter((n) => n.data.type === "unresolved");
    expect(unresolved.length).toBe(graph.meta.stats.unresolved);
    for (const { data } of unresolved) {
      expect(data.unresolved_target).toBeDefined();
      expect(data.resolution_status).toMatch(/unresolved|ambiguous/);
      expect(data.evidence?.length).toBeGreaterThan(0);
    }
  });
});

describe("validateGraph", () => {
  it("rejects malformed payloads and duplicate IDs", () => {
    expect(validateGraph(null)).not.toEqual([]);
    expect(validateGraph({ nodes: [], edges: [] })).toContain("Missing graph meta.");
    const dup = { ...graph, edges: [...graph.edges, graph.edges[0]] };
    expect(validateGraph(dup).join(" ")).toMatch(/Duplicate edge id/);
  });
});

describe("nodeDisplayLabel", () => {
  it("never renders @undefined for unknown versions", () => {
    expect(nodeDisplayLabel({ id: "x", label: "x", type: "package", directness: "unknown", depth: null, name: "left-pad" }))
      .toBe("left-pad");
    expect(nodeDisplayLabel({ id: "x", label: "x", type: "package", directness: "unknown", depth: null, name: "left-pad", version: null }))
      .toBe("left-pad");
    expect(nodeDisplayLabel(graph.nodes.find((n) => n.data.id === "cmp:1a2b3c")!.data)).toBe("express@4.18.2");
  });
});

describe("searchNodes", () => {
  it("matches name, PURL and version case-insensitively with deterministic order", () => {
    expect(searchNodes(graph, "EXPRESS").map((d) => d.id)).toEqual(["cmp:1a2b3c"]);
    expect(searchNodes(graph, "pkg:pypi/").map((d) => d.id)).toEqual(["cmp:6d7e8f"]);
    expect(searchNodes(graph, "2.6.9").map((d) => d.id)).toEqual(["cmp:7a8b9c"]);
    expect(searchNodes(graph, "flask").map((d) => d.id)).toEqual(["unresolved:f1a5"]);
    const first = searchNodes(graph, "e").map((d) => d.id);
    expect(searchNodes(graph, "e").map((d) => d.id)).toEqual(first);
    expect(searchNodes(graph, "   ")).toEqual([]);
  });
});

describe("filterGraph", () => {
  it("direct keeps roots and only direct packages, without dangling edges", () => {
    const view = filterGraph(graph, "direct");
    const ids = view.nodes.map((n) => n.data.id);
    expect(ids).toEqual(expect.arrayContaining(["app:root", "root:6d7e", "cmp:1a2b3c", "cmp:3a4b5c", "cmp:6d7e8f"]));
    expect(ids).not.toContain("cmp:4d5e6f");
    expect(ids).not.toContain("unresolved:f1a5");
    assertNoDanglingEdges(view);
    expect(view.hiddenByFilter).toBe(4);
  });

  it("transitive and unresolved views have no edges to hidden nodes", () => {
    const transitive = filterGraph(graph, "transitive");
    expect(transitive.nodes.filter((n) => n.data.type === "package").map((n) => n.data.id).sort())
      .toEqual(["cmp:0d1e2f", "cmp:4d5e6f", "cmp:7a8b9c"]);
    assertNoDanglingEdges(transitive);
    const unresolved = filterGraph(graph, "unresolved");
    expect(unresolved.nodes.filter((n) => n.data.type === "unresolved")).toHaveLength(1);
    assertNoDanglingEdges(unresolved);
  });

  it("ecosystem toggles hide packages but not roots, and do not mutate input", () => {
    const before = JSON.stringify(graph);
    const view = filterGraph(graph, "all", new Set(["pypi"]));
    expect(view.nodes.some((n) => n.data.ecosystem === "npm")).toBe(false);
    expect(view.nodes.some((n) => n.data.id === "root:6d7e")).toBe(true);
    assertNoDanglingEdges(view);
    expect(JSON.stringify(graph)).toBe(before);
  });

  it("buckets unresolved nodes by unresolved_target.ecosystem", () => {
    const noPypi = filterGraph(graph, "all", new Set(["npm", "other"]));
    expect(noPypi.nodes.some((n) => n.data.id === "unresolved:f1a5")).toBe(false);
    const onlyPypi = filterGraph(graph, "unresolved", new Set(["pypi"]));
    expect(onlyPypi.nodes.some((n) => n.data.id === "unresolved:f1a5")).toBe(true);
  });
});

describe("limitView", () => {
  it("caps large graphs to a root neighborhood and reports hidden count", () => {
    const view = limitView(filterGraph(graph, "all"), 4);
    expect(view.nodes).toHaveLength(4);
    expect(view.hiddenByLimit).toBe(graph.nodes.length - 4);
    expect(view.nodes.map((n) => n.data.id)).toContain("app:root");
    assertNoDanglingEdges(view);
  });

  it("returns the view unchanged when under the limit", () => {
    const full = filterGraph(graph, "all");
    expect(limitView(full, 1000)).toBe(full);
  });
});

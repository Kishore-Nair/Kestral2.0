import { beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import graphFixture from "@/mocks/graph.json";
import type { GraphDocument } from "@/types/graph";
import GraphShell from "@/components/graph/GraphShell";
import PackageInspector from "@/components/graph/PackageInspector";

// Cytoscape needs a real canvas; verify it manually in a browser instead.
vi.mock("next/dynamic", () => ({
  default: () =>
    function GraphCanvasStub(props: { nodes: unknown[]; edges: unknown[] }) {
      return <div data-testid="graph-canvas">{props.nodes.length} nodes / {props.edges.length} edges</div>;
    },
}));

beforeAll(() => {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: true, media: query, onchange: null,
    addEventListener: vi.fn(), removeEventListener: vi.fn(),
    addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn(),
  }));
});

const graph = graphFixture as GraphDocument;

describe("GraphShell", () => {
  it("renders all elements and a visible partial-data warning", () => {
    render(<GraphShell graph={graph} />);
    expect(screen.getByTestId("graph-canvas")).toHaveTextContent(`${graph.nodes.length} nodes / ${graph.edges.length} edges`);
    expect(screen.getByText("Incomplete dependency data")).toBeInTheDocument();
    expect(screen.getByText(/no lockfile; transitive Python/)).toBeInTheDocument();
  });

  it("search result selection opens the inspector with evidence", () => {
    render(<GraphShell graph={graph} />);
    fireEvent.change(screen.getByLabelText(/Search packages/i), { target: { value: "Express" } });
    expect(screen.getByText("1 matching node")).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole("list", { name: "Search results" })).getByRole("button", { name: "express@4.18.2" }));
    const details = screen.getByRole("complementary", { name: "Package details" });
    expect(within(details).getByText("pkg:npm/express@4.18.2")).toBeInTheDocument();
    expect(within(details).getByText("packages.node_modules/express")).toBeInTheDocument();
  });

  it("filters show a hidden-node notice", () => {
    render(<GraphShell graph={graph} />);
    fireEvent.click(screen.getByRole("radio", { name: /Unresolved/ }));
    expect(screen.getByText(/Showing 4 of 10 nodes/)).toBeInTheDocument();
  });

  it("empty graph shows a useful empty state", () => {
    const empty: GraphDocument = {
      meta: { ...graph.meta, partial: false, warnings: [], stats: { applications: 1, projects: 0, packages: 0, unresolved: 0, depends_on_edges: 0, max_depth: 0, cycles: 0 } },
      nodes: [graph.nodes[0]],
      edges: [],
    };
    render(<GraphShell graph={empty} />);
    expect(screen.getByText("No supported dependencies discovered.")).toBeInTheDocument();
    expect(screen.queryByText(/No risks found/)).not.toBeInTheDocument();
  });
});

describe("PackageInspector", () => {
  it("makes unknown values explicit", () => {
    render(<PackageInspector node={{ id: "cmp:x", label: "left-pad", type: "package", name: "left-pad", directness: "unknown", depth: null, version: null, purl: null }} />);
    expect(screen.getByText("Version not resolved")).toBeInTheDocument();
    expect(screen.getByText("No PURL")).toBeInTheDocument();
    expect(screen.getByText(/Evidence unavailable/)).toBeInTheDocument();
  });

  it("explains unresolved targets", () => {
    const node = graph.nodes.find((n) => n.data.type === "unresolved")!.data;
    render(<PackageInspector node={node} />);
    expect(screen.getByText("flask")).toBeInTheDocument();
    expect(screen.getByText(">=2.0")).toBeInTheDocument();
    expect(screen.getByText(/no lockfile evidence/i)).toBeInTheDocument();
  });
});

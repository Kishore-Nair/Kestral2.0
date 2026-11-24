import { beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import graphFixture from "@/mocks/graph.json";
import findingsFixture from "@/mocks/findings.json";
import type { GraphDocument } from "@/types/graph";
import type { Finding, FindingsDocument } from "@/types/findings";
import GraphShell from "@/components/graph/GraphShell";
import FindingsPanel from "@/components/risk/FindingsPanel";
import {
  categoryLabel,
  filterFindings,
  findingsByNode,
  highestReportedSeverity,
  sortFindings,
  sourceAgreement,
} from "@/lib/findings";

vi.mock("@/services/aiApi", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/services/aiApi")>();
  return { ...actual, aiService: actual.mockAiApi };
});

vi.mock("next/dynamic", () => ({
  default: () =>
    function GraphCanvasStub(props: { nodes: Array<{ data: { id: string }; classes?: string }>; pathIds?: string[] | null }) {
      const vulnerable = props.nodes.filter((n) => n.classes === "vulnerable").map((n) => n.data.id);
      return (
        <div data-testid="graph-canvas">
          vulnerable:{vulnerable.join(",")} path:{(props.pathIds ?? []).join(">")}
        </div>
      );
    },
}));

beforeAll(() => {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: true, media: query, onchange: null,
    addEventListener: vi.fn(), removeEventListener: vi.fn(),
    addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn(),
  }));
  Element.prototype.scrollIntoView = vi.fn();
});

const doc = findingsFixture as FindingsDocument;
const graph = graphFixture as GraphDocument;
const [bodyParser, requests, pin, script] = doc.findings as Finding[];

describe("findings helpers", () => {
  it("labels source agreement without voting", () => {
    expect(sourceAgreement(bodyParser)).toBe("Both");
    expect(sourceAgreement(requests)).toBe("OSV only");
    expect(sourceAgreement(pin)).toBe("Workflow scan");
  });

  it("keeps severity labels verbatim and sorts by highest reported", () => {
    expect(highestReportedSeverity(bodyParser)).toBe("High");
    expect(highestReportedSeverity(pin)).toBeNull();
    expect(sortFindings([requests, bodyParser]).map((f) => f.finding_id)).toEqual([
      bodyParser.finding_id, requests.finding_id,
    ]);
  });

  it("sorts by priority, then CVSS, and searches CWEs", () => {
    expect(sortFindings([requests, bodyParser]).map((f) => f.priority?.score)).toEqual([61, 45]);
    expect(filterFindings(doc.findings, "vulnerability", "cwe-400")).toEqual([bodyParser]);
  });

  it("filters by kind and search and groups by graph node", () => {
    expect(filterFindings(doc.findings, "vulnerability", "")).toHaveLength(2);
    expect(filterFindings(doc.findings, "vulnerability", "sample-0002")).toEqual([requests]);
    expect(filterFindings(doc.findings, "workflow_pin", "")).toEqual([pin]);
    const byNode = findingsByNode(doc);
    expect([...byNode.keys()].sort()).toEqual(["cmp:4d5e6f", "cmp:6d7e8f"]);
    expect(findingsByNode(null).size).toBe(0);
  });
});

describe("suspicious-change helpers", () => {
  it("labels, sorts and searches suspicious findings", () => {
    expect(sourceAgreement(script)).toBe("Repository files");
    expect(categoryLabel(script.category)).toBe("Install script");
    expect(filterFindings(doc.findings, "suspicious", "install script")).toEqual([script]);
    const high = { ...script, finding_id: "finding:high", risk_level: "high" as const };
    expect(sortFindings([script, high]).map((f) => f.finding_id)).toEqual(["finding:high", script.finding_id]);
  });
});

describe("FindingsPanel", () => {
  it("shows suspicious changes with risk level, evidence and the scan comparison", () => {
    const onShow = vi.fn();
    render(<FindingsPanel findings={doc} labelFor={(id) => `label:${id}`} onShowInGraph={onShow} />);
    fireEvent.click(screen.getByRole("tab", { name: /Suspicious changes \(1\)/ }));
    const changes = screen.getByRole("region", { name: "Changes since last scan" });
    expect(within(changes).getByText(/1 added · 0 removed · 0 upgraded · 1 downgraded/)).toBeInTheDocument();
    expect(within(changes).getByText("package-lock.json")).toBeInTheDocument();
    expect(screen.getByText("Install script")).toBeInTheDocument();
    expect(screen.getAllByText("Risk low").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: /runs an install script/ }));
    expect(screen.getByText("Initial risk level")).toBeInTheDocument();
    expect(screen.getByText("packages.node_modules/jest hasInstallScript")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show in graph" }));
    expect(onShow).toHaveBeenCalledWith(script, ["root:6d7e", "cmp:3a4b5c"]);
  });

  it("shows extraction-gap caveats instead of hiding them", () => {
    const changes = {
      ...doc.changes!,
      totals: { ...doc.changes!.totals, excluded: 808 },
      caveats: ["package-lock.json: no packages were extracted from it in the earlier scan"],
    };
    render(<FindingsPanel findings={{ ...doc, changes }} labelFor={(id) => id} onShowInGraph={vi.fn()} />);
    fireEvent.click(screen.getByRole("tab", { name: /Suspicious changes/ }));
    expect(screen.getByText(/808 left out \(extraction gap\)/)).toBeInTheDocument();
    expect(screen.getByText(/no packages were extracted from it in the earlier scan/)).toBeInTheDocument();
  });

  it("says when there is no earlier scan to compare with", () => {
    render(<FindingsPanel findings={{ ...doc, changes: null }} labelFor={(id) => id} onShowInGraph={vi.fn()} />);
    fireEvent.click(screen.getByRole("tab", { name: /Suspicious changes/ }));
    expect(screen.getByText(/No earlier scan of this repository to compare with/)).toBeInTheDocument();
  });

  it("shows stats, sources, warnings, evidence, paths and uncertainty", () => {
    const onShow = vi.fn();
    render(<FindingsPanel findings={doc} labelFor={(id) => `label:${id}`} onShowInGraph={onShow} />);
    expect(screen.getByText("Incomplete risk assessment")).toBeInTheDocument();
    expect(screen.getByText("5 / 6")).toBeInTheDocument();
    expect(screen.getByText(/database built 2026-11-23/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /SAMPLE-0001/ }));
    expect(screen.getByText("label:root:6d7e → label:cmp:1a2b3c → label:cmp:4d5e6f")).toBeInTheDocument();
    expect(screen.getByText("packages.node_modules/body-parser")).toBeInTheDocument();
    expect(screen.getByText(/Not reachability-checked/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Show path/ }));
    expect(onShow).toHaveBeenCalledWith(bodyParser, ["root:6d7e", "cmp:1a2b3c", "cmp:4d5e6f"]);

    expect(screen.getAllByText("Priority 61 · high").length).toBeGreaterThan(0);
    expect(screen.getByText("CVSS 3.1 base score 7.5")).toBeInTheDocument();
    expect(screen.getByText("Computed by Kestral from the vector.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /CWE-400/ })).toHaveAttribute(
      "href", "https://cwe.mitre.org/data/definitions/400.html",
    );
    expect(screen.getByText("transitive runtime dependency")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("tab", { name: /Workflow pins \(1\)/ }));
    expect(screen.getByText("actions/checkout: Pinned to mutable ref 'v4'")).toBeInTheDocument();
  });

  it("says not assessed instead of clean when no source ran", () => {
    const none: FindingsDocument = {
      ...doc,
      findings: [],
      sources: doc.sources.map((s) => (s.name === "workflow-scan" ? s : { ...s, status: "failed", message: "down" })),
    };
    render(<FindingsPanel findings={none} labelFor={(id) => id} onShowInGraph={vi.fn()} />);
    expect(screen.getByText("Not assessed")).toBeInTheDocument();
    expect(screen.getByText("Vulnerabilities were not assessed: no source was available.")).toBeInTheDocument();
  });
});

describe("GraphShell with findings", () => {
  it("rings vulnerable nodes, lists them in the inspector and highlights a path", () => {
    render(<GraphShell graph={graph} findings={doc} />);
    expect(screen.getByTestId("graph-canvas")).toHaveTextContent(/vulnerable:\S*cmp:6d7e8f/);
    expect(screen.getByText(/Double ring: known vulnerability/)).toBeInTheDocument();

    const panel = screen.getByRole("region", { name: "Risk findings" });
    fireEvent.click(within(panel).getAllByRole("button", { name: "Show in graph" })[0]);
    expect(screen.getByTestId("graph-canvas")).toHaveTextContent("path:root:6d7e>cmp:1a2b3c>cmp:4d5e6f");
    expect(screen.getByTestId("graph-canvas")).toHaveTextContent("cmp:4d5e6f");
    const details = screen.getByRole("complementary", { name: "Package details" });
    expect(within(details).getByText("Known vulnerabilities (1)")).toBeInTheDocument();
  });

  it("shows the fallback when findings are not available", () => {
    render(<GraphShell graph={graph} findingsFallback={<p>Risk findings: not ready.</p>} />);
    expect(screen.getByText("Risk findings: not ready.")).toBeInTheDocument();
  });
});

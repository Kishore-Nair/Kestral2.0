"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import dynamic from "next/dynamic";
import { Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import WarningsNotice from "@/components/WarningsNotice";
import GraphToolbar from "@/components/graph/GraphToolbar";
import PackageInspector from "@/components/graph/PackageInspector";
import FindingsPanel from "@/components/risk/FindingsPanel";
import type { GraphControls } from "@/components/graph/GraphCanvas";
import { NODE_KIND_STYLE, VULNERABLE_COLOR } from "@/components/graph/graphStyles";
import { useGraphFilter } from "@/hooks/useGraphFilter";
import { FOCUS_THRESHOLD, countByDirectness, countByEcosystem, danglingEdges } from "@/lib/graph";
import { findingsByNode } from "@/lib/findings";
import type { GraphDocument } from "@/types/graph";
import type { Finding, FindingsDocument } from "@/types/findings";

const GraphCanvas = dynamic(() => import("./GraphCanvas"), {
  ssr: false,
  loading: () => <Skeleton className="h-full min-h-[480px] w-full rounded-none" />,
});

function useIsDesktop() {
  const [desktop, setDesktop] = useState(true);
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const update = () => setDesktop(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);
  return desktop;
}

function Legend({ showVulnerable }: { showVulnerable: boolean }) {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 border-t px-3 py-2 text-xs text-muted-foreground" aria-label="Legend">
      {Object.values(NODE_KIND_STYLE).map((k) => (
        <li key={k.label} className="flex items-center gap-1.5">
          <span aria-hidden className="inline-block size-2.5 rounded-sm" style={{ backgroundColor: k.color }} />
          {k.label} ({k.shape.replace("round-rectangle", "rectangle")})
        </li>
      ))}
      <li>Arrow: depends on · dotted: contains · dashed: unresolved (uncertainty, not risk)</li>
      {showVulnerable && (
        <li className="flex items-center gap-1.5">
          <span aria-hidden className="inline-block size-2.5 rounded-full border-[3px] border-double" style={{ borderColor: VULNERABLE_COLOR }} />
          Double ring: known vulnerability (see Risk findings)
        </li>
      )}
    </ul>
  );
}

interface GraphShellProps {
  graph: GraphDocument;
  /** Risk findings for this scan; null while loading, unavailable or for older scans. */
  findings?: FindingsDocument | null;
  /** Shown in the findings row when findings is null (loading / not ready / error). */
  findingsFallback?: ReactNode;
}

/**
 * Graph explorer: renders the center graph panel, the inspector (right column on
 * desktop, sheet on mobile) and a full-width risk findings row. Intended as children
 * of the dashboard grid.
 */
export default function GraphShell({ graph, findings = null, findingsFallback = null }: GraphShellProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [pathIds, setPathIds] = useState<string[] | null>(null);
  const graphSection = useRef<HTMLElement>(null);
  const [controls, setControls] = useState<GraphControls | null>(null);
  const isDesktop = useIsDesktop();
  const f = useGraphFilter(graph, selectedId);

  useEffect(() => {
    setSelectedId(null);
    setPathIds(null);
  }, [graph]);

  const nodesById = useMemo(() => new Map(graph.nodes.map((n) => [n.data.id, n.data])), [graph]);
  const selected = selectedId ? nodesById.get(selectedId) ?? null : null;
  const filterCounts = useMemo(() => countByDirectness(graph), [graph]);
  const ecosystemCounts = useMemo(() => countByEcosystem(graph), [graph]);
  const dangling = useMemo(() => danglingEdges(graph), [graph]);
  const onReady = useCallback((c: GraphControls | null) => setControls(c), []);
  const byNode = useMemo(() => findingsByNode(findings), [findings]);
  const labelFor = useCallback((id: string) => nodesById.get(id)?.label ?? id, [nodesById]);

  // Selecting a node also expands it, so its neighbours appear in the focused view.
  const select = (id: string | null) => {
    setSelectedId(id);
    setPathIds(null);
    if (id) f.expand(id);
  };

  // From a finding: expand every node on the path so it is drawn, then select and mark it.
  const showInGraph = (finding: Finding, path: string[] | null) => {
    if (!finding.subject_id) return;
    for (const id of path ?? [finding.subject_id]) f.expand(id);
    setSelectedId(finding.subject_id);
    setPathIds(path);
    controls?.focus(finding.subject_id);
    graphSection.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const pick = (id: string) => {
    select(id);
    controls?.focus(id);
  };

  const { view } = f;
  const nodes = useMemo(
    () => (byNode.size === 0
      ? view.nodes
      : view.nodes.map((n) => (byNode.has(n.data.id) ? { ...n, classes: "vulnerable" } : n))),
    [view.nodes, byNode],
  );
  const packageCount = filterCounts.all;
  const selectedHidden = selectedId !== null && !view.nodes.some((n) => n.data.id === selectedId);

  return (
    <>
      <section
        ref={graphSection}
        aria-label="Dependency graph"
        className="flex min-w-0 scroll-mt-4 flex-col overflow-hidden rounded-xl border bg-card"
      >
        <GraphToolbar
          query={f.query}
          onQueryChange={f.setQuery}
          matches={f.matches}
          onPick={pick}
          filter={f.filter}
          onFilterChange={f.setFilter}
          filterCounts={filterCounts}
          ecosystems={f.ecosystems}
          ecosystemCounts={ecosystemCounts}
          onToggleEcosystem={f.toggleEcosystem}
          controls={controls}
        />
        <div className="grid gap-2 px-3 pt-3 empty:hidden">
          <WarningsNotice
            title="Incomplete dependency data"
            partial={graph.meta.partial}
            warnings={graph.meta.warnings}
          />
          {dangling.length > 0 && (
            <WarningsNotice
              title={`${dangling.length} edge(s) reference missing nodes and were not drawn (contract issue)`}
              warnings={dangling.slice(0, 5).map((e) => `${e.id}: ${e.source} → ${e.target}`)}
            />
          )}
          {(view.hiddenByFilter > 0 || view.hiddenByLimit > 0) && (
            <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground" role="status">
              <Info className="size-3.5" aria-hidden />
              Showing {view.nodes.length} of {view.totalNodes} nodes.
              {view.hiddenByFilter > 0 && ` ${view.hiddenByFilter} hidden by filters.`}
              {view.hiddenByLimit > 0 && ` ${view.hiddenByLimit} not drawn to keep the page responsive; they still exist.`}
              {view.hiddenByLimit > 0 && (
                <Button variant="link" size="xs" className="h-auto p-0" onClick={() => f.setShowAll(true)}>
                  Show all
                </Button>
              )}
            </p>
          )}
          {(view.hiddenByFocus > 0 || (f.showAll && view.totalNodes > FOCUS_THRESHOLD)) && (
            <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground" role="status">
              <Info className="size-3.5" aria-hidden />
              {view.hiddenByFocus > 0
                ? `Focused view: projects and direct dependencies. ${view.hiddenByFocus} deeper or unconnected nodes are collapsed; click a node to expand its neighbours.`
                : "All nodes shown."}
              {view.hiddenByFocus > 0 && (
                <Button variant="link" size="xs" className="h-auto p-0" onClick={() => f.setShowAll(true)}>
                  Show all
                </Button>
              )}
              {(f.expandedCount > 0 || f.showAll) && (
                <Button variant="link" size="xs" className="h-auto p-0" onClick={f.collapseAll}>
                  Collapse
                </Button>
              )}
            </p>
          )}
          {selectedHidden && (
            <p className="text-xs text-muted-foreground" role="status">
              The selected node is hidden by the current filters.
            </p>
          )}
        </div>
        <div className="relative min-h-[480px] flex-1">
          {packageCount === 0 ? (
            <div className="flex h-full min-h-[480px] items-center justify-center p-6 text-center text-sm text-muted-foreground">
              No supported dependencies discovered.
            </div>
          ) : (
            <GraphCanvas
              nodes={nodes}
              edges={view.edges}
              selectedId={selectedId}
              pathIds={pathIds}
              onSelect={select}
              onReady={onReady}
            />
          )}
        </div>
        <Legend showVulnerable={byNode.size > 0} />
      </section>

      {isDesktop ? (
        <aside aria-label="Package details" className="min-w-0 overflow-auto rounded-xl border bg-card lg:max-h-[calc(100vh-2rem)]">
          <h2 className="border-b px-4 py-3 text-sm font-medium">Package details</h2>
          <PackageInspector node={selected} findings={selectedId ? byNode.get(selectedId) : undefined} />
        </aside>
      ) : (
        <Sheet open={selected !== null} onOpenChange={(open) => { if (!open) setSelectedId(null); }}>
          <SheetContent side="right" className="w-[88vw] overflow-y-auto">
            <SheetHeader>
              <SheetTitle>Package details</SheetTitle>
              <SheetDescription>Evidence for the selected graph node.</SheetDescription>
            </SheetHeader>
            <PackageInspector node={selected} findings={selectedId ? byNode.get(selectedId) : undefined} />
          </SheetContent>
        </Sheet>
      )}

      {(findings || findingsFallback) && (
        <div className="min-w-0 lg:col-span-3">
          {findings ? (
            <FindingsPanel findings={findings} labelFor={labelFor} onShowInGraph={showInGraph} />
          ) : (
            <section aria-label="Risk findings" className="grid gap-2 rounded-xl border bg-card p-4">
              <h2 className="text-base font-semibold">Risk findings</h2>
              {findingsFallback}
            </section>
          )}
        </div>
      )}
    </>
  );
}

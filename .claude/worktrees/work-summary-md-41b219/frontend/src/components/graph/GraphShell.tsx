"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import dynamic from "next/dynamic";
import { Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import WarningsNotice from "@/components/WarningsNotice";
import GraphToolbar from "@/components/graph/GraphToolbar";
import PackageInspector from "@/components/graph/PackageInspector";
import type { GraphControls } from "@/components/graph/GraphCanvas";
import { NODE_KIND_STYLE } from "@/components/graph/graphStyles";
import { useGraphFilter } from "@/hooks/useGraphFilter";
import { countByDirectness, countByEcosystem, danglingEdges } from "@/lib/graph";
import type { GraphDocument } from "@/types/graph";

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

function Legend() {
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 border-t px-3 py-2 text-xs text-muted-foreground" aria-label="Legend">
      {Object.values(NODE_KIND_STYLE).map((k) => (
        <li key={k.label} className="flex items-center gap-1.5">
          <span aria-hidden className="inline-block size-2.5 rounded-sm" style={{ backgroundColor: k.color }} />
          {k.label} ({k.shape.replace("round-rectangle", "rectangle")})
        </li>
      ))}
      <li>Arrow: depends on · dotted: contains · dashed: unresolved (uncertainty, not risk)</li>
    </ul>
  );
}

/**
 * Graph explorer: renders the center graph panel and the inspector (right column on
 * desktop, sheet on mobile). Intended as two children of the dashboard grid.
 */
export default function GraphShell({ graph }: { graph: GraphDocument }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [controls, setControls] = useState<GraphControls | null>(null);
  const isDesktop = useIsDesktop();
  const f = useGraphFilter(graph, selectedId);

  useEffect(() => setSelectedId(null), [graph]);

  const nodesById = useMemo(() => new Map(graph.nodes.map((n) => [n.data.id, n.data])), [graph]);
  const selected = selectedId ? nodesById.get(selectedId) ?? null : null;
  const filterCounts = useMemo(() => countByDirectness(graph), [graph]);
  const ecosystemCounts = useMemo(() => countByEcosystem(graph), [graph]);
  const dangling = useMemo(() => danglingEdges(graph), [graph]);
  const onReady = useCallback((c: GraphControls | null) => setControls(c), []);

  const pick = (id: string) => {
    setSelectedId(id);
    controls?.focus(id);
  };

  const { view } = f;
  const packageCount = filterCounts.all;
  const selectedHidden = selectedId !== null && !view.nodes.some((n) => n.data.id === selectedId);

  return (
    <>
      <section aria-label="Dependency graph" className="flex min-w-0 flex-col overflow-hidden rounded-xl border bg-card">
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
              nodes={view.nodes}
              edges={view.edges}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onReady={onReady}
            />
          )}
        </div>
        <Legend />
      </section>

      {isDesktop ? (
        <aside aria-label="Package details" className="min-w-0 overflow-auto rounded-xl border bg-card lg:max-h-[calc(100vh-2rem)]">
          <h2 className="border-b px-4 py-3 text-sm font-medium">Package details</h2>
          <PackageInspector node={selected} />
        </aside>
      ) : (
        <Sheet open={selected !== null} onOpenChange={(open) => { if (!open) setSelectedId(null); }}>
          <SheetContent side="right" className="w-[88vw] overflow-y-auto">
            <SheetHeader>
              <SheetTitle>Package details</SheetTitle>
              <SheetDescription>Evidence for the selected graph node.</SheetDescription>
            </SheetHeader>
            <PackageInspector node={selected} />
          </SheetContent>
        </Sheet>
      )}
    </>
  );
}

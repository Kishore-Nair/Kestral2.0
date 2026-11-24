"use client";

import { useId } from "react";
import { LayoutGrid, Maximize2, Search, ZoomIn, ZoomOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { GraphNodeData } from "@/types/graph";
import {
  ECOSYSTEM_BUCKETS,
  nodeDisplayLabel,
  type DirectnessFilter,
  type EcosystemBucket,
} from "@/lib/graph";
import type { GraphControls } from "@/components/graph/GraphCanvas";
import { cn } from "@/lib/utils";

const FILTERS: Array<{ value: DirectnessFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "direct", label: "Direct" },
  { value: "transitive", label: "Transitive" },
  { value: "unresolved", label: "Unresolved" },
];

const MAX_RESULTS = 8;

interface Props {
  query: string;
  onQueryChange: (q: string) => void;
  matches: GraphNodeData[];
  onPick: (id: string) => void;
  filter: DirectnessFilter;
  onFilterChange: (f: DirectnessFilter) => void;
  filterCounts: Record<DirectnessFilter, number>;
  ecosystems: ReadonlySet<EcosystemBucket>;
  ecosystemCounts: Record<EcosystemBucket, number>;
  onToggleEcosystem: (b: EcosystemBucket) => void;
  controls: GraphControls | null;
}

export default function GraphToolbar(props: Props) {
  const {
    query, onQueryChange, matches, onPick, filter, onFilterChange, filterCounts,
    ecosystems, ecosystemCounts, onToggleEcosystem, controls,
  } = props;
  const searchId = useId();
  const resultsId = useId();
  const hasQuery = query.trim().length > 0;

  return (
    <div className="grid gap-2 border-b p-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-48 flex-1">
          <label htmlFor={searchId} className="sr-only">Search packages by name, PURL or version</label>
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            id={searchId}
            type="search"
            placeholder="Search name, PURL or version"
            value={query}
            onChange={(e) => onQueryChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && matches[0]) onPick(matches[0].id);
            }}
            aria-controls={hasQuery ? resultsId : undefined}
            className="pl-8"
          />
        </div>
        <div className="flex items-center gap-1" role="group" aria-label="Graph view controls">
          <Button variant="outline" size="icon-sm" onClick={() => controls?.zoomIn()} disabled={!controls} aria-label="Zoom in" title="Zoom in"><ZoomIn /></Button>
          <Button variant="outline" size="icon-sm" onClick={() => controls?.zoomOut()} disabled={!controls} aria-label="Zoom out" title="Zoom out"><ZoomOut /></Button>
          <Button variant="outline" size="icon-sm" onClick={() => controls?.fit()} disabled={!controls} aria-label="Fit graph" title="Fit graph"><Maximize2 /></Button>
          <Button variant="outline" size="icon-sm" onClick={() => controls?.relayout()} disabled={!controls} aria-label="Reset layout" title="Reset layout"><LayoutGrid /></Button>
        </div>
      </div>

      {hasQuery && (
        <div id={resultsId} className="grid gap-1">
          <p className="text-xs text-muted-foreground" aria-live="polite">
            {matches.length} matching {matches.length === 1 ? "node" : "nodes"}
          </p>
          {matches.length > 0 && (
            <ul className="flex flex-wrap gap-1" aria-label="Search results">
              {matches.slice(0, MAX_RESULTS).map((m) => (
                <li key={m.id}>
                  <Button variant="secondary" size="xs" onClick={() => onPick(m.id)}>
                    {nodeDisplayLabel(m)}
                  </Button>
                </li>
              ))}
              {matches.length > MAX_RESULTS && (
                <li className="self-center text-xs text-muted-foreground">+{matches.length - MAX_RESULTS} more</li>
              )}
            </ul>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex flex-wrap gap-1" role="radiogroup" aria-label="Filter by directness">
          {FILTERS.map((f) => (
            <Button
              key={f.value}
              role="radio"
              aria-checked={filter === f.value}
              variant={filter === f.value ? "default" : "outline"}
              size="xs"
              onClick={() => onFilterChange(f.value)}
            >
              {f.label} <span className="tabular-nums opacity-70">{filterCounts[f.value]}</span>
            </Button>
          ))}
        </div>
        <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by ecosystem">
          {ECOSYSTEM_BUCKETS.map((b) => {
            const on = ecosystems.has(b);
            return (
              <Button
                key={b}
                aria-pressed={on}
                variant="ghost"
                size="xs"
                className={cn("border", on ? "border-foreground/30" : "border-dashed text-muted-foreground line-through")}
                onClick={() => onToggleEcosystem(b)}
              >
                {b} <span className="tabular-nums opacity-70">{ecosystemCounts[b]}</span>
              </Button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

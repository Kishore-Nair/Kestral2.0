"use client";

import { useEffect, useRef } from "react";
import type { Core } from "cytoscape";
import type { GraphEdgeData, GraphNodeData } from "@/types/graph";
import { graphStyles } from "@/components/graph/graphStyles";

export interface GraphControls {
  fit: () => void;
  zoomIn: () => void;
  zoomOut: () => void;
  relayout: () => void;
  focus: (id: string) => void;
}

interface Props {
  nodes: Array<{ data: GraphNodeData; classes?: string }>;
  edges: Array<{ data: GraphEdgeData }>;
  selectedId: string | null;
  /** Node IDs of one dependency path to highlight (project -> ... -> package). */
  pathIds?: string[] | null;
  onSelect: (id: string | null) => void;
  onReady?: (controls: GraphControls | null) => void;
}

// Package labels sit to the right of nodes (see graphStyles), so rows can pack tightly
// while ranks get enough room for the label text.
const LAYOUT = { name: "dagre", rankDir: "LR", nodeSep: 10, rankSep: 170, fit: true, padding: 30 };

/**
 * Select a node, fade everything outside its neighborhood, highlight incident edges.
 * When a dependency path is given, its nodes and edges stay visible and are marked.
 */
function applySelection(cy: Core, selectedId: string | null, pathIds: string[] | null | undefined) {
  cy.batch(() => {
    cy.elements().unselect().removeClass("faded highlighted path");
    if (!selectedId) return;
    const node = cy.getElementById(selectedId);
    if (node.empty()) return;
    node.select();
    let keep = node.closedNeighborhood();
    if (pathIds && pathIds.length > 1) {
      let path = cy.collection();
      pathIds.forEach((id, i) => {
        path = path.union(cy.getElementById(id));
        if (i > 0) path = path.union(cy.getElementById(pathIds[i - 1]).edgesTo(cy.getElementById(id)));
      });
      path.addClass("path");
      keep = keep.union(path);
    }
    cy.elements().not(keep).addClass("faded");
    node.connectedEdges().addClass("highlighted");
  });
}

/** Client-only Cytoscape renderer. Load via next/dynamic with ssr:false. */
export default function GraphCanvas({ nodes, edges, selectedId, pathIds, onSelect, onReady }: Props) {
  const container = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | undefined>(undefined);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const selectedRef = useRef(selectedId);
  selectedRef.current = selectedId;
  const pathRef = useRef(pathIds);
  pathRef.current = pathIds;

  useEffect(() => {
    let alive = true;
    let current: Core | undefined;
    (async () => {
      const cytoscape = (await import("cytoscape")).default;
      const dagre = (await import("cytoscape-dagre")).default;
      try {
        cytoscape.use(dagre);
      } catch {
        // already registered (fast refresh / remount)
      }
      if (!alive || !container.current) return;
      current = cytoscape({
        container: container.current,
        elements: [...nodes, ...edges],
        layout: LAYOUT,
        style: graphStyles,
        wheelSensitivity: 0.15,
        minZoom: 0.05,
        maxZoom: 4,
      });
      cyRef.current = current;
      applySelection(current, selectedRef.current, pathRef.current);
      current.on("tap", "node", (event) => onSelectRef.current(event.target.id()));
      current.on("tap", (event) => {
        if (event.target === current) onSelectRef.current(null);
      });
      const cy = current;
      onReady?.({
        fit: () => cy.animate({ fit: { eles: cy.elements(), padding: 30 } }, { duration: 250 }),
        zoomIn: () => cy.zoom({ level: cy.zoom() * 1.25, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }),
        zoomOut: () => cy.zoom({ level: cy.zoom() / 1.25, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }),
        relayout: () => cy.layout(LAYOUT).run(),
        focus: (id) => {
          const node = cy.getElementById(id);
          if (node.nonempty()) cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1.2) }, { duration: 300 });
        },
      });
    })();
    return () => {
      alive = false;
      onReady?.(null);
      current?.destroy();
      cyRef.current = undefined;
    };
    // Recreate the instance when the visible element set changes.
  }, [nodes, edges, onReady]);

  useEffect(() => {
    if (cyRef.current) applySelection(cyRef.current, selectedId, pathIds);
  }, [selectedId, pathIds]);

  return (
    <div
      ref={container}
      role="img"
      aria-label={`Dependency graph with ${nodes.length} nodes and ${edges.length} edges. Use search to select nodes with the keyboard.`}
      className="h-full min-h-[480px] w-full"
    />
  );
}

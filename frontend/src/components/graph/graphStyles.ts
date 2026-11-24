import type { NodeSingular, StylesheetJson } from "cytoscape";
import type { GraphNodeData } from "@/types/graph";
import { nodeDisplayLabel } from "@/lib/graph";

// Node kinds differ by shape AND color so status is never encoded by color alone.
// The palette is categorical and deliberately avoids red/green severity cues.
export const NODE_KIND_STYLE = {
  application: { color: "#334155", shape: "round-rectangle", label: "Application" },
  project: { color: "#4f46e5", shape: "hexagon", label: "Project" },
  package: { color: "#0d9488", shape: "ellipse", label: "Package" },
  unresolved: { color: "#b45309", shape: "diamond", label: "Unresolved" },
} as const;

export const VULNERABLE_COLOR = "#9f1239";

export const graphStyles: StylesheetJson = [
  {
    selector: "node",
    style: {
      label: (ele: NodeSingular) => nodeDisplayLabel(ele.data() as GraphNodeData),
      "font-size": 11,
      "font-family": "ui-sans-serif, system-ui, sans-serif",
      color: "#0f172a",
      "text-valign": "bottom",
      "text-margin-y": 4,
      "text-wrap": "ellipsis",
      "text-max-width": "140px",
      "text-background-color": "#ffffff",
      "text-background-opacity": 0.85,
      "text-background-padding": "2px",
      width: 22,
      height: 22,
      "border-width": 2,
      "border-color": "#ffffff",
    },
  },
  {
    selector: 'node[type = "application"]',
    style: {
      "background-color": NODE_KIND_STYLE.application.color,
      shape: NODE_KIND_STYLE.application.shape,
      width: 44, height: 28, "font-weight": "bold",
    },
  },
  {
    selector: 'node[type = "project"]',
    style: {
      "background-color": NODE_KIND_STYLE.project.color,
      shape: NODE_KIND_STYLE.project.shape,
      width: 34, height: 30, "font-weight": "bold",
    },
  },
  {
    selector: 'node[type = "package"]',
    style: { "background-color": NODE_KIND_STYLE.package.color, shape: NODE_KIND_STYLE.package.shape },
  },
  {
    // Labels beside package/unresolved nodes keep left-to-right columns compact.
    selector: 'node[type = "package"], node[type = "unresolved"]',
    style: {
      width: 16, height: 16, "border-width": 1,
      "text-valign": "center", "text-halign": "right", "text-margin-x": 5, "text-margin-y": 0,
    },
  },
  {
    selector: 'node[type = "package"][directness = "direct"]',
    style: { width: 18, height: 18, "border-color": "#134e4a", "border-width": 2 },
  },
  {
    selector: 'node[type = "package"][directness = "transitive"]',
    style: { "background-opacity": 0.75 },
  },
  {
    selector: 'node[type = "unresolved"]',
    style: {
      "background-color": "#fef3c7",
      shape: NODE_KIND_STYLE.unresolved.shape,
      "border-color": NODE_KIND_STYLE.unresolved.color,
      "border-style": "dashed",
      "border-width": 2,
    },
  },
  {
    selector: "edge",
    style: {
      width: 1,
      opacity: 0.55,
      "curve-style": "bezier",
      "target-arrow-shape": "triangle",
      "arrow-scale": 0.6,
      "line-color": "#94a3b8",
      "target-arrow-color": "#94a3b8",
    },
  },
  {
    selector: 'edge[type = "CONTAINS"]',
    style: {
      "line-color": "#c7d2fe",
      "target-arrow-color": "#c7d2fe",
      "line-style": "dotted",
      width: 1.5,
      opacity: 0.4,
      "target-arrow-shape": "tee",
    },
  },
  {
    selector: 'edge[type = "DEPENDS_ON"]',
    style: { "line-color": "#64748b", "target-arrow-color": "#64748b" },
  },
  {
    selector: 'edge[resolution_status = "unresolved"], edge[resolution_status = "ambiguous"]',
    style: {
      "line-style": "dashed",
      "line-color": NODE_KIND_STYLE.unresolved.color,
      "target-arrow-color": NODE_KIND_STYLE.unresolved.color,
    },
  },
  {
    // Known vulnerability (from risk findings): a thick dark ring, shape-independent.
    selector: "node.vulnerable",
    style: { "border-color": VULNERABLE_COLOR, "border-width": 3, "border-style": "double" },
  },
  {
    selector: "node:selected",
    style: { "overlay-color": "#2563eb", "overlay-opacity": 0.18, "overlay-padding": 6, "border-color": "#2563eb", "border-width": 3 },
  },
  {
    selector: ".faded",
    style: { opacity: 0.25 },
  },
  {
    selector: "edge.highlighted",
    style: { "line-color": "#2563eb", "target-arrow-color": "#2563eb", width: 2.5, opacity: 1 },
  },
  {
    // Dependency path from a finding; listed last so it wins over selection highlight.
    selector: "node.path",
    style: { "border-color": VULNERABLE_COLOR, "border-width": 3, opacity: 1 },
  },
  {
    selector: "edge.path",
    style: { "line-color": VULNERABLE_COLOR, "target-arrow-color": VULNERABLE_COLOR, width: 3, opacity: 1 },
  },
];

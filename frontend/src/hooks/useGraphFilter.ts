"use client";

import { useMemo, useState } from "react";
import type { GraphDocument } from "@/types/graph";
import {
  ECOSYSTEM_BUCKETS,
  LARGE_GRAPH_LIMIT,
  filterGraph,
  focusView,
  limitView,
  searchNodes,
  type DirectnessFilter,
  type EcosystemBucket,
} from "@/lib/graph";

const NO_EXPANDED: ReadonlySet<string> = new Set();

export function useGraphFilter(graph: GraphDocument, focusId: string | null) {
  const [filter, setFilter] = useState<DirectnessFilter>("all");
  const [ecosystems, setEcosystems] = useState<Set<EcosystemBucket>>(
    () => new Set(ECOSYSTEM_BUCKETS),
  );
  const [query, setQuery] = useState("");
  const [showAll, setShowAll] = useState(false);
  // Expanded nodes belong to one graph; a new scan starts collapsed again.
  const [expandedState, setExpandedState] = useState({ graph, ids: NO_EXPANDED });
  const expanded = expandedState.graph === graph ? expandedState.ids : NO_EXPANDED;

  const filtered = useMemo(() => filterGraph(graph, filter, ecosystems), [graph, filter, ecosystems]);
  const focused = useMemo(
    // Focus only applies to the unfiltered view; directness filters already narrow it.
    () => (showAll || filter !== "all" ? filtered : focusView(filtered, expanded)),
    [filtered, showAll, filter, expanded],
  );
  const view = useMemo(
    () => (showAll ? focused : limitView(focused, LARGE_GRAPH_LIMIT, focusId)),
    [focused, showAll, focusId],
  );
  const matches = useMemo(() => searchNodes(graph, query), [graph, query]);

  const toggleEcosystem = (bucket: EcosystemBucket) =>
    setEcosystems((prev) => {
      const next = new Set(prev);
      if (next.has(bucket)) next.delete(bucket);
      else next.add(bucket);
      return next;
    });

  const expand = (id: string) =>
    setExpandedState((prev) => {
      const ids = prev.graph === graph ? prev.ids : NO_EXPANDED;
      return ids.has(id) ? prev : { graph, ids: new Set([...ids, id]) };
    });

  const collapseAll = () => {
    setExpandedState({ graph, ids: NO_EXPANDED });
    setShowAll(false);
  };

  return {
    filter, setFilter,
    ecosystems, toggleEcosystem,
    query, setQuery, matches,
    view, showAll, setShowAll,
    expand, collapseAll, expandedCount: expanded.size,
  };
}

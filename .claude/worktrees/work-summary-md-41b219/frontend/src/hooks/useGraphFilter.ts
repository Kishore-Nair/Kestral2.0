"use client";

import { useMemo, useState } from "react";
import type { GraphDocument } from "@/types/graph";
import {
  ECOSYSTEM_BUCKETS,
  LARGE_GRAPH_LIMIT,
  filterGraph,
  limitView,
  searchNodes,
  type DirectnessFilter,
  type EcosystemBucket,
} from "@/lib/graph";

export function useGraphFilter(graph: GraphDocument, focusId: string | null) {
  const [filter, setFilter] = useState<DirectnessFilter>("all");
  const [ecosystems, setEcosystems] = useState<Set<EcosystemBucket>>(
    () => new Set(ECOSYSTEM_BUCKETS),
  );
  const [query, setQuery] = useState("");
  const [showAll, setShowAll] = useState(false);

  const filtered = useMemo(() => filterGraph(graph, filter, ecosystems), [graph, filter, ecosystems]);
  const view = useMemo(
    () => (showAll ? filtered : limitView(filtered, LARGE_GRAPH_LIMIT, focusId)),
    [filtered, showAll, focusId],
  );
  const matches = useMemo(() => searchNodes(graph, query), [graph, query]);

  const toggleEcosystem = (bucket: EcosystemBucket) =>
    setEcosystems((prev) => {
      const next = new Set(prev);
      if (next.has(bucket)) next.delete(bucket);
      else next.add(bucket);
      return next;
    });

  return {
    filter, setFilter,
    ecosystems, toggleEcosystem,
    query, setQuery, matches,
    view, showAll, setShowAll,
  };
}

// Offline sample adapter: same signatures as `api`, static fixtures from src/mocks.
// Every getScan call advances one stage, so progress is deterministic (no random delays).
import type { ScanState, ScanStatus } from "@/types/api";
import type { ScanApi } from "@/services/api";
import scanFixture from "@/mocks/scan.json";
import inventoryFixture from "@/mocks/inventory.json";
import sbomFixture from "@/mocks/sbom.json";
import graphFixture from "@/mocks/graph.json";
import findingsFixture from "@/mocks/findings.json";
import type { FindingsDocument } from "@/types/findings";
import type { Inventory } from "@/types/api";
import type { DependencyDocument } from "@/types/sbom";
import type { GraphDocument } from "@/types/graph";

const STAGES: ScanStatus[] = [
  "QUEUED", "CLONING", "DISCOVERING", "GENERATING_SBOM", "BUILDING_GRAPH", "ANALYZING_RISK",
  "COMPLETED",
];

const completed = scanFixture as ScanState;
const polls = new Map<string, number>();

function stateAt(id: string, step: number): ScanState {
  const status = STAGES[Math.min(step, STAGES.length - 1)];
  const done = status === "COMPLETED";
  return {
    ...completed,
    scan_id: id,
    status,
    current_stage: status === "QUEUED" ? null : done ? "ANALYZING_RISK" : status,
    started_at: status === "QUEUED" ? null : completed.started_at,
    finished_at: done ? completed.finished_at : null,
    repository: {
      ...completed.repository,
      commit_sha: step >= 2 ? completed.repository.commit_sha : null,
    },
    warnings: done ? completed.warnings : [],
  };
}

function withId<T extends object>(fixture: T, id: string): T {
  return { ...fixture, scan_id: id };
}

export function resetMockApi() {
  polls.clear();
}

export const mockApi: ScanApi = {
  createScan: async () => {
    const id = completed.scan_id;
    polls.set(id, 0);
    return { scan_id: id, status: "QUEUED", repository_name: completed.repository.name };
  },
  getScan: async (id) => {
    const step = polls.get(id) ?? STAGES.length - 1;
    polls.set(id, step + 1);
    return stateAt(id, step);
  },
  getInventory: async (id) => withId(inventoryFixture as Inventory, id),
  getSbom: async (id) => withId(sbomFixture as DependencyDocument, id),
  getGraph: async (id) => {
    const graph = graphFixture as GraphDocument;
    return { ...graph, meta: { ...graph.meta, scan_id: id } };
  },
  getFindings: async (id) => withId(findingsFixture as FindingsDocument, id),
};

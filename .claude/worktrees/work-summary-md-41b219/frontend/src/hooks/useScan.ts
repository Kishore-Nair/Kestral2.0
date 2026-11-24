"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { Inventory, ScanState } from "@/types/api";
import type { GraphDocument } from "@/types/graph";
import type { DependencyDocument } from "@/types/sbom";
import type { ScanApi } from "@/services/api";
import { scanService as defaultService } from "@/services/scanService";
import { classifyError, type FriendlyError } from "@/services/errors";
import { validateGraph } from "@/lib/graph";

export const POLL_INTERVAL_MS = 1800;
const MAX_BACKOFF_MS = 15_000;
const MAX_TRANSIENT_FAILURES = 5;

export type ArtifactState<T> =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; data: T }
  | { status: "error"; error: FriendlyError };

export interface ScanArtifacts {
  inventory: ArtifactState<Inventory>;
  sbom: ArtifactState<DependencyDocument>;
  graph: ArtifactState<GraphDocument>;
}

export type PollState =
  | { status: "idle" }
  | { status: "polling"; transientError: FriendlyError | null }
  | { status: "stopped"; error: FriendlyError }
  | { status: "done" };

const IDLE: ScanArtifacts = {
  inventory: { status: "idle" },
  sbom: { status: "idle" },
  graph: { status: "idle" },
};

function settle<T>(result: PromiseSettledResult<T>): ArtifactState<T> {
  return result.status === "fulfilled"
    ? { status: "ready", data: result.value }
    : { status: "error", error: classifyError(result.reason) };
}

/**
 * Polls GET /scans/{id} with a single timer until COMPLETED/FAILED, then fetches
 * inventory, normalized SBOM and graph in parallel. Stale responses from a previous
 * scan ID are ignored; network failures back off and eventually require manual retry.
 */
export function useScan(scanId: string | null, service: ScanApi = defaultService) {
  const [scan, setScan] = useState<ScanState | null>(null);
  const [poll, setPoll] = useState<PollState>({ status: "idle" });
  const [artifacts, setArtifacts] = useState<ScanArtifacts>(IDLE);
  const [pollRun, setPollRun] = useState(0);
  const [artifactRun, setArtifactRun] = useState(0);
  const activeId = useRef<string | null>(scanId);
  activeId.current = scanId;

  // Reset everything when the scan changes.
  useEffect(() => {
    setScan(null);
    setArtifacts(IDLE);
    setPoll(scanId ? { status: "polling", transientError: null } : { status: "idle" });
  }, [scanId]);

  useEffect(() => {
    if (!scanId) return;
    let stopped = false;
    let failures = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      try {
        const state = await service.getScan(scanId);
        if (stopped) return;
        failures = 0;
        setScan(state);
        if (state.status === "COMPLETED" || state.status === "FAILED") {
          setPoll({ status: "done" });
          return;
        }
        setPoll({ status: "polling", transientError: null });
        timer = setTimeout(tick, POLL_INTERVAL_MS);
      } catch (err) {
        if (stopped) return;
        const error = classifyError(err);
        failures += 1;
        if (error.kind === "not_found" || error.kind === "validation" || failures >= MAX_TRANSIENT_FAILURES) {
          setPoll({ status: "stopped", error });
          return;
        }
        setPoll({ status: "polling", transientError: error });
        timer = setTimeout(tick, Math.min(POLL_INTERVAL_MS * 2 ** failures, MAX_BACKOFF_MS));
      }
    };
    setPoll({ status: "polling", transientError: null });
    void tick();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [scanId, service, pollRun]);

  const completed = scan?.status === "COMPLETED" && scan.scan_id === scanId;

  useEffect(() => {
    if (!scanId || !completed) return;
    let stopped = false;
    setArtifacts({
      inventory: { status: "loading" },
      sbom: { status: "loading" },
      graph: { status: "loading" },
    });
    void Promise.allSettled([
      service.getInventory(scanId),
      service.getSbom(scanId),
      service.getGraph(scanId),
    ]).then(([inventory, sbom, graph]) => {
      if (stopped || activeId.current !== scanId) return;
      let graphState = settle(graph);
      if (graphState.status === "ready") {
        const problems = validateGraph(graphState.data);
        if (problems.length) {
          graphState = {
            status: "error",
            error: { kind: "unknown", status: 200, message: `Invalid graph payload: ${problems.join(" ")}` },
          };
        }
      }
      setArtifacts({ inventory: settle(inventory), sbom: settle(sbom), graph: graphState });
    });
    return () => {
      stopped = true;
    };
  }, [scanId, completed, service, artifactRun]);

  const retryPolling = useCallback(() => setPollRun((n) => n + 1), []);
  const retryArtifacts = useCallback(() => setArtifactRun((n) => n + 1), []);

  return { scan, poll, artifacts, retryPolling, retryArtifacts };
}

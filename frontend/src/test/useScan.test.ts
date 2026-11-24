import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { POLL_INTERVAL_MS, useScan } from "@/hooks/useScan";
import type { ScanApi } from "@/services/api";
import type { ScanState, ScanStatus } from "@/types/api";
import scanFixture from "@/mocks/scan.json";
import inventoryFixture from "@/mocks/inventory.json";
import sbomFixture from "@/mocks/sbom.json";
import graphFixture from "@/mocks/graph.json";
import findingsFixture from "@/mocks/findings.json";
import type { GraphDocument } from "@/types/graph";
import { httpError } from "@/test/helpers";

function state(id: string, status: ScanStatus): ScanState {
  return { ...(scanFixture as ScanState), scan_id: id, status, error: status === "FAILED" ? "Clone failed" : null };
}

function makeService(statuses: ScanStatus[]): ScanApi & { getScan: ReturnType<typeof vi.fn> } {
  let i = 0;
  return {
    createScan: vi.fn(),
    getScan: vi.fn(async (id: string) => state(id, statuses[Math.min(i++, statuses.length - 1)])),
    getInventory: vi.fn(async () => inventoryFixture as never),
    getSbom: vi.fn(async () => sbomFixture as never),
    getGraph: vi.fn(async () => graphFixture as GraphDocument),
    getFindings: vi.fn(async () => findingsFixture as never),
    getRemediations: vi.fn(async () => ({ schema_version: "1.0" as const, scan_id: "scan", proposals: [] })),
    decideRemediation: vi.fn(),
  };
}

async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe("useScan", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("polls until COMPLETED, then stops and loads artifacts in parallel", async () => {
    const service = makeService(["QUEUED", "CLONING", "COMPLETED"]);
    const { result } = renderHook(() => useScan("scan_a", service));
    await advance(0);
    expect(result.current.scan?.status).toBe("QUEUED");
    await advance(POLL_INTERVAL_MS);
    await advance(POLL_INTERVAL_MS);
    expect(result.current.scan?.status).toBe("COMPLETED");
    expect(result.current.poll.status).toBe("done");
    await advance(0);
    expect(result.current.artifacts.graph.status).toBe("ready");
    expect(result.current.artifacts.inventory.status).toBe("ready");
    expect(result.current.artifacts.findings.status).toBe("ready");
    const calls = service.getScan.mock.calls.length;
    await advance(POLL_INTERVAL_MS * 5);
    expect(service.getScan.mock.calls.length).toBe(calls);
  });

  it("stops polling on FAILED and keeps the sanitized error", async () => {
    const service = makeService(["CLONING", "FAILED"]);
    const { result } = renderHook(() => useScan("scan_b", service));
    await advance(0);
    await advance(POLL_INTERVAL_MS);
    expect(result.current.scan?.error).toBe("Clone failed");
    await advance(POLL_INTERVAL_MS * 5);
    expect(service.getScan).toHaveBeenCalledTimes(2);
    expect(service.getGraph).toHaveBeenCalledTimes(1);
    expect(result.current.artifacts.graph.status).toBe("ready");
  });

  it("preserves completed artifacts when a failed scan has missing later artifacts", async () => {
    const service = makeService(["FAILED"]);
    service.getFindings = vi.fn().mockRejectedValue(httpError(409));
    const { result } = renderHook(() => useScan("scan_partial", service));
    await advance(0);
    await advance(0);
    expect(result.current.scan?.status).toBe("FAILED");
    expect(result.current.artifacts.inventory.status).toBe("ready");
    expect(result.current.artifacts.sbom.status).toBe("ready");
    expect(result.current.artifacts.graph.status).toBe("ready");
    expect(result.current.artifacts.findings).toMatchObject({ status: "error", error: { kind: "not_ready" } });
  });

  it("never overlaps requests: one in-flight poll at a time", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const service = makeService(["QUEUED"]);
    service.getScan.mockImplementation(async (id: string) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS * 2));
      inFlight -= 1;
      return state(id, "QUEUED");
    });
    renderHook(() => useScan("scan_c", service));
    await advance(POLL_INTERVAL_MS * 10);
    expect(maxInFlight).toBe(1);
  });

  it("clears stale scan state when the scan ID changes", async () => {
    const service = makeService(["CLONING"]);
    const { result, rerender } = renderHook(({ id }) => useScan(id, service), { initialProps: { id: "scan_old" } });
    await advance(0);
    expect(result.current.scan?.scan_id).toBe("scan_old");
    rerender({ id: "scan_new" });
    expect(result.current.scan).toBeNull();
    await advance(0);
    expect(result.current.scan?.scan_id).toBe("scan_new");
  });

  it("stops on 404 and requires manual action", async () => {
    const service = makeService(["QUEUED"]);
    service.getScan.mockRejectedValue(httpError(404));
    const { result } = renderHook(() => useScan("scan_missing", service));
    await advance(0);
    expect(result.current.poll).toMatchObject({ status: "stopped", error: { kind: "not_found" } });
    await advance(POLL_INTERVAL_MS * 5);
    expect(service.getScan).toHaveBeenCalledTimes(1);
  });

  it("reports a graph fetch failure instead of substituting sample data", async () => {
    const service = makeService(["COMPLETED"]);
    service.getGraph = vi.fn().mockRejectedValue(httpError(503));
    const { result } = renderHook(() => useScan("scan_d", service));
    await advance(0);
    await advance(0);
    expect(result.current.artifacts.graph).toMatchObject({ status: "error", error: { kind: "unavailable" } });
  });
});

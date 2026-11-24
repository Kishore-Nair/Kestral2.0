"use client";

import { AlertTriangle, CheckCircle2, Circle, Loader2, RotateCw, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PIPELINE_STAGES, type ScanState, type ScanStatus } from "@/types/api";
import type { PollState } from "@/hooks/useScan";
import { cn } from "@/lib/utils";

export const STAGE_LABELS: Record<ScanStatus, string> = {
  QUEUED: "Queued",
  CLONING: "Cloning",
  DISCOVERING: "Discovering",
  GENERATING_SBOM: "Generating SBOM",
  BUILDING_GRAPH: "Building graph",
  COMPLETED: "Completed",
  FAILED: "Failed",
};

type StepState = "done" | "active" | "pending" | "failed";

function stepState(stage: ScanStatus, scan: ScanState | null): StepState {
  if (!scan) return stage === "QUEUED" ? "active" : "pending";
  const order = PIPELINE_STAGES.indexOf(stage);
  if (scan.status === "FAILED") {
    const reached = scan.current_stage ? PIPELINE_STAGES.indexOf(scan.current_stage) : 0;
    if (order < reached) return "done";
    return order === reached ? "failed" : "pending";
  }
  const current = PIPELINE_STAGES.indexOf(scan.status);
  if (scan.status === "COMPLETED") return "done";
  if (order < current) return "done";
  return order === current ? "active" : "pending";
}

const ICONS: Record<StepState, typeof Circle> = {
  done: CheckCircle2,
  active: Loader2,
  pending: Circle,
  failed: XCircle,
};

interface Props {
  scan: ScanState | null;
  poll: PollState;
  graphReady: boolean;
  onRetryPolling: () => void;
  onResubmit: () => void;
}

export default function ScanProgress({ scan, poll, graphReady, onRetryPolling, onResubmit }: Props) {
  const status = scan?.status ?? "QUEUED";
  const headline =
    status === "COMPLETED" ? (graphReady ? "Graph ready" : "Scan completed — loading results")
      : status === "FAILED" ? "Scan failed"
      : STAGE_LABELS[status];

  return (
    <section aria-labelledby="scan-progress-title" className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 id="scan-progress-title" className="text-sm font-medium">
          Scan stage: <span aria-live="polite" className="text-primary">{headline}</span>
        </h2>
        {scan && (
          <span className="font-mono text-xs text-muted-foreground" title={scan.scan_id}>
            {scan.scan_id}
          </span>
        )}
      </div>

      <ol className="grid grid-cols-3 gap-2 sm:grid-cols-6" aria-label="Scan pipeline">
        {PIPELINE_STAGES.map((stage) => {
          const state = stepState(stage, scan);
          const Icon = ICONS[state];
          return (
            <li
              key={stage}
              aria-current={state === "active" ? "step" : undefined}
              className={cn(
                "flex items-center gap-1.5 rounded-md border px-2 py-1.5 text-xs",
                state === "done" && "border-primary/30 bg-primary/5",
                state === "active" && "border-primary bg-primary/10 font-medium",
                state === "pending" && "text-muted-foreground",
                state === "failed" && "border-destructive/50 bg-destructive/10 text-destructive",
              )}
            >
              <Icon className={cn("size-3.5 shrink-0", state === "active" && "animate-spin")} aria-hidden />
              <span className="truncate">{STAGE_LABELS[stage]}</span>
              <span className="sr-only">({state})</span>
            </li>
          );
        })}
      </ol>

      {scan?.status === "FAILED" && (
        <div role="alert" className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm">
          <span className="flex items-center gap-2">
            <XCircle className="size-4 text-destructive" aria-hidden />
            {scan.error ?? "The scan failed without a reported reason."}
          </span>
          <Button variant="outline" size="sm" onClick={onResubmit}>Scan again</Button>
        </div>
      )}

      {poll.status === "polling" && poll.transientError && (
        <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
          <AlertTriangle className="size-4" aria-hidden />
          {poll.transientError.message} Retrying automatically…
        </p>
      )}

      {poll.status === "stopped" && (
        <div role="alert" className="flex flex-wrap items-center justify-between gap-2 rounded-md border p-3 text-sm">
          <span className="flex items-center gap-2">
            <AlertTriangle className="size-4" aria-hidden />
            {poll.error.message}
          </span>
          {poll.error.kind === "not_found" ? (
            <Button variant="outline" size="sm" onClick={onResubmit}>Start a new scan</Button>
          ) : (
            <Button variant="outline" size="sm" onClick={onRetryPolling}>
              <RotateCw aria-hidden /> Check status again
            </Button>
          )}
        </div>
      )}
    </section>
  );
}

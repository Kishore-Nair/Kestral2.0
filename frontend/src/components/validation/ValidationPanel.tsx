"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Box, FlaskConical, Loader2, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { classifyError } from "@/services/errors";
import { validationService, type ValidationApi } from "@/services/validationApi";
import { cn } from "@/lib/utils";
import type {
  StepStatus, ValidationCandidate, ValidationOverview, ValidationRun, Verdict,
} from "@/types/validation";

const POLL_MS = 3000;

export const VERDICT_LABEL: Record<Verdict, string> = {
  FIXED: "Fix verified in sandbox",
  FIXED_WITH_NEW_RISK: "Fixed, but new risk introduced",
  FIXED_TESTS_FAILED: "Fixed, but tests regressed",
  NOT_FIXED: "Not fixed",
  FAILED: "Validation failed",
  UNSUPPORTED: "Unsupported change",
};

const VERDICT_STYLE: Record<Verdict, string> = {
  FIXED: "border-slate-400 bg-slate-900 text-white",
  FIXED_WITH_NEW_RISK: "border-amber-600/50 bg-amber-100 text-amber-900",
  FIXED_TESTS_FAILED: "border-amber-600/50 bg-amber-100 text-amber-900",
  NOT_FIXED: "border-transparent bg-rose-700 text-white",
  FAILED: "border-transparent bg-rose-700 text-white",
  UNSUPPORTED: "border-slate-300 text-slate-700",
};

const STEP_STYLE: Record<StepStatus, string> = {
  passed: "border-slate-300 text-slate-700",
  warning: "border-amber-600/50 bg-amber-50 text-amber-900",
  failed: "border-transparent bg-rose-700 text-white",
  not_run: "border-dashed text-muted-foreground",
  skipped: "border-dashed text-muted-foreground",
};

function RunDetails({ run }: { run: ValidationRun }) {
  const result = run.result;
  if (!result) {
    return run.error ? <p role="alert" className="text-rose-800 dark:text-rose-300">{run.error}</p> : null;
  }
  const c = result.comparison;
  const rows = ["critical", "high", "medium", "low", "suspicious", "workflow_pins"];
  return (
    <div className="grid gap-3 border-t pt-3 text-xs">
      <p className="text-sm">{result.verdict_reason}</p>
      <section className="grid gap-1">
        <h4 className="font-medium text-muted-foreground uppercase">Steps</h4>
        <ol className="grid gap-1">
          {result.steps.map((s) => (
            <li key={s.id} className="flex flex-wrap items-baseline gap-1.5">
              <Badge variant="outline" className={STEP_STYLE[s.status]}>{s.status.replace("_", " ")}</Badge>
              <span className="font-medium">{s.label}</span>
              <span className="text-muted-foreground">{s.detail}</span>
            </li>
          ))}
        </ol>
      </section>
      {result.diffs.length > 0 && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">Proposed change</h4>
          {result.diffs.map((d) => (
            <details key={d.path} open={result.diffs.length === 1 && d.lines_added + d.lines_removed < 40}>
              <summary className="cursor-pointer">
                <code>{d.path}</code> <span className="text-muted-foreground">+{d.lines_added} −{d.lines_removed}{d.truncated ? " (truncated)" : ""}</span>
              </summary>
              <pre className="mt-1 max-h-72 overflow-auto rounded bg-slate-950 p-2 text-[11px] text-slate-100">{d.diff}</pre>
            </details>
          ))}
        </section>
      )}
      <section className="grid gap-1">
        <h4 className="font-medium text-muted-foreground uppercase">Build and tests</h4>
        <p>{result.tests_detail}</p>
        {result.tests.filter((t) => t.status !== "not_run").map((t) => (
          <details key={t.phase}>
            <summary className="cursor-pointer">
              {t.phase}: {t.status.replace("_", " ")} {t.runtime && <span className="text-muted-foreground">· {t.runtime} · {t.image} · {t.duration_s}s</span>}
            </summary>
            <pre className="mt-1 max-h-60 overflow-auto rounded bg-slate-950 p-2 text-[11px] text-slate-100">{t.output_tail}</pre>
          </details>
        ))}
      </section>
      {c && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">Before / after</h4>
          <table className="w-fit text-left tabular-nums">
            <thead><tr className="text-muted-foreground"><th className="pr-4 font-normal">Category</th><th className="pr-4 font-normal">Before</th><th className="font-normal">After</th></tr></thead>
            <tbody>
              {rows.map((k) => (
                <tr key={k}><td className="pr-4">{k.replace("_", " ")}</td><td className="pr-4">{c.before_counts[k] ?? 0}</td><td>{c.after_counts[k] ?? 0}</td></tr>
              ))}
            </tbody>
          </table>
          <p>
            Target finding {c.target_resolved ? "no longer detected" : c.target_resolved === false ? "still detected" : "n/a"} ·{" "}
            {c.resolved.length} resolved · {c.introduced.length} introduced · {c.introduced_suspicious.length} new suspicious
          </p>
          {c.changed_packages.length > 0 && (
            <p className="text-muted-foreground">Packages changed: {c.changed_packages.slice(0, 8).join("; ")}</p>
          )}
        </section>
      )}
      {result.residual_risks.length > 0 && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">Remaining risk</h4>
          <ul className="list-disc space-y-0.5 pl-5">{result.residual_risks.slice(0, 12).map((r) => <li key={r}>{r}</li>)}</ul>
        </section>
      )}
      <p className="text-muted-foreground">
        Nothing was merged, pushed or deployed. The change was applied to an isolated copy of commit{" "}
        <code>{(result.sandbox_commit ?? "").slice(0, 12)}</code> only.
      </p>
    </div>
  );
}

function CandidateRow({
  candidate, busy, onStart,
}: { candidate: ValidationCandidate; busy: boolean; onStart: (c: ValidationCandidate) => void }) {
  return (
    <li className="flex flex-wrap items-center gap-2 rounded-md border bg-card px-3 py-2 text-xs">
      <Badge variant="outline">{candidate.source_type === "ai" ? "AI proposal" : "Remediation"}</Badge>
      <span className="font-medium">{candidate.package}</span>
      <span className="text-muted-foreground">
        {candidate.from_version ?? "?"} → {candidate.to_version ?? "?"} · approved by {candidate.approved_by ?? "unknown"}
      </span>
      <span className="ml-auto">
        {candidate.supported ? (
          <Button size="xs" onClick={() => onStart(candidate)} disabled={busy}>
            <FlaskConical aria-hidden /> Validate in sandbox
          </Button>
        ) : (
          <span className="text-muted-foreground">{candidate.reason}</span>
        )}
      </span>
    </li>
  );
}

/** Day 2 steps 4-5: validate an approved fix in an isolated sandbox, then rescan and compare. */
export default function ValidationPanel({ scanId, client = validationService }: { scanId: string; client?: ValidationApi }) {
  const [overview, setOverview] = useState<ValidationOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [runTests, setRunTests] = useState(true);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await client.overview(scanId);
      setOverview(data);
      setError(null);
      if (data.runs.some((r) => r.status === "queued" || r.status === "running")) {
        timer.current = setTimeout(load, POLL_MS);
      }
    } catch (e) {
      setError(classifyError(e).message);
    }
  }, [client, scanId]);

  useEffect(() => {
    void load();
    return () => { if (timer.current) clearTimeout(timer.current); };
  }, [load]);

  const start = async (candidate: ValidationCandidate) => {
    setBusy(true);
    setError(null);
    try {
      await client.start(scanId, candidate.source_type, candidate.source_id, runTests);
      if (timer.current) clearTimeout(timer.current);
      await load();
    } catch (e) {
      setError(classifyError(e).message);
    } finally {
      setBusy(false);
    }
  };

  const running = overview?.runs.some((r) => r.status === "queued" || r.status === "running");

  return (
    <section aria-label="Sandbox validation" className="grid gap-3 rounded-xl border bg-card p-4">
      <h2 className="flex items-center gap-2 text-base font-semibold">
        <ShieldCheck className="size-4" aria-hidden /> Sandbox validation
      </h2>
      <p className="text-xs text-muted-foreground">
        Validates an approved fix: applies it to a fresh copy of the exact scanned commit, runs the project&apos;s tests
        inside a locked-down container (before and after), rescans the patched copy and compares the results.
        Nothing is merged, pushed or deployed.
      </p>
      {overview && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <Badge variant="outline" className={cn(!overview.sandbox.container_runtime && "border-dashed")}>
            <Box aria-hidden className="mr-1 size-3" />
            {overview.sandbox.container_runtime ? `Container: ${overview.sandbox.container_runtime}` : "No container runtime"}
          </Badge>
          <label className="flex items-center gap-1.5">
            <input
              type="checkbox"
              checked={runTests && Boolean(overview.sandbox.container_runtime)}
              disabled={!overview.sandbox.container_runtime}
              onChange={(e) => setRunTests(e.target.checked)}
            />
            Run project tests in the container
          </label>
          {overview.sandbox.notes.map((n) => <span key={n} className="text-muted-foreground">· {n}</span>)}
        </div>
      )}
      {error && <p role="alert" className="text-sm text-rose-800 dark:text-rose-300">{error}</p>}

      <div className="grid gap-1.5">
        <h3 className="text-sm font-medium">Approved changes</h3>
        {!overview ? (
          <p className="text-xs text-muted-foreground">Loading…</p>
        ) : overview.candidates.length === 0 ? (
          <p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">
            No approved changes yet. Approve a remediation proposal or an AI recommendation to validate it here.
          </p>
        ) : (
          <ul className="grid gap-1.5">
            {overview.candidates.map((c) => (
              <CandidateRow key={`${c.source_type}:${c.source_id}`} candidate={c} busy={busy || Boolean(running)} onStart={start} />
            ))}
          </ul>
        )}
      </div>

      {overview && overview.runs.length > 0 && (
        <div className="grid gap-2">
          <h3 className="text-sm font-medium">Validation runs</h3>
          {overview.runs.map((run) => (
            <article key={run.validation_id} aria-label={`Validation ${run.validation_id}`} className="grid gap-2 rounded-md border px-3 py-2">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-medium">{run.change.package} {run.change.from_version} → {run.change.to_version}</span>
                {run.result ? (
                  <Badge className={VERDICT_STYLE[run.result.verdict]}>{VERDICT_LABEL[run.result.verdict]}</Badge>
                ) : run.status === "failed" ? (
                  <Badge className={VERDICT_STYLE.FAILED}>Validation failed</Badge>
                ) : (
                  <span className="flex items-center gap-1 text-xs text-muted-foreground">
                    <Loader2 className="size-3.5 animate-spin" aria-hidden /> {run.status === "queued" ? "Queued" : "Running in sandbox…"}
                  </span>
                )}
                <span className="ml-auto text-xs text-muted-foreground">{run.change.project_path || "."} · {run.change.ecosystem}</span>
              </div>
              <RunDetails run={run} />
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

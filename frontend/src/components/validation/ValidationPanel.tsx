"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  Bot, Box, ChevronDown, ChevronRight, ClipboardCopy, ExternalLink, FileText, FlaskConical,
  GitPullRequest, ListChecks, Loader2, Play, RefreshCw, RotateCcw, ShieldCheck,
} from "lucide-react";
import {
  DECISION_RECORDED, openRemediationPanel, scrollToFindings, type DecisionRecordedDetail,
} from "@/lib/decisionEvents";
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

function PullRequestAction({
  run, githubConfigured, busy, onOpen,
}: { run: ValidationRun; githubConfigured: boolean; busy: boolean; onOpen: (run: ValidationRun) => void }) {
  if (run.pull_request) {
    return (
      <p className="flex flex-wrap items-center gap-1.5 text-sm">
        <GitPullRequest className="size-4" aria-hidden />
        <a href={run.pull_request.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-medium underline">
          Pull request #{run.pull_request.number} <ExternalLink className="size-3" aria-hidden />
        </a>
        <span className="text-muted-foreground">
          opened on <code>{run.pull_request.branch}</code> → <code>{run.pull_request.base}</code>. Review and merge it on GitHub.
        </span>
      </p>
    );
  }
  const eligible = run.result?.verdict === "FIXED" && run.result.tests_status !== "regression";
  if (!eligible) return null;
  if (!run.patch_available) {
    return <p className="text-xs text-muted-foreground">Run this validation again to open a pull request (no saved patch).</p>;
  }
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" onClick={() => onOpen(run)} disabled={busy || !githubConfigured}>
        <GitPullRequest aria-hidden /> Open pull request
      </Button>
      <span className="text-xs text-muted-foreground">
        {githubConfigured
          ? "Creates a branch from the scanned commit with this exact patch and opens a PR. Kestral never merges it."
          : "Set GITHUB_TOKEN in .env (Contents and Pull requests write access) to enable."}
      </span>
    </div>
  );
}

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
        {run.pull_request
          ? "The patch was proposed as a pull request; nothing was merged or deployed."
          : "Nothing was merged, pushed or deployed."}{" "}
        The change was applied to an isolated copy of commit{" "}
        <code>{(result.sandbox_commit ?? "").slice(0, 12)}</code> only.
      </p>
    </div>
  );
}

function CandidateRow({
  candidate, busy, lastRun, testsAvailable, onStart,
}: {
  candidate: ValidationCandidate; busy: boolean; lastRun: ValidationRun | undefined; testsAvailable: boolean;
  onStart: (c: ValidationCandidate, runTests: boolean) => void;
}) {
  const verdict = lastRun?.result?.verdict;
  return (
    <li className="flex flex-wrap items-center gap-2 rounded-md border bg-card px-3 py-2 text-xs">
      <Badge variant="outline">{candidate.source_type === "ai" ? "AI proposal" : "Remediation"}</Badge>
      <span className="font-medium">{candidate.package}</span>
      <span className="text-muted-foreground">
        {candidate.from_version ?? "?"} → {candidate.to_version ?? "?"} · approved by {candidate.approved_by ?? "unknown"}
      </span>
      {verdict && <Badge className={VERDICT_STYLE[verdict]}>Last: {VERDICT_LABEL[verdict]}</Badge>}
      <span className="ml-auto flex flex-wrap gap-1.5">
        {candidate.supported ? (
          <>
            <Button size="xs" onClick={() => onStart(candidate, testsAvailable)} disabled={busy}>
              {lastRun ? <RotateCcw aria-hidden /> : <FlaskConical aria-hidden />}
              {lastRun ? "Validate again" : "Validate in sandbox"}
            </Button>
            {testsAvailable && (
              <Button size="xs" variant="outline" onClick={() => onStart(candidate, false)} disabled={busy}
                title="Patch, re-lock and rescan without running the project's tests (faster)">
                <Play aria-hidden /> Validate without tests
              </Button>
            )}
          </>
        ) : (
          <span className="text-muted-foreground">{candidate.reason}</span>
        )}
      </span>
    </li>
  );
}

function diffText(run: ValidationRun): string {
  return (run.result?.diffs ?? []).map((d) => d.diff).join("\n");
}

/** Day 2 steps 4-5: validate an approved fix in an isolated sandbox, then rescan and compare. */
export default function ValidationPanel({ scanId, client = validationService }: { scanId: string; client?: ValidationApi }) {
  const [overview, setOverview] = useState<ValidationOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [runTests, setRunTests] = useState(true);
  const [openRuns, setOpenRuns] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState<string | null>(null);
  const [retry, setRetry] = useState<(() => Promise<void>) | null>(null);
  // Changes waiting to be validated by the header play button, run one at a time.
  const [queue, setQueue] = useState<ValidationCandidate[]>([]);
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

  // Refresh as soon as a reviewer approves or rejects something in another panel.
  useEffect(() => {
    const onDecision = (event: Event) => {
      const detail = (event as CustomEvent<DecisionRecordedDetail>).detail;
      if (!detail || detail.scanId === scanId) void load();
    };
    window.addEventListener(DECISION_RECORDED, onDecision);
    return () => window.removeEventListener(DECISION_RECORDED, onDecision);
  }, [load, scanId]);

  /** Run an action with shared busy/error handling; a busy scanner offers "Try again". */
  const act = async (action: () => Promise<void>, retryable = false): Promise<boolean> => {
    setBusy(true);
    setError(null);
    setNotice(null);
    setRetry(null);
    try {
      await action();
      return true;
    } catch (e) {
      const friendly = classifyError(e);
      setError(friendly.message);
      if (retryable && (friendly.kind === "busy" || friendly.kind === "network" || friendly.kind === "unavailable")) {
        setRetry(() => async () => { await act(action, retryable); });
      }
      return false;
    } finally {
      setBusy(false);
    }
  };

  const start = (sourceType: ValidationCandidate["source_type"], sourceId: string, tests: boolean) =>
    act(async () => {
      const run = await client.start(scanId, sourceType, sourceId, tests);
      if (timer.current) clearTimeout(timer.current);
      setOpenRuns((ids) => new Set([...ids, run.validation_id]));
      await load();
    }, true);

  const startRuntime = () =>
    act(async () => {
      setNotice("Starting Podman… this can take up to a minute.");
      await client.startRuntime();
      await load();
      setNotice("Podman is running; project tests will run in the container.");
    });

  const copyDiff = async (run: ValidationRun) => {
    try {
      await navigator.clipboard.writeText(diffText(run));
      setNotice("Diff copied to the clipboard.");
    } catch {
      setError("Could not copy the diff; select it from the details instead.");
    }
  };

  const toggleRun = (id: string) => setOpenRuns((ids) => {
    const next = new Set(ids);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  const openPullRequest = (run: ValidationRun) =>
    act(async () => {
      await client.openPullRequest(scanId, run.validation_id);
      await load();
    });

  const running = overview?.runs.some((r) => r.status === "queued" || r.status === "running");
  const runtime = overview?.sandbox.container_runtime ?? null;
  const testsAvailable = Boolean(runtime) && runTests;
  const reportUrl = client.reportUrl(scanId, "html", false);
  const latestRunId = overview?.runs[0]?.validation_id;
  const lastRunFor = (c: ValidationCandidate) =>
    overview?.runs.find((r) => r.change.source_type === c.source_type && r.change.source_id === c.source_id);
  const candidateFor = (run: ValidationRun) =>
    overview?.candidates.find((c) => c.source_type === run.change.source_type && c.source_id === run.change.source_id);
  const supported = overview?.candidates.filter((c) => c.supported) ?? [];
  const notYetValidated = supported.filter((c) => lastRunFor(c)?.status !== "completed");
  const playTargets = notYetValidated.length > 0 ? notYetValidated : supported;

  const play = () => {
    if (playTargets.length === 0) return;
    setNotice(`Validating ${playTargets.length} approved change${playTargets.length === 1 ? "" : "s"} one at a time…`);
    setQueue(playTargets);
  };

  // Start the next queued change whenever the sandbox is idle.
  useEffect(() => {
    if (queue.length === 0 || busy || running || !overview) return;
    const [next, ...rest] = queue;
    setQueue(rest);
    void start(next.source_type, next.source_id, testsAvailable).then((ok) => {
      if (!ok) setQueue([]); // stop the queue on an error; the error message offers Try again
    });
  }, [queue, busy, running, overview]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <section aria-label="Sandbox validation" className="grid gap-3 rounded-xl border bg-card p-4">
      <h2 className="flex items-center gap-2 text-base font-semibold">
        <ShieldCheck className="size-4" aria-hidden /> Sandbox validation
        <Button
          size="icon-sm"
          className="rounded-full"
          onClick={play}
          disabled={busy || Boolean(running) || queue.length > 0 || playTargets.length === 0}
          aria-label="Run sandbox validation"
          title={
            playTargets.length === 0
              ? "Approve a version upgrade first"
              : `Validate ${playTargets.length} approved change${playTargets.length === 1 ? "" : "s"}${testsAvailable ? " with tests" : ""}`
          }
        >
          {running || queue.length > 0 ? <Loader2 className="animate-spin" aria-hidden /> : <Play aria-hidden />}
        </Button>
        {queue.length > 0 && <span className="text-xs font-normal text-muted-foreground">{queue.length} queued</span>}
        <span className="ml-auto flex gap-1">
          {reportUrl && (
            <a href={reportUrl} target="_blank" rel="noreferrer"
              className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-normal hover:bg-muted">
              <FileText className="size-3.5" aria-hidden /> Open report
            </a>
          )}
          <Button size="xs" variant="ghost" className="font-normal" onClick={() => void load()} disabled={busy}>
            <RefreshCw aria-hidden /> Refresh
          </Button>
        </span>
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
          {!runtime && (
            <>
              <Button size="xs" onClick={startRuntime} disabled={busy}>
                <Box aria-hidden /> Start Podman
              </Button>
              <Button size="xs" variant="ghost" onClick={() => void load()} disabled={busy}>Check again</Button>
            </>
          )}
          {overview.sandbox.notes.map((n) => <span key={n} className="text-muted-foreground">· {n}</span>)}
        </div>
      )}
      {notice && <p role="status" className="text-xs text-muted-foreground">{notice}</p>}
      {error && (
        <p role="alert" className="flex flex-wrap items-center gap-2 text-sm text-rose-800 dark:text-rose-300">
          {error}
          {retry && (
            <Button size="xs" variant="outline" onClick={() => void retry()} disabled={busy}>
              <RotateCcw aria-hidden /> Try again
            </Button>
          )}
        </p>
      )}

      <div className="grid gap-1.5">
        <h3 className="text-sm font-medium">Approved changes</h3>
        {!overview ? (
          <p className="text-xs text-muted-foreground">Loading…</p>
        ) : overview.candidates.length === 0 ? (
          <div className="grid gap-2 rounded-md border border-dashed p-3 text-xs text-muted-foreground">
            <p>No approved changes yet. Approve a version upgrade, then validate it here.</p>
            <div className="flex flex-wrap gap-2">
              <Button size="xs" variant="outline" onClick={openRemediationPanel}>
                <ListChecks aria-hidden /> Review remediation proposals
              </Button>
              <Button size="xs" variant="outline" onClick={scrollToFindings}>
                <Bot aria-hidden /> Analyze a finding with AI
              </Button>
            </div>
          </div>
        ) : (
          <ul className="grid gap-1.5">
            {overview.candidates.map((c) => (
              <CandidateRow
                key={`${c.source_type}:${c.source_id}`}
                candidate={c}
                busy={busy || Boolean(running)}
                lastRun={lastRunFor(c)}
                testsAvailable={testsAvailable}
                onStart={(candidate, tests) => start(candidate.source_type, candidate.source_id, tests)}
              />
            ))}
          </ul>
        )}
      </div>

      {overview && overview.runs.length > 0 && (
        <div className="grid gap-2">
          <h3 className="text-sm font-medium">Validation runs</h3>
          {overview.runs.map((run) => {
            const isOpen = openRuns.has(run.validation_id) || (run.validation_id === latestRunId && !openRuns.has(`closed:${run.validation_id}`));
            const Chevron = isOpen ? ChevronDown : ChevronRight;
            const candidate = candidateFor(run);
            const finished = run.status === "completed" || run.status === "failed";
            const toggle = () => {
              if (run.validation_id === latestRunId) {
                setOpenRuns((ids) => {
                  const next = new Set(ids);
                  const key = `closed:${run.validation_id}`;
                  if (isOpen) { next.add(key); next.delete(run.validation_id); } else { next.delete(key); }
                  return next;
                });
              } else {
                toggleRun(run.validation_id);
              }
            };
            return (
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
              <div className="flex flex-wrap items-center gap-1.5">
                <Button size="xs" variant="outline" onClick={toggle} aria-expanded={isOpen}>
                  <Chevron aria-hidden /> {isOpen ? "Hide details" : "Show details"}
                </Button>
                {finished && candidate?.supported && (
                  <Button size="xs" variant="outline" disabled={busy || Boolean(running)}
                    onClick={() => start(run.change.source_type, run.change.source_id, testsAvailable)}>
                    <RotateCcw aria-hidden /> Re-run
                  </Button>
                )}
                {(run.result?.diffs.length ?? 0) > 0 && (
                  <Button size="xs" variant="outline" onClick={() => void copyDiff(run)}>
                    <ClipboardCopy aria-hidden /> Copy diff
                  </Button>
                )}
              </div>
              <PullRequestAction
                run={run}
                githubConfigured={Boolean(overview.sandbox.github_configured)}
                busy={busy}
                onOpen={openPullRequest}
              />
              {isOpen && <RunDetails run={run} />}
            </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

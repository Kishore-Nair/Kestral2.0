"use client";

import { announceDecision } from "@/lib/decisionEvents";
import { useCallback, useEffect, useRef, useState } from "react";
import { Bot, ExternalLink, Loader2, RotateCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { classifyError } from "@/services/errors";
import type { AiApi } from "@/services/aiApi";
import type {
  AiAnalysis,
  AiDecisionRequest,
  AiFeedbackEntry,
  AiFeedbackReason,
  AiRecommendation,
  AiStatus,
  AnalysisStatus,
  ValidationCheck,
} from "@/types/ai";
import { cn } from "@/lib/utils";

const POLL_MS = 2000;

const STATUS_LABEL: Record<AnalysisStatus, string> = {
  queued: "Queued",
  running: "Investigating",
  recommendation_ready: "Proposal ready (not applied)",
  needs_human_review: "Needs human review",
  insufficient_evidence: "Insufficient evidence",
  no_verified_fix: "No verified fix",
  ai_unavailable: "AI unavailable",
  validation_failed: "Failed deterministic validation",
  failed: "Analysis failed",
};

const STRATEGY_LABEL: Record<string, string> = {
  upgrade: "Upgrade",
  upgrade_parent: "Upgrade the parent dependency",
  override: "Package-manager override",
  remove: "Remove the dependency",
  replace: "Replace the dependency",
  config_mitigation: "Configuration mitigation",
  pin_source: "Pin to an immutable source",
  compensating_control: "Temporary compensating control",
  manual_review: "Manual review",
};

const CHECK_STYLE: Record<ValidationCheck["status"], string> = {
  passed: "border-slate-300 text-slate-700",
  warning: "border-amber-600/50 bg-amber-50 text-amber-900",
  failed: "border-transparent bg-rose-700 text-white",
  not_run: "border-dashed text-muted-foreground",
};

const APPROVAL_REASONS: Array<[AiFeedbackReason, string]> = [
  ["VERIFIED_SAFE_UPGRADE", "Verified safe upgrade"],
  ["LOW_COMPATIBILITY_RISK", "Low compatibility risk"],
  ["TESTS_COVER_PATH", "Tests cover affected path"],
  ["ACCEPTABLE_TRADEOFF", "Acceptable risk trade-off"],
  ["OWNER_CONFIRMED", "Owner confirmed"],
  ["OTHER", "Other"],
];

const FEEDBACK_REASONS: Array<[AiFeedbackReason, string]> = [
  ["BREAKING_CHANGE", "Breaking change"],
  ["WRONG_STRATEGY", "Wrong strategy"],
  ["VERSION_UNSUITABLE", "Unsuitable version"],
  ["MISSING_CONTEXT", "Missing context"],
  ["INSUFFICIENT_EVIDENCE", "Insufficient evidence"],
  ["ALTERNATIVE_PREFERRED", "Alternative preferred"],
  ["NOT_APPLICABLE", "Not applicable"],
  ["OTHER", "Other"],
];

const REASON_LABEL: Record<AiFeedbackReason, string> = Object.fromEntries([
  ...APPROVAL_REASONS,
  ...FEEDBACK_REASONS,
]) as Record<AiFeedbackReason, string>;

function FeedbackHistory({ entries }: { entries: AiFeedbackEntry[] }) {
  if (entries.length === 0) return null;
  return (
    <section className="grid gap-1.5 rounded-md border bg-muted/30 p-2.5 text-xs">
      <h5 className="font-medium text-muted-foreground uppercase">
        Feedback loop history ({entries.length} prior {entries.length === 1 ? "round" : "rounds"})
      </h5>
      <ol className="grid gap-2">
        {entries.map((entry) => (
          <li key={entry.analysis_id} className="grid gap-1 border-l-2 pl-2">
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge variant="outline">Rev {entry.revision}</Badge>
              <Badge variant={entry.decision === "rejected" ? "destructive" : "secondary"}>
                {entry.decision === "rejected"
                  ? "Rejected"
                  : entry.decision === "approved"
                    ? "Approved"
                    : "Changes requested"}
              </Badge>
              {entry.previous_strategy && (
                <span className="text-muted-foreground">
                  Proposed: {STRATEGY_LABEL[entry.previous_strategy] ?? entry.previous_strategy}
                  {entry.previous_target_version ? ` (${entry.previous_target_version})` : ""}
                </span>
              )}
            </div>
            {entry.reasons.length > 0 && (
              <p className="text-muted-foreground">
                Reasons: {entry.reasons.map((r) => REASON_LABEL[r] ?? r).join(" · ")}
              </p>
            )}
            {entry.note && <p>{entry.note}</p>}
          </li>
        ))}
      </ol>
    </section>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="grid gap-1">
      <h5 className="font-medium text-muted-foreground uppercase">{title}</h5>
      {children}
    </section>
  );
}

function List({ items }: { items: string[] }) {
  if (items.length === 0) return <p className="text-muted-foreground">None stated.</p>;
  return <ul className="list-disc space-y-0.5 pl-5">{items.map((i) => <li key={i}>{i}</li>)}</ul>;
}

function Refs({ ids }: { ids: string[] }) {
  if (ids.length === 0) return null;
  return <span className="font-mono text-muted-foreground"> [{ids.join(", ")}]</span>;
}

function Recommendation({ rec }: { rec: AiRecommendation }) {
  const rem = rec.recommended_remediation;
  const okCalls = rec.tool_trace.length;
  return (
    <div className="grid gap-3">
      <Section title="Summary">
        <p className="font-medium">{rec.title}</p>
        <p>{rec.summary}</p>
      </Section>
      <Section title="Why it matters here">
        <p>{rec.why_it_matters}</p>
      </Section>
      <Section title="Proposed action">
        <p>
          <span className="font-medium">{STRATEGY_LABEL[rem.type] ?? rem.type}</span>
          {rem.target_version && <> to <code>{rem.target_version}</code></>}
          <Refs ids={rem.evidence_refs} />
        </p>
        {rem.target_version && (
          <p>
            {rem.fixed_version_verified ? (
              <>
                Fixed version confirmed by {rem.version_source}
                {rem.version_source_url && (
                  <a href={rem.version_source_url} target="_blank" rel="noreferrer" className="ml-1 inline-flex items-center gap-0.5 underline">
                    source <ExternalLink className="size-3" aria-hidden />
                  </a>
                )}
                .
              </>
            ) : (
              <span className="text-amber-800 dark:text-amber-300">Not verified as a fixed version.</span>
            )}
          </p>
        )}
        <ol className="list-decimal space-y-0.5 pl-5">{rem.steps.map((s) => <li key={s}>{s}</li>)}</ol>
      </Section>
      <Section title="Compatibility">
        <p>
          Breaking-change risk: {rec.compatibility.breaking_change_risk} · Manifest:{" "}
          {rec.compatibility.manifest_status === "not_checked" ? "not checked" : rec.compatibility.manifest_status} ({rec.compatibility.manifest_detail})
        </p>
        {rec.compatibility.notes.length > 0 && <List items={rec.compatibility.notes} />}
      </Section>
      {rec.alternatives.length > 0 && (
        <Section title="Alternatives (model suggestions, not verified)">
          <ul className="list-disc space-y-0.5 pl-5">
            {rec.alternatives.map((a) => (
              <li key={a.description}>
                <span className="font-medium">{STRATEGY_LABEL[a.type] ?? a.type}:</span> {a.description}{" "}
                <span className="text-muted-foreground">({a.tradeoffs})</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
      <Section title="Risks and trade-offs"><List items={rec.risks_and_tradeoffs} /></Section>
      <Section title="Validation checklist"><List items={rec.validation_plan} /></Section>
      <Section title="Residual risk"><List items={rec.residual_risk} /></Section>
      <Section title="Unknowns"><List items={rec.unknowns} /></Section>
      <Section title="Claims">
        <ul className="grid gap-1">
          {rec.claims.map((c) => (
            <li key={c.claim} className="flex flex-wrap items-baseline gap-1.5">
              <Badge variant="outline" className={cn(c.verification_status === "rejected" && "border-rose-700 text-rose-800")}>
                {c.verification_status}
              </Badge>
              <span>{c.claim}</span>
              <span className="text-muted-foreground">({c.kind.replace(/_/g, " ")})</span>
              <Refs ids={c.evidence_refs} />
            </li>
          ))}
        </ul>
      </Section>
      <Section title="Evidence">
        <ul className="grid gap-0.5">
          {rec.evidence.map((e) => (
            <li key={e.id}>
              <code>{e.id}</code> <span className="text-muted-foreground">{e.kind} · {e.source}{e.external ? " · live" : ""}</span> — {e.summary}
            </li>
          ))}
        </ul>
      </Section>
      <Section title={`Investigation trace (${okCalls} tool call${okCalls === 1 ? "" : "s"})`}>
        {rec.tool_trace.length === 0 ? (
          <p className="text-muted-foreground">No tools were called; the answer used the preloaded finding context.</p>
        ) : (
          <ol className="list-decimal space-y-0.5 pl-5">
            {rec.tool_trace.map((t) => (
              <li key={t.index}>
                <code>{t.name}</code>({Object.values(t.arguments).join(", ")}) · {t.status}
                {t.external ? " · network" : ""}
                {t.message ? ` · ${t.message}` : ""}
                <Refs ids={t.evidence_ids} />
              </li>
            ))}
          </ol>
        )}
        <p className="text-muted-foreground">Stopped because: {rec.stop_reason}.</p>
      </Section>
      <Section title={`Deterministic validation: ${rec.validation.status}`}>
        <ul className="grid gap-1">
          {rec.validation.checks.map((c) => (
            <li key={c.id} className="flex flex-wrap items-baseline gap-1.5">
              <Badge variant="outline" className={CHECK_STYLE[c.status]}>{c.status.replace("_", " ")}</Badge>
              <code>{c.id}</code> <span className="text-muted-foreground">{c.detail}</span>
            </li>
          ))}
        </ul>
        {rec.validation.warnings.length > 0 && <List items={rec.validation.warnings} />}
      </Section>
      <p className="text-muted-foreground">
        {rec.model_metadata.provider} · {rec.model_metadata.model} · prompt v{rec.model_metadata.prompt_version} ·
        confidence {rec.confidence} · {rec.model_metadata.input_tokens + rec.model_metadata.output_tokens} tokens
      </p>
    </div>
  );
}

interface Props {
  scanId: string;
  findingId: string;
  status: AiStatus | null;
  client: AiApi;
}

/** On-demand AI explanation and remediation proposal for one finding. Never applies anything. */
export default function AiAnalysisPanel({ scanId, findingId, status, client }: Props) {
  const [analysis, setAnalysis] = useState<AiAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<"idle" | "approved" | "changes_requested" | "rejected">("idle");
  const [reasons, setReasons] = useState<AiFeedbackReason[]>([]);
  const [note, setNote] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const configured = Boolean(status?.configured);

  const resetFeedbackForm = () => {
    setMode("idle");
    setReasons([]);
    setNote("");
  };

  const toggleReason = (reason: AiFeedbackReason) =>
    setReasons((prev) => (prev.includes(reason) ? prev.filter((item) => item !== reason) : [...prev, reason]));

  const poll = useCallback(
    (current: AiAnalysis) => {
      if (current.status !== "queued" && current.status !== "running") return;
      timer.current = setTimeout(async () => {
        try {
          const next = await client.get(scanId, current.analysis_id);
          setAnalysis(next);
          poll(next);
        } catch (e) {
          setError(classifyError(e).message);
        }
      }, POLL_MS);
    },
    [client, scanId],
  );

  useEffect(() => {
    if (!configured) return;
    let cancelled = false;
    client.getRemediation(scanId, findingId).then(
      (existing) => {
        if (cancelled || !existing) return;
        setAnalysis(existing);
        poll(existing);
      },
      () => undefined,
    );
    return () => {
      cancelled = true;
      if (timer.current) clearTimeout(timer.current);
    };
  }, [client, configured, findingId, poll, scanId]);

  const start = async (refresh: boolean) => {
    setBusy(true);
    setError(null);
    resetFeedbackForm();
    try {
      const started = await client.start(scanId, findingId, refresh);
      setAnalysis(started);
      poll(started);
    } catch (e) {
      setError(classifyError(e).message);
    } finally {
      setBusy(false);
    }
  };

  const decide = async (body: AiDecisionRequest) => {
    if (!analysis) return;
    setBusy(true);
    setError(null);
    try {
      const decided = await client.decide(scanId, analysis.analysis_id, body);
      announceDecision({ scanId, source: "ai" });
      resetFeedbackForm();
      if (decided.next_analysis_id) {
        const next = await client.get(scanId, decided.next_analysis_id);
        setAnalysis(next);
        poll(next);
      } else {
        setAnalysis(decided);
      }
    } catch (e) {
      setError(classifyError(e).message);
    } finally {
      setBusy(false);
    }
  };

  const revise = async () => {
    if (!analysis) return;
    setBusy(true);
    setError(null);
    resetFeedbackForm();
    try {
      const revised = await client.revise(scanId, analysis.analysis_id);
      setAnalysis(revised);
      poll(revised);
    } catch (e) {
      setError(classifyError(e).message);
    } finally {
      setBusy(false);
    }
  };

  const running = analysis?.status === "queued" || analysis?.status === "running";
  const rec = analysis?.recommendation ?? null;
  const trimmedNote = note.trim();
  const canApprove = reasons.length > 0 && trimmedNote.length >= 10;
  const canRequestChanges = trimmedNote.length >= 10;
  const canReject = reasons.length > 0 && trimmedNote.length >= 10;
  const activeReasons = mode === "approved" ? APPROVAL_REASONS : FEEDBACK_REASONS;

  const openMode = (next: "approved" | "changes_requested" | "rejected") => {
    setError(null);
    setReasons([]);
    setMode((current) => (current === next ? "idle" : next));
  };

  return (
    <section aria-label="Kestral AI analysis" className="grid gap-2 rounded-md border bg-background px-3 py-2">
      <h4 className="flex flex-wrap items-center gap-1.5 font-medium">
        <Bot className="size-4" aria-hidden /> Kestral AI analysis
        {analysis && analysis.revision > 1 && <Badge variant="secondary">Rev {analysis.revision}</Badge>}
        {analysis && !running && <Badge variant="outline">{STATUS_LABEL[analysis.status]}</Badge>}
        {analysis?.stale && <Badge className="border-amber-600/50 bg-amber-100 text-amber-900">Stale</Badge>}
        {analysis?.cached && <Badge variant="outline">Cached</Badge>}
      </h4>

      {!status ? (
        <p className="text-muted-foreground">Checking whether AI analysis is available…</p>
      ) : !configured ? (
        <p className="text-muted-foreground">
          {status.enabled
            ? `Kestral AI is enabled but ${status.api_key_env || "the provider API key"} is not set on the server.`
            : `Kestral AI is not configured on this server. Set AI_ENABLED=true and ${status.api_key_env || "the provider API key"} in .env (see SETUP.md).`}{" "}
          Scanning and findings work without it.
        </p>
      ) : (
        <>
          <p className="text-muted-foreground">{status.data_notice}</p>
          <div className="flex flex-wrap gap-2">
            {!analysis || analysis.stale || ["failed", "ai_unavailable"].includes(analysis.status) ? (
              <Button size="sm" onClick={() => start(Boolean(analysis))} disabled={busy || running}>
                <Bot aria-hidden /> Analyze with Kestral AI
              </Button>
            ) : (
              !running && (
                <Button size="sm" variant="outline" onClick={() => start(true)} disabled={busy}>
                  <RotateCw aria-hidden /> Analyze again
                </Button>
              )
            )}
          </div>
        </>
      )}

      {running && (
        <p className="flex items-center gap-1.5">
          <Loader2 className="size-3.5 animate-spin" aria-hidden />
          {analysis && analysis.revision > 1
            ? `Revising proposal (Rev ${analysis.revision}) using your feedback…`
            : `Investigating with up to ${status?.tool_budget ?? 5} read-only tool calls…`}
        </p>
      )}
      {error && <p role="alert" className="text-rose-800 dark:text-rose-300">{error}</p>}
      {analysis?.error && !running && <p role="alert" className="text-rose-800 dark:text-rose-300">{analysis.error}</p>}
      {analysis?.stale && (
        <p className="text-amber-800 dark:text-amber-300">
          The scan evidence, prompt or model changed since this analysis; it is not current. Analyze again before deciding.
        </p>
      )}

      {analysis && analysis.feedback_history.length > 0 && (
        <FeedbackHistory entries={analysis.feedback_history} />
      )}

      {rec && <Recommendation rec={rec} />}

      {rec && (
        <div className="grid gap-2 border-t pt-2">
          {analysis?.decision ? (
            <div className="grid gap-1.5">
              <p>
                {analysis.decision.decision === "approved" && (
                  <>
                    You approved this proposal{analysis.revision > 1 ? ` (Rev ${analysis.revision})` : ""}.
                    No change has been applied, tested or rescanned.
                  </>
                )}
                {analysis.decision.decision === "changes_requested" && (
                  <>You requested changes on this proposal.</>
                )}
                {analysis.decision.decision === "rejected" && (
                  <>You rejected this proposal. Rejection does not suppress the underlying finding.</>
                )}
              </p>
              {analysis.decision.reasons.length > 0 && (
                <p className="text-xs text-muted-foreground">
                  Reasons: {analysis.decision.reasons.map((r) => REASON_LABEL[r] ?? r).join(" · ")}
                </p>
              )}
              {analysis.decision.note && (
                <p className="text-xs">
                  <span className="font-medium">Feedback:</span> {analysis.decision.note}
                </p>
              )}
              {(analysis.decision.decision === "rejected" || analysis.decision.decision === "changes_requested") &&
                configured && (
                  <Button size="xs" variant="outline" className="w-fit" onClick={revise} disabled={busy}>
                    <RotateCw aria-hidden /> Revise with AI using this feedback
                  </Button>
                )}
            </div>
          ) : (
            <div className="grid gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-muted-foreground">Human decision (recorded only; nothing is applied):</span>
                <Button
                  size="xs"
                  variant={mode === "approved" ? "default" : "outline"}
                  onClick={() => openMode("approved")}
                  disabled={busy || analysis?.stale}
                >
                  Approve proposal
                </Button>
                <Button
                  size="xs"
                  variant={mode === "changes_requested" ? "secondary" : "outline"}
                  onClick={() => openMode("changes_requested")}
                  disabled={busy || analysis?.stale}
                >
                  Ask for changes
                </Button>
                <Button
                  size="xs"
                  variant={mode === "rejected" ? "destructive" : "outline"}
                  onClick={() => openMode("rejected")}
                  disabled={busy || analysis?.stale}
                >
                  Reject
                </Button>
              </div>

              {mode !== "idle" && (
                <div className="grid gap-2 rounded-md border bg-muted/30 p-2.5">
                  <fieldset className="grid gap-1.5">
                    <legend className="text-xs font-medium">
                      {mode === "approved"
                        ? "Approval reasons (select at least one)"
                        : mode === "rejected"
                          ? "Rejection reasons (select at least one)"
                          : "Change categories (optional)"}
                    </legend>
                    <div className="flex flex-wrap gap-1.5">
                      {activeReasons.map(([code, label]) => (
                        <label
                          key={code}
                          className="flex cursor-pointer items-center gap-1 rounded border bg-background px-2 py-1 text-xs"
                        >
                          <input
                            type="checkbox"
                            checked={reasons.includes(code)}
                            onChange={() => toggleReason(code)}
                          />
                          {label}
                        </label>
                      ))}
                    </div>
                  </fieldset>
                  <label className="grid gap-1 text-xs">
                    <span className="font-medium">
                      {mode === "approved"
                        ? "Approval feedback (min 10 characters)"
                        : mode === "rejected"
                          ? "Why are you rejecting this proposal? (min 10 characters)"
                          : "What changes should Kestral AI make? (min 10 characters)"}
                    </span>
                    <textarea
                      className="min-h-20 rounded-md border bg-background p-2 text-xs"
                      value={note}
                      maxLength={1000}
                      onChange={(e) => setNote(e.target.value)}
                      placeholder={
                        mode === "approved"
                          ? "Share why this fix is safe to approve and any context or conditions for the audit log."
                          : mode === "rejected"
                            ? "Explain why this fix is unsuitable (e.g., breaks our API, wrong upgrade path, not reachable)."
                            : "Describe what to change (e.g., avoid a major bump, suggest a parent upgrade or config mitigation)."
                      }
                    />
                  </label>
                  <div className="flex flex-wrap items-center gap-2">
                    {mode === "approved" ? (
                      <Button
                        size="xs"
                        disabled={busy || !canApprove}
                        onClick={() =>
                          decide({
                            decision: "approved",
                            reasons,
                            note: trimmedNote,
                          })
                        }
                      >
                        Confirm approval &amp; record feedback
                      </Button>
                    ) : mode === "changes_requested" ? (
                      <Button
                        size="xs"
                        disabled={busy || !canRequestChanges}
                        onClick={() =>
                          decide({
                            decision: "changes_requested",
                            reasons,
                            note: trimmedNote,
                            trigger_revision: true,
                          })
                        }
                      >
                        Send feedback &amp; revise fix
                      </Button>
                    ) : (
                      <>
                        <Button
                          size="xs"
                          variant="destructive"
                          disabled={busy || !canReject}
                          onClick={() =>
                            decide({
                              decision: "rejected",
                              reasons,
                              note: trimmedNote,
                              trigger_revision: true,
                            })
                          }
                        >
                          Reject &amp; revise with AI
                        </Button>
                        <Button
                          size="xs"
                          variant="outline"
                          disabled={busy || !canReject}
                          onClick={() =>
                            decide({
                              decision: "rejected",
                              reasons,
                              note: trimmedNote,
                              trigger_revision: false,
                            })
                          }
                        >
                          Reject proposal
                        </Button>
                      </>
                    )}
                    <Button size="xs" variant="ghost" onClick={resetFeedbackForm} disabled={busy}>
                      Cancel
                    </Button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

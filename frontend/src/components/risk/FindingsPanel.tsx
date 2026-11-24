"use client";

import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, ExternalLink, FileText, GitCompare, Route, Search, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import WarningsNotice from "@/components/WarningsNotice";
import AiAnalysisPanel from "@/components/risk/AiAnalysisPanel";
import { aiService, type AiApi } from "@/services/aiApi";
import type { AiStatus } from "@/types/ai";
import { categoryLabel, filterFindings, highestReportedSeverity, sortFindings, sourceAgreement } from "@/lib/findings";
import { cn } from "@/lib/utils";
import type {
  ChangeSummary, Finding, FindingKind, FindingsDocument, PackageChange, Priority, RiskLevel, SourceRun,
} from "@/types/findings";

const PAGE_SIZE = 25;

interface Props {
  findings: FindingsDocument;
  labelFor: (id: string) => string;
  /** Select the finding's package in the graph and highlight one dependency path. */
  onShowInGraph: (finding: Finding, path: string[] | null) => void;
  /** AI analyst client; defaults to the configured service (mock mode reports AI unavailable). */
  ai?: AiApi;
}

interface AiProps {
  scanId: string;
  aiStatus: AiStatus | null;
  ai: AiApi;
}

function formatDate(value: string | null): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString().slice(0, 10);
}

const SOURCE_LABEL: Partial<Record<SourceRun["name"], string>> = {
  "workflow-scan": "Workflow scan",
  "supply-chain-scan": "Supply-chain checks",
  "scan-diff": "Change comparison",
};

function SourceStatus({ run }: { run: SourceRun }) {
  const label = SOURCE_LABEL[run.name] ?? run.name;
  const detail =
    run.status === "ok"
      ? [
          run.tool_version && `v${run.tool_version}`,
          run.database_built && `database built ${formatDate(run.database_built)}`,
          run.retrieved_at && `queried ${formatDate(run.retrieved_at)}`,
          run.message,
        ].filter(Boolean).join(", ")
      : run.message ?? "";
  return (
    <li className="flex flex-wrap items-center gap-1.5">
      <span
        aria-hidden
        className={cn(
          "inline-block size-2 rounded-full",
          run.status === "ok" ? "bg-slate-700" : run.status === "failed" ? "bg-amber-600" : "bg-slate-300",
        )}
      />
      <span className="font-medium">{label}</span>
      <span>{run.status}</span>
      {detail && <span className="text-muted-foreground">· {detail}</span>}
    </li>
  );
}

const BAND_STYLE: Record<Priority["band"], string> = {
  critical: "border-transparent bg-rose-900 text-white",
  high: "border-transparent bg-rose-700 text-white",
  medium: "border-amber-600/50 bg-amber-100 text-amber-900",
  low: "border-slate-300 bg-slate-100 text-slate-700",
};

export function PriorityBadge({ priority }: { priority: Priority }) {
  return (
    <Badge className={cn("tabular-nums", BAND_STYLE[priority.band])}>
      Priority {priority.score} · {priority.band}
    </Badge>
  );
}

const RISK_STYLE: Record<RiskLevel, string> = {
  high: "border-transparent bg-rose-700 text-white",
  medium: "border-amber-600/50 bg-amber-100 text-amber-900",
  low: "border-slate-300 bg-slate-100 text-slate-700",
};

export function RiskBadge({ level }: { level: RiskLevel }) {
  return <Badge className={RISK_STYLE[level]}>Risk {level}</Badge>;
}

function shortSha(sha: string | null): string {
  return sha ? sha.slice(0, 12) : "unknown commit";
}

function versions(change: PackageChange): string {
  const from = change.from_versions.join(", ");
  const to = change.to_versions.join(", ");
  if (!from) return to;
  if (!to) return from;
  return `${from} → ${to}`;
}

function ChangeList({ title, items, total }: { title: string; items: PackageChange[]; total: number }) {
  if (total === 0) return null;
  return (
    <details className="text-xs">
      <summary className="cursor-pointer font-medium">
        {title} ({total})
      </summary>
      <ul className="mt-1 grid gap-0.5 pl-4">
        {items.slice(0, 50).map((c) => (
          <li key={`${c.ecosystem}:${c.project_path}:${c.name}`}>
            <code>{c.name}</code> <span className="text-muted-foreground">{versions(c)}</span>
          </li>
        ))}
        {total > Math.min(items.length, 50) && (
          <li className="text-muted-foreground">…and {total - Math.min(items.length, 50)} more (see changes.json)</li>
        )}
      </ul>
    </details>
  );
}

/** What changed since the previous completed scan of this repository. */
function ChangesSection({ changes }: { changes: ChangeSummary | null | undefined }) {
  if (!changes) {
    return (
      <p className="rounded-md border border-dashed px-3 py-2 text-xs text-muted-foreground">
        <GitCompare className="mr-1 inline size-3.5" aria-hidden />
        No earlier scan of this repository to compare with. Scan it again after a change to see what changed.
      </p>
    );
  }
  const t = changes.totals;
  const finished = formatDate(changes.baseline_finished_at);
  return (
    <section aria-label="Changes since last scan" className="grid gap-1.5 rounded-md border px-3 py-2 text-xs">
      <h3 className="flex items-center gap-1.5 text-sm font-medium">
        <GitCompare className="size-4" aria-hidden /> What changed since the last scan
      </h3>
      <p className="text-muted-foreground">
        Compared with <code>{changes.baseline_scan_id}</code> (commit <code>{shortSha(changes.baseline_commit)}</code>
        {changes.baseline_ref ? ` on ${changes.baseline_ref}` : ""}{finished ? `, scanned ${finished}` : ""}) →
        now <code>{shortSha(changes.current_commit)}</code>
        {changes.same_commit ? " (same commit)" : ""}.
      </p>
      <p className="tabular-nums">
        {t.added ?? 0} added · {t.removed ?? 0} removed · {t.upgraded ?? 0} upgraded · {t.downgraded ?? 0} downgraded
        {t.other_changes ? ` · ${t.other_changes} other version changes` : ""}
        {t.excluded ? ` · ${t.excluded} left out (extraction gap)` : ""}
      </p>
      {(changes.caveats ?? []).length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5 text-amber-800 dark:text-amber-300">
          {(changes.caveats ?? []).map((c) => <li key={c}>{c}</li>)}
        </ul>
      )}
      {changes.files_compared ? (
        changes.files_changed.length > 0 ? (
          <p>
            Files changed:{" "}
            {changes.files_changed.map((f) => (
              <span key={f.path} className="mr-2">
                <code>{f.path}</code> <span className="text-muted-foreground">({f.change})</span>
              </span>
            ))}
          </p>
        ) : (
          <p className="text-muted-foreground">No manifest, lockfile, container or CI file changed.</p>
        )
      ) : (
        <p className="text-muted-foreground">File-level changes not compared: the earlier scan predates file snapshots.</p>
      )}
      <ChangeList title="Added" items={changes.added} total={t.added ?? 0} />
      <ChangeList title="Removed" items={changes.removed} total={t.removed ?? 0} />
      <ChangeList title="Downgraded" items={changes.downgraded} total={t.downgraded ?? 0} />
      <ChangeList title="Upgraded" items={changes.upgraded} total={t.upgraded ?? 0} />
      <ChangeList title="Other version changes" items={changes.other_changes} total={t.other_changes ?? 0} />
    </section>
  );
}

function ScoreSection({ finding }: { finding: Finding }) {
  const { cvss, epss, priority } = finding;
  return (
    <section className="grid gap-2">
      <h4 className="font-medium text-muted-foreground uppercase">Scores</h4>
      {cvss ? (
        <div className="grid gap-0.5">
          <p>
            <span className="font-medium">CVSS {cvss.version} base score {cvss.base_score ?? "unknown"}</span>
            {cvss.severity && ` (${cvss.severity})`} · source: {cvss.source}
            {cvss.source_type && ` ${cvss.source_type}`}
            {cvss.cve_id && ` · ${cvss.cve_id}`}
          </p>
          <code className="break-all text-muted-foreground">{cvss.vector}</code>
          <p className="text-muted-foreground">
            {cvss.computed
              ? cvss.published_score === null
                ? "Computed by Kestral from the vector."
                : cvss.matches_published
                  ? `Computed by Kestral from the vector; matches the published ${cvss.published_score}.`
                  : `Computed by Kestral from the vector; differs from the published ${cvss.published_score}.`
              : "CVSS 4.0 score as published (not recomputed by Kestral)."}
          </p>
        </div>
      ) : (
        <p className="text-muted-foreground">No CVSS vector available from NVD, OSV or Grype.</p>
      )}
      <p>
        <span className="font-medium">EPSS</span>{" "}
        {epss
          ? `${(epss.probability * 100).toFixed(2)}% chance of exploitation in the next 30 days ` +
            `(${Math.round(epss.percentile * 100)}th percentile, ${epss.cve_id}${epss.date ? `, ${epss.date}` : ""}) · ${epss.source}`
          : <span className="text-muted-foreground">not available</span>}
      </p>
      {priority && (
        <div className="grid gap-1">
          <p className="flex flex-wrap items-center gap-2">
            <PriorityBadge priority={priority} />
            <span className="text-muted-foreground">{priority.method}</span>
          </p>
          <table className="w-full max-w-2xl text-left">
            <thead className="text-muted-foreground">
              <tr><th className="font-normal">Factor</th><th className="font-normal">Value</th><th className="text-right font-normal">Points</th></tr>
            </thead>
            <tbody>
              {priority.factors.map((f) => (
                <tr key={f.name} className="border-t">
                  <td className="py-0.5 pr-2">{f.name} <span className="text-muted-foreground">({Math.round(f.weight * 100)}%)</span></td>
                  <td className="py-0.5 pr-2 break-words">{f.value}</td>
                  <td className="py-0.5 text-right tabular-nums">{f.points}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function CveCweSection({ finding }: { finding: Finding }) {
  const cves = finding.cves ?? [];
  const cwes = finding.cwes ?? [];
  if (cves.length === 0 && cwes.length === 0) return null;
  return (
    <>
      {cves.length > 0 && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">CVEs (NVD)</h4>
          <ul className="grid gap-1.5">
            {cves.map((cve) => (
              <li key={cve.id} className="grid gap-0.5">
                <span className="flex flex-wrap items-center gap-1.5">
                  <a href={cve.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 font-mono underline">
                    {cve.id} <ExternalLink className="size-3" aria-hidden />
                  </a>
                  <span className="text-muted-foreground">
                    {!cve.looked_up
                      ? "not looked up in NVD during this scan"
                      : !cve.in_nvd
                        ? "no NVD record"
                        : [cve.nvd_status, cve.published && `published ${formatDate(cve.published)}`]
                            .filter(Boolean).join(" · ")}
                  </span>
                </span>
                {cve.description && <span className="text-muted-foreground">{cve.description}</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
      {cwes.length > 0 && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">Weaknesses (CWE)</h4>
          <ul className="flex flex-wrap gap-x-4 gap-y-1">
            {cwes.map((cwe) => (
              <li key={cwe.id} className="flex items-center gap-1.5">
                {cwe.url ? (
                  <a href={cwe.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 font-mono underline">
                    {cwe.id} <ExternalLink className="size-3" aria-hidden />
                  </a>
                ) : (
                  <code>{cwe.id}</code>
                )}
                <span className="text-muted-foreground">via {cwe.sources.join(", ")}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </>
  );
}

function StatTile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border bg-card px-3 py-2">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-lg font-semibold tabular-nums">{value}</dd>
    </div>
  );
}

function FindingDetails({
  finding, labelFor, onShowInGraph, aiProps,
}: { finding: Finding; labelFor: Props["labelFor"]; onShowInGraph: Props["onShowInGraph"]; aiProps: AiProps }) {
  const isVuln = finding.kind === "vulnerability";
  return (
    <div className="grid gap-3 border-t bg-muted/30 px-3 py-3 text-xs">
      {isVuln && <ScoreSection finding={finding} />}
      {finding.risk_level && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">Initial risk level</h4>
          <p>
            <RiskBadge level={finding.risk_level} /> <span className="ml-1">{finding.risk_reason}</span>
          </p>
          <p className="text-muted-foreground">Rule-based rating by Kestral from the evidence below; not proof of malice.</p>
        </section>
      )}
      {isVuln && <CveCweSection finding={finding} />}
      {isVuln && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">Reported by</h4>
          <ul className="grid gap-1">
            {finding.sources.map((s) => (
              <li key={`${s.name}-${s.record_id}`} className="flex flex-wrap items-center gap-1.5">
                <span className="font-medium">{s.name}</span>
                {s.url ? (
                  <a href={s.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 font-mono underline">
                    {s.record_id} <ExternalLink className="size-3" aria-hidden />
                  </a>
                ) : (
                  <code>{s.record_id}</code>
                )}
                <span className="text-muted-foreground">
                  severity: {s.severity ?? "not stated"}
                  {s.match_type && ` · match: ${s.match_type}`}
                </span>
              </li>
            ))}
          </ul>
          {finding.advisory_ids.length > 1 && (
            <p className="text-muted-foreground">Also known as: {finding.advisory_ids.slice(1).join(", ")}</p>
          )}
        </section>
      )}

      {(isVuln || finding.subject_id) && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">How it gets in</h4>
          {finding.dependency_paths.length === 0 ? (
            <p className="text-muted-foreground">No proven dependency path from any project.</p>
          ) : (
            <ul className="grid gap-1.5">
              {finding.dependency_paths.map((path) => (
                <li key={path.join(">")} className="flex flex-wrap items-center gap-2">
                  <span className="break-all">{path.map(labelFor).join(" → ")}</span>
                  <Button variant="outline" size="xs" onClick={() => onShowInGraph(finding, path)}>
                    <Route aria-hidden /> Show path
                  </Button>
                </li>
              ))}
            </ul>
          )}
          {finding.affected_projects.length > 0 && (
            <p className="text-muted-foreground">
              Affects {finding.affected_projects.map(labelFor).join(", ")}
              {finding.dependent_packages ? ` · ${finding.dependent_packages} package(s) depend on it` : ""}
            </p>
          )}
        </section>
      )}

      <section className="grid gap-1">
        <h4 className="font-medium text-muted-foreground uppercase">Evidence</h4>
        <ul className="grid gap-1">
          {finding.evidence.map((e, i) => (
            <li key={`${e.path}-${e.locator}-${i}`} className="flex flex-wrap items-center gap-1.5">
              <FileText className="size-3.5 shrink-0" aria-hidden />
              <code className="font-medium break-all">{e.path}</code>
              <span className="text-muted-foreground">{e.kind} · <code className="break-all">{e.locator}</code></span>
            </li>
          ))}
        </ul>
      </section>

      {finding.uncertainty.length > 0 && (
        <section className="grid gap-1">
          <h4 className="font-medium text-muted-foreground uppercase">Uncertainty</h4>
          <ul className="list-disc space-y-0.5 pl-5 text-muted-foreground">
            {finding.uncertainty.map((u) => <li key={u}>{u}</li>)}
          </ul>
        </section>
      )}

      <AiAnalysisPanel
        scanId={aiProps.scanId}
        findingId={finding.finding_id}
        status={aiProps.aiStatus}
        client={aiProps.ai}
      />
    </div>
  );
}

function FindingRow({
  finding, open, onToggle, labelFor, onShowInGraph, aiProps,
}: {
  finding: Finding; open: boolean; onToggle: () => void;
  labelFor: Props["labelFor"]; onShowInGraph: Props["onShowInGraph"]; aiProps: AiProps;
}) {
  const isVuln = finding.kind === "vulnerability";
  const severity = highestReportedSeverity(finding);
  const Chevron = open ? ChevronDown : ChevronRight;
  return (
    <li className="overflow-hidden rounded-md border bg-card">
      <div className="flex items-start gap-2 px-3 py-2">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          className="flex min-w-0 flex-1 items-start gap-2 text-left"
        >
          <Chevron className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
          <span className="grid min-w-0 gap-1">
            <span className="text-sm font-medium break-words">{finding.title}</span>
            <span className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
              <code className="text-foreground">{finding.subject_label}</code>
              {isVuln && finding.priority && <PriorityBadge priority={finding.priority} />}
              {isVuln && finding.cvss?.base_score != null && (
                <Badge variant="outline" className="tabular-nums">
                  CVSS {finding.cvss.base_score}{finding.cvss.severity ? ` ${finding.cvss.severity}` : ""}
                </Badge>
              )}
              {isVuln && finding.cvss?.base_score == null && (
                <Badge variant="outline">{severity ? `Severity ${severity}` : "Severity not stated"}</Badge>
              )}
              {isVuln && (finding.cwes ?? []).filter((c) => c.url).slice(0, 2).map((c) => (
                <Badge key={c.id} variant="outline" className="font-mono">{c.id}</Badge>
              ))}
              {finding.risk_level && <RiskBadge level={finding.risk_level} />}
              {finding.kind === "suspicious" && <Badge variant="secondary">{categoryLabel(finding.category)}</Badge>}
              <Badge variant={sourceAgreement(finding) === "Both" ? "secondary" : "outline"}>
                {sourceAgreement(finding)}
              </Badge>
              {finding.directness && <Badge variant="outline">{finding.directness}</Badge>}
              {finding.scope && finding.scope !== "runtime" && <Badge variant="outline">{finding.scope}</Badge>}
              {isVuln && (
                <span>
                  {finding.fixed_versions.length
                    ? `Fixed in ${finding.fixed_versions.join(", ")}`
                    : "No fixed version reported"}
                </span>
              )}
              {!isVuln && <span>{finding.evidence[0]?.path}</span>}
            </span>
          </span>
        </button>
        {finding.subject_id && (
          <Button
            variant="ghost"
            size="xs"
            onClick={() => onShowInGraph(finding, finding.dependency_paths[0] ?? null)}
          >
            Show in graph
          </Button>
        )}
      </div>
      {open && <FindingDetails finding={finding} labelFor={labelFor} onShowInGraph={onShowInGraph} aiProps={aiProps} />}
    </li>
  );
}

/** Phase 1B findings: vulnerabilities, suspicious supply-chain changes and workflow pins, with evidence. */
export default function FindingsPanel({ findings, labelFor, onShowInGraph, ai = aiService }: Props) {
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);
  useEffect(() => {
    let cancelled = false;
    ai.getStatus().then(
      (s) => { if (!cancelled) setAiStatus(s); },
      () => {
        if (!cancelled) {
          setAiStatus({
            enabled: false, configured: false, provider: "", api_key_env: "", model: "", prompt_version: "", tool_budget: 0,
            data_notice: "",
          });
        }
      },
    );
    return () => { cancelled = true; };
  }, [ai]);
  const aiProps: AiProps = { scanId: findings.scan_id, aiStatus, ai };
  const [kind, setKind] = useState<FindingKind>("vulnerability");
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(PAGE_SIZE);
  const [openId, setOpenId] = useState<string | null>(null);

  const sorted = useMemo(() => sortFindings(findings.findings), [findings]);
  const visible = useMemo(() => filterFindings(sorted, kind, query), [sorted, kind, query]);
  const { stats } = findings;
  const assessedAny = findings.sources.some((s) => s.name !== "workflow-scan" && s.status === "ok");

  const tabs: Array<[FindingKind, string, number]> = [
    ["vulnerability", "Vulnerabilities", stats.vulnerabilities],
    ["suspicious", "Suspicious changes", stats.suspicious ?? 0],
    ["workflow_pin", "Workflow pins", stats.workflow_pins],
  ];

  return (
    <section aria-label="Risk findings" className="grid gap-3 rounded-xl border bg-card p-4">
      <h2 className="flex items-center gap-2 text-base font-semibold">
        <ShieldAlert className="size-4" aria-hidden /> Risk findings
      </h2>

      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        <StatTile label="Vulnerabilities" value={assessedAny ? stats.vulnerabilities : "Not assessed"} />
        <StatTile label="Vulnerable packages" value={assessedAny ? stats.vulnerable_packages : "—"} />
        <StatTile label="Confirmed by both" value={assessedAny ? stats.confirmed_by_both : "—"} />
        <StatTile label="CVEs linked (NVD)" value={assessedAny ? stats.cves_linked ?? "—" : "—"} />
        <StatTile label="Suspicious changes" value={stats.suspicious ?? "—"} />
        <StatTile label="Workflow pins" value={stats.workflow_pins} />
        <StatTile label="Packages assessed" value={`${stats.components_assessed} / ${stats.components_total}`} />
      </dl>

      <ul className="grid gap-1 text-xs" aria-label="Sources">
        {findings.sources.map((run) => <SourceStatus key={run.name} run={run} />)}
      </ul>

      <WarningsNotice title="Incomplete risk assessment" partial={findings.partial} warnings={findings.warnings} />

      <div className="flex flex-wrap items-center gap-2">
        <div role="tablist" aria-label="Finding type" className="flex gap-1">
          {tabs.map(([value, label, count]) => (
            <Button
              key={value}
              role="tab"
              aria-selected={kind === value}
              variant={kind === value ? "default" : "outline"}
              size="sm"
              onClick={() => { setKind(value); setLimit(PAGE_SIZE); setOpenId(null); }}
            >
              {label} ({count})
            </Button>
          ))}
        </div>
        <div className="relative min-w-48 flex-1">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            aria-label="Search findings"
            placeholder="Search package, CVE, GHSA, CWE or category"
            value={query}
            onChange={(e) => { setQuery(e.target.value); setLimit(PAGE_SIZE); }}
            className="pl-8"
          />
        </div>
      </div>

      {kind === "vulnerability" && (
        <p className="text-xs text-muted-foreground">
          Sorted by Kestral priority (50% CVSS, 20% EPSS, 20% exposure, 10% fix available), then CVSS.
          Each source&apos;s own severity is kept verbatim; nothing here is reachability-checked.
        </p>
      )}

      {kind === "suspicious" && (
        <>
          <ChangesSection changes={findings.changes} />
          <p className="text-xs text-muted-foreground">
            Non-CVE checks of lockfiles, manifests and container files: install scripts, packages from outside the
            registry, missing integrity hashes, loose versions, unpinned images, lookalike names and changes since the
            last scan. Sorted by Kestral&apos;s rule-based initial risk level.
          </p>
        </>
      )}

      {visible.length === 0 ? (
        <p className="rounded-md border border-dashed p-4 text-center text-sm text-muted-foreground">
          {query
            ? "No findings match this search."
            : kind === "vulnerability"
              ? assessedAny
                ? "No known vulnerabilities were reported for the assessed packages."
                : "Vulnerabilities were not assessed: no source was available."
              : kind === "suspicious"
                ? "No suspicious changes found by the supply-chain checks."
                : "No mutable workflow references found."}
        </p>
      ) : (
        <ul className="grid gap-2">
          {visible.slice(0, limit).map((finding) => (
            <FindingRow
              key={finding.finding_id}
              finding={finding}
              open={openId === finding.finding_id}
              onToggle={() => setOpenId((id) => (id === finding.finding_id ? null : finding.finding_id))}
              labelFor={labelFor}
              onShowInGraph={onShowInGraph}
              aiProps={aiProps}
            />
          ))}
        </ul>
      )}
      {visible.length > limit && (
        <Button variant="outline" size="sm" className="w-fit" onClick={() => setLimit((n) => n + PAGE_SIZE)}>
          Show {Math.min(PAGE_SIZE, visible.length - limit)} more of {visible.length - limit}
        </Button>
      )}
    </section>
  );
}

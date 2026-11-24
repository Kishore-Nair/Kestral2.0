"use client";

import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, ExternalLink, FileText, Route, Search, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import WarningsNotice from "@/components/WarningsNotice";
import { filterFindings, highestReportedSeverity, sortFindings, sourceAgreement } from "@/lib/findings";
import { cn } from "@/lib/utils";
import type { Finding, FindingKind, FindingsDocument, Priority, SourceRun } from "@/types/findings";

const PAGE_SIZE = 25;

interface Props {
  findings: FindingsDocument;
  labelFor: (id: string) => string;
  /** Select the finding's package in the graph and highlight one dependency path. */
  onShowInGraph: (finding: Finding, path: string[] | null) => void;
}

function formatDate(value: string | null): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString().slice(0, 10);
}

function SourceStatus({ run }: { run: SourceRun }) {
  const label = run.name === "workflow-scan" ? "Workflow scan" : run.name;
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
  finding, labelFor, onShowInGraph,
}: { finding: Finding; labelFor: Props["labelFor"]; onShowInGraph: Props["onShowInGraph"] }) {
  const isVuln = finding.kind === "vulnerability";
  return (
    <div className="grid gap-3 border-t bg-muted/30 px-3 py-3 text-xs">
      {isVuln && <ScoreSection finding={finding} />}
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

      {isVuln && (
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
    </div>
  );
}

function FindingRow({
  finding, open, onToggle, labelFor, onShowInGraph,
}: {
  finding: Finding; open: boolean; onToggle: () => void;
  labelFor: Props["labelFor"]; onShowInGraph: Props["onShowInGraph"];
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
        {isVuln && finding.subject_id && (
          <Button
            variant="ghost"
            size="xs"
            onClick={() => onShowInGraph(finding, finding.dependency_paths[0] ?? null)}
          >
            Show in graph
          </Button>
        )}
      </div>
      {open && <FindingDetails finding={finding} labelFor={labelFor} onShowInGraph={onShowInGraph} />}
    </li>
  );
}

/** Phase 1B findings: OSV + Grype vulnerabilities and workflow-pin anomalies, with evidence. */
export default function FindingsPanel({ findings, labelFor, onShowInGraph }: Props) {
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
    ["workflow_pin", "Workflow pins", stats.workflow_pins],
  ];

  return (
    <section aria-label="Risk findings" className="grid gap-3 rounded-xl border bg-card p-4">
      <h2 className="flex items-center gap-2 text-base font-semibold">
        <ShieldAlert className="size-4" aria-hidden /> Risk findings
      </h2>

      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <StatTile label="Vulnerabilities" value={assessedAny ? stats.vulnerabilities : "Not assessed"} />
        <StatTile label="Vulnerable packages" value={assessedAny ? stats.vulnerable_packages : "—"} />
        <StatTile label="Confirmed by both" value={assessedAny ? stats.confirmed_by_both : "—"} />
        <StatTile label="CVEs linked (NVD)" value={assessedAny ? stats.cves_linked ?? "—" : "—"} />
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
            placeholder="Search package, CVE, GHSA or CWE"
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

      {visible.length === 0 ? (
        <p className="rounded-md border border-dashed p-4 text-center text-sm text-muted-foreground">
          {query
            ? "No findings match this search."
            : kind === "vulnerability"
              ? assessedAny
                ? "No known vulnerabilities were reported for the assessed packages."
                : "Vulnerabilities were not assessed: no source was available."
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

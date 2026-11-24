"use client";

import { useEffect, useState } from "react";
import { ShieldAlert, RotateCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { classifyError } from "@/services/errors";
import { privacyService, type PrivacyApi } from "@/services/privacyApi";
import type { DataContext, MappingStatus, PrivacyAssessment, PrivacyBand, PrivacyImpact } from "@/types/privacy";
import { cn } from "@/lib/utils";

const BAND_LABEL: Record<PrivacyBand, string> = {
  very_high: "Very high",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const BAND_STYLE: Record<PrivacyBand, string> = {
  very_high: "border-transparent bg-rose-700 text-white",
  high: "border-transparent bg-orange-600 text-white",
  medium: "border-amber-600/50 bg-amber-100 text-amber-900",
  low: "border-slate-300 bg-slate-100 text-slate-700",
};

const STATUS_LABEL: Record<MappingStatus, string> = {
  mapped: "Mapped",
  no_cwe: "No CWE on finding",
  cwe_excluded: "Excluded (non-privacy CWE)",
  cwe_has_no_category: "Unmapped CWE (no category)",
  category_has_no_linddun: "Category has no LINDDUN class",
  cwe_not_in_dataset: "CWE not in dataset",
};

function ImpactRow({ impact }: { impact: PrivacyImpact }) {
  return (
    <details className="rounded-lg border bg-background px-3 py-2 text-sm">
      <summary className="flex cursor-pointer flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          {impact.band && impact.score !== null ? (
            <Badge className={BAND_STYLE[impact.band]}>
              {impact.score.toFixed(2)} · {BAND_LABEL[impact.band]}
            </Badge>
          ) : (
            <Badge variant="outline" className="text-muted-foreground">
              Unmapped
            </Badge>
          )}
          <code className="text-xs font-medium">{impact.subject_label}</code>
          <span className="font-medium">{impact.title}</span>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          {impact.linddun.length > 0 ? (
            impact.linddun.map((cls) => (
              <Badge key={cls} variant="secondary" className="text-xs">
                {cls}
              </Badge>
            ))
          ) : (
            <span className="text-xs text-muted-foreground">{STATUS_LABEL[impact.status]}</span>
          )}
        </div>
      </summary>

      <div className="mt-3 grid gap-2.5 border-t pt-2.5 text-xs">
        {impact.advisory_ids.length > 0 && (
          <p className="text-muted-foreground">
            Advisories: <span className="font-mono">{impact.advisory_ids.join(", ")}</span>
            {impact.security_priority !== null && <> · Security priority: {impact.security_priority}</>}
          </p>
        )}

        {impact.factors.length > 0 && (
          <div className="grid gap-1">
            <h5 className="font-medium text-muted-foreground uppercase">
              ENISA breakdown (SE = DPC × EI + CB)
            </h5>
            <ul className="grid gap-1">
              {impact.factors.map((f) => (
                <li key={f.name} className="flex flex-wrap items-baseline gap-1.5">
                  <Badge variant="outline" className="font-mono">
                    {f.name} = {f.value}
                  </Badge>
                  <span>{f.basis}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {impact.mappings.length > 0 && (
          <div className="grid gap-1">
            <h5 className="font-medium text-muted-foreground uppercase">CWE → LINDDUN mapping</h5>
            <ul className="grid gap-1">
              {impact.mappings.map((m) => (
                <li key={m.cwe_id} className="grid gap-0.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <code className="font-medium">{m.cwe_id}</code>
                    <Badge variant="outline">{STATUS_LABEL[m.status]}</Badge>
                    {m.linddun.length > 0 && <span>→ {m.linddun.join(", ")}</span>}
                    {m.source && <span className="text-muted-foreground">({m.source})</span>}
                  </div>
                  {m.rationale && <p className="text-muted-foreground">{m.rationale}</p>}
                </li>
              ))}
            </ul>
          </div>
        )}

        {impact.uncertainty.length > 0 && (
          <div className="grid gap-1 text-amber-800 dark:text-amber-300">
            <h5 className="font-medium uppercase">Uncertainty</h5>
            <ul className="list-disc pl-4">
              {impact.uncertainty.map((u) => (
                <li key={u}>{u}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </details>
  );
}

/** ENISA personal data breach severity + CVE→LINDDUN privacy threat mapping for a completed scan. */
export default function PrivacyPanel({
  scanId,
  client = privacyService,
}: {
  scanId: string;
  client?: PrivacyApi;
}) {
  const [dataContext, setDataContext] = useState<DataContext | undefined>(undefined);
  const [assessment, setAssessment] = useState<PrivacyAssessment | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [bandFilter, setBandFilter] = useState<"all" | PrivacyBand | "unmapped">("all");
  const [linddunFilter, setLinddunFilter] = useState<string | null>(null);
  const [reloadNonce, setReloadNonce] = useState(0);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    client
      .getPrivacy(scanId, dataContext)
      .then((result) => {
        if (!active) return;
        setAssessment(result);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(classifyError(err).message);
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [scanId, dataContext, client, reloadNonce]);

  const filtered =
    assessment?.impacts.filter((item) => {
      if (bandFilter === "unmapped" && item.status === "mapped") return false;
      if (bandFilter !== "all" && bandFilter !== "unmapped" && item.band !== bandFilter) return false;
      if (linddunFilter && !item.linddun.includes(linddunFilter)) return false;
      return true;
    }) ?? [];

  const activeContext = assessment?.data_context ?? dataContext ?? "simple";

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="size-5" aria-hidden />
            Privacy impact (ENISA &amp; LINDDUN)
          </CardTitle>
          {assessment?.summary.max_band && assessment.summary.max_score !== null && (
            <Badge className={BAND_STYLE[assessment.summary.max_band]}>
              Worst: {assessment.summary.max_score.toFixed(2)} ({BAND_LABEL[assessment.summary.max_band]})
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="grid gap-4">
        <p className="text-sm text-muted-foreground">
          Maps vulnerability CWEs to LINDDUN privacy threat classes and computes ENISA personal data breach
          severity (<code>SE = DPC × EI + CB</code>). Unmapped or DoS-only CWEs are flagged rather than guessed.
        </p>

        {error && (
          <div role="alert" className="grid gap-2 text-sm">
            <p className="text-destructive">{error}</p>
            <Button size="sm" variant="outline" className="w-fit" onClick={() => setReloadNonce((n) => n + 1)}>
              <RotateCw aria-hidden /> Retry
            </Button>
          </div>
        )}

        {loading && !assessment && <Skeleton className="h-28 w-full" />}

        {assessment && (
          <>
            <fieldset className="grid gap-1.5">
              <legend className="text-xs font-medium text-muted-foreground uppercase">
                Data Processing Context (DPC = {assessment.dpc})
              </legend>
              <div className="flex flex-wrap gap-2">
                {assessment.data_contexts.map((opt) => (
                  <Button
                    key={opt.value}
                    size="sm"
                    variant={activeContext === opt.value ? "default" : "outline"}
                    aria-pressed={activeContext === opt.value}
                    disabled={loading}
                    onClick={() => setDataContext(opt.value)}
                    title={opt.examples}
                  >
                    {opt.label} (DPC {opt.dpc})
                  </Button>
                ))}
              </div>
              {assessment.data_contexts.find((o) => o.value === activeContext)?.examples && (
                <p className="text-xs text-muted-foreground">
                  Examples: {assessment.data_contexts.find((o) => o.value === activeContext)?.examples}
                </p>
              )}
            </fieldset>

            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <div className="rounded-lg border bg-card px-3 py-2">
                <dt className="text-xs text-muted-foreground">Assessed findings</dt>
                <dd className="text-lg font-semibold tabular-nums">{assessment.summary.assessed}</dd>
              </div>
              <div className="rounded-lg border bg-card px-3 py-2">
                <dt className="text-xs text-muted-foreground">Mapped to LINDDUN</dt>
                <dd className="text-lg font-semibold tabular-nums">{assessment.summary.mapped}</dd>
              </div>
              <div className="rounded-lg border bg-card px-3 py-2">
                <dt className="text-xs text-muted-foreground">Unmapped (no guess)</dt>
                <dd className="text-lg font-semibold tabular-nums">{assessment.summary.unmapped}</dd>
              </div>
              <div className="rounded-lg border bg-card px-3 py-2">
                <dt className="text-xs text-muted-foreground">Worst ENISA score</dt>
                <dd className="text-lg font-semibold tabular-nums">
                  {assessment.summary.max_score !== null ? assessment.summary.max_score.toFixed(2) : "—"}
                </dd>
              </div>
            </dl>

            {Object.keys(assessment.summary.by_linddun).length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                <span className="font-medium text-muted-foreground">LINDDUN classes:</span>
                {Object.entries(assessment.summary.by_linddun).map(([cls, count]) => (
                  <Button
                    key={cls}
                    size="xs"
                    variant={linddunFilter === cls ? "default" : "outline"}
                    onClick={() => setLinddunFilter((current) => (current === cls ? null : cls))}
                  >
                    {cls} ({count})
                  </Button>
                ))}
                {linddunFilter && (
                  <Button size="xs" variant="ghost" onClick={() => setLinddunFilter(null)}>
                    Clear class filter
                  </Button>
                )}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <span className="font-medium text-muted-foreground">Filter by band:</span>
              {(["all", "very_high", "high", "medium", "low", "unmapped"] as const).map((b) => {
                const count =
                  b === "all"
                    ? assessment.summary.assessed
                    : b === "unmapped"
                      ? assessment.summary.unmapped
                      : (assessment.summary.by_band[b] ?? 0);
                return (
                  <Button
                    key={b}
                    size="xs"
                    variant={bandFilter === b ? "secondary" : "outline"}
                    className={cn(bandFilter === b && "font-semibold")}
                    onClick={() => setBandFilter(b)}
                  >
                    {b === "all" ? "All" : b === "unmapped" ? "Unmapped" : BAND_LABEL[b]} ({count})
                  </Button>
                );
              })}
            </div>

            {filtered.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No findings match the selected privacy filters.
              </p>
            ) : (
              <div className="grid gap-2">
                {filtered.map((impact) => (
                  <ImpactRow key={impact.finding_id} impact={impact} />
                ))}
              </div>
            )}

            <details className="text-xs text-muted-foreground">
              <summary className="cursor-pointer font-medium">
                Dataset &amp; ENISA methodology caveats ({assessment.dataset.cwes_mapped} of{" "}
                {assessment.dataset.cwes} CWEs mapped)
              </summary>
              <div className="mt-2 grid gap-1">
                <p>
                  Method: {assessment.method}. Dataset: <code>{assessment.dataset.dataset_file}</code> (
                  {assessment.dataset.dataset_rows.toLocaleString()} rows, {assessment.dataset.cwes_from_chain}{" "}
                  CWEs supplemented from MITRE chain).
                </p>
                {assessment.caveats.length > 0 && (
                  <ul className="list-disc space-y-0.5 pl-4">
                    {assessment.caveats.map((c) => (
                      <li key={c}>{c}</li>
                    ))}
                  </ul>
                )}
              </div>
            </details>
          </>
        )}
      </CardContent>
    </Card>
  );
}

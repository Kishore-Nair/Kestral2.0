"use client";

import { useState, type ReactNode } from "react";
import Image from "next/image";
import { FlaskConical, RotateCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import RepositoryForm from "@/components/scan/RepositoryForm";
import ScanProgress from "@/components/scan/ScanProgress";
import RepositorySummary from "@/components/scan/RepositorySummary";
import ArtifactInventory from "@/components/inventory/ArtifactInventory";
import SbomSummary from "@/components/inventory/SbomSummary";
import GraphShell from "@/components/graph/GraphShell";
import WarningsNotice from "@/components/WarningsNotice";
import { useScan, type ArtifactState } from "@/hooks/useScan";
import { USE_MOCKS } from "@/services/scanService";
import type { GraphStats } from "@/types/graph";
import RemediationPanel from "@/components/remediation/RemediationPanel";
import PrivacyPanel from "@/components/privacy/PrivacyPanel";
import ReportDownload from "@/components/validation/ReportDownload";
import ValidationPanel from "@/components/validation/ValidationPanel";
import { usePersistentScanId } from "@/hooks/usePersistentScanId";

function ArtifactPanel<T>({
  state, label, onRetry, children,
}: {
  state: ArtifactState<T>;
  label: string;
  onRetry: () => void;
  children: (data: T) => ReactNode;
}) {
  if (state.status === "idle") return <p className="text-xs text-muted-foreground">Available after the scan completes.</p>;
  if (state.status === "loading") return <Skeleton className="h-24 w-full" />;
  if (state.status === "error") {
    const notReady = state.error.kind === "not_ready";
    return (
      <div role={notReady ? "status" : "alert"} className="grid gap-2 text-sm">
        <p className={notReady ? "text-muted-foreground" : "text-destructive"}>
          {notReady ? `${label}: not ready.` : `${label} could not be loaded: ${state.error.message}`}
        </p>
        <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}>
          <RotateCw aria-hidden /> Retry
        </Button>
      </div>
    );
  }
  return <>{children(state.data)}</>;
}

function StatsBar({ stats }: { stats: GraphStats }) {
  const items: Array<[string, number]> = [
    ["Packages", stats.packages],
    ["Projects", stats.projects],
    ["Dependency edges", stats.depends_on_edges],
    ["Unresolved", stats.unresolved],
    ["Max depth", stats.max_depth],
    ["Cycles", stats.cycles],
  ];
  return (
    <dl className="grid grid-cols-3 gap-2 sm:grid-cols-6">
      {items.map(([label, value]) => (
        <div key={label} className="rounded-lg border bg-card px-3 py-2">
          <dt className="text-xs text-muted-foreground">{label}</dt>
          <dd className="text-lg font-semibold tabular-nums">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export default function Home() {
  const [scanId, setScanId] = usePersistentScanId();
  const [formKey, setFormKey] = useState(0);
  const { scan, poll, artifacts, retryPolling, retryArtifacts } = useScan(scanId);

  const inProgress = scanId !== null && poll.status === "polling";
  const graph = artifacts.graph.status === "ready" ? artifacts.graph.data : null;

  const resubmit = () => {
    setScanId(null);
    setFormKey((k) => k + 1);
  };

  return (
    <div className="min-h-screen bg-muted/40">
      <header className="border-b bg-background">
        <div className="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-3 px-4 py-4">
          <div className="flex items-center gap-3">
            {/* mix-blend-multiply drops the JPG's white background on tinted surfaces */}
            <Image src="/kestral-logo.jpg" alt="" width={56} height={56} priority className="mix-blend-multiply" />
            <h1 className="text-4xl font-bold tracking-tight">Kestral</h1>
          </div>
          {USE_MOCKS && (
            <Badge variant="outline" className="gap-1.5 border-amber-500/60 bg-amber-500/10 px-2.5 py-1 text-amber-800">
              <FlaskConical aria-hidden /> Sample data (offline)
            </Badge>
          )}
        </div>
      </header>

      <main className="mx-auto grid max-w-[1600px] gap-4 px-4 py-4">
        {USE_MOCKS && (
          <p role="note" className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">
            Mock mode: results below are synthetic, labelled sample fixtures — not a real repository scan.
          </p>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Scan a public GitHub repository</CardTitle>
          </CardHeader>
          <CardContent>
            <RepositoryForm key={formKey} busy={inProgress} onSubmitted={(created) => setScanId(created.scan_id)} />
          </CardContent>
        </Card>

        {scanId && (
          <Card>
            <CardContent className="grid gap-4">
              <ScanProgress
                scan={scan}
                poll={poll}
                graphReady={graph !== null}
                onRetryPolling={retryPolling}
                onResubmit={resubmit}
              />
              {scan && <RepositorySummary scan={scan} />}
              {scan && scan.warnings.length > 0 && (
                <WarningsNotice title={`Scan warnings (${scan.warnings.length})`} warnings={scan.warnings} />
              )}
            </CardContent>
          </Card>
        )}

        {graph && <StatsBar stats={graph.meta.stats} />}

        {scan?.status === "COMPLETED" && (
          <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)_320px]">
            <aside aria-label="Artifacts" className="grid content-start gap-4">
              <Card size="sm">
                <CardHeader><CardTitle>Artifacts</CardTitle></CardHeader>
                <CardContent>
                  <ArtifactPanel state={artifacts.inventory} label="Inventory" onRetry={retryArtifacts}>
                    {(inventory) => <ArtifactInventory inventory={inventory} />}
                  </ArtifactPanel>
                </CardContent>
              </Card>
              <Card size="sm">
                <CardHeader><CardTitle>Normalized SBOM</CardTitle></CardHeader>
                <CardContent>
                  <ArtifactPanel state={artifacts.sbom} label="SBOM" onRetry={retryArtifacts}>
                    {(sbom) => <SbomSummary sbom={sbom} />}
                  </ArtifactPanel>
                </CardContent>
              </Card>
            </aside>

            {graph ? (
              <GraphShell
                graph={graph}
                findings={artifacts.findings.status === "ready" ? artifacts.findings.data : null}
                findingsFallback={
                  <ArtifactPanel state={artifacts.findings} label="Risk findings" onRetry={retryArtifacts}>
                    {() => null}
                  </ArtifactPanel>
                }
              />
            ) : (
              <Card className="lg:col-span-2">
                <CardContent>
                  <ArtifactPanel state={artifacts.graph} label="Graph" onRetry={retryArtifacts}>
                    {() => null}
                  </ArtifactPanel>
                </CardContent>
              </Card>
            )}
          </div>
        )}
        {scan?.status === "COMPLETED" && <PrivacyPanel scanId={scan.scan_id} />}
        {scan?.status === "COMPLETED" && <RemediationPanel scanId={scan.scan_id} />}
        {scan?.status === "COMPLETED" && <ValidationPanel scanId={scan.scan_id} />}
        {scan?.status === "COMPLETED" && <ReportDownload scanId={scan.scan_id} />}
      </main>
    </div>
  );
}

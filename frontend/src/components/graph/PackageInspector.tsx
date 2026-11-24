import type { ReactNode } from "react";
import { AlertTriangle, FileText, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { GraphNodeData } from "@/types/graph";
import { nodeDisplayLabel } from "@/lib/graph";
import { NODE_KIND_STYLE } from "@/components/graph/graphStyles";
import { highestReportedSeverity, sortFindings, sourceAgreement } from "@/lib/findings";
import type { Finding } from "@/types/findings";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-sm break-all">{children}</dd>
    </div>
  );
}

function Unknown({ children }: { children: ReactNode }) {
  return <span className="text-muted-foreground italic">{children}</span>;
}

export default function PackageInspector({ node, findings }: { node: GraphNodeData | null; findings?: Finding[] }) {
  if (!node) {
    return (
      <p className="p-4 text-sm text-muted-foreground">
        Select a node in the graph or a search result to inspect its details and source evidence.
      </p>
    );
  }

  const kind = NODE_KIND_STYLE[node.type];
  const isPackage = node.type === "package";
  const isUnresolved = node.type === "unresolved";
  const evidence = node.evidence ?? [];
  const showEvidence = isPackage || isUnresolved;

  return (
    <div className="grid gap-4 p-4">
      <div className="grid gap-1.5">
        <Badge variant="outline" className="gap-1.5">
          <span aria-hidden className="inline-block size-2 rounded-full" style={{ backgroundColor: kind.color }} />
          {kind.label}
        </Badge>
        <h3 className="text-base font-semibold break-all">{nodeDisplayLabel(node)}</h3>
      </div>

      <dl className="grid gap-3">
        {isPackage && (
          <>
            <Field label="Name">{node.name ?? <Unknown>Name unavailable</Unknown>}</Field>
            <Field label="Version">{node.version ? node.version : <Unknown>Version not resolved</Unknown>}</Field>
            <Field label="PURL">
              {node.purl ? <code className="font-mono text-xs">{node.purl}</code> : <Unknown>No PURL</Unknown>}
            </Field>
          </>
        )}
        {isUnresolved && (
          <>
            <Field label="Requested name">{node.unresolved_target?.name ?? <Unknown>Unknown</Unknown>}</Field>
            <Field label="Specifier">
              {node.unresolved_target?.specifier
                ? <code className="font-mono text-xs">{node.unresolved_target.specifier}</code>
                : <Unknown>No specifier</Unknown>}
            </Field>
            <Field label="Resolution">
              <span className="flex items-start gap-1.5">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-amber-600" aria-hidden />
                {node.resolution_status === "ambiguous"
                  ? "Ambiguous: more than one candidate matched, so no package was chosen."
                  : "Unresolved: no lockfile evidence identifies a concrete package version."}
              </span>
            </Field>
          </>
        )}
        {(isPackage || isUnresolved) && (
          <Field label="Ecosystem">{node.ecosystem ?? node.unresolved_target?.ecosystem ?? <Unknown>Unknown</Unknown>}</Field>
        )}
        {node.directness !== "not_applicable" && <Field label="Directness">{node.directness}</Field>}
        <Field label="Shortest dependency depth">
          {node.depth === null ? <Unknown>Not applicable</Unknown> : node.depth}
        </Field>
        {node.project_path !== undefined && (
          <Field label="Project path"><code className="font-mono text-xs">{node.project_path || "(repository root)"}</code></Field>
        )}
        {isPackage && (
          <Field label="Install path">
            {node.install_path ? <code className="font-mono text-xs">{node.install_path}</code> : <Unknown>Not recorded</Unknown>}
          </Field>
        )}
        <Field label="Node ID"><code className="font-mono text-xs text-muted-foreground">{node.id}</code></Field>
      </dl>

      {findings && findings.length > 0 && (
        <section className="grid gap-2" aria-label="Known vulnerabilities">
          <h4 className="flex items-center gap-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">
            <ShieldAlert className="size-3.5" aria-hidden /> Known vulnerabilities ({findings.length})
          </h4>
          <ul className="grid gap-2">
            {sortFindings(findings).map((f) => (
              <li key={f.finding_id} className="rounded-md border p-2 text-xs">
                <p className="font-medium break-words">{f.title}</p>
                <p className="mt-1 text-muted-foreground">
                  {f.priority && `Priority ${f.priority.score} (${f.priority.band}) · `}
                  {f.cvss?.base_score != null ? `CVSS ${f.cvss.base_score}` : highestReportedSeverity(f) ?? "Severity not stated"} · {sourceAgreement(f)} ·{" "}
                  {f.fixed_versions.length ? `fixed in ${f.fixed_versions.join(", ")}` : "no fixed version reported"}
                </p>
              </li>
            ))}
          </ul>
          <p className="text-xs text-muted-foreground">Full evidence and paths are in Risk findings below.</p>
        </section>
      )}

      {showEvidence && (
        <section className="grid gap-2">
          <h4 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">Source evidence</h4>
          {evidence.length === 0 ? (
            <p className="rounded-md border border-dashed p-2 text-xs text-muted-foreground">
              Evidence unavailable — flagged for backend contract review.
            </p>
          ) : (
            <ul className="grid gap-2">
              {evidence.map((e, i) => (
                <li key={`${e.path}-${e.locator}-${i}`} className="rounded-md border p-2 text-xs">
                  <p className="flex items-center gap-1.5 font-mono font-medium break-all">
                    <FileText className="size-3.5 shrink-0" aria-hidden />
                    {e.path}
                  </p>
                  <p className="mt-1 text-muted-foreground">
                    <span className="font-medium">{e.kind}</span> · <code className="break-all">{e.locator}</code>
                  </p>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}

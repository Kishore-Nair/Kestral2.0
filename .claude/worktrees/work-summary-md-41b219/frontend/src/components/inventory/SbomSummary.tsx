import WarningsNotice from "@/components/WarningsNotice";
import type { DependencyDocument } from "@/types/sbom";

export default function SbomSummary({ sbom }: { sbom: DependencyDocument }) {
  const resolved = sbom.relationships.filter((r) => r.resolution_status === "resolved").length;
  const unresolved = sbom.relationships.length - resolved;
  const unversioned = sbom.components.filter((c) => !c.version).length;
  const byScope = sbom.components.reduce<Record<string, number>>((acc, c) => {
    acc[c.scope] = (acc[c.scope] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="grid gap-3 text-sm">
      <WarningsNotice
        title="Incomplete dependency evidence"
        partial={sbom.partial}
        warnings={sbom.warnings}
      />
      <dl className="grid grid-cols-2 gap-2">
        <div>
          <dt className="text-xs text-muted-foreground">Project roots</dt>
          <dd className="tabular-nums">{sbom.roots.length}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Package instances</dt>
          <dd className="tabular-nums">{sbom.components.length}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Resolved relationships</dt>
          <dd className="tabular-nums">{resolved}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Unresolved / ambiguous</dt>
          <dd className="tabular-nums">{unresolved}</dd>
        </div>
      </dl>
      {Object.keys(byScope).length > 0 && (
        <p className="text-xs text-muted-foreground">
          Scope: {Object.entries(byScope).map(([scope, n]) => `${scope} ${n}`).join(" · ")}
        </p>
      )}
      {unversioned > 0 && (
        <p className="text-xs text-muted-foreground">{unversioned} package(s): version not resolved</p>
      )}
      <ul className="grid gap-1">
        {sbom.roots.map((r) => (
          <li key={r.root_id} className="truncate font-mono text-xs" title={r.manifest_path}>
            {r.name} <span className="text-muted-foreground">({r.ecosystem}) · {r.manifest_path}</span>
          </li>
        ))}
      </ul>
      <p className="text-xs text-muted-foreground">
        Counts are discovered package instances from the normalized SBOM, not vulnerabilities or severity.
      </p>
    </div>
  );
}

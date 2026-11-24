import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import WarningsNotice from "@/components/WarningsNotice";
import type { ArtifactEntry, Inventory } from "@/types/api";

function Section({ title, count, children }: { title: string; count: number; children: ReactNode }) {
  return (
    <section className="grid gap-1">
      <h4 className="flex items-center justify-between text-xs font-medium tracking-wide text-muted-foreground uppercase">
        {title}
        <span className="tabular-nums">{count}</span>
      </h4>
      {count === 0 ? <p className="text-xs text-muted-foreground">None found</p> : children}
    </section>
  );
}

function PathList({ paths }: { paths: string[] }) {
  return (
    <ul className="grid gap-0.5">
      {paths.map((p) => (
        <li key={p} className="truncate font-mono text-xs" title={p}>{p}</li>
      ))}
    </ul>
  );
}

function EntryList({ entries }: { entries: ArtifactEntry[] }) {
  return (
    <ul className="grid gap-1">
      {entries.map((e) => (
        <li key={e.path} className="flex items-center justify-between gap-2">
          <span className="truncate font-mono text-xs" title={e.path}>{e.path}</span>
          <Badge variant="outline" className="shrink-0">{e.ecosystem}</Badge>
        </li>
      ))}
    </ul>
  );
}

export default function ArtifactInventory({ inventory }: { inventory: Inventory }) {
  return (
    <div className="grid gap-4">
      <WarningsNotice
        title="Inventory is incomplete"
        partial={inventory.partial}
        warnings={inventory.warnings}
      />
      <p className="text-xs text-muted-foreground">
        {inventory.file_count} files visited
      </p>
      <Section title="Languages" count={inventory.languages.length}>
        <ul className="flex flex-wrap gap-1">
          {inventory.languages.map((l) => (
            <li key={l.name}>
              <Badge variant="secondary">{l.name} · {l.file_count}</Badge>
            </li>
          ))}
        </ul>
      </Section>
      <Section title="Manifests" count={inventory.manifests.length}>
        <EntryList entries={inventory.manifests} />
      </Section>
      <Section title="Lockfiles" count={inventory.lockfiles.length}>
        <EntryList entries={inventory.lockfiles} />
      </Section>
      <Section title="Dockerfiles" count={inventory.dockerfiles.length}>
        <PathList paths={inventory.dockerfiles} />
      </Section>
      <Section title="CI" count={inventory.ci_files.length}>
        <PathList paths={inventory.ci_files} />
      </Section>
      <Section title="IaC" count={inventory.iac_files.length}>
        <PathList paths={inventory.iac_files} />
      </Section>
      <Section title="Existing SBOMs" count={inventory.existing_sboms.length}>
        <PathList paths={inventory.existing_sboms} />
      </Section>
    </div>
  );
}

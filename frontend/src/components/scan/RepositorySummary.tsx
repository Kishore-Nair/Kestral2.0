import { ExternalLink, GitCommit } from "lucide-react";
import type { ScanState } from "@/types/api";

function formatTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function RepositorySummary({ scan }: { scan: ScanState }) {
  const { repository } = scan;
  const sha = repository.commit_sha;
  return (
    <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
      <div className="min-w-0">
        <dt className="text-xs text-muted-foreground">Repository</dt>
        <dd className="truncate">
          <a
            href={repository.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-medium hover:underline"
          >
            {repository.owner}/{repository.name}
            <ExternalLink className="size-3" aria-hidden />
          </a>
        </dd>
      </div>
      <div>
        <dt className="text-xs text-muted-foreground">Ref (requested → resolved)</dt>
        <dd>
          {repository.requested_ref ?? "default"} → {repository.resolved_ref ?? "pending"}
        </dd>
      </div>
      <div>
        <dt className="text-xs text-muted-foreground">Commit</dt>
        <dd className="flex items-center gap-1 font-mono">
          <GitCommit className="size-3.5 text-muted-foreground" aria-hidden />
          {sha ? <abbr title={sha} className="no-underline">{sha.slice(0, 7)}</abbr> : "not yet resolved"}
        </dd>
      </div>
      <div>
        <dt className="text-xs text-muted-foreground">Started / finished</dt>
        <dd className="text-xs">
          <time dateTime={scan.started_at ?? undefined}>{formatTime(scan.started_at)}</time>
          {" / "}
          <time dateTime={scan.finished_at ?? undefined}>{formatTime(scan.finished_at)}</time>
        </dd>
      </div>
    </dl>
  );
}

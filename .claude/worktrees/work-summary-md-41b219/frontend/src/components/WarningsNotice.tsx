import { AlertTriangle } from "lucide-react";

interface Props {
  title: string;
  partial?: boolean;
  warnings: string[];
}

/** Visible notice for partial results and backend warnings, even on HTTP 200. */
export default function WarningsNotice({ title, partial = false, warnings }: Props) {
  if (!partial && warnings.length === 0) return null;
  return (
    <div role="status" className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
      <p className="flex items-center gap-2 font-medium">
        <AlertTriangle className="size-4 text-amber-600" aria-hidden />
        {title}
      </p>
      {warnings.length > 0 && (
        <ul className="mt-1.5 list-disc space-y-0.5 pl-6 text-xs text-muted-foreground">
          {warnings.map((w, i) => <li key={i}>{w}</li>)}
        </ul>
      )}
    </div>
  );
}

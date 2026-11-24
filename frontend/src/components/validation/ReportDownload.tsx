"use client";

import Image from "next/image";
import { Download, FileJson, FileText } from "lucide-react";
import { validationService, type ValidationApi } from "@/services/validationApi";

/** Guardian report downloads: printable HTML (save as PDF) and machine-readable JSON. */
export default function ReportDownload({ scanId, client = validationService }: { scanId: string; client?: ValidationApi }) {
  const html = client.reportUrl(scanId, "html");
  const json = client.reportUrl(scanId, "json");
  const view = client.reportUrl(scanId, "html", false);
  return (
    <section aria-label="Guardian report" className="flex flex-wrap items-center gap-3 rounded-xl border bg-card p-4">
      <Image src="/kestral-logo.jpg" alt="" width={40} height={40} className="mix-blend-multiply" />
      <div className="grid gap-0.5">
        <h2 className="text-base font-semibold">Guardian report</h2>
        <p className="text-xs text-muted-foreground">
          Inventory, ranked findings with evidence, recommended actions and decisions, sandbox validation results,
          remaining risk, audit trail and the Responsible AI note.
        </p>
      </div>
      {html && json && view ? (
        <div className="ml-auto flex flex-wrap gap-2">
          <a href={view} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted">
            <FileText className="size-4" aria-hidden /> Open report (print to PDF)
          </a>
          <a href={html} className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90">
            <Download className="size-4" aria-hidden /> Download HTML
          </a>
          <a href={json} className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-muted">
            <FileJson className="size-4" aria-hidden /> Download JSON
          </a>
        </div>
      ) : (
        <p className="ml-auto text-xs text-muted-foreground">Reports are not available in sample data mode.</p>
      )}
    </section>
  );
}

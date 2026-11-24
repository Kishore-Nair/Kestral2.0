import type { Finding, FindingKind, FindingsDocument } from "@/types/findings";

/** Who reported a finding. Agreement is shown, never voted on. */
export function sourceAgreement(
  finding: Finding,
): "Both" | "OSV only" | "Grype only" | "Workflow scan" | "Repository files" | "Scan comparison" {
  const names = new Set(finding.sources.map((s) => s.name));
  if (names.has("workflow-scan")) return "Workflow scan";
  if (names.has("supply-chain-scan")) return "Repository files";
  if (names.has("scan-diff")) return "Scan comparison";
  if (names.has("OSV") && names.has("Grype")) return "Both";
  return names.has("OSV") ? "OSV only" : "Grype only";
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4, high: 3, moderate: 2, medium: 2, low: 1,
};

/** Highest severity label any source reported (verbatim labels, normalised only for ordering). */
export function highestReportedSeverity(finding: Finding): string | null {
  let best: string | null = null;
  let bestRank = 0;
  for (const source of finding.sources) {
    const rank = source.severity ? SEVERITY_RANK[source.severity.toLowerCase()] ?? 0 : 0;
    if (rank > bestRank) {
      bestRank = rank;
      best = source.severity;
    }
  }
  return best;
}

export function severityRank(finding: Finding): number {
  const label = highestReportedSeverity(finding);
  return label ? SEVERITY_RANK[label.toLowerCase()] ?? 0 : 0;
}

const RISK_RANK = { high: 3, medium: 2, low: 1 } as const;

/** Human label for a suspicious-finding category ("install_script" -> "Install script"). */
export function categoryLabel(category: string | null | undefined): string {
  if (!category) return "Other";
  const text = category.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

const DIRECTNESS_RANK = { direct: 0, transitive: 1, unknown: 2 } as const;

/**
 * Kestral priority first (when scored), then rule-based risk level, then CVSS base score, then highest reported
 * severity, then direct before transitive, then by package.
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      (b.priority?.score ?? -1) - (a.priority?.score ?? -1) ||
      (b.risk_level ? RISK_RANK[b.risk_level] : 0) - (a.risk_level ? RISK_RANK[a.risk_level] : 0) ||
      (b.cvss?.base_score ?? -1) - (a.cvss?.base_score ?? -1) ||
      severityRank(b) - severityRank(a) ||
      DIRECTNESS_RANK[a.directness ?? "unknown"] - DIRECTNESS_RANK[b.directness ?? "unknown"] ||
      a.subject_label.localeCompare(b.subject_label) ||
      a.finding_id.localeCompare(b.finding_id),
  );
}

export function filterFindings(findings: Finding[], kind: FindingKind, query: string): Finding[] {
  const q = query.trim().toLowerCase();
  return findings.filter(
    (f) =>
      f.kind === kind &&
      (!q ||
        f.subject_label.toLowerCase().includes(q) ||
        f.title.toLowerCase().includes(q) ||
        f.advisory_ids.some((id) => id.toLowerCase().includes(q)) ||
        (f.category ?? "").replace(/_/g, " ").includes(q) ||
        (f.cwes ?? []).some((c) => c.id.toLowerCase().includes(q))),
  );
}

/** Vulnerability findings grouped by the graph node they belong to. */
export function findingsByNode(doc: FindingsDocument | null): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const finding of doc?.findings ?? []) {
    if (finding.kind !== "vulnerability" || !finding.subject_id) continue;
    const list = map.get(finding.subject_id) ?? [];
    list.push(finding);
    map.set(finding.subject_id, list);
  }
  return map;
}

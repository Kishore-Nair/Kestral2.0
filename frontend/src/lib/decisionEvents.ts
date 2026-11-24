/** Tells other panels that a human decision was recorded, so they can refresh. */
export const DECISION_RECORDED = "kestral:decision-recorded";

export interface DecisionRecordedDetail {
  scanId: string;
  source: "remediation" | "ai";
}

export function announceDecision(detail: DecisionRecordedDetail): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent<DecisionRecordedDetail>(DECISION_RECORDED, { detail }));
}

/** Ask the remediation panel to open and scroll into view. */
export const OPEN_REMEDIATION = "kestral:open-remediation";

export function openRemediationPanel(): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(OPEN_REMEDIATION));
}

/** Scroll to the risk findings, where each finding has "Analyze with Kestral AI". */
export function scrollToFindings(): void {
  if (typeof document === "undefined") return;
  document.querySelector('[aria-label="Risk findings"]')?.scrollIntoView({ behavior: "smooth", block: "start" });
}

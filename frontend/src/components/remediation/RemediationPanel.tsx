"use client";

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { scanService } from "@/services/scanService";
import { classifyError } from "@/services/errors";
import type { ScanApi } from "@/services/api";
import type { DecisionFactor, DecisionType, RemediationProposal } from "@/types/remediation";

const FACTORS: Array<[DecisionFactor, string]> = [
  ["SECURITY_RISK", "Security risk"], ["EXPLOITABILITY", "Exploitability"],
  ["DEPENDENCY_PATH", "Dependency path"], ["APPLICATION_CONTEXT", "Application context"],
  ["COMPATIBILITY", "Compatibility"], ["BUSINESS_IMPACT", "Business impact"],
  ["TEST_EVIDENCE", "Test evidence"], ["SOURCE_CONFIDENCE", "Source confidence"],
  ["INCOMPLETE_EVIDENCE", "Incomplete evidence"], ["LICENSE_OR_POLICY", "License or policy"],
  ["OPERATIONAL_RISK", "Operational risk"], ["ROLLBACK_READINESS", "Rollback readiness"],
  ["ALTERNATIVE_AVAILABLE", "Alternative available"], ["OTHER", "Other"],
];

function DecisionRecord({ proposal }: { proposal: RemediationProposal }) {
  const decision = proposal.decision;
  if (!decision) return null;
  return (
    <div className="grid gap-2 rounded-md border bg-muted/40 p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={decision.decision === "APPROVED" ? "secondary" : "destructive"}>{decision.decision}</Badge>
        <span>by {decision.decided_by}</span>
        <span className="text-xs text-muted-foreground">{new Date(decision.decided_at).toLocaleString()}</span>
      </div>
      <p><span className="font-medium">Reason:</span> {decision.reason}</p>
      <p className="text-xs text-muted-foreground">Factors: {decision.factors.map((f) => f.replaceAll("_", " ")).join(" · ")}</p>
      {decision.conditions && <p><span className="font-medium">Conditions:</span> {decision.conditions}</p>}
      {decision.alternative && <p><span className="font-medium">Alternative:</span> {decision.alternative}</p>}
      {decision.external_reference && <p><span className="font-medium">Reference:</span> {decision.external_reference}</p>}
      <p className="font-mono text-xs text-muted-foreground">Bound to commit {decision.repository_commit.slice(0, 12)}</p>
    </div>
  );
}

function DecisionForm({ scanId, proposal, service, onDecided }: {
  scanId: string; proposal: RemediationProposal; service: ScanApi;
  onDecided: (value: RemediationProposal) => void;
}) {
  const [decision, setDecision] = useState<DecisionType>("APPROVED");
  const [reviewer, setReviewer] = useState("");
  const [reason, setReason] = useState("");
  const [factors, setFactors] = useState<DecisionFactor[]>([]);
  const [conditions, setConditions] = useState("");
  const [alternative, setAlternative] = useState("");
  const [reference, setReference] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const toggle = (factor: DecisionFactor) => setFactors((items) =>
    items.includes(factor) ? items.filter((item) => item !== factor) : [...items, factor]);
  const valid = reviewer.trim().length >= 2 && reason.trim().length >= 30 && factors.length > 0;

  const submit = async () => {
    if (!valid) { setError("Provide reviewer identity, at least one factor, and a reason of 30 or more characters."); return; }
    const verb = decision === "APPROVED" ? "approve" : "reject";
    if (!window.confirm(`You are about to ${verb} this exact proposal for commit ${proposal.repository_commit.slice(0, 12)}. This records an audit decision but does not modify the repository. Continue?`)) return;
    setBusy(true); setError(null);
    try {
      onDecided(await service.decideRemediation(scanId, proposal.proposal_id, {
        decision, decided_by: reviewer.trim(), reason: reason.trim(), factors,
        conditions: conditions.trim() || null, alternative: alternative.trim() || null,
        external_reference: reference.trim() || null, expected_proposal_version: proposal.version,
      }));
    } catch (err) { setError(classifyError(err).message); } finally { setBusy(false); }
  };

  return (
    <div className="grid gap-3 rounded-md border p-3">
      <p className="text-xs text-muted-foreground">Reviewer identity is self-declared in this prototype and is not authenticated.</p>
      <div className="flex gap-2">
        <Button size="sm" variant={decision === "APPROVED" ? "default" : "outline"} onClick={() => setDecision("APPROVED")}>Approve</Button>
        <Button size="sm" variant={decision === "REJECTED" ? "destructive" : "outline"} onClick={() => setDecision("REJECTED")}>Reject</Button>
      </div>
      <label className="grid gap-1 text-sm">Reviewer identity<Input value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="name or email" /></label>
      <fieldset className="grid gap-2"><legend className="text-sm font-medium">Decision factors</legend>
        <div className="flex flex-wrap gap-2">{FACTORS.map(([value, label]) => (
          <label key={value} className="flex items-center gap-1 rounded border px-2 py-1 text-xs">
            <input type="checkbox" checked={factors.includes(value)} onChange={() => toggle(value)} />{label}
          </label>
        ))}</div>
      </fieldset>
      <label className="grid gap-1 text-sm">Reasoning (required)
        <textarea className="min-h-24 rounded-lg border bg-transparent p-2 text-sm" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Explain the evidence, trade-offs, and application context behind this decision." />
      </label>
      <label className="grid gap-1 text-sm">Conditions<Input value={conditions} onChange={(e) => setConditions(e.target.value)} placeholder="Optional approval conditions" /></label>
      <label className="grid gap-1 text-sm">Alternative<Input value={alternative} onChange={(e) => setAlternative(e.target.value)} placeholder="Optional alternative remediation" /></label>
      <label className="grid gap-1 text-sm">Ticket or reference<Input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="Optional external reference" /></label>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      <Button className="w-fit" disabled={busy || !valid} variant={decision === "REJECTED" ? "destructive" : "default"} onClick={submit}>
        {busy ? "Recording decision..." : decision === "APPROVED" ? "Approve remediation" : "Reject remediation"}
      </Button>
    </div>
  );
}

export default function RemediationPanel({ scanId, service = scanService }: { scanId: string; service?: ScanApi }) {
  const [proposals, setProposals] = useState<RemediationProposal[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true; setProposals(null); setError(null);
    void service.getRemediations(scanId).then((result) => { if (active) setProposals(result.proposals); })
      .catch((err) => { if (active) setError(classifyError(err).message); });
    return () => { active = false; };
  }, [scanId, service]);

  const update = (value: RemediationProposal) => setProposals((items) => items?.map((item) => item.proposal_id === value.proposal_id ? value : item) ?? [value]);
  return (
    <Card><CardHeader><CardTitle>Remediation decisions</CardTitle></CardHeader><CardContent className="grid gap-4">
      <p className="text-sm text-muted-foreground">Approval authorizes this evidence-bound recommendation to advance. It does not apply code, prove the fix, merge, or deploy anything.</p>
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      {proposals === null && !error && <p className="text-sm text-muted-foreground">Loading proposals...</p>}
      {proposals?.length === 0 && <p className="text-sm text-muted-foreground">No actionable findings produced remediation proposals.</p>}
      {proposals?.map((proposal) => (
        <section key={proposal.proposal_id} className="grid gap-3 rounded-lg border p-4">
          <div className="flex flex-wrap items-center gap-2"><Badge>{proposal.action}</Badge><Badge variant="outline">{proposal.status}</Badge><code className="text-sm">{proposal.subject_label}</code></div>
          <p className="font-medium">{proposal.recommendation}</p><p className="text-sm text-muted-foreground">{proposal.rationale}</p>
          <dl className="grid gap-2 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Expected risk reduction</dt><dd>{proposal.expected_risk_reduction}</dd></div><div><dt className="text-muted-foreground">Compatibility impact</dt><dd>{proposal.compatibility_impact}</dd></div></dl>
          {proposal.proposed_value && <p className="text-sm">Version: <code>{proposal.current_value ?? "unknown"}</code> → <code>{proposal.proposed_value}</code></p>}
          <details className="text-sm"><summary className="cursor-pointer font-medium">Evidence and uncertainty</summary><ul className="mt-2 grid gap-1 text-xs">{proposal.evidence.map((e, i) => <li key={`${e.path}-${i}`}><code>{e.path}</code> · {e.kind} · {e.locator}</li>)}{proposal.uncertainty.map((u) => <li key={u} className="text-muted-foreground">Uncertainty: {u}</li>)}</ul></details>
          {proposal.status === "PENDING" ? <DecisionForm scanId={scanId} proposal={proposal} service={service} onDecided={update} /> : <DecisionRecord proposal={proposal} />}
        </section>
      ))}
    </CardContent></Card>
  );
}

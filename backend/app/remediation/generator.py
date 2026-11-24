"""Generate conservative remediation proposals without inventing evidence."""

import hashlib
import json
from dataclasses import dataclass

from app.schemas.findings import Finding
from app.schemas.remediation import RemediationAction


@dataclass(frozen=True)
class GeneratedProposal:
    proposal_id: str
    finding_id: str
    action: RemediationAction
    subject_label: str
    current_value: str | None
    proposed_value: str | None
    recommendation: str
    rationale: str
    expected_risk_reduction: str
    compatibility_impact: str
    evidence_json: list[dict]
    uncertainty_json: list[str]
    finding_digest: str
    proposal_digest: str


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _current_version(finding: Finding) -> str | None:
    label = finding.subject_label
    return label.rsplit("@", 1)[1] if "@" in label else None


def generate_proposal(finding: Finding, scan_id: str) -> GeneratedProposal:
    finding_data = finding.model_dump(mode="json")
    finding_digest = _digest(finding_data)
    current = _current_version(finding) if finding.kind == "vulnerability" else None
    proposed: str | None = None
    action: RemediationAction
    expected = "unknown"
    compatibility = "unknown"

    if finding.kind == "workflow_pin":
        action = "pin"
        recommendation = "Resolve the intended release to a verified full commit SHA, then pin it."
        rationale = (
            "The workflow uses a mutable reference. Kestral does not invent a commit SHA; "
            "the selected SHA must be independently verified before a patch is prepared."
        )
        expected = "medium"
        compatibility = "low"
    elif finding.fixed_versions and finding.directness != "unknown":
        action = "upgrade"
        if len(finding.fixed_versions) == 1:
            proposed = finding.fixed_versions[0]
            recommendation = (
                f"Evaluate upgrading {finding.subject_label} to fixed version {proposed}."
            )
        else:
            versions = ", ".join(finding.fixed_versions)
            recommendation = (
                f"Evaluate a compatible fixed release for {finding.subject_label}; "
                f"sources report: {versions}."
            )
        rationale = (
            "A vulnerability source reports a fixed version and the dependency graph contains "
            "a proven path. Compatibility and lockfile changes still require validation."
        )
        expected = "high"
        compatibility = "unknown"
    else:
        action = "security_review"
        recommendation = "Request security review before selecting a remediation."
        reason = (
            "no fixed version was reported"
            if not finding.fixed_versions
            else "no proven dependency path is available"
        )
        rationale = f"Kestral cannot safely select an automatic change because {reason}."

    proposal_data = {
        "scan_id": scan_id,
        "finding_id": finding.finding_id,
        "action": action,
        "subject_label": finding.subject_label,
        "current_value": current,
        "proposed_value": proposed,
        "recommendation": recommendation,
        "rationale": rationale,
        "expected_risk_reduction": expected,
        "compatibility_impact": compatibility,
        "evidence": [item.model_dump(mode="json") for item in finding.evidence],
        "uncertainty": finding.uncertainty,
        "finding_digest": finding_digest,
    }
    proposal_digest = _digest(proposal_data)
    return GeneratedProposal(
        proposal_id=f"rem_{proposal_digest[:32]}",
        finding_id=finding.finding_id,
        action=action,
        subject_label=finding.subject_label,
        current_value=current,
        proposed_value=proposed,
        recommendation=recommendation,
        rationale=rationale,
        expected_risk_reduction=expected,
        compatibility_impact=compatibility,
        evidence_json=proposal_data["evidence"],
        uncertainty_json=list(finding.uncertainty),
        finding_digest=finding_digest,
        proposal_digest=proposal_digest,
    )

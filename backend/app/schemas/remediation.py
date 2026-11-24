"""Evidence-bound remediation proposals and human decision contracts."""

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.schemas.base import StrictModel
from app.schemas.inventory import Evidence

RemediationAction = Literal[
    "upgrade", "replace", "remove", "pin", "mitigate", "block", "security_review"
]
ProposalStatus = Literal["PENDING", "APPROVED", "REJECTED", "SUPERSEDED"]
DecisionType = Literal["APPROVED", "REJECTED"]
DecisionFactor = Literal[
    "SECURITY_RISK",
    "EXPLOITABILITY",
    "DEPENDENCY_PATH",
    "APPLICATION_CONTEXT",
    "COMPATIBILITY",
    "BUSINESS_IMPACT",
    "TEST_EVIDENCE",
    "SOURCE_CONFIDENCE",
    "INCOMPLETE_EVIDENCE",
    "LICENSE_OR_POLICY",
    "OPERATIONAL_RISK",
    "ROLLBACK_READINESS",
    "ALTERNATIVE_AVAILABLE",
    "OTHER",
]

TRIVIAL_REASONS = {
    "approve",
    "approved",
    "looks good",
    "ok",
    "reject",
    "rejected",
    "no",
    "yes",
}


class RemediationDecisionCreate(StrictModel):
    decision: DecisionType
    decided_by: str = Field(min_length=2, max_length=200)
    reason: str = Field(min_length=30, max_length=4_000)
    factors: list[DecisionFactor] = Field(min_length=1, max_length=14)
    conditions: str | None = Field(default=None, max_length=2_000)
    alternative: str | None = Field(default=None, max_length=2_000)
    external_reference: str | None = Field(default=None, max_length=500)
    expected_proposal_version: int = Field(ge=1)

    @field_validator("decided_by", "reason", "conditions", "alternative", "external_reference")
    @classmethod
    def strip_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("Text fields may not contain only whitespace")
        return stripped

    @model_validator(mode="after")
    def meaningful_reason(self) -> "RemediationDecisionCreate":
        if self.reason.casefold().rstrip(".! ") in TRIVIAL_REASONS:
            raise ValueError("Explain the evidence and trade-offs behind the decision")
        if len(set(self.factors)) != len(self.factors):
            raise ValueError("Decision factors must be unique")
        return self


class RemediationDecision(StrictModel):
    decision_id: str
    proposal_id: str
    decision: DecisionType
    decided_by: str
    reason: str
    factors: list[DecisionFactor]
    conditions: str | None
    alternative: str | None
    external_reference: str | None
    repository_commit: str
    finding_digest: str
    proposal_digest: str
    decided_at: datetime


class RemediationProposal(StrictModel):
    proposal_id: str
    scan_id: str
    finding_id: str
    action: RemediationAction
    subject_label: str
    current_value: str | None
    proposed_value: str | None
    recommendation: str
    rationale: str
    expected_risk_reduction: Literal["high", "medium", "low", "unknown"]
    compatibility_impact: Literal["high", "medium", "low", "unknown"]
    evidence: list[Evidence] = Field(min_length=1)
    uncertainty: list[str]
    repository_commit: str
    finding_digest: str
    proposal_digest: str
    status: ProposalStatus
    version: int = Field(ge=1)
    created_at: datetime
    decision: RemediationDecision | None = None


class RemediationList(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    proposals: list[RemediationProposal]

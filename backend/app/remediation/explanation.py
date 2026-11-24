"""Deterministic audit explanations generated from a reviewer's structured assessment.

Reviewers choose from fixed options instead of writing a risk narrative. The
explanation stored on the decision is rendered here, from those choices and the
exact proposal reviewed, so records are consistent and never contain context
the reviewer did not actually provide. ``UNKNOWN`` is reported as not assessed.
"""

from app.database.models import RemediationProposalRow
from app.schemas.remediation import DecisionType, ReviewAssessment

DIMENSION_LABELS: dict[str, str] = {
    "production_usage": "production usage",
    "compatibility": "compatibility",
    "test_confidence": "test confidence",
    "ownership": "ownership",
    "alternatives": "alternatives",
    "timing": "timing",
}

PHRASES: dict[str, dict[str, str]] = {
    "production_usage": {
        "IN_PRODUCTION": "the affected component is used in production",
        "NOT_IN_PRODUCTION": "the affected component is not used in production",
        "DEV_OR_TEST_ONLY": "the affected component is used only in development or test",
    },
    "compatibility": {
        "COMPATIBLE": "the change is expected to be compatible",
        "MINOR_CHANGES": "the change is expected to need minor adjustments",
        "BREAKING": "the change is expected to break existing behaviour",
    },
    "test_confidence": {
        "HIGH": "tests give high confidence in the affected code",
        "PARTIAL": "tests cover the affected code only partially",
        "NONE": "no tests cover the affected code",
    },
    "ownership": {
        "OWNER_CONFIRMED": "the owning team has confirmed the decision",
        "OWNER_IDENTIFIED": "an owning team is identified but has not confirmed",
        "NO_OWNER": "no owning team exists for the affected code",
    },
    "alternatives": {
        "ALTERNATIVE_PREFERRED": "a different remediation is preferred",
        "ALTERNATIVE_AVAILABLE": "an alternative remediation exists",
        "NO_ALTERNATIVE": "no viable alternative remediation exists",
    },
    "timing": {
        "IMMEDIATE": "action is needed immediately",
        "NEXT_RELEASE": "action fits the next planned release",
        "BACKLOG": "action can be scheduled in the backlog",
    },
}

# Selections that an approver accepted despite them weakening the case for approval.
APPROVAL_RISKS: dict[tuple[str, str], str] = {
    ("compatibility", "BREAKING"): "breaking compatibility",
    ("test_confidence", "NONE"): "no test coverage",
    ("ownership", "NO_OWNER"): "no owning team",
    ("alternatives", "ALTERNATIVE_PREFERRED"): "a preferred alternative",
}


def _subject(row: RemediationProposalRow) -> str:
    text = f"{row.action.replace('_', ' ')} of {row.subject_label}"
    if row.proposed_value:
        text += f" ({row.current_value or 'unknown'} → {row.proposed_value})"
    return text


def _join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def generate_explanation(
    decision: DecisionType,
    assessment: ReviewAssessment,
    row: RemediationProposalRow,
    note: str | None = None,
) -> str:
    verb = "Approved" if decision == "APPROVED" else "Rejected"
    sentences = [
        f"{verb} the proposed {_subject(row)} at commit {row.repository_commit[:12]}."
    ]
    values = assessment.model_dump()
    known = [PHRASES[key][value] for key, value in values.items() if value != "UNKNOWN"]
    unknown = [DIMENSION_LABELS[key] for key, value in values.items() if value == "UNKNOWN"]

    if known:
        sentences.append("Reviewer assessment: " + "; ".join(known) + ".")
    if not known:
        sentences.append(
            "The reviewer could not assess any dimension; the decision rests on the "
            "proposal evidence alone."
        )
    elif unknown:
        sentences.append(f"Not assessed (reported as unknown): {_join(unknown)}.")

    if decision == "APPROVED":
        risks = [label for (key, value), label in APPROVAL_RISKS.items() if values[key] == value]
        if risks:
            sentences.append(f"Approved despite {_join(risks)}.")
    else:
        sentences.append("Rejection does not suppress the underlying finding.")

    if note:
        sentences.append(f"Reviewer note: {note}")
    return " ".join(sentences)

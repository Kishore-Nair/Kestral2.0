from app.database.models import RemediationProposalRow
from app.remediation.explanation import generate_explanation
from app.schemas.remediation import ReviewAssessment


def proposal() -> RemediationProposalRow:
    return RemediationProposalRow(
        action="upgrade",
        subject_label="example@1.0.0",
        current_value="1.0.0",
        proposed_value="1.0.1",
        repository_commit="a" * 40,
    )


def assessment(**overrides: str) -> ReviewAssessment:
    values = dict.fromkeys(ReviewAssessment.model_fields, "UNKNOWN")
    values.update(overrides)
    return ReviewAssessment(**values)


def test_all_unknown_is_reported_honestly_without_invented_context() -> None:
    text = generate_explanation("APPROVED", assessment(), proposal())
    assert text == (
        "Approved the proposed upgrade of example@1.0.0 (1.0.0 → 1.0.1) at commit aaaaaaaaaaaa. "
        "The reviewer could not assess any dimension; the decision rests on the proposal "
        "evidence alone."
    )


def test_known_and_unknown_dimensions_are_separated() -> None:
    text = generate_explanation(
        "APPROVED",
        assessment(production_usage="IN_PRODUCTION", timing="IMMEDIATE"),
        proposal(),
    )
    assert (
        "Reviewer assessment: the affected component is used in production; "
        "action is needed immediately." in text
    )
    assert (
        "Not assessed (reported as unknown): compatibility, test confidence, ownership "
        "and alternatives." in text
    )


def test_approval_flags_accepted_risks() -> None:
    text = generate_explanation(
        "APPROVED",
        assessment(compatibility="BREAKING", test_confidence="NONE"),
        proposal(),
    )
    assert "Approved despite breaking compatibility and no test coverage." in text


def test_rejection_keeps_finding_open_and_appends_note() -> None:
    text = generate_explanation(
        "REJECTED", assessment(alternatives="ALTERNATIVE_PREFERRED"), proposal(), "Use v2 API."
    )
    assert "Approved despite" not in text
    assert "Rejection does not suppress the underlying finding." in text
    assert text.endswith("Reviewer note: Use v2 API.")


def test_explanation_is_deterministic() -> None:
    selection = assessment(ownership="OWNER_CONFIRMED")
    assert generate_explanation("APPROVED", selection, proposal()) == generate_explanation(
        "APPROVED", selection, proposal()
    )

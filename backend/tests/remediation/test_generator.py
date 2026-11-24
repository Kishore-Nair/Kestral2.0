from app.remediation.generator import generate_proposal
from app.schemas.findings import Finding, FindingSource
from app.schemas.inventory import Evidence


def finding(*, fixed: list[str], directness: str = "direct") -> Finding:
    return Finding(
        finding_id="finding_1",
        kind="vulnerability",
        title="CVE-2026-1000",
        subject_id="cmp_1",
        subject_label="example@1.0.0",
        advisory_ids=["CVE-2026-1000"],
        sources=[FindingSource(name="OSV", record_id="CVE-2026-1000")],
        fixed_versions=fixed,
        evidence=[Evidence(path="package-lock.json", kind="lockfile", locator="example")],
        directness=directness,
    )


def test_generates_deterministic_upgrade_from_verified_fix() -> None:
    first = generate_proposal(finding(fixed=["1.0.1"]), "scan_1")
    second = generate_proposal(finding(fixed=["1.0.1"]), "scan_1")
    assert first == second
    assert first.action == "upgrade"
    assert first.current_value == "1.0.0"
    assert first.proposed_value == "1.0.1"


def test_uses_review_when_no_fix_or_path_is_proven() -> None:
    assert generate_proposal(finding(fixed=[]), "scan_1").action == "security_review"
    assert (
        generate_proposal(finding(fixed=["1.0.1"], directness="unknown"), "scan_1").action
        == "security_review"
    )


def test_does_not_choose_between_multiple_fixed_release_lines() -> None:
    proposal = generate_proposal(finding(fixed=["1.0.1", "2.1.0"]), "scan_1")
    assert proposal.action == "upgrade"
    assert proposal.proposed_value is None
    assert "1.0.1, 2.1.0" in proposal.recommendation

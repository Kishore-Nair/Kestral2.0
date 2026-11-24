"""Sandbox validation of an approved fix (Bosch Day 2 steps 4-5).

A validation applies one approved change to an isolated copy of the exact scanned
commit, optionally runs the project's tests inside a container, rescans the patched
copy with the full Kestral pipeline and compares before and after. It never touches
the original scan artifacts or the upstream repository.
"""

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.base import StrictModel

SourceType = Literal["remediation", "ai"]
StepStatus = Literal["passed", "failed", "warning", "not_run", "skipped"]
Verdict = Literal[
    "FIXED",
    "FIXED_WITH_NEW_RISK",
    "FIXED_TESTS_FAILED",
    "NOT_FIXED",
    "FAILED",
    "UNSUPPORTED",
]
TestsStatus = Literal[
    "passed",
    "regression",
    "failed_before_and_after",
    "no_tests",
    "not_run",
    "error",
]


class ValidationChange(StrictModel):
    """The approved change being validated, copied from the approval record."""

    source_type: SourceType
    source_id: str
    finding_id: str
    component_id: str
    package: str
    ecosystem: str
    project_path: str
    from_version: str | None
    to_version: str
    approved_by: str | None
    approved_at: datetime | None


class ValidationCandidate(StrictModel):
    source_type: SourceType
    source_id: str
    finding_id: str
    title: str
    package: str
    ecosystem: str | None
    from_version: str | None
    to_version: str | None
    approved_by: str | None
    approved_at: datetime | None
    supported: bool
    reason: str | None


class ValidationStep(StrictModel):
    id: str
    label: str
    status: StepStatus
    detail: str
    duration_ms: int = 0


class FileDiff(StrictModel):
    path: str
    lines_added: int = Field(ge=0)
    lines_removed: int = Field(ge=0)
    diff: str
    truncated: bool


class TestRun(StrictModel):
    phase: Literal["baseline", "patched"]
    status: Literal["passed", "failed", "no_tests", "error", "not_run"]
    runtime: str | None
    image: str | None
    command: str | None
    exit_code: int | None
    duration_s: float | None
    output_tail: str


class FindingRef(StrictModel):
    finding_id: str
    kind: str
    title: str
    package: str
    advisory_ids: list[str]
    level: str | None


class Comparison(StrictModel):
    target_resolved: bool | None
    target_remaining: list[FindingRef]
    resolved: list[FindingRef]
    introduced: list[FindingRef]
    introduced_suspicious: list[FindingRef]
    before_counts: dict[str, int]
    after_counts: dict[str, int]
    package_changes: dict[str, int]
    changed_packages: list[str]


class ValidationResult(StrictModel):
    verdict: Verdict
    verdict_reason: str
    tests_status: TestsStatus
    tests_detail: str
    sandbox_commit: str | None
    steps: list[ValidationStep]
    diffs: list[FileDiff]
    tests: list[TestRun]
    comparison: Comparison | None
    rescan_artifacts: str | None
    residual_risks: list[str]


class PullRequestInfo(StrictModel):
    """A pull request Kestral opened for a validated fix. Merging is always a human action."""

    url: str
    number: int
    branch: str
    base: str
    created_at: datetime


class ValidationRun(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    validation_id: str
    scan_id: str
    status: Literal["queued", "running", "completed", "failed"]
    change: ValidationChange
    error: str | None
    created_at: datetime
    finished_at: datetime | None
    result: ValidationResult | None
    pull_request: PullRequestInfo | None = None
    patch_available: bool = False
    progress: list[ValidationStep] = Field(default_factory=list)


class SandboxInfo(StrictModel):
    container_runtime: str | None
    tests_enabled: bool
    npm_available: bool
    notes: list[str]
    github_configured: bool = False


class ValidationStartRequest(StrictModel):
    source_type: SourceType
    source_id: str = Field(min_length=3, max_length=80)
    run_tests: bool = True


class ValidationOverview(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    sandbox: SandboxInfo
    candidates: list[ValidationCandidate]
    runs: list[ValidationRun]

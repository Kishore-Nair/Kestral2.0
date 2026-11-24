"""Risk findings contract (Phase 1B): vulnerabilities and non-CVE anomalies with evidence."""

from typing import Literal

from pydantic import Field, model_validator

from app.schemas.base import StrictModel
from app.schemas.inventory import Evidence

FindingKind = Literal["vulnerability", "workflow_pin", "suspicious"]
SourceName = Literal["OSV", "Grype", "NVD", "workflow-scan", "supply-chain-scan", "scan-diff"]
RiskLevel = Literal["high", "medium", "low"]
Directness = Literal["direct", "transitive", "unknown"]


class FindingSource(StrictModel):
    """One source that reported this finding, with its own record and severity, verbatim."""

    name: SourceName
    record_id: str
    url: str | None = None
    severity: str | None = None
    cvss_vectors: list[str] = Field(default_factory=list)
    match_type: str | None = None


class CveRef(StrictModel):
    """A CVE linked to the finding and what NVD says about it."""

    id: str
    url: str
    looked_up: bool
    in_nvd: bool
    nvd_status: str | None = None
    published: str | None = None
    last_modified: str | None = None
    description: str | None = None


class CweRef(StrictModel):
    id: str
    url: str | None
    sources: list[str] = Field(min_length=1)


class CvssScore(StrictModel):
    """Base score computed by Kestral from the vector, next to the score the source published."""

    version: str
    vector: str
    base_score: float | None = Field(default=None, ge=0, le=10)
    severity: str | None
    source: str
    source_type: str | None = None
    cve_id: str | None = None
    computed: bool
    published_score: float | None = Field(default=None, ge=0, le=10)
    matches_published: bool | None = None


class EpssScore(StrictModel):
    cve_id: str
    probability: float = Field(ge=0, le=1)
    percentile: float = Field(ge=0, le=1)
    date: str | None = None
    source: str


class PriorityFactor(StrictModel):
    name: str
    value: str
    weight: float = Field(ge=0, le=1)
    points: float = Field(ge=0, le=100)


class Priority(StrictModel):
    """Kestral's rule-based priority; every factor and its points are listed."""

    score: int = Field(ge=0, le=100)
    band: Literal["critical", "high", "medium", "low"]
    factors: list[PriorityFactor]
    method: str


class Finding(StrictModel):
    finding_id: str
    kind: FindingKind
    title: str
    subject_id: str | None
    subject_label: str
    advisory_ids: list[str]
    sources: list[FindingSource] = Field(min_length=1)
    fixed_versions: list[str]
    evidence: list[Evidence] = Field(min_length=1)
    scope: str | None = None
    directness: Directness | None = None
    dependency_paths: list[list[str]] = Field(default_factory=list)
    affected_projects: list[str] = Field(default_factory=list)
    dependent_packages: int | None = Field(default=None, ge=0)
    uncertainty: list[str] = Field(default_factory=list)
    cves: list[CveRef] = Field(default_factory=list)
    cwes: list[CweRef] = Field(default_factory=list)
    cvss: CvssScore | None = None
    epss: EpssScore | None = None
    priority: Priority | None = None
    # Non-CVE findings: what kind of anomaly, and a rule-based initial risk level with its reason.
    category: str | None = None
    risk_level: RiskLevel | None = None
    risk_reason: str | None = None

    @model_validator(mode="after")
    def vulnerability_has_subject(self) -> "Finding":
        if self.kind == "vulnerability" and self.subject_id is None:
            raise ValueError("A vulnerability finding must reference a package component")
        return self


class SourceRun(StrictModel):
    """How one source ran: ok, failed or skipped, plus its version and data freshness."""

    name: SourceName
    status: Literal["ok", "failed", "skipped"]
    tool_version: str | None = None
    database_built: str | None = None
    retrieved_at: str | None = None
    queried: int = Field(default=0, ge=0)
    raw_output: str | None = None
    message: str | None = None


class FindingStats(StrictModel):
    vulnerabilities: int = Field(ge=0)
    vulnerable_packages: int = Field(ge=0)
    confirmed_by_both: int = Field(ge=0)
    workflow_pins: int = Field(ge=0)
    components_total: int = Field(ge=0)
    components_assessed: int = Field(ge=0)
    components_not_assessed: int = Field(ge=0)
    cves_linked: int = Field(default=0, ge=0)
    nvd_scored: int = Field(default=0, ge=0)
    suspicious: int = Field(default=0, ge=0)


class PackageChange(StrictModel):
    ecosystem: str
    name: str
    project_path: str
    from_versions: list[str]
    to_versions: list[str]
    component_id: str | None = None


class FileChange(StrictModel):
    path: str
    change: Literal["added", "removed", "modified"]


class ChangeSummary(StrictModel):
    """What changed since the previous completed scan of the same repository."""

    baseline_scan_id: str
    baseline_commit: str | None
    baseline_ref: str | None
    baseline_finished_at: str | None
    current_commit: str | None
    same_commit: bool
    added: list[PackageChange]
    removed: list[PackageChange]
    upgraded: list[PackageChange]
    downgraded: list[PackageChange]
    other_changes: list[PackageChange]
    totals: dict[str, int]
    files_compared: bool
    files_changed: list[FileChange]
    truncated: bool
    # Lockfiles whose packages were extracted in only one of the two scans; their packages
    # are left out of added/removed (counted in totals["excluded"]) with a caveat each.
    extraction_gaps: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)


class FindingsDocument(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    findings: list[Finding]
    sources: list[SourceRun]
    stats: FindingStats
    partial: bool
    warnings: list[str]
    changes: ChangeSummary | None = None

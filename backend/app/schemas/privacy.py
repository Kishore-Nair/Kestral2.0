"""Privacy impact contract: LINDDUN threat classes per finding and an ENISA severity score."""

from typing import Literal

from pydantic import Field

from app.schemas.base import StrictModel

DataContext = Literal["simple", "behavioural", "financial", "sensitive"]
PrivacyBand = Literal["low", "medium", "high", "very_high"]
MappingStatus = Literal[
    "mapped",
    "no_cwe",
    "cwe_excluded",
    "cwe_has_no_category",
    "category_has_no_linddun",
    "cwe_not_in_dataset",
]


class LinddunMapping(StrictModel):
    """How one CWE maps to LINDDUN, restated from the CVE-LINDDUN dataset row for that CWE."""

    cwe_id: str
    status: MappingStatus
    linddun: list[str]
    inherited: list[str] = Field(default_factory=list)
    override: bool = False
    rationale: str | None = None
    mitre_categories: list[str] = Field(default_factory=list)
    nvd_cves: int = Field(default=0, ge=0)
    source: str | None = None


class EnisaFactor(StrictModel):
    """One term of SE = DPC x EI + CB, with the value used and why."""

    name: str
    value: float
    basis: str


class PrivacyImpact(StrictModel):
    finding_id: str
    title: str
    subject_label: str
    advisory_ids: list[str]
    status: MappingStatus
    linddun: list[str]
    mappings: list[LinddunMapping]
    score: float | None = Field(default=None, ge=0, le=6)
    band: PrivacyBand | None = None
    dpc: float
    ei: float | None = None
    cb: float | None = None
    factors: list[EnisaFactor] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    security_priority: int | None = None


class DataContextOption(StrictModel):
    value: DataContext
    label: str
    dpc: float
    examples: str


class PrivacyDataset(StrictModel):
    dataset_file: str
    dataset_sha256: str
    dataset_rows: int
    dataset_labelled_rows: int
    built_at: str
    cwes: int
    cwes_mapped: int
    cwes_from_chain: int
    label_rule: str


class PrivacySummary(StrictModel):
    assessed: int = Field(ge=0)
    mapped: int = Field(ge=0)
    unmapped: int = Field(ge=0)
    by_band: dict[str, int]
    by_linddun: dict[str, int]
    unmapped_reasons: dict[str, int]
    max_score: float | None = None
    max_band: PrivacyBand | None = None


class PrivacyAssessment(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    data_context: DataContext
    dpc: float
    data_contexts: list[DataContextOption]
    method: str
    dataset: PrivacyDataset
    summary: PrivacySummary
    impacts: list[PrivacyImpact]
    caveats: list[str]

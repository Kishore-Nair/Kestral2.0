"""Scan creation and lifecycle API contracts."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from app.schemas.base import StrictModel


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    CLONING = "CLONING"
    DISCOVERING = "DISCOVERING"
    GENERATING_SBOM = "GENERATING_SBOM"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    ANALYZING_RISK = "ANALYZING_RISK"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanCreate(StrictModel):
    repository_url: str = Field(min_length=1, max_length=400)
    ref: str | None = Field(default=None, max_length=120)


class ScanCreated(StrictModel):
    scan_id: str
    status: Literal["QUEUED"]
    repository_name: str


class Repository(StrictModel):
    url: str
    owner: str
    name: str
    requested_ref: str | None
    resolved_ref: str | None
    commit_sha: str | None


class ScanState(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    status: ScanStatus
    current_stage: ScanStatus | None
    repository: Repository
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_stage(self) -> "ScanState":
        if self.current_stage in {ScanStatus.QUEUED, ScanStatus.COMPLETED, ScanStatus.FAILED}:
            raise ValueError("current_stage must be null or an executable processing stage")
        return self


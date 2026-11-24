"""Normalized dependency contract produced by M3 and consumed by M4."""

from typing import Literal

from pydantic import Field, model_validator

from app.schemas.base import StrictModel
from app.schemas.inventory import Evidence

DependencyScope = Literal["runtime", "dev", "optional", "unknown"]
ResolutionStatus = Literal["resolved", "unresolved", "ambiguous"]


class DependencyRoot(StrictModel):
    root_id: str
    name: str
    path: str
    manifest_path: str
    ecosystem: str


class License(StrictModel):
    id: str | None = None
    name: str | None = None
    url: str | None = None

    @model_validator(mode="after")
    def require_identity(self) -> "License":
        if not self.id and not self.name:
            raise ValueError("A license requires an id or name")
        return self


class ComponentHash(StrictModel):
    alg: str
    content: str


class DependencyComponent(StrictModel):
    component_id: str
    name: str
    version: str | None
    ecosystem: str
    purl: str | None
    install_path: str | None
    project_path: str
    scope: DependencyScope
    licenses: list[License]
    hashes: list[ComponentHash]
    evidence: list[Evidence] = Field(min_length=1)
    resolved: bool


class UnresolvedTarget(StrictModel):
    name: str
    specifier: str
    ecosystem: str


class DependencyRelationship(StrictModel):
    relationship_id: str
    from_id: str
    to_id: str | None
    unresolved_target: UnresolvedTarget | None
    resolution_status: ResolutionStatus
    type: Literal["DEPENDS_ON"]
    evidence: list[Evidence] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_resolution(self) -> "DependencyRelationship":
        if self.resolution_status == "resolved":
            if self.to_id is None or self.unresolved_target is not None:
                raise ValueError("Resolved relationships require to_id and no unresolved_target")
        elif self.to_id is not None or self.unresolved_target is None:
            raise ValueError("Unresolved relationships require unresolved_target and a null to_id")
        return self


class DependencyDocument(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    roots: list[DependencyRoot]
    components: list[DependencyComponent]
    relationships: list[DependencyRelationship]
    partial: bool
    warnings: list[str]


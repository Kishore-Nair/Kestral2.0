"""Repository discovery contract owned by M1 and produced by M2."""

from typing import Literal

from pydantic import Field

from app.schemas.base import StrictModel


class Evidence(StrictModel):
    path: str
    kind: str
    locator: str


class FileEntry(StrictModel):
    path: str
    kind: str
    ecosystem: str


class LanguageCount(StrictModel):
    name: str
    file_count: int = Field(ge=0)


class Inventory(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    languages: list[LanguageCount]
    manifests: list[FileEntry]
    lockfiles: list[FileEntry]
    dockerfiles: list[str]
    ci_files: list[str]
    iac_files: list[str]
    existing_sboms: list[str]
    source_directories: list[str]
    file_count: int = Field(ge=0)
    partial: bool
    warnings: list[str]


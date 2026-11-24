"""Internal record types shared by the npm/Python parsers and normalization.

Parsers produce these mutable records; ``normalization.finalize`` converts
them into the canonical ``DependencyDocument``. Keeping them separate from the
Pydantic contract lets reconciliation enrich components without depending on
whether M1's models are frozen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .identities import relationship_id

MAX_MANIFEST_BYTES = 2 * 1024 * 1024  # package.json, requirements, pyproject
MAX_LOCKFILE_BYTES = 25 * 1024 * 1024  # package-lock, poetry.lock, uv.lock

SCOPES = ("runtime", "dev", "optional", "unknown")

License = tuple[str | None, str | None]  # (spdx_id, name); one of them is set

_SPDX_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")


def license_from_text(value: str) -> License:
    """Classify a free-text license field: a bare SPDX-like token is an id."""
    value = value.strip()
    return (value, None) if _SPDX_ID_RE.match(value) else (None, value)


class UnsafePathError(ValueError):
    """A repo-relative path is absolute, escapes the checkout or is not a file."""


@dataclass(frozen=True, order=True)
class Evidence:
    path: str
    kind: str  # "manifest" | "lockfile" | "syft-sbom"
    locator: str

    def as_dict(self) -> dict:
        return {"path": self.path, "kind": self.kind, "locator": self.locator}


@dataclass
class RootRecord:
    root_id: str
    name: str
    path: str
    manifest_path: str
    ecosystem: str


@dataclass
class ComponentRecord:
    component_id: str
    name: str
    normalized_name: str
    version: str | None
    ecosystem: str
    purl: str | None
    install_path: str | None
    project_path: str
    scope: str
    evidence: list[Evidence]
    resolved: bool
    licenses: list[License] = field(default_factory=list)  # (spdx_id, name)
    hashes: list[tuple[str, str]] = field(default_factory=list)  # (alg, content)
    # Internal: the lockfile/manifest that evidences this instance (not exported).
    context_path: str | None = None

    def add_evidence(self, item: Evidence) -> None:
        if item not in self.evidence:
            self.evidence.append(item)

    def add_licenses(self, values: tuple[License, ...] | list[License]) -> None:
        # "MIT" as an SPDX id (Syft) and "MIT" as free text (lockfile) are one license.
        known = {(spdx_id or name) for spdx_id, name in self.licenses}
        for spdx_id, name in values:
            key = spdx_id or name
            if key and key not in known:
                self.licenses.append((spdx_id, name))
                known.add(key)

    def add_hashes(self, values: tuple[tuple[str, str], ...] | list[tuple[str, str]]) -> None:
        for value in values:
            if value not in self.hashes:
                self.hashes.append(value)


@dataclass
class RelationshipRecord:
    from_id: str
    to_id: str | None
    unresolved_target: dict | None
    resolution_status: str  # "resolved" | "unresolved" | "ambiguous"
    evidence: list[Evidence]

    @property
    def relationship_id(self) -> str:
        return relationship_id(
            self.from_id,
            self.to_id,
            self.unresolved_target,
            self.resolution_status,
            ((e.path, e.kind, e.locator) for e in self.evidence),
        )


@dataclass
class ExtractionResult:
    roots: list[RootRecord] = field(default_factory=list)
    components: list[ComponentRecord] = field(default_factory=list)
    relationships: list[RelationshipRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    partial: bool = False

    def warn(self, message: str, *, partial: bool = True) -> None:
        if message not in self.warnings:
            self.warnings.append(message)
        if partial:
            self.partial = True

    def extend(self, other: ExtractionResult) -> None:
        self.roots.extend(other.roots)
        self.components.extend(other.components)
        self.relationships.extend(other.relationships)
        for message in other.warnings:
            if message not in self.warnings:
                self.warnings.append(message)
        self.partial = self.partial or other.partial


def resolved_edge(from_id: str, to_id: str, evidence: list[Evidence]) -> RelationshipRecord:
    return RelationshipRecord(from_id, to_id, None, "resolved", list(evidence))


def unresolved_edge(
    from_id: str,
    name: str,
    specifier: str,
    ecosystem: str,
    evidence: list[Evidence],
    status: str = "unresolved",
) -> RelationshipRecord:
    if status not in ("unresolved", "ambiguous"):
        raise ValueError(f"invalid unresolved status: {status}")
    target = {"name": name, "specifier": specifier, "ecosystem": ecosystem}
    return RelationshipRecord(from_id, None, target, status, list(evidence))


# --------------------------------------------------------------------------
# Safe repository file access
# --------------------------------------------------------------------------


def normalize_rel_path(rel_path: str) -> str:
    """Validate a repo-relative POSIX path from the inventory and return it."""
    if not isinstance(rel_path, str) or not rel_path or "\\" in rel_path or "\x00" in rel_path:
        raise UnsafePathError("Path must be a non-empty POSIX repo-relative string")
    pure = PurePosixPath(rel_path)
    if pure.is_absolute() or ".." in pure.parts or (pure.parts and ":" in pure.parts[0]):
        raise UnsafePathError("Path must be relative and stay inside the repository")
    return pure.as_posix()


def safe_repo_file(repo_dir: Path, rel_path: str) -> Path:
    """Resolve ``rel_path`` inside ``repo_dir``; reject escapes (incl. symlinks)."""
    rel_path = normalize_rel_path(rel_path)
    root = Path(repo_dir).resolve()
    candidate = (root / rel_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise UnsafePathError("Path resolves outside the repository") from exc
    if not candidate.is_file():
        raise UnsafePathError("Path is not a regular file")
    return candidate


def read_text_bounded(path: Path, max_bytes: int) -> str:
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"file is larger than the {max_bytes} byte limit")
    return path.read_text(encoding="utf-8-sig")


def project_path_of(rel_path: str) -> str:
    parent = PurePosixPath(rel_path).parent.as_posix()
    return "" if parent == "." else parent


def join_rel(project_path: str, name: str) -> str:
    return f"{project_path}/{name}" if project_path else name


# --------------------------------------------------------------------------
# Python lockfile shape shared by poetry_lock / uv_lock
# --------------------------------------------------------------------------


@dataclass
class LockedDependency:
    name: str  # as written in the lock
    normalized: str
    version: str | None  # only when the lock itself pins the reference (uv)
    specifier: str  # display text for unresolved targets
    locator: str


@dataclass
class LockedPackage:
    name: str
    normalized: str
    version: str | None
    locator: str  # evidence locator of the package record
    scope: str
    local: bool = False  # project itself / workspace / path source
    hashes: list[tuple[str, str]] = field(default_factory=list)
    dependencies: list[LockedDependency] = field(default_factory=list)


@dataclass
class ParsedLock:
    path: str
    packages: list[LockedPackage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    supported: bool = True

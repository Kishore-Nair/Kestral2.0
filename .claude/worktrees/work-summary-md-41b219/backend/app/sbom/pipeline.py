"""Member 3 integration entry point: ``generate_dependency_document``.

No GitHub fetch. No pip/npm/uv/Poetry install, build or script execution.
The only file written is ``<scan_dir>/sbom.cdx.json`` (raw, validated Syft
CycloneDX). Syft failures propagate as typed ``SyftError`` subclasses so the
orchestrator (Member 1) can mark the scan FAILED; nothing is fabricated.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from app.schemas.dependency import DependencyDocument
from app.schemas.inventory import Inventory

from .cyclonedx_parser import parse_cyclonedx
from .normalization import finalize, reconcile_with_sbom
from .npm_lock import LOCKFILE_NAMES, extract_npm_project, find_lockfile
from .python_project import extract_python_manifest, is_requirements_file
from .records import ExtractionResult, UnsafePathError, normalize_rel_path
from .syft_runner import DEFAULT_TIMEOUT_SECONDS, run_syft

SCHEMA_VERSION = "1.0"


def generate_dependency_document(
    repo_dir: Path,
    inventory: Inventory,
    scan_id: str,
    scan_dir: Path,
    *,
    syft_timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> DependencyDocument:
    """Write scan_dir/sbom.cdx.json; return normalized document v1.0.

    scan_dir is provided by Member 1 and must be outside repo_dir.
    Raises ``ValueError`` for invalid directories and ``SyftError`` for tool failures.
    """
    repo_dir = Path(repo_dir).resolve()
    sbom_data = run_syft(repo_dir, Path(scan_dir), timeout=syft_timeout)
    return build_document(repo_dir, inventory, scan_id, sbom_data)


def build_document(
    repo_dir: Path, inventory: Inventory, scan_id: str, sbom_data: dict | None
) -> DependencyDocument:
    """Pure part of the pipeline (no subprocess); ``sbom_data`` is raw CycloneDX."""
    result = extract_from_inventory(Path(repo_dir).resolve(), inventory)
    if sbom_data is not None:
        sbom = parse_cyclonedx(sbom_data)
        for message in sbom.warnings:
            result.warn(f"sbom.cdx.json: {message}", partial=False)
        reconcile_with_sbom(result, sbom)
    return finalize(result, scan_id)


def extract_from_inventory(repo_dir: Path, inventory: Inventory) -> ExtractionResult:
    result = ExtractionResult()
    if inventory.partial:
        result.warn("Repository inventory is partial; dependency extraction may be incomplete")

    lockfiles: list[str] = []
    for entry in sorted(inventory.lockfiles, key=lambda e: e.path):
        try:
            lockfiles.append(normalize_rel_path(entry.path))
        except UnsafePathError:
            result.warn("Inventory lists an unsafe lockfile path; ignored")
    used_locks: set[str] = set()

    for entry in sorted(inventory.manifests, key=lambda e: e.path):
        try:
            path = normalize_rel_path(entry.path)
        except UnsafePathError:
            result.warn("Inventory lists an unsafe manifest path; ignored")
            continue
        name = PurePosixPath(path).name
        if name == "package.json":
            lock = find_lockfile(path, lockfiles)
            if lock:
                used_locks.add(lock)
            result.extend(extract_npm_project(repo_dir, path, lock))
        elif name == "pyproject.toml" or is_requirements_file(path, entry.kind):
            extracted, consumed = extract_python_manifest(repo_dir, path, entry.kind, lockfiles)
            used_locks |= consumed
            result.extend(extracted)
        else:
            result.warn(f"{path}: {entry.kind} manifests are not supported yet; not parsed")

    for lock in lockfiles:
        if lock in used_locks:
            continue
        name = PurePosixPath(lock).name
        if name in LOCKFILE_NAMES:
            result.warn(f"{lock}: no package.json in the same directory; lockfile not used")
        elif name in ("poetry.lock", "uv.lock"):
            result.warn(f"{lock}: not paired with a pyproject.toml manager unambiguously; not used")
        else:
            result.warn(f"{lock}: lockfile format is not supported yet; not parsed")
    return result

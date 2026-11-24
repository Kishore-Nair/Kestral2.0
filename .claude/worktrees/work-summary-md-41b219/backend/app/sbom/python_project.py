"""Turn Python declarations (+ optional Poetry/uv lock) into roots and edges."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from packageurl import PackageURL
from packaging.utils import canonicalize_name

from .identities import component_id, root_id
from .poetry_lock import parse_poetry_lock
from .python_reqs import (
    ECOSYSTEM,
    ParsedManifest,
    PyDeclaration,
    parse_pyproject,
    parse_requirements,
)
from .records import (
    SCOPES,
    ComponentRecord,
    Evidence,
    ExtractionResult,
    LockedPackage,
    ParsedLock,
    RootRecord,
    project_path_of,
    resolved_edge,
    unresolved_edge,
)
from .uv_lock import parse_uv_lock


def is_requirements_file(path: str, kind: str = "") -> bool:
    name = PurePosixPath(path).name
    return (name.startswith("requirements") and name.endswith(".txt")) or (
        kind.startswith("requirements") and name.endswith(".txt")
    )


def _pypi_purl(normalized: str, version: str | None) -> str | None:
    if version is None:
        return None
    try:
        return PackageURL(type="pypi", name=normalized, version=version).to_string()
    except ValueError:
        return None


def _merge_scope(current: str, new: str) -> str:
    return current if SCOPES.index(current) <= SCOPES.index(new) else new


def select_python_lock(
    pyproject_path: str, manager: str | None, lockfile_paths: list[str]
) -> tuple[str | None, str | None, str | None]:
    """Return (lock_kind, lock_path, warning) for a pyproject in the same directory."""
    directory = project_path_of(pyproject_path)
    available = set(lockfile_paths)
    found = {
        kind: path
        for kind, path in (
            ("poetry", f"{directory}/poetry.lock" if directory else "poetry.lock"),
            ("uv", f"{directory}/uv.lock" if directory else "uv.lock"),
        )
        if path in available
    }
    if len(found) == 2:
        if manager in found:
            return manager, found[manager], None
        return (
            None,
            None,
            (
                f"{pyproject_path}: both poetry.lock and uv.lock are present and the manager "
                "is not "
                "declared unambiguously; neither lock is used"
            ),
        )
    if found:
        kind, path = next(iter(found.items()))
        return kind, path, None
    return None, None, None


def extract_python_manifest(
    repo_dir: Path, manifest_path: str, kind: str, lockfile_paths: list[str]
) -> tuple[ExtractionResult, set[str]]:
    """Extract one Python manifest. Returns the result and lockfile paths it consumed."""
    result = ExtractionResult()
    project_path = project_path_of(manifest_path)
    used_locks: set[str] = set()

    if PurePosixPath(manifest_path).name == "pyproject.toml":
        parsed = parse_pyproject(repo_dir, manifest_path)
    else:
        parsed = parse_requirements(repo_dir, manifest_path)
    for message in parsed.warnings:
        result.warn(message, partial=False)
    result.partial = result.partial or parsed.partial

    if not parsed.is_dependency_manifest:
        return result, used_locks  # tool-only pyproject: no project root to report

    # requirements files carry no project name: label the root by its manifest path.
    name = parsed.name or manifest_path
    root = RootRecord(
        root_id(ECOSYSTEM, project_path, manifest_path),
        name,
        project_path,
        manifest_path,
        ECOSYSTEM,
    )
    result.roots.append(root)

    lock: ParsedLock | None = None
    if PurePosixPath(manifest_path).name == "pyproject.toml":
        lock_kind, lock_path, warning = select_python_lock(
            manifest_path, parsed.manager, lockfile_paths
        )
        if warning:
            result.warn(warning)
        if lock_kind and lock_path:
            used_locks.add(lock_path)
            lock = (parse_poetry_lock if lock_kind == "poetry" else parse_uv_lock)(
                repo_dir, lock_path
            )
            for message in lock.warnings:
                result.warn(message)
            if not lock.supported:
                lock = None

    if lock is None:
        _emit_declarations_only(result, root, project_path, parsed)
    else:
        _emit_with_lock(result, root, project_path, parsed, lock)
    return result, used_locks


def _emit_declarations_only(
    result: ExtractionResult, root: RootRecord, project_path: str, parsed: ParsedManifest
) -> None:
    components: dict[str, ComponentRecord] = {}
    unresolved = 0
    for decl in parsed.declarations:
        if decl.exact_version is None:
            unresolved += 1
            result.relationships.append(
                unresolved_edge(root.root_id, decl.name, decl.specifier, ECOSYSTEM, [decl.evidence])
            )
            continue
        cid = component_id(
            ECOSYSTEM, decl.normalized, decl.exact_version, project_path, decl.evidence.path, None
        )
        component = components.get(cid)
        if component is None:
            component = ComponentRecord(
                component_id=cid,
                name=decl.name,
                normalized_name=decl.normalized,
                version=decl.exact_version,
                ecosystem=ECOSYSTEM,
                purl=_pypi_purl(decl.normalized, decl.exact_version),
                install_path=None,
                project_path=project_path,
                scope=decl.scope,
                evidence=[decl.evidence],
                resolved=True,
                context_path=decl.evidence.path,
            )
            components[cid] = component
            result.components.append(component)
        else:
            component.add_evidence(decl.evidence)
            component.scope = _merge_scope(component.scope, decl.scope)
        result.relationships.append(resolved_edge(root.root_id, cid, [decl.evidence]))

    if unresolved:
        result.warn(
            f"{root.manifest_path}: {unresolved} declarations are not pinned exactly; "
            "their versions are unknown and left unresolved"
        )
    if parsed.declarations:
        result.warn(
            f"{root.manifest_path}: no supported lockfile; transitive dependencies "
            "are unknown (declarations only)"
        )


def _emit_with_lock(
    result: ExtractionResult,
    root: RootRecord,
    project_path: str,
    parsed: ParsedManifest,
    lock: ParsedLock,
) -> None:
    by_name: dict[str, list[ComponentRecord]] = {}
    component_of: dict[int, ComponentRecord] = {}
    project_normalized = canonicalize_name(parsed.name) if parsed.name else None
    local_names: set[str] = set()
    root_package: LockedPackage | None = None

    for package in lock.packages:
        if package.local:
            local_names.add(package.normalized)
            if package.normalized == project_normalized:
                root_package = package
            continue
        cid = component_id(
            ECOSYSTEM, package.normalized, package.version, project_path, lock.path, None
        )
        evidence = Evidence(lock.path, "lockfile", package.locator)
        existing = next(
            (c for c in by_name.get(package.normalized, []) if c.component_id == cid), None
        )
        if existing is not None:
            existing.add_evidence(evidence)
            component_of[id(package)] = existing
            continue
        component = ComponentRecord(
            component_id=cid,
            name=package.name,
            normalized_name=package.normalized,
            version=package.version,
            ecosystem=ECOSYSTEM,
            purl=_pypi_purl(package.normalized, package.version),
            install_path=None,
            project_path=project_path,
            scope=package.scope,
            evidence=[evidence],
            resolved=package.version is not None,
            hashes=list(package.hashes),
            context_path=lock.path,
        )
        by_name.setdefault(package.normalized, []).append(component)
        component_of[id(package)] = component
        result.components.append(component)

    other_local = local_names - ({project_normalized} if project_normalized else set())
    if other_local:
        result.warn(f"{lock.path}: {len(other_local)} local/workspace packages are not modeled")

    # Versions the lock itself records for the project's direct dependencies (uv).
    root_versions: dict[str, set[str]] = {}
    if root_package is not None:
        for dep in root_package.dependencies:
            if dep.version:
                root_versions.setdefault(dep.normalized, set()).add(dep.version)

    unresolved = 0

    def link(
        from_id: str,
        name: str,
        normalized: str,
        version: str | None,
        specifier: str,
        evidence: list[Evidence],
        hint: set[str] | None = None,
    ) -> ComponentRecord | None:
        nonlocal unresolved
        candidates = by_name.get(normalized, [])
        if version is not None:
            candidates = [c for c in candidates if c.version == version]
        if len(candidates) > 1 and hint:
            narrowed = [c for c in candidates if c.version in hint]
            candidates = narrowed if narrowed else candidates
        if len(candidates) == 1:
            result.relationships.append(
                resolved_edge(from_id, candidates[0].component_id, evidence)
            )
            return candidates[0]
        unresolved += 1
        status = "ambiguous" if len(candidates) > 1 else "unresolved"
        result.relationships.append(
            unresolved_edge(from_id, name, specifier, ECOSYSTEM, evidence, status)
        )
        return None

    for decl in parsed.declarations:
        target = link(
            root.root_id,
            decl.name,
            decl.normalized,
            decl.exact_version,
            decl.specifier,
            [decl.evidence],
            root_versions.get(decl.normalized),
        )
        if target is not None and target.scope == "unknown":
            target.scope = decl.scope  # lock had no scope info; the declaration does

    for package in lock.packages:
        component = component_of.get(id(package))
        if component is None:
            continue
        for dep in package.dependencies:
            link(
                component.component_id,
                dep.name,
                dep.normalized,
                dep.version,
                dep.specifier,
                [Evidence(lock.path, "lockfile", dep.locator)],
            )

    if unresolved:
        result.warn(
            f"{lock.path}: {unresolved} dependency references could not be mapped to "
            "exactly one locked package"
        )


__all__ = ["PyDeclaration", "extract_python_manifest", "is_requirements_file", "select_python_lock"]

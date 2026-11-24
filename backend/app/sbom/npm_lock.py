"""npm ``package-lock.json`` / ``npm-shrinkwrap.json`` (lockfileVersion 2 and 3).

Semantics follow https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json :
``packages[""]`` is the project root and every other key is an *installed
location* relative to the lockfile's directory. Edges are created only by
replaying Node's module lookup over those locations; anything that cannot be
proven is kept as an explicit unresolved relationship.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

from packageurl import PackageURL

from .identities import component_id, root_id
from .records import (
    MAX_LOCKFILE_BYTES,
    MAX_MANIFEST_BYTES,
    ComponentRecord,
    Evidence,
    ExtractionResult,
    RootRecord,
    UnsafePathError,
    license_from_text,
    normalize_rel_path,
    project_path_of,
    read_text_bounded,
    resolved_edge,
    safe_repo_file,
    unresolved_edge,
)

ECOSYSTEM = "npm"
SUPPORTED_LOCKFILE_VERSIONS = (2, 3)
LOCKFILE_NAMES = ("npm-shrinkwrap.json", "package-lock.json")  # npm prefers shrinkwrap

_SEGMENT = r"[a-z0-9~-][a-z0-9._~-]*"
_NPM_NAME_RE = re.compile(rf"^(?:@{_SEGMENT}/)?{_SEGMENT}$", re.IGNORECASE)

ROOT_SECTIONS = (
    ("dependencies", "runtime"),
    ("optionalDependencies", "optional"),
    ("devDependencies", "dev"),
)
PACKAGE_SECTIONS = ("dependencies", "optionalDependencies")

_INTEGRITY_ALGS = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}


def is_valid_npm_name(name: object) -> bool:
    return isinstance(name, str) and len(name) <= 214 and bool(_NPM_NAME_RE.match(name))


def name_from_location(location: str) -> str | None:
    """Package name implied by an install location (last ``node_modules`` segment)."""
    parts = location.split("/")
    indexes = [i for i, part in enumerate(parts) if part == "node_modules"]
    if not indexes:
        return None
    tail = parts[indexes[-1] + 1 :]
    if len(tail) == 1 or (len(tail) == 2 and tail[0].startswith("@")):
        name = "/".join(tail)
        return name if is_valid_npm_name(name) else None
    return None


def npm_candidate_locations(parent_location: str, dependency: str) -> list[str]:
    """Locations Node would search for ``dependency`` required from ``parent_location``.

    Nearest first. Implements NODE_MODULES_PATHS: for every ancestor directory
    of the parent (skipping ``node_modules`` and ``@scope`` dirs), try
    ``<dir>/node_modules/<dependency>``.
    """
    if not is_valid_npm_name(dependency):
        raise ValueError("invalid npm package name")
    parts = [part for part in parent_location.split("/") if part] if parent_location else []
    result: list[str] = []
    for i in range(len(parts), -1, -1):
        directory = parts[:i]
        if directory and directory[-1] == "node_modules":
            continue
        if (
            len(directory) >= 2
            and directory[-2] == "node_modules"
            and directory[-1].startswith("@")
        ):
            continue
        result.append("/".join([*directory, "node_modules", dependency]))
    return list(dict.fromkeys(result))


def resolve_location(packages: dict, parent_location: str, dependency: str) -> str | None:
    """First installed location found by Node's lookup, or ``None``."""
    for candidate in npm_candidate_locations(parent_location, dependency):
        if candidate in packages:
            return candidate
    return None


def find_lockfile(manifest_path: str, lockfile_paths: list[str]) -> str | None:
    """Pair a manifest with a lockfile in the *same* directory only."""
    directory = project_path_of(manifest_path)
    available = set(lockfile_paths)
    for name in LOCKFILE_NAMES:
        candidate = f"{directory}/{name}" if directory else name
        if candidate in available:
            return candidate
    return None


def _alias_target(spec: object) -> str | None:
    """``npm:real-name@range`` -> ``real-name``; otherwise ``None``."""
    if not isinstance(spec, str) or not spec.startswith("npm:"):
        return None
    body = spec[4:]
    at = body.find("@", 1)  # skip a leading scope '@'
    return body if at == -1 else body[:at]


def _integrity_hashes(value: object) -> list[tuple[str, str]]:
    if not isinstance(value, str):
        return []
    hashes: list[tuple[str, str]] = []
    for token in value.split():
        alg, _, b64 = token.partition("-")
        if alg.lower() not in _INTEGRITY_ALGS or not b64:
            continue
        try:
            content = base64.b64decode(b64, validate=True).hex()
        except ValueError:
            continue
        hashes.append((_INTEGRITY_ALGS[alg.lower()], content))
    return hashes


def _npm_purl(name: str, version: str | None) -> str | None:
    if version is None:
        return None
    namespace, _, short = name.rpartition("/")
    try:
        return PackageURL(
            type="npm", namespace=namespace or None, name=short, version=version
        ).to_string()
    except ValueError:
        return None


def _scope(entry: dict) -> str:
    if entry.get("dev") is True or entry.get("devOptional") is True:
        return "dev"
    if entry.get("optional") is True:
        return "optional"
    return "runtime"


def _load_json(repo_dir: Path, rel_path: str, max_bytes: int) -> object:
    path = safe_repo_file(repo_dir, rel_path)
    return json.loads(read_text_bounded(path, max_bytes))


def _spec_text(spec: object) -> str:
    return spec if isinstance(spec, str) else ""


def extract_npm_project(
    repo_dir: Path, manifest_path: str, lockfile_path: str | None
) -> ExtractionResult:
    """Extract one npm project: its root, installed instances and edges."""
    result = ExtractionResult()
    manifest_path = normalize_rel_path(manifest_path)
    project_path = project_path_of(manifest_path)

    manifest: dict | None = None
    try:
        loaded = _load_json(repo_dir, manifest_path, MAX_MANIFEST_BYTES)
        if isinstance(loaded, dict):
            manifest = loaded
        else:
            result.warn(f"{manifest_path}: not a JSON object; declarations ignored")
    except (OSError, ValueError, UnsafePathError):
        result.warn(f"{manifest_path}: could not be read safely; declarations ignored")

    lock: dict | None = None
    if lockfile_path is None:
        result.warn(
            f"{manifest_path}: no package-lock.json or npm-shrinkwrap.json in the same "
            "directory; direct dependencies left unresolved"
        )
    else:
        lock = _load_lockfile(repo_dir, lockfile_path, result)

    lock_root = lock["packages"].get("") if lock else None
    lock_root = lock_root if isinstance(lock_root, dict) else {}

    name = next(
        (
            value
            for value in (
                (manifest or {}).get("name"),
                lock_root.get("name"),
                lock.get("name") if lock else None,
            )
            if isinstance(value, str) and value.strip()
        ),
        project_path.rsplit("/", 1)[-1] if project_path else "root",
    )
    root = RootRecord(
        root_id(ECOSYSTEM, project_path, manifest_path),
        name,
        project_path,
        manifest_path,
        ECOSYSTEM,
    )
    result.roots.append(root)

    declarations = _root_declarations(manifest, manifest_path, lock_root, lockfile_path)

    if lock is None:
        for dep_name, spec, evidence in declarations:
            result.relationships.append(
                unresolved_edge(root.root_id, dep_name, _spec_text(spec), ECOSYSTEM, evidence)
            )
        return result

    assert lockfile_path is not None
    _extract_from_lock(result, root, project_path, lockfile_path, lock["packages"], declarations)
    return result


def _load_lockfile(repo_dir: Path, lockfile_path: str, result: ExtractionResult) -> dict | None:
    try:
        lock = _load_json(repo_dir, lockfile_path, MAX_LOCKFILE_BYTES)
    except (OSError, ValueError, UnsafePathError):
        result.warn(f"{lockfile_path}: could not be read as bounded JSON; dependencies unresolved")
        return None
    if not isinstance(lock, dict):
        result.warn(f"{lockfile_path}: not a JSON object; dependencies unresolved")
        return None
    version = lock.get("lockfileVersion")
    if version not in SUPPORTED_LOCKFILE_VERSIONS:
        result.warn(
            f"{lockfile_path}: lockfileVersion {version!r} is not supported (only 2 and 3); "
            "direct dependencies left unresolved"
        )
        return None
    if not isinstance(lock.get("packages"), dict):
        result.warn(f"{lockfile_path}: missing 'packages' map; dependencies unresolved")
        return None
    return lock


def _root_declarations(
    manifest: dict | None, manifest_path: str, lock_root: dict, lockfile_path: str | None
) -> list[tuple[str, object, list[Evidence]]]:
    """Direct declarations of the project, each with manifest and/or lock evidence."""
    declarations: list[tuple[str, object, list[Evidence]]] = []
    for section, _scope_name in ROOT_SECTIONS:
        from_manifest = (manifest or {}).get(section)
        from_manifest = from_manifest if isinstance(from_manifest, dict) else {}
        from_lock = lock_root.get(section)
        from_lock = from_lock if isinstance(from_lock, dict) else {}
        for dep_name in sorted(set(from_manifest) | set(from_lock)):
            evidence: list[Evidence] = []
            if dep_name in from_manifest:
                evidence.append(Evidence(manifest_path, "manifest", f"{section}.{dep_name}"))
            if dep_name in from_lock and lockfile_path:
                evidence.append(
                    Evidence(lockfile_path, "lockfile", f"packages[''].{section}.{dep_name}")
                )
            spec = from_manifest.get(dep_name, from_lock.get(dep_name))
            declarations.append((dep_name, spec, evidence))
    return declarations


def _extract_from_lock(
    result: ExtractionResult,
    root: RootRecord,
    project_path: str,
    lockfile_path: str,
    packages: dict,
    declarations: list[tuple[str, object, list[Evidence]]],
) -> None:
    components: dict[str, ComponentRecord] = {}
    local_locations: set[str] = set()
    bad_keys = 0

    for location in sorted(k for k in packages if k != ""):
        entry = packages[location]
        try:
            normalize_rel_path(location)
        except UnsafePathError:
            bad_keys += 1
            continue
        if not isinstance(entry, dict):
            bad_keys += 1
            continue
        segment_name = name_from_location(location)
        if entry.get("link") is True or segment_name is None:
            local_locations.add(location)  # workspace folder or symlink to one
            continue
        declared_name = entry.get("name")
        name = declared_name if is_valid_npm_name(declared_name) else segment_name
        version = (
            entry.get("version")
            if isinstance(entry.get("version"), str) and entry["version"]
            else None
        )
        licenses = (
            [license_from_text(entry["license"])]
            if isinstance(entry.get("license"), str) and entry["license"].strip()
            else []
        )
        components[location] = ComponentRecord(
            component_id=component_id(
                ECOSYSTEM, name, version, project_path, lockfile_path, location
            ),
            name=name,
            normalized_name=name,
            version=version,
            ecosystem=ECOSYSTEM,
            purl=_npm_purl(name, version),
            install_path=location,
            project_path=project_path,
            scope=_scope(entry),
            evidence=[Evidence(lockfile_path, "lockfile", f"packages.{location}")],
            resolved=version is not None,
            licenses=licenses,
            hashes=_integrity_hashes(entry.get("integrity")),
            context_path=lockfile_path,
        )
    result.components.extend(components[loc] for loc in sorted(components))

    if bad_keys:
        result.warn(f"{lockfile_path}: {bad_keys} malformed or unsafe 'packages' entries skipped")
    if local_locations:
        result.warn(
            f"{lockfile_path}: {len(local_locations)} workspace/link entries are local packages "
            "and are not modeled as registry components"
        )

    unresolved_count = 0

    def link(
        from_id: str, parent: str, dep_name: str, spec: object, evidence: list[Evidence]
    ) -> None:
        nonlocal unresolved_count
        relationship = _resolve_declaration(
            packages, components, local_locations, from_id, parent, dep_name, spec, evidence
        )
        if relationship.resolution_status != "resolved":
            unresolved_count += 1
        result.relationships.append(relationship)

    for dep_name, spec, evidence in declarations:
        link(root.root_id, "", dep_name, spec, evidence)

    peer_count = 0
    for location in sorted(components):
        entry = packages[location]
        component = components[location]
        for section in PACKAGE_SECTIONS:
            deps = entry.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name in sorted(deps):
                evidence = [
                    Evidence(lockfile_path, "lockfile", f"packages.{location}.{section}.{dep_name}")
                ]
                link(component.component_id, location, dep_name, deps[dep_name], evidence)
        peers = entry.get("peerDependencies")
        if isinstance(peers, dict):
            peer_count += len(peers)

    if unresolved_count:
        result.warn(
            f"{lockfile_path}: {unresolved_count} dependency declarations could not be resolved "
            "to exactly one installed lockfile location"
        )
    if peer_count:
        result.warn(
            f"{lockfile_path}: {peer_count} peerDependencies are requirements, not proven "
            "installed children; they are not modeled as edges",
            partial=False,
        )


def _resolve_declaration(
    packages: dict,
    components: dict[str, ComponentRecord],
    local_locations: set[str],
    from_id: str,
    parent_location: str,
    dep_name: str,
    spec: object,
    evidence: list[Evidence],
):
    spec_text = _spec_text(spec)

    def unresolved(status: str = "unresolved"):
        return unresolved_edge(from_id, dep_name, spec_text, ECOSYSTEM, evidence, status)

    if not is_valid_npm_name(dep_name):
        return unresolved()
    location = resolve_location(packages, parent_location, dep_name)
    if location is None or location in local_locations:
        return unresolved()
    component = components.get(location)
    if component is None:
        return unresolved()
    alias = _alias_target(spec)
    if alias is not None:
        # npm alias: the installed package must be the alias target.
        if component.name != alias:
            return unresolved()
    elif component.name != dep_name:
        # Installed entry claims a different package name without an alias spec.
        return unresolved("ambiguous")
    return resolved_edge(from_id, component.component_id, evidence)

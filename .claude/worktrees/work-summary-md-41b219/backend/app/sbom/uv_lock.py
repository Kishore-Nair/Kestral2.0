"""Conservative ``uv.lock`` extraction (lock format ``version = 1``).

The uv lock format can evolve; only ``version = 1`` (the fixture-tested
format) is accepted, anything else is reported and ignored. This module only
*reads* the file: it never runs ``uv sync``/``uv run`` or any resolver.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.utils import canonicalize_name

from .poetry_lock import package_locator
from .records import (
    MAX_LOCKFILE_BYTES,
    LockedDependency,
    LockedPackage,
    ParsedLock,
    UnsafePathError,
    normalize_rel_path,
    read_text_bounded,
    safe_repo_file,
)

SUPPORTED_LOCK_VERSIONS = (1,)
_LOCAL_SOURCES = ("virtual", "editable", "directory", "path")


def _hash(value: object) -> list[tuple[str, str]]:
    if isinstance(value, dict) and isinstance(value.get("hash"), str):
        alg, _, content = value["hash"].partition(":")
        if content:
            return [(alg.upper().replace("SHA", "SHA-", 1), content)]
    return []


def _dependency(entry: object, owner_locator: str, section: str) -> LockedDependency | None:
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
        return None
    name = entry["name"]
    version = entry.get("version") if isinstance(entry.get("version"), str) else None
    spec_parts = []
    if version:
        spec_parts.append(f"=={version}")
    if isinstance(entry.get("marker"), str):
        spec_parts.append(f"; {entry['marker']}")
    locator = f"{owner_locator}.{section}.{name}"
    if isinstance(entry.get("marker"), str):
        locator = f"{locator} [marker: {entry['marker']}]"
    return LockedDependency(
        name=name,
        normalized=canonicalize_name(name),
        version=version,
        specifier="".join(spec_parts),
        locator=locator,
    )


def parse_uv_lock(repo_dir: Path, rel_path: str) -> ParsedLock:
    rel_path = normalize_rel_path(rel_path)
    parsed = ParsedLock(path=rel_path)
    try:
        data = tomllib.loads(
            read_text_bounded(safe_repo_file(repo_dir, rel_path), MAX_LOCKFILE_BYTES)
        )
    except (OSError, ValueError, UnsafePathError):
        parsed.supported = False
        parsed.warnings.append(f"{rel_path}: could not be parsed safely as TOML; lock ignored")
        return parsed

    if data.get("version") not in SUPPORTED_LOCK_VERSIONS:
        parsed.supported = False
        parsed.warnings.append(
            f"{rel_path}: uv lock version {data.get('version')!r} is not supported (1); "
            "lock ignored"
        )
        return parsed

    records = data.get("package", [])
    if not isinstance(records, list):
        parsed.supported = False
        parsed.warnings.append(f"{rel_path}: [[package]] is not an array; lock ignored")
        return parsed

    skipped = 0
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("name"), str):
            skipped += 1
            continue
        name = record["name"]
        version = record.get("version") if isinstance(record.get("version"), str) else None
        source = record.get("source") if isinstance(record.get("source"), dict) else {}
        locator = package_locator(name, version)
        package = LockedPackage(
            name=name,
            normalized=canonicalize_name(name),
            version=version,
            locator=locator,
            scope="unknown",  # uv.lock does not record per-package scope
            local=any(key in source for key in _LOCAL_SOURCES),
            hashes=_hash(record.get("sdist")),
        )
        for entry in (
            record.get("dependencies", []) if isinstance(record.get("dependencies"), list) else []
        ):
            dep = _dependency(entry, locator, "dependencies")
            if dep is not None:
                package.dependencies.append(dep)
        optional = record.get("optional-dependencies")
        if isinstance(optional, dict):
            for extra in sorted(optional):
                for entry in optional[extra] if isinstance(optional[extra], list) else []:
                    dep = _dependency(entry, locator, f"optional-dependencies.{extra}")
                    if dep is not None:
                        package.dependencies.append(dep)
        parsed.packages.append(package)
    if skipped:
        parsed.warnings.append(f"{rel_path}: {skipped} malformed [[package]] records skipped")
    return parsed

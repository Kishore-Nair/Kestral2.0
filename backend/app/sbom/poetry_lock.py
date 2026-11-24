"""Conservative ``poetry.lock`` extraction.

Supported: ``[metadata].lock-version`` 1.1, 2.0 and 2.1 (the versions covered by
fixtures). Poetry dependency entries name a target but not its locked version,
so a dependency is linked only when exactly one locked record has that name;
several records (multi-version / environment forks) stay ``ambiguous``.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.utils import canonicalize_name

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

SUPPORTED_LOCK_VERSIONS = ("1.1", "2.0", "2.1")


def package_locator(name: str, version: str | None) -> str:
    return f"package[{name}=={version}]" if version else f"package[{name}]"


def _scope(record: dict) -> str:
    if record.get("optional") is True:
        return "optional"
    groups = record.get("groups")
    if isinstance(groups, list) and groups:
        if "main" in groups:
            return "runtime"
        return "dev" if set(groups) == {"dev"} else "unknown"
    category = record.get("category")
    if category == "main":
        return "runtime"
    if category == "dev":
        return "dev"
    return "unknown"


def _dependency_specifier(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        spec = value.get("version") if isinstance(value.get("version"), str) else ""
        if isinstance(value.get("markers"), str):
            spec = f"{spec}; {value['markers']}".strip()
        return spec
    if isinstance(value, list):
        return "<multiple constraints>"
    return ""


def parse_poetry_lock(repo_dir: Path, rel_path: str) -> ParsedLock:
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

    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    lock_version = metadata.get("lock-version")
    if lock_version not in SUPPORTED_LOCK_VERSIONS:
        parsed.supported = False
        parsed.warnings.append(
            f"{rel_path}: Poetry lock-version {lock_version!r} is not supported "
            f"({', '.join(SUPPORTED_LOCK_VERSIONS)}); lock ignored"
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
        locator = package_locator(name, version)
        source = record.get("source") if isinstance(record.get("source"), dict) else {}
        package = LockedPackage(
            name=name,
            normalized=canonicalize_name(name),
            version=version,
            locator=locator,
            scope=_scope(record),
            local=source.get("type") in ("directory", "file"),
        )
        deps = record.get("dependencies")
        if isinstance(deps, dict):
            for dep_name in sorted(deps):
                package.dependencies.append(
                    LockedDependency(
                        name=dep_name,
                        normalized=canonicalize_name(dep_name),
                        version=None,
                        specifier=_dependency_specifier(deps[dep_name]),
                        locator=f"{locator}.dependencies.{dep_name}",
                    )
                )
        parsed.packages.append(package)
    if skipped:
        parsed.warnings.append(f"{rel_path}: {skipped} malformed [[package]] records skipped")
    return parsed

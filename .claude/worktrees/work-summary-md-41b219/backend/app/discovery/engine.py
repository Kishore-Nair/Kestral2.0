"""Read-only, deterministic discovery of repository inventory artifacts."""

import os
import stat
from pathlib import Path

from app.config import settings
from app.discovery.paths import SKIP_DIRECTORIES, to_repo_relative_posix
from app.discovery.rules import (
    artifact_rule,
    is_ci_file,
    is_docker_file,
    is_iac_file,
    is_sbom_file,
    is_source_directory_name,
    language_for,
)
from app.schemas.inventory import FileEntry, Inventory, LanguageCount


class DiscoveryLimitError(RuntimeError):
    """Raised when repository traversal exceeds its configured hard cap."""


def _is_reparse_point(file_stat: os.stat_result) -> bool:
    attributes = getattr(file_stat, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def discover_repository(repo_dir: Path, scan_id: str) -> Inventory:
    """Inspect a checkout without reading or executing repository file contents."""
    requested_root = Path(repo_dir)
    requested_stat = requested_root.lstat()
    if stat.S_ISLNK(requested_stat.st_mode) or _is_reparse_point(requested_stat):
        raise ValueError("Repository path must not be a symlink or junction")
    root = requested_root.resolve(strict=True)
    root_stat = root.stat()
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError("Repository path must be a directory")

    file_count = 0
    language_counts: dict[str, int] = {}
    manifests: list[FileEntry] = []
    lockfiles: list[FileEntry] = []
    dockerfiles: set[str] = set()
    ci_files: set[str] = set()
    iac_files: set[str] = set()
    existing_sboms: set[str] = set()
    source_directories: set[str] = set()
    warnings: set[str] = set()

    # Explicit stack traversal lets us inspect each directory entry without following
    # symlinks or Windows junctions and abort as soon as the file cap is exceeded.
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                ordered_entries = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            warnings.add("Some repository paths could not be inspected")
            continue

        child_directories: list[Path] = []
        for entry in ordered_entries:
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError:
                warnings.add("Some repository paths could not be inspected")
                continue

            if stat.S_ISDIR(entry_stat.st_mode):
                if entry.name.casefold() in SKIP_DIRECTORIES or _is_reparse_point(entry_stat):
                    if entry.name.casefold() == "vendor":
                        warnings.add("Vendored files were excluded; inventory may be incomplete")
                    continue
                child_directories.append(Path(entry.path))
                continue
            if not stat.S_ISREG(entry_stat.st_mode) or _is_reparse_point(entry_stat):
                continue

            relative = to_repo_relative_posix(Path(entry.path), root)
            file_count += 1
            if file_count > settings.max_file_count:
                raise DiscoveryLimitError("Repository file count exceeded configured limit")

            rule = artifact_rule(relative)
            if rule is not None:
                item = FileEntry(path=relative, kind=rule.kind, ecosystem=rule.ecosystem)
                (manifests if rule.category == "manifest" else lockfiles).append(item)

            language = language_for(relative)
            if language:
                language_counts[language] = language_counts.get(language, 0) + 1
                parts = Path(relative).parts
                for index, part in enumerate(parts[:-1]):
                    if is_source_directory_name(part):
                        source_directories.add("/".join(parts[: index + 1]))

            if is_docker_file(relative):
                dockerfiles.add(relative)
            if is_ci_file(relative):
                ci_files.add(relative)
            if is_iac_file(relative):
                iac_files.add(relative)
            if is_sbom_file(relative):
                existing_sboms.add(relative)

        pending.extend(reversed(child_directories))

    return Inventory(
        schema_version="1.0",
        scan_id=scan_id,
        languages=[
            LanguageCount(name=name, file_count=count)
            for name, count in sorted(language_counts.items())
        ],
        manifests=sorted(manifests, key=lambda item: item.path),
        lockfiles=sorted(lockfiles, key=lambda item: item.path),
        dockerfiles=sorted(dockerfiles),
        ci_files=sorted(ci_files),
        iac_files=sorted(iac_files),
        existing_sboms=sorted(existing_sboms),
        source_directories=sorted(source_directories),
        file_count=file_count,
        partial=bool(warnings),
        warnings=sorted(warnings),
    )

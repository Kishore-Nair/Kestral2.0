"""Safe per-scan workspace allocation."""

import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

SCAN_ID = re.compile(r"^scan_[0-9a-f]{32}$")


@dataclass(frozen=True)
class ScanDirectories:
    workspace: Path
    output: Path


class WorkspaceLimitError(RuntimeError):
    pass


def _child(root: Path, scan_id: str) -> Path:
    candidate = (root / scan_id).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("Scan directory escaped its configured root") from exc
    return candidate


def allocate_scan_dirs(
    scan_id: str, workspace_root: Path, scan_output_root: Path
) -> ScanDirectories:
    if not SCAN_ID.fullmatch(scan_id):
        raise ValueError("Invalid scan ID")
    workspace_root.mkdir(parents=True, exist_ok=True)
    scan_output_root.mkdir(parents=True, exist_ok=True)
    workspace = _child(workspace_root, scan_id)
    output = _child(scan_output_root, scan_id)
    workspace.mkdir(exist_ok=False)
    try:
        output.mkdir(exist_ok=False)
    except Exception:
        workspace.rmdir()
        raise
    return ScanDirectories(workspace=workspace, output=output)


def enforce_workspace_limits(
    repo_dir: Path,
    *,
    max_repository_size_mb: int,
    max_file_count: int,
) -> None:
    root = repo_dir.resolve(strict=True)
    byte_limit = max_repository_size_mb * 1024 * 1024
    total_bytes = 0
    checkout_files = 0

    for path in root.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise WorkspaceLimitError("Repository contents could not be inspected safely") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            continue
        total_bytes += metadata.st_size
        if total_bytes > byte_limit:
            raise WorkspaceLimitError(
                f"Repository exceeds the {max_repository_size_mb} MB on-disk limit"
            )
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] != ".git":
            checkout_files += 1
            if checkout_files > max_file_count:
                raise WorkspaceLimitError(
                    f"Repository exceeds the {max_file_count} file limit"
                )


def remove_scan_workspace(scan_id: str, workspace_root: Path) -> None:
    if not SCAN_ID.fullmatch(scan_id):
        raise ValueError("Invalid scan ID")
    root = workspace_root.resolve()
    workspace = _child(root, scan_id)
    if workspace.parent != root:
        raise ValueError("Refusing to remove a workspace outside its configured root")
    if workspace.exists():
        shutil.rmtree(workspace, onexc=_remove_readonly)


def _remove_readonly(function, path: str, error: OSError) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
        function(path)
    except OSError:
        raise error from None


from pathlib import Path

import pytest

from app.ingestion.workspace import allocate_scan_dirs, remove_scan_workspace


def test_allocates_unique_scan_directories(tmp_path: Path) -> None:
    directories = allocate_scan_dirs(
        "scan_550e8400e29b41d4a716446655440000",
        tmp_path / "workspaces",
        tmp_path / "scans",
    )
    assert directories.workspace.is_dir()
    assert directories.output.is_dir()
    assert directories.workspace.parent == tmp_path / "workspaces"
    assert directories.output.parent == tmp_path / "scans"


@pytest.mark.parametrize("scan_id", ["../escape", "scan_not_hex", "scan_" + "a" * 33])
def test_rejects_unsafe_scan_ids(tmp_path: Path, scan_id: str) -> None:
    with pytest.raises(ValueError):
        allocate_scan_dirs(scan_id, tmp_path / "workspaces", tmp_path / "scans")


def test_cleanup_removes_readonly_checkout_files(tmp_path: Path) -> None:
    scan_id = "scan_550e8400e29b41d4a716446655440000"
    workspace_root = tmp_path / "workspaces"
    checkout = workspace_root / scan_id / "repo" / ".git" / "objects"
    checkout.mkdir(parents=True)
    pack = checkout / "pack.idx"
    pack.write_bytes(b"git pack")
    pack.chmod(0o444)

    remove_scan_workspace(scan_id, workspace_root)
    assert not (workspace_root / scan_id).exists()


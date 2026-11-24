from pathlib import Path

import pytest

from app.ingestion.workspace import WorkspaceLimitError, enforce_workspace_limits


def test_workspace_file_limit_excludes_git_metadata(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "index").write_bytes(b"git metadata")
    (repo / "one.txt").write_text("one", encoding="utf-8")
    enforce_workspace_limits(repo, max_repository_size_mb=1, max_file_count=1)
    (repo / "two.txt").write_text("two", encoding="utf-8")
    with pytest.raises(WorkspaceLimitError, match="file limit"):
        enforce_workspace_limits(repo, max_repository_size_mb=1, max_file_count=1)


def test_workspace_size_limit_includes_git_download(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "large-pack").write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(WorkspaceLimitError, match="on-disk limit"):
        enforce_workspace_limits(repo, max_repository_size_mb=1, max_file_count=10)


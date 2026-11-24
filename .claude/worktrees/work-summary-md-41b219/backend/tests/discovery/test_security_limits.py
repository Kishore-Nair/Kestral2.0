from pathlib import Path

import pytest

from app.discovery import engine
from app.discovery.engine import DiscoveryLimitError, discover_repository


def test_file_limit_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "one.txt").touch()
    (tmp_path / "two.txt").touch()
    monkeypatch.setattr(engine.settings, "max_file_count", 1)

    with pytest.raises(DiscoveryLimitError, match="file count"):
        discover_repository(tmp_path, "scan-limit")


def test_symlink_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "package.json").write_text("{}", encoding="utf-8")
    try:
        (tmp_path / "linked-dir").symlink_to(outside, target_is_directory=True)
        (tmp_path / "linked-file").symlink_to(outside / "package.json")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"Symlink creation is unavailable: {exc}")

    result = discover_repository(tmp_path, "scan-links")
    assert result.file_count == 0
    assert result.manifests == []


def test_bad_path_has_clear_failure(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        discover_repository(tmp_path / "missing", "scan-missing")

    file_path = tmp_path / "regular-file"
    file_path.touch()
    with pytest.raises(ValueError, match="directory"):
        discover_repository(file_path, "scan-file")

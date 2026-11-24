from pathlib import Path

import pytest

from app.ingestion.artifacts import load_validated_json, resolve_artifact_path, save_validated_json
from app.schemas.inventory import Inventory


def test_artifact_path_stays_under_output_root(tmp_path: Path) -> None:
    root = tmp_path / "scans"
    expected = (root / "scan_123" / "graph.json").resolve()
    assert resolve_artifact_path(root, "scan_123/graph.json") == expected


def test_artifact_path_rejects_escape(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        resolve_artifact_path(tmp_path / "scans", "../secret.json")


def test_atomic_write_rejects_oversized_artifact(tmp_path: Path) -> None:
    inventory = Inventory(
        scan_id="scan_" + "1" * 32,
        languages=[],
        manifests=[],
        lockfiles=[],
        dockerfiles=[],
        ci_files=[],
        iac_files=[],
        existing_sboms=[],
        source_directories=[],
        file_count=0,
        partial=False,
        warnings=[],
    )
    target = tmp_path / "inventory.json"
    with pytest.raises(ValueError, match="size limit"):
        save_validated_json(target, inventory, max_bytes=5)
    assert not target.exists()


def test_load_rejects_oversized_artifact_before_parsing(tmp_path: Path) -> None:
    target = tmp_path / "inventory.json"
    target.write_text("{}" * 10, encoding="utf-8")
    with pytest.raises(ValueError, match="size limit"):
        load_validated_json(target, Inventory, max_bytes=5)


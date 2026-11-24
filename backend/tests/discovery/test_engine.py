import json
import shutil
from pathlib import Path

from app.discovery.engine import discover_repository

FIXTURES = Path(__file__).parent / "fixtures"


def test_npm_files_and_other_artifacts() -> None:
    result = discover_repository(FIXTURES / "npm_simple", "scan-test")

    assert [item.path for item in result.manifests] == ["package.json"]
    assert [item.path for item in result.lockfiles] == ["package-lock.json"]
    assert result.languages[0].name == "JavaScript"
    assert result.languages[0].file_count == 1
    assert result.dockerfiles == ["Dockerfile"]
    assert result.ci_files == [".github/workflows/ci.yml"]
    assert result.iac_files == ["infra/main.tf"]


def test_python_manifests_and_locks() -> None:
    requirements = discover_repository(FIXTURES / "python_requirements", "scan-python")
    uv = discover_repository(FIXTURES / "python_uv", "scan-uv")

    assert [entry.path for entry in requirements.manifests] == [
        "requirements-dev.txt",
        "requirements.txt",
    ]
    assert [entry.path for entry in uv.manifests] == ["pyproject.toml"]
    assert [entry.path for entry in uv.lockfiles] == ["uv.lock"]
    assert requirements.languages[0].name == "Python"


def test_monorepo_paths_are_preserved() -> None:
    result = discover_repository(FIXTURES / "multi_project", "scan-mono")

    assert [entry.path for entry in result.manifests] == [
        "backend/pyproject.toml",
        "frontend/package.json",
    ]
    assert [entry.path for entry in result.lockfiles] == ["frontend/package-lock.json"]


def test_empty_and_repeatable_inventory(tmp_path: Path) -> None:
    empty = discover_repository(tmp_path, "scan-empty")
    assert empty.file_count == 0
    assert empty.partial is False

    first = discover_repository(FIXTURES / "npm_simple", "scan-repeat")
    second = discover_repository(FIXTURES / "npm_simple", "scan-repeat")
    assert json.dumps(first.model_dump(mode="json"), sort_keys=True) == json.dumps(
        second.model_dump(mode="json"), sort_keys=True
    )


def test_unrelated_json_is_not_a_manifest(tmp_path: Path) -> None:
    (tmp_path / "settings.json").write_text("{}", encoding="utf-8")
    result = discover_repository(tmp_path, "scan-json")
    assert result.manifests == []
    assert result.file_count == 1


def test_generated_directories_are_excluded(tmp_path: Path) -> None:
    for folder in ("node_modules", ".git", ".venv", "vendor"):
        path = tmp_path / folder
        path.mkdir()
        (path / "package.json").write_text("{}", encoding="utf-8")
    result = discover_repository(tmp_path, "scan-generated")
    assert result.file_count == 0
    assert result.manifests == []
    assert result.partial is True
    assert result.warnings == ["Vendored files were excluded; inventory may be incomplete"]


def test_sbom_detection(tmp_path: Path) -> None:
    (tmp_path / "service.cdx.json").touch()
    (tmp_path / "bom.xml").touch()
    (tmp_path / "ordinary.json").touch()
    result = discover_repository(tmp_path, "scan-sbom")
    assert result.existing_sboms == ["bom.xml", "service.cdx.json"]


def test_fixture_tree_is_copyable(tmp_path: Path) -> None:
    copied = tmp_path / "repo"
    shutil.copytree(FIXTURES / "strange_paths", copied)
    result = discover_repository(copied, "scan-strange")
    assert result.languages[0].name == "TypeScript"
    assert result.source_directories == ["nested/src"]

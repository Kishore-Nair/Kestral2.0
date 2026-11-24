"""Deterministic manifest patching inside the sandbox copy."""

import json
from pathlib import Path

import pytest

from app.validation.patching import PatchError, apply_change, snapshot, unified_diffs


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_requirements_pin_moves_and_range_rules(tmp_path: Path) -> None:
    write(
        tmp_path / "examples/app/requirements.txt",
        "# pinned\nWerkzeug==2.3.3  # web\nflask>=2.0\n"
        "requests[socks]>=2.0,<2.20 ; python_version >= '3.8'\n",
    )
    result = apply_change(
        tmp_path,
        ecosystem="pypi",
        project_path="examples/app",
        package="werkzeug",
        new_version="3.0.3",
        direct=True,
    )
    text = (tmp_path / "examples/app/requirements.txt").read_text()
    assert "Werkzeug==3.0.3  # web" in text
    assert result.changed_files == ["examples/app/requirements.txt"]

    apply_change(
        tmp_path,
        ecosystem="pypi",
        project_path="examples/app",
        package="flask",
        new_version="3.1.0",
        direct=True,
    )
    assert (
        "flask>=2.0\n" in (tmp_path / "examples/app/requirements.txt").read_text()
    )  # already allowed

    apply_change(
        tmp_path,
        ecosystem="pypi",
        project_path="examples/app",
        package="requests",
        new_version="2.32.0",
        direct=True,
    )
    text = (tmp_path / "examples/app/requirements.txt").read_text()
    assert 'requests[socks]>=2.32.0; python_version >= "3.8"' in text


def test_pyproject_requirement_strings(tmp_path: Path) -> None:
    write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "demo"\ndependencies = ["jinja2>=3.0,<3.1.4", "click>=8"]\n',
    )
    result = apply_change(
        tmp_path,
        ecosystem="pypi",
        project_path="",
        package="Jinja2",
        new_version="3.1.6",
        direct=True,
    )
    text = (tmp_path / "pyproject.toml").read_text()
    assert '"jinja2>=3.1.6"' in text and '"click>=8"' in text and 'name = "demo"' in text
    assert result.edits == ["pyproject.toml: jinja2>=3.0,<3.1.4 -> jinja2>=3.1.6"]


def test_package_json_direct_and_transitive(tmp_path: Path) -> None:
    write(
        tmp_path / "package.json",
        json.dumps({"dependencies": {"express": "~4.0.0"}}, indent=4) + "\n",
    )
    write(tmp_path / "package-lock.json", "{}\n")
    result = apply_change(
        tmp_path,
        ecosystem="npm",
        project_path="",
        package="express",
        new_version="4.21.2",
        direct=True,
    )
    manifest = json.loads((tmp_path / "package.json").read_text())
    assert manifest["dependencies"]["express"] == "4.21.2"
    assert manifest["overrides"]["express"] == "$express"
    assert result.lockfiles == ["package-lock.json"]
    assert (
        (tmp_path / "package.json").read_text().startswith('{\n    "dependencies"')
    )  # indent kept

    apply_change(
        tmp_path, ecosystem="npm", project_path="", package="qs", new_version="6.2.4", direct=False
    )
    assert json.loads((tmp_path / "package.json").read_text())["overrides"] == {
        "express": "$express", "qs": "6.2.4",
    }


def test_guards(tmp_path: Path) -> None:
    write(tmp_path / "package.json", "{}")
    with pytest.raises(PatchError, match="escapes"):
        apply_change(
            tmp_path,
            ecosystem="npm",
            project_path="../..",
            package="x",
            new_version="1.0.0",
            direct=True,
        )
    with pytest.raises(PatchError, match="No sandbox patcher"):
        apply_change(
            tmp_path, ecosystem="maven", project_path="", package="x", new_version="1", direct=True
        )
    (tmp_path / "evil").mkdir()
    (tmp_path / "evil" / "package.json").symlink_to(tmp_path / "package.json")
    with pytest.raises(PatchError, match="cannot be edited safely"):
        apply_change(
            tmp_path,
            ecosystem="npm",
            project_path="evil",
            package="x",
            new_version="1.0.0",
            direct=True,
        )


def test_unified_diff(tmp_path: Path) -> None:
    write(tmp_path / "requirements.txt", "werkzeug==2.3.3\n")
    before = snapshot(tmp_path, ["requirements.txt"])
    apply_change(
        tmp_path,
        ecosystem="pypi",
        project_path="",
        package="werkzeug",
        new_version="3.0.3",
        direct=True,
    )
    [diff] = unified_diffs(tmp_path, before)
    assert diff["path"] == "requirements.txt"
    assert (diff["lines_added"], diff["lines_removed"]) == (1, 1)
    assert "-werkzeug==2.3.3" in diff["diff"] and "+werkzeug==3.0.3" in diff["diff"]


def test_pyproject_only_edits_runtime_dependency_tables(tmp_path: Path) -> None:
    write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "demo"\ndependencies = [\n    "werkzeug==3.1.0",\n]\n\n'
        '[dependency-groups]\ntests-min = ["werkzeug==3.1.0"]\n\n'
        '[tool.tox]\ndeps = ["werkzeug==3.1.0"]\n',
    )
    apply_change(
        tmp_path,
        ecosystem="pypi",
        project_path="",
        package="werkzeug",
        new_version="3.1.9",
        direct=True,
    )
    text = (tmp_path / "pyproject.toml").read_text()
    assert text.count("werkzeug==3.1.9") == 1  # only [project].dependencies
    assert 'tests-min = ["werkzeug==3.1.0"]' in text and 'deps = ["werkzeug==3.1.0"]' in text


def test_dev_scoped_package_edits_dependency_groups_but_not_min_groups(tmp_path: Path) -> None:
    write(
        tmp_path / "pyproject.toml",
        '[project]\nname = "d"\ndependencies = ["httpx>=0.27"]\n\n'
        '[dependency-groups]\ndev = ["pytest==8.3.2"]\ntests-min = ["pytest==8.0.0"]\n',
    )
    result = apply_change(
        tmp_path,
        ecosystem="pypi",
        project_path="",
        package="pytest",
        new_version="9.0.3",
        direct=True,
        dev=True,
    )
    text = (tmp_path / "pyproject.toml").read_text()
    assert 'dev = ["pytest==9.0.3"]' in text and 'tests-min = ["pytest==8.0.0"]' in text
    assert result.edits == ["pyproject.toml: pytest==8.3.2 -> pytest==9.0.3"]

    write(tmp_path / "pyproject.toml", '[dependency-groups]\ndev = ["pytest==8.3.2"]\n')
    apply_change(
        tmp_path,
        ecosystem="pypi",
        project_path="",
        package="pytest",
        new_version="9.0.3",
        direct=True,
        dev=False,
    )  # runtime package: groups untouched
    assert "pytest==8.3.2" in (tmp_path / "pyproject.toml").read_text()


def test_tool_error_keeps_only_the_tools_error_lines() -> None:
    from app.validation.sandbox import tool_error

    stderr = (
        "WARNING: Running pip as the 'root' user can result in broken permissions\n"
        "Using CPython 3.12.16 interpreter at: /usr/local/bin/python3\n"
        "error: Failed to parse `uv.lock`\n"
        "  cause: Dependency `colorama` has missing `source` field\n"
    )
    assert tool_error(stderr) == (
        "error: Failed to parse `uv.lock` cause: Dependency `colorama` has missing `source` field"
    )

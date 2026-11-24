import pytest

from app.sbom.normalization import finalize
from app.sbom.python_project import extract_python_manifest
from app.sbom.python_reqs import parse_pyproject, parse_requirements

from .helpers import FIXTURES, SCAN_ID, edges

REQ = FIXTURES / "python_requirements"


def decls(parsed):
    return {d.normalized: d for d in parsed.declarations}


def document_for(repo, manifest, locks=()):
    result, _ = extract_python_manifest(repo, manifest, manifest, list(locks))
    return finalize(result, SCAN_ID)


# ---------------------------------------------------------------- requirements


def test_pinned_requirement_is_a_direct_version_with_zero_transitives():
    document = document_for(REQ, "requirements.txt")
    requests = next(c for c in document.components if c.name == "requests")
    assert requests.version == "2.31.0"
    assert requests.purl == "pkg:pypi/requests@2.31.0"
    assert requests.scope == "runtime"
    assert requests.evidence[0].model_dump() == {
        "path": "requirements.txt",
        "kind": "manifest",
        "locator": "line:2",
    }
    # nothing ever depends *from* a requirements-only component
    component_ids = {c.component_id for c in document.components}
    assert not [r for r in document.relationships if r.from_id in component_ids]


def test_range_requirement_has_unknown_version_and_unresolved_target():
    document = document_for(REQ, "requirements.txt")
    flask = next(
        r
        for r in document.relationships
        if r.unresolved_target and r.unresolved_target.name == "flask"
    )
    assert flask.to_id is None
    assert flask.resolution_status == "unresolved"
    assert flask.unresolved_target.model_dump() == {
        "name": "flask",
        "specifier": ">=2,<3",
        "ecosystem": "pypi",
    }
    assert not [c for c in document.components if c.name == "flask"]  # no invented flask@x
    assert document.partial is True


def test_requirements_fixture_edges():
    assert edges(document_for(REQ, "requirements.txt")) == {
        ("ROOT:requirements.txt", "requests@2.31.0[.]", "resolved"),
        ("ROOT:requirements.txt", "?flask", "unresolved"),
        ("ROOT:requirements.txt", "uvicorn@0.30.1[.]", "resolved"),
        ("ROOT:requirements.txt", "pywin32@306[.]", "resolved"),
        ("ROOT:requirements.txt", "Foo_Bar@1.0.0[.]", "resolved"),
        ("ROOT:requirements.txt", "click@8.1.7[.]", "resolved"),  # via -r requirements/base.txt
    }


def test_markers_and_extras_are_preserved():
    parsed = decls(parse_requirements(REQ, "requirements.txt"))
    assert parsed["pywin32"].evidence.locator == 'line:5 [marker: sys_platform == "win32"]'
    assert parsed["uvicorn"].specifier == "[standard] ==0.30.1"
    assert parsed["foo-bar"].name == "Foo_Bar"  # original presentation kept
    assert parsed["foo-bar"].exact_version == "1.0.0"  # --hash option stripped


def test_include_is_followed_with_its_own_evidence_path_and_cycle_stopped():
    parsed = parse_requirements(REQ, "requirements.txt")
    click = decls(parsed)["click"]
    assert (click.evidence.path, click.evidence.locator) == ("requirements/base.txt", "line:1")
    assert any("cycle" in w for w in parsed.warnings)


def test_install_options_never_leak_values():
    parsed = parse_requirements(REQ, "requirements.txt")
    text = " ".join(parsed.warnings)
    assert "--index-url" in text
    assert "hunter2" not in text and "example.invalid" not in text
    assert any("-e" in w for w in parsed.warnings)


def test_escaping_and_absolute_includes_are_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "secret.txt").write_text("leaked==1.0\n")
    (repo / "requirements.txt").write_text(
        "-r ../secret.txt\n-r /etc/passwd\n-r https://example.invalid/r.txt\nok==1.0\n"
    )
    parsed = parse_requirements(repo, "requirements.txt")
    assert list(decls(parsed)) == ["ok"]
    assert any("escapes the repository" in w for w in parsed.warnings)
    assert any("remote or absolute" in w for w in parsed.warnings)
    assert "example.invalid" not in " ".join(parsed.warnings)


def test_symlink_escape_is_rejected(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (tmp_path / "outside.txt").write_text("leaked==1.0\n")
    try:
        (repo / "link.txt").symlink_to(tmp_path / "outside.txt")
    except OSError:
        pytest.skip("symlinks not permitted on this platform")
    (repo / "requirements.txt").write_text("-r link.txt\n")
    parsed = parse_requirements(repo, "requirements.txt")
    assert parsed.declarations == []


def test_include_depth_is_bounded(tmp_path):
    for i in range(10):
        (tmp_path / f"r{i}.txt").write_text(f"-r r{i + 1}.txt\npkg{i}==1.0\n")
    (tmp_path / "r10.txt").write_text("last==1.0\n")
    parsed = parse_requirements(tmp_path, "r0.txt")
    assert "last" not in decls(parsed)
    assert any("limit" in w for w in parsed.warnings)


def test_comments_continuations_urls_and_garbage(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# full comment\n\n"
        "six==1.16.0 \\\n"
        "    # trailing comment\n"
        "pkg @ https://user:token@example.invalid/pkg.whl\n"
        "git+https://example.invalid/repo.git\n"
        "!!! not a requirement\n"
    )
    parsed = parse_requirements(tmp_path, "requirements.txt")
    found = decls(parsed)
    assert found["six"].exact_version == "1.16.0"
    assert found["pkg"].exact_version is None
    assert found["pkg"].specifier == "@ <direct reference>"  # URL never echoed
    assert "token" not in " ".join(parsed.warnings + [d.specifier for d in parsed.declarations])
    assert sum("unsupported requirement line" in w for w in parsed.warnings) == 2


def test_wildcard_pin_is_not_exact(tmp_path):
    (tmp_path / "requirements.txt").write_text("a==1.*\nb===2.0\nc==1.0,<2\n")
    found = decls(parse_requirements(tmp_path, "requirements.txt"))
    assert found["a"].exact_version is None
    assert found["b"].exact_version == "2.0"
    assert found["c"].exact_version is None


def test_non_default_requirements_file_is_not_assumed_runtime():
    document = document_for(REQ, "requirements-dev.txt")
    assert edges(document) == {("ROOT:requirements-dev.txt", "?pytest", "unresolved")}


def test_subproject_requirements_create_a_subproject_root(tmp_path):
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "requirements.txt").write_text("a==1.0\n")
    document = document_for(tmp_path, "svc/requirements.txt")
    assert (document.roots[0].path, document.roots[0].manifest_path) == (
        "svc",
        "svc/requirements.txt",
    )
    assert document.components[0].project_path == "svc"


# ---------------------------------------------------------------- pyproject


def test_pep621_groups_scopes_preserved(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["a==1.0", "b>=2"]\n'
        '[project.optional-dependencies]\nfast = ["c==3.0"]\n'
        '[dependency-groups]\ndev = ["d==4.0"]\nlint = ["e==5.0", {include-group = "dev"}]\n'
    )
    parsed = decls(parse_pyproject(tmp_path, "pyproject.toml"))
    assert {n: d.scope for n, d in parsed.items()} == {
        "a": "runtime",
        "b": "runtime",
        "c": "optional",
        "d": "dev",
        "e": "unknown",
    }
    assert parsed["c"].evidence.locator == "project.optional-dependencies.fast[0]"
    document = document_for(tmp_path, "pyproject.toml")
    # extras / groups are not collapsed into unconditional runtime edges
    assert {c.name: c.scope for c in document.components} == {
        "a": "runtime",
        "c": "optional",
        "d": "dev",
        "e": "unknown",
    }


def test_dynamic_dependencies_warn_instead_of_guessing(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndynamic = ["dependencies"]\n')
    parsed = parse_pyproject(tmp_path, "pyproject.toml")
    assert parsed.declarations == [] and parsed.partial is True
    assert any("dynamic" in w for w in parsed.warnings)


def test_tool_only_pyproject_creates_no_root(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n")
    document = document_for(tmp_path, "pyproject.toml")
    assert document.roots == [] and document.relationships == []


def test_poetry_tables(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "p"\n'
        '[tool.poetry.dependencies]\npython = "^3.12"\nrequests = "^2.31"\nexact = "1.2.3"\n'
        'opt = {version = "==1.0", optional = true, markers = "sys_platform == \'linux\'"}\n'
        'local = {path = "../local"}\n'
        '[tool.poetry.group.dev.dependencies]\npytest = "8.3.2"\n'
        '[tool.poetry.group.docs.dependencies]\nmkdocs = "1.6.0"\n'
    )
    parsed = parse_pyproject(tmp_path, "pyproject.toml")
    found = decls(parsed)
    assert "python" not in found
    assert parsed.manager == "poetry"
    assert found["requests"].exact_version is None
    assert found["exact"].exact_version == "1.2.3"
    assert found["opt"].scope == "optional" and "markers" in found["opt"].evidence.locator
    assert found["local"].specifier == "<non-registry source>"
    assert (found["pytest"].scope, found["mkdocs"].scope) == ("dev", "unknown")


def test_invalid_toml_is_reported(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project\n")
    parsed = parse_pyproject(tmp_path, "pyproject.toml")
    assert parsed.partial and parsed.warnings

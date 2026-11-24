import pytest

from app.sbom.normalization import finalize
from app.sbom.poetry_lock import parse_poetry_lock
from app.sbom.python_project import extract_python_manifest, select_python_lock
from app.sbom.uv_lock import parse_uv_lock

from .helpers import FIXTURES, SCAN_ID, edges

POETRY = FIXTURES / "python_poetry"
UV = FIXTURES / "python_uv"


def document_for(repo, locks):
    result, used = extract_python_manifest(repo, "pyproject.toml", "pyproject.toml", locks)
    return finalize(result, SCAN_ID), used


def test_poetry_only_unambiguous_edges():
    document, used = document_for(POETRY, ["poetry.lock"])
    assert used == {"poetry.lock"}
    assert edges(document) == {
        ("ROOT:pyproject.toml", "requests@2.31.0[.]", "resolved"),
        ("ROOT:pyproject.toml", "pytest@8.3.2[.]", "resolved"),
        ("requests@2.31.0[.]", "certifi@2024.7.4[.]", "resolved"),
        ("requests@2.31.0[.]", "idna@3.7[.]", "resolved"),
        ("requests@2.31.0[.]", "?urllib3", "unresolved"),  # not in lock: never invented
        ("pytest@8.3.2[.]", "colorama@0.4.6[.]", "resolved"),
        ("pytest@8.3.2[.]", "?typing-extensions", "ambiguous"),  # two locked versions
    }
    assert document.partial is True
    # declared root deps only; transitive packages are not direct
    assert sum(r.from_id.startswith("root:") for r in document.relationships) == 2


def test_poetry_scopes_and_evidence():
    document, _ = document_for(POETRY, ["poetry.lock"])
    by_name = {(c.name, c.version): c for c in document.components}
    assert by_name[("requests", "2.31.0")].scope == "runtime"
    assert by_name[("pytest", "8.3.2")].scope == "dev"
    assert by_name[("requests", "2.31.0")].evidence[0].model_dump() == {
        "path": "poetry.lock",
        "kind": "lockfile",
        "locator": "package[requests==2.31.0]",
    }
    assert len([c for c in document.components if c.name == "typing-extensions"]) == 2


def test_uv_edges_and_root_package_not_a_component():
    document, used = document_for(UV, ["uv.lock"])
    assert used == {"uv.lock"}
    assert edges(document) == {
        ("ROOT:pyproject.toml", "httpx@0.27.0[.]", "resolved"),
        ("ROOT:pyproject.toml", "rich@13.7.1[.]", "resolved"),
        ("ROOT:pyproject.toml", "pytest@8.3.2[.]", "resolved"),
        ("httpx@0.27.0[.]", "certifi@2024.7.4[.]", "resolved"),
        ("httpx@0.27.0[.]", "httpcore@1.0.5[.]", "resolved"),
        ("httpx@0.27.0[.]", "idna@3.7[.]", "resolved"),
        ("httpcore@1.0.5[.]", "certifi@2024.7.4[.]", "resolved"),
        ("httpcore@1.0.5[.]", "h11@0.14.0[.]", "resolved"),
        ("pytest@8.3.2[.]", "iniconfig@2.0.0[.]", "resolved"),
        ("pytest@8.3.2[.]", "?colorama", "unresolved"),
    }
    assert "uv-demo" not in {c.name for c in document.components}
    scopes = {c.name: c.scope for c in document.components}
    assert (scopes["httpx"], scopes["rich"], scopes["pytest"], scopes["h11"]) == (
        "runtime",
        "optional",
        "dev",
        "unknown",
    )
    certifi = next(c for c in document.components if c.name == "certifi")
    assert certifi.hashes[0].alg == "SHA-256"


def test_uv_marker_is_kept_on_evidence():
    lock = parse_uv_lock(UV, "uv.lock")
    pytest_pkg = next(p for p in lock.packages if p.name == "pytest")
    colorama = next(d for d in pytest_pkg.dependencies if d.name == "colorama")
    assert "sys_platform == 'win32'" in colorama.locator


def test_uv_versioned_reference_disambiguates(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["a"]\n')
    (tmp_path / "uv.lock").write_text(
        "version = 1\n"
        '[[package]]\nname = "x"\nversion = "0"\nsource = { editable = "." }\n'
        'dependencies = [{ name = "a", version = "2.0" }]\n'
        '[[package]]\nname = "a"\nversion = "1.0"\nsource = { registry = "r" }\n'
        '[[package]]\nname = "a"\nversion = "2.0"\nsource = { registry = "r" }\n'
        '[[package]]\nname = "b"\nversion = "1.0"\nsource = { registry = "r" }\n'
        'dependencies = [{ name = "a", version = "1.0" }, { name = "a" }]\n'
    )
    document, _ = document_for(tmp_path, ["uv.lock"])
    assert edges(document) == {
        ("ROOT:pyproject.toml", "a@2.0[.]", "resolved"),  # root package pins 2.0 in the lock
        ("b@1.0[.]", "a@1.0[.]", "resolved"),
        ("b@1.0[.]", "?a", "ambiguous"),
    }


@pytest.mark.parametrize(
    ("parser", "filename", "content"),
    [
        (parse_uv_lock, "uv.lock", "version = 99\n"),
        (parse_poetry_lock, "poetry.lock", '[metadata]\nlock-version = "9.9"\n'),
        (parse_uv_lock, "uv.lock", "not = [valid\n"),
    ],
)
def test_unsupported_lock_formats_are_rejected(tmp_path, parser, filename, content):
    (tmp_path / filename).write_text(content)
    lock = parser(tmp_path, filename)
    assert lock.supported is False and lock.warnings


def test_unsupported_lock_falls_back_to_declarations(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["a==1.0", "b>1"]\n'
    )
    (tmp_path / "uv.lock").write_text("version = 99\n")
    document, _ = document_for(tmp_path, ["uv.lock"])
    assert edges(document) == {
        ("ROOT:pyproject.toml", "a@1.0[.]", "resolved"),
        ("ROOT:pyproject.toml", "?b", "unresolved"),
    }
    assert document.partial is True


def test_both_locks_without_declared_manager_are_not_merged():
    kind, path, warning = select_python_lock("pyproject.toml", None, ["poetry.lock", "uv.lock"])
    assert (kind, path) == (None, None) and "both" in warning
    assert select_python_lock("pyproject.toml", "poetry", ["poetry.lock", "uv.lock"])[:2] == (
        "poetry",
        "poetry.lock",
    )
    assert select_python_lock("svc/pyproject.toml", None, ["uv.lock"]) == (None, None, None)


def test_both_locks_present_yields_declarations_only(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\ndependencies = ["a>=1"]\n')
    (tmp_path / "uv.lock").write_text("version = 1\n")
    (tmp_path / "poetry.lock").write_text('[metadata]\nlock-version = "2.1"\n')
    document, used = document_for(tmp_path, ["poetry.lock", "uv.lock"])
    assert used == set()
    assert document.components == []
    assert any("both poetry.lock and uv.lock" in w for w in document.warnings)

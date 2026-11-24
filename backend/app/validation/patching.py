"""Apply one approved version change to manifests in an isolated copy (no LLM, no execution).

Only the manifests of the vulnerable component's own project are edited:
- PyPI: ``requirements*.txt`` and ``pyproject.toml`` requirement strings
- npm: ``package.json`` dependency ranges, or ``overrides`` for a transitive package

PyPI ranges that accept the new version are left alone. npm changes pin the exact
approved version so lock resolution cannot silently select a different upgrade.
Files are read and written as text inside the sandbox only.
"""

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

MAX_DIFF_LINES = 400
MAX_FILE_BYTES = 8 * 1024 * 1024


class PatchError(RuntimeError):
    """The change could not be applied safely."""


@dataclass
class PatchResult:
    edits: list[str] = field(default_factory=list)  # human-readable "file: old -> new"
    unchanged: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def project_dir(repo_dir: Path, project_path: str) -> Path:
    root = repo_dir.resolve()
    target = (root / project_path).resolve() if project_path else root
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise PatchError("Project path escapes the sandbox") from exc
    if not target.is_dir():
        raise PatchError(f"Project directory {project_path or '.'} not found in the sandbox")
    return target


def _read(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise PatchError(f"{path.name} cannot be edited safely")
    return path.read_text(encoding="utf-8")


def _rel(repo_dir: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_dir.resolve()).as_posix()


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------


def _new_pypi_spec(requirement: Requirement, new: str) -> str | None:
    """New specifier text, or None when the current one already accepts ``new``."""
    specs = list(requirement.specifier)
    if any(s.operator in ("==", "===") for s in specs):
        return f"=={new}"
    try:
        if not specs or SpecifierSet(str(requirement.specifier)).contains(
            Version(new), prereleases=True
        ):
            return None
    except InvalidVersion as exc:
        raise PatchError(f"{new} is not a valid PyPI version") from exc
    return f">={new}"


def _render(requirement: Requirement, original_name: str, spec: str) -> str:
    extras = f"[{','.join(sorted(requirement.extras))}]" if requirement.extras else ""
    marker = f"; {requirement.marker}" if requirement.marker else ""
    return f"{original_name}{extras}{spec}{marker}"


def patch_requirements(path: Path, package: str, new: str, result: PatchResult, rel: str) -> bool:
    text = _read(path)
    lines = text.splitlines(keepends=True)
    changed = False
    for index, raw in enumerate(lines):
        body, sep, comment = raw.rstrip("\n").partition(" #")
        stripped = body.strip()
        if not stripped or stripped.startswith(("#", "-")) or "://" in stripped:
            continue
        try:
            requirement = Requirement(stripped)
        except InvalidRequirement:
            continue
        if _canonical(requirement.name) != _canonical(package):
            continue
        spec = _new_pypi_spec(requirement, new)
        if spec is None:
            result.unchanged.append(f"{rel}: {stripped} already accepts {new}")
            continue
        leading = body[: len(body) - len(body.lstrip())]
        trailing = body[len(body.rstrip()) :]
        name = re.match(r"[A-Za-z0-9._-]+", stripped).group(0)
        rendered = (
            leading + _render(requirement, name, spec) + trailing + (sep + comment if sep else "")
        )
        newline = "\n" if raw.endswith("\n") else ""
        lines[index] = rendered + newline
        result.edits.append(f"{rel}: {stripped} -> {_render(requirement, name, spec)}")
        changed = True
    if changed:
        path.write_text("".join(lines), encoding="utf-8")
    return changed


_QUOTED = re.compile(r"""(["'])([A-Za-z0-9][^"'\n]{0,300})\1""")


def patch_pyproject(
    path: Path, package: str, new: str, result: PatchResult, rel: str, *, dev: bool = False
) -> bool:
    text = _read(path)
    changed = False

    def replace(match: re.Match) -> str:
        nonlocal changed
        quote, content = match.group(1), match.group(2)
        try:
            requirement = Requirement(content)
        except InvalidRequirement:
            return match.group(0)
        if _canonical(requirement.name) != _canonical(package) or not requirement.specifier:
            return match.group(0)
        spec = _new_pypi_spec(requirement, new)
        if spec is None:
            result.unchanged.append(f"{rel}: {content} already accepts {new}")
            return match.group(0)
        name = re.match(r"[A-Za-z0-9._-]+", content).group(0)
        rendered = _render(requirement, name, spec)
        result.edits.append(f"{rel}: {content} -> {rendered}")
        changed = True
        return f"{quote}{rendered}{quote}"

    # Runtime packages: [project] dependencies and [project.optional-dependencies] only.
    # Development packages (scope "dev") also: [dependency-groups], except groups whose name
    # marks a minimum-version environment (e.g. "tests-min"). Tool config is never edited.
    out_lines = []
    table = ""
    group = ""
    for line in text.splitlines(keepends=True):
        header = re.match(r"\s*\[\[?([^\]]+)\]\]?\s*$", line)
        if header:
            table, group = header.group(1).strip(), ""
            out_lines.append(line)
            continue
        key = re.match(r"\s*([A-Za-z0-9_.-]+)\s*=", line)
        if key:
            group = key.group(1)
        runtime_table = table == "project" or table.startswith("project.optional-dependencies")
        dev_group = dev and table == "dependency-groups" and "min" not in group.lower()
        out_lines.append(_QUOTED.sub(replace, line) if runtime_table or dev_group else line)
    patched = "".join(out_lines)
    if changed:
        path.write_text(patched, encoding="utf-8")
    return changed


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def _indent(text: str) -> int:
    match = re.search(r"\n([ \t]+)\"", text)
    return len(match.group(1).expandtabs(2)) if match else 2


def patch_package_json(
    path: Path, package: str, new: str, result: PatchResult, rel: str, *, direct: bool
) -> bool:
    text = _read(path)
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PatchError(f"{rel} is not valid JSON") from exc
    changed = False
    found = False
    for section in _NPM_SECTIONS:
        deps = manifest.get(section)
        if not isinstance(deps, dict) or package not in deps:
            continue
        found = True
        old = str(deps[package])
        # Approval names one version. Pin it so an already-satisfying old lock
        # cannot survive resolution and a newer unapproved version is not selected.
        deps[package] = new
        result.edits.append(f"{rel}: {section}.{package} {old!r} -> {deps[package]!r}")
        changed = True
    if found or not direct:
        overrides = manifest.setdefault("overrides", {})
        if not isinstance(overrides, dict):
            raise PatchError(f"{rel} has an unsupported overrides field")
        old = overrides.get(package)
        # npm requires an override of a direct dependency to match its spec.
        # Referencing the exact pin also fixes nested copies of the same package.
        overrides[package] = f"${package}" if found else new
        result.edits.append(
            f"{rel}: overrides.{package} {old!r} -> {overrides[package]!r} "
            "(all occurrences in this project)"
        )
        changed = True
    if changed:
        trailing = "\n" if text.endswith("\n") else ""
        path.write_text(json.dumps(manifest, indent=_indent(text), ensure_ascii=False) + trailing)
    return changed


# ---------------------------------------------------------------------------
# Entry point and diffs
# ---------------------------------------------------------------------------


def apply_change(
    repo_dir: Path,
    *,
    ecosystem: str,
    project_path: str,
    package: str,
    new_version: str,
    direct: bool,
    dev: bool = False,
) -> PatchResult:
    target = project_dir(repo_dir, project_path)
    result = PatchResult()
    if ecosystem == "pypi":
        for path in sorted(target.glob("requirements*.txt")):
            if patch_requirements(path, package, new_version, result, _rel(repo_dir, path)):
                result.changed_files.append(_rel(repo_dir, path))
        pyproject = target / "pyproject.toml"
        if pyproject.is_file() and patch_pyproject(
            pyproject, package, new_version, result, _rel(repo_dir, pyproject), dev=dev
        ):
            result.changed_files.append(_rel(repo_dir, pyproject))
        result.lockfiles = [
            _rel(repo_dir, p) for p in (target / "uv.lock", target / "poetry.lock") if p.is_file()
        ]
    elif ecosystem == "npm":
        manifest = target / "package.json"
        if not manifest.is_file():
            raise PatchError("No package.json in the component's project")
        if patch_package_json(
            manifest, package, new_version, result, _rel(repo_dir, manifest), direct=direct
        ):
            result.changed_files.append(_rel(repo_dir, manifest))
        result.lockfiles = [
            _rel(repo_dir, p)
            for p in (target / "package-lock.json", target / "npm-shrinkwrap.json")
            if p.is_file()
        ]
    else:
        raise PatchError(f"No sandbox patcher for ecosystem {ecosystem!r}")
    return result


def snapshot(repo_dir: Path, paths: list[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for rel in paths:
        path = repo_dir / rel
        out[rel] = path.read_text(encoding="utf-8") if path.is_file() else None
    return out


def unified_diffs(repo_dir: Path, before: dict[str, str | None]) -> list[dict]:
    diffs = []
    for rel, old in sorted(before.items()):
        path = repo_dir / rel
        new = path.read_text(encoding="utf-8") if path.is_file() else None
        if old == new:
            continue
        lines = list(
            difflib.unified_diff(
                (old or "").splitlines(keepends=True),
                (new or "").splitlines(keepends=True),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
                n=2,
            )
        )
        added = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
        removed = sum(1 for line in lines if line.startswith("-") and not line.startswith("---"))
        diffs.append(
            {
                "path": rel,
                "lines_added": added,
                "lines_removed": removed,
                "diff": "".join(lines[:MAX_DIFF_LINES]),
                "truncated": len(lines) > MAX_DIFF_LINES,
            }
        )
    return diffs

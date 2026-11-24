"""Python *declarations*: ``requirements*.txt`` and ``pyproject.toml``.

Declarations are not a resolution graph. An exact pin (``==1.2.3``) evidences
a concrete direct package version; any range stays an unresolved target. No
transitive package is ever inferred from a declaration.
"""

from __future__ import annotations

import posixpath
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from .records import (
    MAX_MANIFEST_BYTES,
    Evidence,
    UnsafePathError,
    normalize_rel_path,
    project_path_of,
    read_text_bounded,
    safe_repo_file,
)

ECOSYSTEM = "pypi"
MAX_INCLUDE_DEPTH = 5
MAX_INCLUDED_FILES = 20

# Options whose *values* may carry URLs/credentials: report only the option name.
_INSTALL_OPTIONS = (
    "-i",
    "--index-url",
    "--extra-index-url",
    "--trusted-host",
    "-f",
    "--find-links",
    "--no-index",
    "--prefer-binary",
    "--only-binary",
    "--no-binary",
    "--pre",
    "--require-hashes",
    "--use-feature",
    "--no-deps",
)
_PER_REQUIREMENT_OPTION = re.compile(r"\s--?[A-Za-z]")
_NAME_PREFIX = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?\s*")
_POETRY_EXACT = re.compile(r"^\s*(?:==\s*)?(\d[0-9A-Za-z.+!_-]*)\s*$")


@dataclass
class PyDeclaration:
    name: str  # as written, for display
    normalized: str
    specifier: str  # original constraint text incl. extras / marker
    exact_version: str | None
    scope: str
    evidence: Evidence


@dataclass
class ParsedManifest:
    name: str | None = None
    declarations: list[PyDeclaration] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    partial: bool = False
    is_dependency_manifest: bool = True
    manager: str | None = None  # "poetry" | "uv" | None (pyproject only)

    def warn(self, message: str, *, partial: bool = True) -> None:
        if message not in self.warnings:
            self.warnings.append(message)
        self.partial = self.partial or partial


def exact_pin(requirement: Requirement) -> str | None:
    """Version if the requirement pins exactly one version (``==X`` / ``===X``)."""
    specs = list(requirement.specifier)
    if len(specs) != 1:
        return None
    spec = specs[0]
    if spec.operator == "===" or (spec.operator == "==" and "*" not in spec.version):
        return spec.version
    return None


def _original_specifier(text: str, requirement: Requirement) -> str:
    """Constraint as written (packaging re-orders it), plus extras and marker."""
    body = text.split(";", 1)[0]
    constraint = _NAME_PREFIX.sub("", body, count=1).strip()
    if constraint.startswith("(") and constraint.endswith(")"):
        constraint = constraint[1:-1].strip()
    if requirement.url:
        constraint = "@ <direct reference>"  # never echo URLs (may embed credentials)
    parts = []
    if requirement.extras:
        parts.append("[" + ",".join(sorted(requirement.extras)) + "]")
    if constraint:
        parts.append(constraint)
    text_out = " ".join(parts)
    if requirement.marker is not None:
        text_out = f"{text_out}; {requirement.marker}".strip()
    return text_out


def declaration_from_pep508(
    text: str, scope: str, evidence_path: str, locator: str
) -> PyDeclaration | None:
    try:
        requirement = Requirement(text)
    except InvalidRequirement:
        return None
    exact = None if requirement.url else exact_pin(requirement)
    if requirement.marker is not None:
        # Conditional declaration: keep the marker visible on the edge evidence
        # so it is never mistaken for an unconditional dependency.
        locator = f"{locator} [marker: {requirement.marker}]"
    return PyDeclaration(
        name=requirement.name,
        normalized=canonicalize_name(requirement.name),
        specifier=_original_specifier(text, requirement),
        exact_version=exact,
        scope=scope,
        evidence=Evidence(evidence_path, "manifest", locator),
    )


# --------------------------------------------------------------------------
# requirements*.txt
# --------------------------------------------------------------------------


def requirements_scope(rel_path: str) -> str:
    # Only the conventional file name is treated as runtime; anything else
    # (requirements-dev.txt, ...) is not assumed to be production.
    return "runtime" if PurePosixPath(rel_path).name == "requirements.txt" else "unknown"


def parse_requirements(repo_dir: Path, rel_path: str) -> ParsedManifest:
    parsed = ParsedManifest()
    rel_path = normalize_rel_path(rel_path)
    state = {"files": 0}
    _parse_requirements_file(
        repo_dir, rel_path, requirements_scope(rel_path), parsed, chain=(), state=state
    )
    return parsed


def _logical_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    buffer, start = "", 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        if raw.endswith("\\"):
            buffer += raw[:-1] + " "
            continue
        lines.append((start, buffer + raw))
        buffer = ""
    if buffer:
        lines.append((start, buffer))
    return lines


def _strip_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return re.sub(r"\s+#.*$", "", line).strip()


def _parse_requirements_file(
    repo_dir: Path,
    rel_path: str,
    scope: str,
    parsed: ParsedManifest,
    chain: tuple[str, ...],
    state: dict,
) -> None:
    state["files"] += 1
    try:
        text = read_text_bounded(safe_repo_file(repo_dir, rel_path), MAX_MANIFEST_BYTES)
    except (OSError, ValueError, UnsafePathError):
        parsed.warn(f"{rel_path}: could not be read safely; declarations ignored")
        return

    for number, raw in _logical_lines(text):
        line = _strip_comment(raw)
        if not line:
            continue
        locator = f"line:{number}"
        include = _include_target(line)
        if include is not None:
            _follow_include(repo_dir, rel_path, include, scope, parsed, chain + (rel_path,), state)
            continue
        if line.startswith("-"):
            _handle_option(rel_path, number, line, parsed)
            continue
        match = _PER_REQUIREMENT_OPTION.search(line)
        requirement_text = line[: match.start()].strip() if match else line
        declaration = declaration_from_pep508(requirement_text, scope, rel_path, locator)
        if declaration is None:
            parsed.warn(f"{rel_path}:{number}: unsupported requirement line (not PEP 508); ignored")
            continue
        parsed.declarations.append(declaration)


def _include_target(line: str) -> str | None:
    for prefix in ("--requirement=", "--requirement ", "-r "):
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    if line.startswith("-r") and len(line) > 2 and not line.startswith("-r-"):
        return line[2:].strip()
    return None


def _handle_option(rel_path: str, number: int, line: str, parsed: ParsedManifest) -> None:
    option = line.split()[0].split("=", 1)[0]
    if option in ("-e", "--editable"):
        parsed.warn(f"{rel_path}:{number}: editable/local install ({option}) is not resolved")
    elif option in ("-c", "--constraint"):
        parsed.warn(f"{rel_path}:{number}: constraints files are not applied", partial=False)
    elif option in _INSTALL_OPTIONS:
        parsed.warn(f"{rel_path}:{number}: install option {option} ignored", partial=False)
    else:
        parsed.warn(f"{rel_path}:{number}: unsupported option {option} ignored")


def _follow_include(
    repo_dir: Path,
    including: str,
    target: str,
    scope: str,
    parsed: ParsedManifest,
    chain: tuple[str, ...],
    state: dict,
) -> None:
    if "://" in target or target.startswith(("/", "~")) or "\\" in target:
        parsed.warn(f"{including}: include '-r' to a remote or absolute path rejected")
        return
    joined = posixpath.normpath(posixpath.join(project_path_of(including), target))
    try:
        rel = normalize_rel_path(joined)
        safe_repo_file(repo_dir, rel)
    except UnsafePathError:
        parsed.warn(
            f"{including}: include '-r {target}' escapes the repository or is missing; rejected"
        )
        return
    if rel in chain:
        parsed.warn(f"{including}: include cycle via '{rel}' stopped", partial=False)
        return
    if len(chain) >= MAX_INCLUDE_DEPTH or state["files"] >= MAX_INCLUDED_FILES:
        parsed.warn(f"{including}: include limit reached at '{rel}'; not followed")
        return
    _parse_requirements_file(repo_dir, rel, scope, parsed, chain, state)


# --------------------------------------------------------------------------
# pyproject.toml
# --------------------------------------------------------------------------


def parse_pyproject(repo_dir: Path, rel_path: str) -> ParsedManifest:
    parsed = ParsedManifest()
    rel_path = normalize_rel_path(rel_path)
    try:
        data = tomllib.loads(
            read_text_bounded(safe_repo_file(repo_dir, rel_path), MAX_MANIFEST_BYTES)
        )
    except (OSError, ValueError, UnsafePathError):  # TOMLDecodeError is a ValueError
        parsed.warn(f"{rel_path}: could not be parsed safely as TOML; declarations ignored")
        return parsed

    project = data.get("project") if isinstance(data.get("project"), dict) else None
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else None
    groups = (
        data.get("dependency-groups") if isinstance(data.get("dependency-groups"), dict) else None
    )
    uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else None

    if project is None and poetry is None and groups is None:
        parsed.is_dependency_manifest = False  # tool-only pyproject (ruff, black, ...)
        return parsed

    backend = (
        data.get("build-system", {}).get("build-backend", "")
        if isinstance(data.get("build-system"), dict)
        else ""
    )
    uses_poetry = poetry is not None or str(backend).startswith("poetry")
    if uses_poetry and uv is None:
        parsed.manager = "poetry"
    elif uv is not None and poetry is None:
        parsed.manager = "uv"

    if project is not None:
        parsed.name = project.get("name") if isinstance(project.get("name"), str) else None
        _parse_pep621(project, rel_path, parsed)
    if poetry is not None:
        parsed.name = parsed.name or (
            poetry.get("name") if isinstance(poetry.get("name"), str) else None
        )
        _parse_poetry_tables(poetry, rel_path, parsed)
    if groups is not None:
        _parse_dependency_groups(groups, rel_path, parsed)
    if uv is not None and isinstance(uv.get("dev-dependencies"), list):
        _parse_pep508_list(
            uv["dev-dependencies"], "dev", rel_path, "tool.uv.dev-dependencies", parsed
        )
    return parsed


def _parse_pep508_list(
    items: object, scope: str, rel_path: str, prefix: str, parsed: ParsedManifest
) -> None:
    if not isinstance(items, list):
        parsed.warn(f"{rel_path}: '{prefix}' is not a list; ignored")
        return
    for index, item in enumerate(items):
        locator = f"{prefix}[{index}]"
        if isinstance(item, dict) and "include-group" in item:
            continue  # PEP 735 group include: its members are parsed under that group
        declaration = (
            declaration_from_pep508(item, scope, rel_path, locator)
            if isinstance(item, str)
            else None
        )
        if declaration is None:
            parsed.warn(f"{rel_path}: {locator} is not a valid PEP 508 requirement; ignored")
            continue
        parsed.declarations.append(declaration)


def _parse_pep621(project: dict, rel_path: str, parsed: ParsedManifest) -> None:
    dynamic = project.get("dynamic") if isinstance(project.get("dynamic"), list) else []
    for key in ("dependencies", "optional-dependencies"):
        if key in dynamic:
            parsed.warn(f"{rel_path}: project.{key} is dynamic and cannot be read statically")
    if "dependencies" in project:
        _parse_pep508_list(
            project["dependencies"], "runtime", rel_path, "project.dependencies", parsed
        )
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for extra in sorted(optional):
            _parse_pep508_list(
                optional[extra],
                "optional",
                rel_path,
                f"project.optional-dependencies.{extra}",
                parsed,
            )


def _parse_dependency_groups(groups: dict, rel_path: str, parsed: ParsedManifest) -> None:
    for group in sorted(groups):
        scope = "dev" if group == "dev" else "unknown"
        _parse_pep508_list(groups[group], scope, rel_path, f"dependency-groups.{group}", parsed)


def _parse_poetry_tables(poetry: dict, rel_path: str, parsed: ParsedManifest) -> None:
    tables: list[tuple[str, object, str]] = [
        ("tool.poetry.dependencies", poetry.get("dependencies"), "runtime"),
        ("tool.poetry.dev-dependencies", poetry.get("dev-dependencies"), "dev"),
    ]
    poetry_groups = poetry.get("group")
    if isinstance(poetry_groups, dict):
        for group in sorted(poetry_groups):
            body = poetry_groups[group]
            deps = body.get("dependencies") if isinstance(body, dict) else None
            tables.append(
                (
                    f"tool.poetry.group.{group}.dependencies",
                    deps,
                    "dev" if group == "dev" else "unknown",
                )
            )
    for prefix, table, scope in tables:
        if table is None:
            continue
        if not isinstance(table, dict):
            parsed.warn(f"{rel_path}: '{prefix}' is not a table; ignored")
            continue
        for name in sorted(table):
            if name.lower() == "python":
                continue  # interpreter constraint, not a package
            declaration = _poetry_declaration(
                name, table[name], scope, rel_path, f"{prefix}.{name}"
            )
            if declaration is None:
                parsed.warn(f"{rel_path}: {prefix}.{name} has an unsupported form; ignored")
                continue
            parsed.declarations.append(declaration)


def _poetry_declaration(
    name: str, value: object, scope: str, rel_path: str, locator: str
) -> PyDeclaration | None:
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name):
        return None
    spec: str
    conditions: list[str] = []
    if isinstance(value, str):
        spec = value.strip()
    elif isinstance(value, dict):
        if value.get("optional") is True:
            scope = "optional"
        if isinstance(value.get("version"), str):
            spec = value["version"].strip()
        elif any(key in value for key in ("git", "path", "url")):
            spec = "<non-registry source>"  # never echo URLs or paths
        else:
            return None
        for key in ("markers", "python", "platform"):
            if isinstance(value.get(key), str):
                conditions.append(f"{key}: {value[key]}")
    elif isinstance(value, list):
        spec = "<multiple constraints>"
    else:
        return None

    match = _POETRY_EXACT.match(spec)
    exact = match.group(1) if match else None
    if conditions:
        locator = f"{locator} [{'; '.join(conditions)}]"
        spec = f"{spec}; {'; '.join(conditions)}"
    return PyDeclaration(
        name=name,
        normalized=canonicalize_name(name),
        specifier=spec,
        exact_version=exact,
        scope=scope,
        evidence=Evidence(rel_path, "manifest", locator),
    )

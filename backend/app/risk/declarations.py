"""Record the version ranges each manifest declares (read as text, never executed).

The scan checkout is deleted after a scan, so the declared ranges are kept in
``supply_chain.json``. Later checks (for example whether a proposed version fits
the manifest) read them from there instead of guessing.
"""

import json
import tomllib
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement

from app.risk.workflows import _read_text
from app.schemas.inventory import Inventory

MAX_BYTES = 8 * 1024 * 1024


def _npm(text: str) -> dict[str, dict[str, str]]:
    manifest = json.loads(text)
    out: dict[str, dict[str, str]] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = manifest.get(section)
        if isinstance(deps, dict):
            out[section] = {str(k): str(v) for k, v in deps.items() if isinstance(v, str)}
    return out


def _requirements(lines: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        out[requirement.name] = str(requirement.specifier) or "*"
    return out


def _pyproject(text: str) -> dict[str, dict[str, str]]:
    data = tomllib.loads(text)
    project = data.get("project") or {}
    out: dict[str, dict[str, str]] = {}
    if isinstance(project.get("dependencies"), list):
        out["dependencies"] = _requirements([str(d) for d in project["dependencies"]])
    for group, deps in (project.get("optional-dependencies") or {}).items():
        if isinstance(deps, list):
            out[f"optional:{group}"] = _requirements([str(d) for d in deps])
    for group, deps in (data.get("dependency-groups") or {}).items():
        if isinstance(deps, list):
            out[f"group:{group}"] = _requirements([d for d in deps if isinstance(d, str)])
    return out


def manifest_declarations(repo_dir: Path, inventory: Inventory) -> dict[str, dict]:
    """{manifest path: {"ecosystem": ..., "sections": {section: {name: range}}}}."""
    result: dict[str, dict] = {}
    for entry in inventory.manifests:
        name = PurePosixPath(entry.path).name.lower()
        text = _read_text(repo_dir, entry.path, MAX_BYTES)
        if text is None:
            continue
        try:
            if name == "package.json":
                sections = _npm(text)
                ecosystem = "npm"
            elif name == "pyproject.toml":
                sections = _pyproject(text)
                ecosystem = "pypi"
            elif name.startswith("requirements") and name.endswith(".txt"):
                sections = {"requirements": _requirements(text.splitlines())}
                ecosystem = "pypi"
            else:
                continue
        except (ValueError, tomllib.TOMLDecodeError):
            continue
        result[entry.path] = {"ecosystem": ecosystem, "sections": sections}
    return result

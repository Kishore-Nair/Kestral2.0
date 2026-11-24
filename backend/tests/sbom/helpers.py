"""Shared helpers for SBOM tests (local Inventory objects, edge labelling)."""

from __future__ import annotations

from pathlib import Path

from app.schemas.inventory import Inventory

FIXTURES = Path(__file__).parent / "fixtures"
SCAN_ID = "scan_550e8400e29b41d4a716446655440000"

_MANIFESTS = {"package.json": "npm", "pyproject.toml": "python"}
_LOCKS = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "poetry.lock": "python",
    "uv.lock": "python",
    "Pipfile.lock": "python",
}


def make_inventory(repo: Path, scan_id: str = SCAN_ID, partial: bool = False) -> Inventory:
    """Mimic Member 2's inventory for a fixture tree (paths repo-relative, sorted)."""
    manifests, lockfiles = [], []
    for path in sorted(p for p in Path(repo).rglob("*") if p.is_file()):
        rel = path.relative_to(repo).as_posix()
        if "node_modules" in rel.split("/"):
            continue
        name = path.name
        if name in _MANIFESTS:
            manifests.append({"path": rel, "kind": name, "ecosystem": _MANIFESTS[name]})
        elif name.startswith("requirements") and name.endswith(".txt"):
            manifests.append({"path": rel, "kind": name, "ecosystem": "python"})
        elif name in _LOCKS:
            lockfiles.append({"path": rel, "kind": name, "ecosystem": _LOCKS[name]})
    return Inventory.model_validate(
        {
            "schema_version": "1.0",
            "scan_id": scan_id,
            "languages": [],
            "manifests": manifests,
            "lockfiles": lockfiles,
            "dockerfiles": [],
            "ci_files": [],
            "iac_files": [],
            "existing_sboms": [],
            "source_directories": [],
            "file_count": len(manifests) + len(lockfiles),
            "partial": partial,
            "warnings": [],
        }
    )


def labels(document) -> dict[str, str]:
    """Map stable hash IDs back to human labels for golden edge assertions."""
    mapping = {r.root_id: f"ROOT:{r.manifest_path}" for r in document.roots}
    for c in document.components:
        where = c.install_path or c.project_path or "."
        mapping[c.component_id] = f"{c.name}@{c.version}[{where}]"
    return mapping


def edges(document) -> set[tuple[str, str, str]]:
    """(from, to-or-?name, status) triples with IDs resolved to labels."""
    names = labels(document)
    result = set()
    for r in document.relationships:
        target = names[r.to_id] if r.to_id else f"?{r.unresolved_target.name}"
        result.add((names[r.from_id], target, r.resolution_status))
    return result

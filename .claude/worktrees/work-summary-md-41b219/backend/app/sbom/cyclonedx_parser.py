"""Parse a CycloneDX SBOM only as far as it proves facts.

Rules (from the Member 3 plan):
* Read documented fields only: components[] and optional dependencies[].
* Missing version / purl / licenses / hashes are valid limitations -> None or ().
* ``bom-ref`` is SBOM-scoped: map it only when it is unique; otherwise
  report it as ambiguous instead of guessing.
* A component list is NOT a dependency tree. Edges come only from
  ``dependencies[]`` (here) or from lockfiles (other modules).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from packageurl import PackageURL
from packaging.utils import canonicalize_name

# Component types we treat as packages. Syft also emits "file" entries
# (file hashes), which are not dependencies.
PACKAGE_TYPES = frozenset({"library", "framework", "application"})

# purl type -> our ecosystem name
_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "pypi",
    "github": "github-actions",
}


class CycloneDXFormatError(ValueError):
    """The document is not a usable CycloneDX JSON SBOM."""


@dataclass(frozen=True)
class SbomComponent:
    index: int  # position in components[]; used for evidence locators
    bom_ref: str | None
    type: str
    name: str
    normalized_name: str
    version: str | None
    purl: str | None
    ecosystem: str | None
    licenses: tuple[tuple[str | None, str | None], ...] = ()  # (spdx_id, name)
    hashes: tuple[tuple[str, str], ...] = ()  # (algorithm, value)
    found_by: str | None = None  # Syft cataloger that found it
    package_type: str | None = None  # Syft package type, e.g. "npm", "github-action"
    locations: tuple[str, ...] = ()  # repo paths Syft saw it in

    @property
    def evidence_locator(self) -> str:
        return f"components[{self.index}]"

    @property
    def is_package(self) -> bool:
        return self.type in PACKAGE_TYPES


@dataclass(frozen=True)
class SbomDependency:
    ref: str
    depends_on: tuple[str, ...]
    index: int = 0  # position in dependencies[]; used for evidence locators


@dataclass
class ParsedSbom:
    spec_version: str | None
    tool_name: str | None
    tool_version: str | None
    components: list[SbomComponent] = field(default_factory=list)
    dependencies: list[SbomDependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def packages(self) -> list[SbomComponent]:
        """Components that are packages (excludes file entries)."""
        return [c for c in self.components if c.is_package]

    def unique_bom_refs(self) -> dict[str, SbomComponent]:
        """bom-ref -> component, only for refs that appear exactly once."""
        counts: dict[str, int] = {}
        for c in self.components:
            if c.bom_ref:
                counts[c.bom_ref] = counts.get(c.bom_ref, 0) + 1
        return {c.bom_ref: c for c in self.components if c.bom_ref and counts[c.bom_ref] == 1}

    def ambiguous_bom_refs(self) -> set[str]:
        """bom-refs used by more than one component (must not be mapped)."""
        seen: set[str] = set()
        dupes: set[str] = set()
        for c in self.components:
            if c.bom_ref:
                (dupes if c.bom_ref in seen else seen).add(c.bom_ref)
        return dupes


def validate_cyclonedx(data: object) -> dict:
    if not isinstance(data, dict):
        raise CycloneDXFormatError("SBOM must be a JSON object")
    if data.get("bomFormat") != "CycloneDX":
        raise CycloneDXFormatError("bomFormat must be 'CycloneDX'")
    if not isinstance(data.get("components", []), list):
        raise CycloneDXFormatError("'components' must be a list")
    if not isinstance(data.get("dependencies", []), list):
        raise CycloneDXFormatError("'dependencies' must be a list")
    return data


def load_cyclonedx(path: Path) -> ParsedSbom:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CycloneDXFormatError("SBOM file could not be read as JSON") from exc
    return parse_cyclonedx(data)


def parse_cyclonedx(data: object) -> ParsedSbom:
    data = validate_cyclonedx(data)
    tool_name, tool_version = _tool_info(data.get("metadata"))
    sbom = ParsedSbom(
        spec_version=_str_or_none(data.get("specVersion")),
        tool_name=tool_name,
        tool_version=tool_version,
    )

    for index, raw in enumerate(data.get("components", [])):
        component = _parse_component(index, raw, sbom.warnings)
        if component is not None:
            sbom.components.append(component)

    for i, raw in enumerate(data.get("dependencies", [])):
        if not isinstance(raw, dict) or not isinstance(raw.get("ref"), str):
            sbom.warnings.append(f"dependencies[{i}] skipped: missing 'ref'")
            continue
        targets = raw.get("dependsOn", [])
        if not isinstance(targets, list):
            sbom.warnings.append(f"dependencies[{i}] skipped: 'dependsOn' is not a list")
            continue
        sbom.dependencies.append(
            SbomDependency(
                ref=raw["ref"],
                depends_on=tuple(t for t in targets if isinstance(t, str)),
                index=i,
            )
        )

    for ref in sorted(sbom.ambiguous_bom_refs()):
        sbom.warnings.append(f"bom-ref '{ref}' is used by multiple components; not mapped")
    return sbom


def _parse_component(index: int, raw: object, warnings: list[str]) -> SbomComponent | None:
    if not isinstance(raw, dict):
        warnings.append(f"components[{index}] skipped: not an object")
        return None
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        warnings.append(f"components[{index}] skipped: missing name")
        return None
    if raw.get("components"):
        warnings.append(f"components[{index}] has nested components; they are not parsed")

    purl_str = _str_or_none(raw.get("purl"))
    purl_type: str | None = None
    if purl_str:
        try:
            purl_type = PackageURL.from_string(purl_str).type
        except ValueError:
            warnings.append(f"components[{index}] has an invalid purl; purl ignored")
            purl_str = None

    ecosystem = _ECOSYSTEMS.get(purl_type, purl_type) if purl_type else None
    normalized = canonicalize_name(name) if ecosystem == "pypi" else name

    properties = _properties(raw.get("properties"))
    locations = tuple(
        value
        for key, value in properties
        if key.startswith("syft:location:") and key.endswith(":path")
    )

    return SbomComponent(
        index=index,
        bom_ref=_str_or_none(raw.get("bom-ref")),
        type=_str_or_none(raw.get("type")) or "unknown",
        name=name,
        normalized_name=normalized,
        version=_str_or_none(raw.get("version")),
        purl=purl_str,
        ecosystem=ecosystem,
        licenses=_licenses(raw.get("licenses")),
        hashes=_hashes(raw.get("hashes")),
        found_by=_first(properties, "syft:package:foundBy"),
        package_type=_first(properties, "syft:package:type"),
        locations=locations,
    )


def _licenses(raw: object) -> tuple[tuple[str | None, str | None], ...]:
    """Licenses as ``(spdx_id, name)`` pairs, matching M1's ``License{id,name}``.

    An SPDX expression has no single id, so it is kept verbatim as the name.
    """
    result: list[tuple[str | None, str | None]] = []
    if not isinstance(raw, list):
        return ()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("expression"), str) and entry["expression"]:
            result.append((None, entry["expression"]))
            continue
        lic = entry.get("license")
        if isinstance(lic, dict):
            spdx_id = _str_or_none(lic.get("id"))
            name = _str_or_none(lic.get("name"))
            if spdx_id or name:
                result.append((spdx_id, name))
    return tuple(dict.fromkeys(result))  # de-duplicate, keep order


def _hashes(raw: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, list):
        return ()
    return tuple(
        (h["alg"], h["content"])
        for h in raw
        if isinstance(h, dict)
        and isinstance(h.get("alg"), str)
        and isinstance(h.get("content"), str)
    )


def _properties(raw: object) -> list[tuple[str, str]]:
    if not isinstance(raw, list):
        return []
    return [
        (p["name"], p["value"])
        for p in raw
        if isinstance(p, dict)
        and isinstance(p.get("name"), str)
        and isinstance(p.get("value"), str)
    ]


def _first(properties: list[tuple[str, str]], key: str) -> str | None:
    return next((value for name, value in properties if name == key), None)


def _tool_info(metadata: object) -> tuple[str | None, str | None]:
    """Read the generating tool from CycloneDX 1.5+ or legacy 1.4 metadata."""
    if not isinstance(metadata, dict):
        return None, None
    tools = metadata.get("tools")
    candidates: list = []
    if isinstance(tools, dict):  # 1.5+: {"components": [...]}
        candidates = tools.get("components", []) or []
    elif isinstance(tools, list):  # 1.4: [{"name":..., "version":...}]
        candidates = tools
    for tool in candidates:
        if isinstance(tool, dict) and isinstance(tool.get("name"), str):
            return tool["name"], _str_or_none(tool.get("version"))
    return None, None


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value != "" else None

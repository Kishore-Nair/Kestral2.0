"""Reconcile Syft components with lockfile/manifest records and finalize.

Merging uses strong identity only: ecosystem + normalized name + exact version
+ the lockfile/manifest Syft says it read (its ``syft:location`` path). One
match enriches that instance; several matches enrich each *without* collapsing
their IDs; no match keeps a Syft-only component in an ``unknown-location``
namespace. Lockfile edges are authoritative: Syft's own ``dependencies[]`` are
used only for packages that no lockfile/manifest describes.
"""

from __future__ import annotations

from packaging.utils import canonicalize_name

from app.schemas.dependency import DependencyDocument

from .cyclonedx_parser import ParsedSbom, SbomComponent
from .identities import syft_only_component_id
from .records import (
    ComponentRecord,
    Evidence,
    ExtractionResult,
    RelationshipRecord,
    project_path_of,
    resolved_edge,
    unresolved_edge,
)
from .syft_runner import SBOM_FILENAME

SYFT_KIND = "syft-sbom"
_ROOT = "root"
_AMBIGUOUS = "ambiguous"


class DocumentIntegrityError(ValueError):
    """The normalized document violates a data-quality invariant."""


def _syft_locations(component: SbomComponent) -> list[str]:
    return sorted({loc.lstrip("/") for loc in component.locations if loc.strip("/")})


def reconcile_with_sbom(result: ExtractionResult, sbom: ParsedSbom) -> None:
    index: dict[tuple[str, str, str], list[ComponentRecord]] = {}
    for component in result.components:
        if component.version is not None:
            key = (component.ecosystem, component.normalized_name, component.version)
            index.setdefault(key, []).append(component)

    root_files: dict[tuple[str, str], str] = {}  # (ecosystem, name) per project file -> root_id
    for root in result.roots:
        name = canonicalize_name(root.name) if root.ecosystem == "pypi" else root.name
        for path in _project_files(result, root.path, root.manifest_path):
            root_files[(path, f"{root.ecosystem}:{name}")] = root.root_id

    syft_only: dict[str, ComponentRecord] = {}
    ref_map: dict[str, tuple[str, list[ComponentRecord]]] = {}
    matched_ids: set[str] = set()
    unique_refs = sbom.unique_bom_refs()

    for sbom_component in sbom.packages():
        ecosystem = sbom_component.ecosystem or "unknown"
        locations = _syft_locations(sbom_component)
        evidence = Evidence(SBOM_FILENAME, SYFT_KIND, sbom_component.evidence_locator)
        is_unique_ref = sbom_component.bom_ref in unique_refs

        if any(
            (loc, f"{ecosystem}:{sbom_component.normalized_name}") in root_files
            for loc in locations
        ):
            if is_unique_ref:
                ref_map[sbom_component.bom_ref] = (_ROOT, [])
            continue  # Syft lists the project itself; it is a root, not a dependency

        candidates = []
        if sbom_component.version is not None:
            key = (ecosystem, sbom_component.normalized_name, sbom_component.version)
            candidates = [c for c in index.get(key, []) if c.context_path in locations]

        if candidates:
            for component in candidates:
                component.add_evidence(evidence)
                component.add_licenses(sbom_component.licenses)
                matched_ids.add(component.component_id)
            if len(candidates) == 1:
                only = candidates[0]
                only.add_hashes(sbom_component.hashes)
                if only.purl is None and sbom_component.purl:
                    only.purl = sbom_component.purl
            if is_unique_ref:
                ref_map[sbom_component.bom_ref] = (
                    "lock" if len(candidates) == 1 else _AMBIGUOUS,
                    candidates,
                )
            continue

        cid = syft_only_component_id(
            ecosystem,
            sbom_component.normalized_name,
            sbom_component.version,
            sbom_component.purl,
            locations,
        )
        component = syft_only.get(cid)
        if component is None:
            component = ComponentRecord(
                component_id=cid,
                name=sbom_component.name,
                normalized_name=sbom_component.normalized_name,
                version=sbom_component.version,
                ecosystem=ecosystem,
                purl=sbom_component.purl,
                install_path=None,
                project_path=project_path_of(locations[0]) if len(locations) == 1 else "",
                scope="unknown",
                evidence=[evidence],
                resolved=sbom_component.version is not None,
                licenses=list(sbom_component.licenses),
                hashes=list(sbom_component.hashes),
                context_path=None,
            )
            syft_only[cid] = component
        else:
            component.add_evidence(evidence)
            component.add_licenses(sbom_component.licenses)
        if is_unique_ref:
            ref_map[sbom_component.bom_ref] = ("syft", [component])

    result.components.extend(syft_only[cid] for cid in sorted(syft_only))
    _syft_edges(result, sbom, ref_map)

    if syft_only:
        result.warn(
            f"Syft reported {len(syft_only)} packages with no lockfile/manifest evidence; "
            "kept as Syft-only components with unknown directness"
        )
    missing = [
        c
        for c in result.components
        if c.context_path is not None and c.component_id not in matched_ids
    ]
    if missing:
        result.warn(
            f"SBOM coverage discrepancy: {len(missing)} lockfile/manifest components were "
            "not reported by Syft (kept, with their own evidence)",
            partial=False,
        )


def _project_files(result: ExtractionResult, project_path: str, manifest_path: str) -> set[str]:
    files = {manifest_path}
    for component in result.components:
        if component.project_path == project_path and component.context_path:
            files.add(component.context_path)
    for name in ("package-lock.json", "npm-shrinkwrap.json", "poetry.lock", "uv.lock"):
        files.add(f"{project_path}/{name}" if project_path else name)
    return files


def _syft_edges(
    result: ExtractionResult,
    sbom: ParsedSbom,
    ref_map: dict[str, tuple[str, list[ComponentRecord]]],
) -> None:
    ignored = 0
    for dependency in sbom.dependencies:
        source = ref_map.get(dependency.ref)
        if source is None:
            continue
        kind, components = source
        if kind != "syft":
            ignored += len(dependency.depends_on)  # lockfile evidence is authoritative here
            continue
        from_id = components[0].component_id
        for position, target_ref in enumerate(dependency.depends_on):
            target = ref_map.get(target_ref)
            if target is None or target[0] == _ROOT:
                continue
            evidence = [
                Evidence(
                    SBOM_FILENAME,
                    SYFT_KIND,
                    f"dependencies[{dependency.index}].dependsOn[{position}]",
                )
            ]
            target_kind, targets = target
            if target_kind == _AMBIGUOUS:
                sample = targets[0]
                result.relationships.append(
                    unresolved_edge(
                        from_id,
                        sample.name,
                        sample.version or "",
                        sample.ecosystem,
                        evidence,
                        "ambiguous",
                    )
                )
            else:
                result.relationships.append(
                    resolved_edge(from_id, targets[0].component_id, evidence)
                )
    if ignored:
        result.warn(
            f"{ignored} Syft dependency references were not used because lockfile "
            "relationships are authoritative for those packages",
            partial=False,
        )


# --------------------------------------------------------------------------
# Finalization
# --------------------------------------------------------------------------


def _merge_relationships(
    relationships: list[RelationshipRecord],
) -> list[tuple[str, RelationshipRecord]]:
    unique: dict[str, RelationshipRecord] = {}
    for relationship in relationships:
        relationship.evidence = sorted(set(relationship.evidence))
        unique.setdefault(relationship.relationship_id, relationship)  # exact duplicates only
    return sorted(unique.items())


def finalize(result: ExtractionResult, scan_id: str) -> DependencyDocument:
    roots = {}
    for root in result.roots:
        roots.setdefault(root.root_id, root)

    components: dict[str, ComponentRecord] = {}
    for component in result.components:
        existing = components.get(component.component_id)
        if existing is None:
            components[component.component_id] = component
        else:  # same instance reached twice: merge evidence, never duplicate
            for item in component.evidence:
                existing.add_evidence(item)

    relationships = _merge_relationships(result.relationships)
    partial = result.partial or any(r.resolution_status != "resolved" for _, r in relationships)

    payload = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "roots": [
            {
                "root_id": r.root_id,
                "name": r.name,
                "path": r.path,
                "manifest_path": r.manifest_path,
                "ecosystem": r.ecosystem,
            }
            for _, r in sorted(roots.items())
        ],
        "components": [
            {
                "component_id": c.component_id,
                "name": c.name,
                "version": c.version,
                "ecosystem": c.ecosystem,
                "purl": c.purl,
                "install_path": c.install_path,
                "project_path": c.project_path,
                "scope": c.scope,
                "licenses": [{"id": spdx_id, "name": name} for spdx_id, name in c.licenses],
                "hashes": [{"alg": alg, "content": content} for alg, content in c.hashes],
                "evidence": [e.as_dict() for e in sorted(set(c.evidence))],
                "resolved": c.resolved,
            }
            for _, c in sorted(components.items())
        ],
        "relationships": [
            {
                "relationship_id": rid,
                "from_id": r.from_id,
                "to_id": r.to_id,
                "unresolved_target": r.unresolved_target,
                "resolution_status": r.resolution_status,
                "type": "DEPENDS_ON",
                "evidence": [e.as_dict() for e in r.evidence],
            }
            for rid, r in relationships
        ],
        "partial": partial,
        "warnings": list(dict.fromkeys(result.warnings)),
    }
    check_integrity(payload)
    return DependencyDocument.model_validate(payload)


def check_integrity(document: dict) -> None:
    """Enforce the Member 3 data-quality invariants; raise on any violation."""
    root_ids = [r["root_id"] for r in document["roots"]]
    component_ids = [c["component_id"] for c in document["components"]]
    if len(set(root_ids)) != len(root_ids) or len(set(component_ids)) != len(component_ids):
        raise DocumentIntegrityError("duplicate root_id or component_id")
    if set(root_ids) & set(component_ids):
        raise DocumentIntegrityError("root and component IDs overlap")
    scan_id = document.get("scan_id") or "\x00"
    known_sources = set(root_ids) | set(component_ids)
    relationship_ids = set()
    for component in document["components"]:
        if not component["evidence"]:
            raise DocumentIntegrityError(f"component {component['component_id']} has no evidence")
        if component["scope"] not in ("runtime", "dev", "optional", "unknown"):
            raise DocumentIntegrityError("invalid scope")
    for rel in document["relationships"]:
        rid = rel["relationship_id"]
        if rid in relationship_ids:
            raise DocumentIntegrityError("duplicate relationship_id")
        relationship_ids.add(rid)
        if rel["from_id"] not in known_sources:
            raise DocumentIntegrityError(f"{rid}: from_id is not a root or component")
        if rel["resolution_status"] == "resolved":
            if (
                rel["to_id"] is None
                or rel["to_id"] not in component_ids
                or rel["unresolved_target"]
            ):
                raise DocumentIntegrityError(f"{rid}: resolved edge must target a known component")
        else:
            if rel["to_id"] is not None or not rel["unresolved_target"]:
                raise DocumentIntegrityError(
                    f"{rid}: unresolved edge needs to_id=null and a target"
                )
        if not rel["evidence"]:
            raise DocumentIntegrityError(f"{rid}: relationship has no evidence")
    for identity in [*root_ids, *component_ids, *relationship_ids]:
        if scan_id in identity:
            raise DocumentIntegrityError("scan id leaked into a stable identity")
    for item in _all_evidence(document):
        path = item["path"]
        if path.startswith("/") or "://" in path or "\\" in path or ".." in path.split("/"):
            raise DocumentIntegrityError("evidence path must be repo- or scan-relative")
        if item["kind"] == SYFT_KIND and path != SBOM_FILENAME:
            raise DocumentIntegrityError("syft-sbom evidence must point to sbom.cdx.json")


def _all_evidence(document: dict):
    for component in document["components"]:
        yield from component["evidence"]
    for rel in document["relationships"]:
        yield from rel["evidence"]

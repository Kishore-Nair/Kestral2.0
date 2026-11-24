"""What changed since the previous scan of the same repository.

Compares this scan's normalized dependency document (and a snapshot of manifest,
lockfile, container and CI file hashes) with the last completed scan's. Raises
findings for the changes that deserve a look:

- unexpected_dependency  a package appeared although no manifest changed
- new_dependency         a package appeared (manifest changed too)
- version_downgrade      a package moved to a lower version
- lockfile_drift         a lockfile changed while every manifest stayed the same
"""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import networkx as nx

from app.graph.serialization import stable_id
from app.risk.suspicious import _attach, _read_text
from app.schemas.dependency import DependencyComponent, DependencyDocument
from app.schemas.findings import (
    ChangeSummary,
    FileChange,
    Finding,
    FindingSource,
    PackageChange,
)
from app.schemas.inventory import Evidence, Inventory

SNAPSHOT_FILE = "supply_chain.json"
CHANGES_FILE = "changes.json"
SOURCE = "scan-diff"
LIST_CAP = 200
FINDING_CAP = 60
MAX_HASH_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class Baseline:
    scan_id: str
    directory: Path
    commit_sha: str | None
    resolved_ref: str | None
    finished_at: str | None


def file_snapshot(repo_dir: Path, inventory: Inventory) -> dict[str, str]:
    """sha256 of every manifest, lockfile, container and CI file (paths repo-relative)."""
    paths = {
        *(m.path for m in inventory.manifests),
        *(lock.path for lock in inventory.lockfiles),
        *inventory.dockerfiles,
        *inventory.ci_files,
    }
    hashes: dict[str, str] = {}
    for path in sorted(paths):
        text = _read_text(repo_dir, path, MAX_HASH_BYTES)
        if text is not None:
            hashes[path] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return hashes


def _version_key(version: str) -> tuple | None:
    parts = re.findall(r"\d+", version.split("+", 1)[0])
    if not parts:
        return None
    prerelease = 0 if re.search(r"[-.]?(a|b|rc|alpha|beta|pre|dev)\d*", version, re.I) else 1
    return (*(int(p) for p in parts[:4]), prerelease)


def _group(
    components: list[DependencyComponent],
) -> dict[tuple[str, str, str], list[DependencyComponent]]:
    groups: dict[tuple[str, str, str], list[DependencyComponent]] = {}
    for component in components:
        key = (component.ecosystem, component.project_path, component.name.lower())
        groups.setdefault(key, []).append(component)
    return groups


def _change(key: tuple[str, str, str], before: list, after: list) -> PackageChange:
    sample = (after or before)[0]
    return PackageChange(
        ecosystem=key[0],
        name=sample.name,
        project_path=key[1],
        from_versions=sorted({c.version or "?" for c in before}),
        to_versions=sorted({c.version or "?" for c in after}),
        component_id=after[0].component_id if after else None,
    )


def _direction(change: PackageChange) -> str:
    if len(change.from_versions) != 1 or len(change.to_versions) != 1:
        return "other"
    old, new = _version_key(change.from_versions[0]), _version_key(change.to_versions[0])
    if old is None or new is None or old == new:
        return "other"
    return "upgraded" if new > old else "downgraded"


def _lockfiles(components: list[DependencyComponent]) -> set[str]:
    return {e.path for c in components for e in c.evidence if e.kind == "lockfile"}


def _from_gap(components: list[DependencyComponent], gaps: set[str]) -> bool:
    return any(e.kind == "lockfile" and e.path in gaps for c in components for e in c.evidence)


def _extraction_gaps(
    current: DependencyDocument,
    baseline_doc: DependencyDocument,
    current_files: dict[str, str],
    baseline_files: dict[str, str] | None,
) -> tuple[set[str], list[str]]:
    """Lockfiles that yielded packages in only one scan although the file existed in both.

    Their packages would all look added or removed, which is a gap in extraction (for
    example an unsupported lockfile version), not a change in the supply chain.
    """
    now, before = _lockfiles(current.components), _lockfiles(baseline_doc.components)
    gaps: set[str] = set()
    caveats: list[str] = []
    for path in sorted(now ^ before):
        existed_both = baseline_files is None or (path in baseline_files and path in current_files)
        if not existed_both:
            continue  # the lockfile itself was added or removed: a real change
        gaps.add(path)
        which = "the earlier scan" if path in now else "this scan"
        caveats.append(
            f"{path}: no packages were extracted from it in {which}, so its packages are "
            "left out of added/removed instead of being reported as changes"
        )
    return gaps, caveats


def compare(
    current: DependencyDocument,
    baseline_doc: DependencyDocument,
    baseline: Baseline,
    current_commit: str | None,
    current_files: dict[str, str],
    baseline_files: dict[str, str] | None,
) -> ChangeSummary:
    gaps, caveats = _extraction_gaps(current, baseline_doc, current_files, baseline_files)
    now, before = _group(current.components), _group(baseline_doc.components)
    new_keys = sorted(k for k in now.keys() - before.keys() if not _from_gap(now[k], gaps))
    gone_keys = sorted(k for k in before.keys() - now.keys() if not _from_gap(before[k], gaps))
    excluded = len(now.keys() ^ before.keys()) - len(new_keys) - len(gone_keys)
    added = [_change(k, [], now[k]) for k in new_keys]
    removed = [_change(k, before[k], []) for k in gone_keys]
    buckets: dict[str, list[PackageChange]] = {"upgraded": [], "downgraded": [], "other": []}
    for key in sorted(now.keys() & before.keys()):
        old = {c.version for c in before[key]}
        new = {c.version for c in now[key]}
        if old != new:
            change = _change(key, before[key], now[key])
            buckets[_direction(change)].append(change)

    files_changed: list[FileChange] = []
    if baseline_files is not None:
        for path in sorted(current_files.keys() | baseline_files.keys()):
            if path not in baseline_files:
                files_changed.append(FileChange(path=path, change="added"))
            elif path not in current_files:
                files_changed.append(FileChange(path=path, change="removed"))
            elif current_files[path] != baseline_files[path]:
                files_changed.append(FileChange(path=path, change="modified"))

    lists = {
        "added": added,
        "removed": removed,
        "upgraded": buckets["upgraded"],
        "downgraded": buckets["downgraded"],
        "other_changes": buckets["other"],
    }
    return ChangeSummary(
        baseline_scan_id=baseline.scan_id,
        baseline_commit=baseline.commit_sha,
        baseline_ref=baseline.resolved_ref,
        baseline_finished_at=baseline.finished_at,
        current_commit=current_commit,
        same_commit=bool(current_commit and current_commit == baseline.commit_sha),
        **{name: items[:LIST_CAP] for name, items in lists.items()},
        totals={**{name: len(items) for name, items in lists.items()}, "excluded": excluded},
        extraction_gaps=sorted(gaps),
        caveats=caveats,
        files_compared=baseline_files is not None,
        files_changed=files_changed,
        truncated=any(len(items) > LIST_CAP for items in lists.values()),
    )


def change_findings(
    summary: ChangeSummary,
    current: DependencyDocument,
    inventory: Inventory,
    graph: nx.DiGraph | None,
) -> list[Finding]:
    by_id = {c.component_id: c for c in current.components}
    manifests = {m.path for m in inventory.manifests}
    locks = {lock.path for lock in inventory.lockfiles}
    changed = {f.path for f in summary.files_changed}
    baseline_ref = f"{summary.baseline_scan_id} ({(summary.baseline_commit or '?')[:12]})"
    manifest_changed = bool(changed & manifests) if summary.files_compared else None
    findings: list[Finding] = []

    def finding(category, title, label, evidence, level, reason, uncertainty, component, record):
        data = {
            "finding_id": stable_id("finding", "change", category, record),
            "kind": "suspicious",
            "category": category,
            "title": title,
            "subject_id": None,
            "subject_label": label,
            "advisory_ids": [],
            "sources": [FindingSource(name=SOURCE, record_id=record)],
            "fixed_versions": [],
            "evidence": evidence,
            "risk_level": level,
            "risk_reason": reason,
            "uncertainty": uncertainty,
        }
        return Finding(**_attach(data, component, graph))

    for change in summary.added[:FINDING_CAP]:
        component = by_id.get(change.component_id or "")
        label = f"{change.name}@{','.join(change.to_versions)}"
        evidence = [
            *(component.evidence[:1] if component else []),
            Evidence(
                path=CHANGES_FILE,
                kind="scan-diff",
                locator=f"added: {label} (baseline {baseline_ref})",
            ),
        ]
        if manifest_changed is False:
            findings.append(
                finding(
                    "unexpected_dependency",
                    f"{label} appeared although no manifest changed",
                    label,
                    evidence,
                    "medium",
                    "A new package arrived through the lockfile alone, without a declared change",
                    ["Regenerating a lockfile can legitimately pull new transitive packages"],
                    component,
                    f"added:{change.ecosystem}:{change.project_path}:{change.name}",
                )
            )
        else:
            findings.append(
                finding(
                    "new_dependency",
                    f"New dependency {label} since the last scan",
                    label,
                    evidence,
                    "low",
                    "New code entered the supply chain; review that it is intended",
                    []
                    if manifest_changed
                    else ["Manifest changes not compared (older baseline scan)"],
                    component,
                    f"added:{change.ecosystem}:{change.project_path}:{change.name}",
                )
            )
    for change in summary.downgraded[:FINDING_CAP]:
        component = by_id.get(change.component_id or "")
        label = f"{change.name} {change.from_versions[0]} → {change.to_versions[0]}"
        findings.append(
            finding(
                "version_downgrade",
                f"{change.name} was downgraded",
                label,
                [
                    *(component.evidence[:1] if component else []),
                    Evidence(path=CHANGES_FILE, kind="scan-diff", locator=f"downgraded: {label}"),
                ],
                "medium",
                "Downgrades can reintroduce fixed vulnerabilities",
                ["A downgrade may be a deliberate compatibility rollback"],
                component,
                f"downgraded:{change.ecosystem}:{change.project_path}:{change.name}",
            )
        )
    if summary.files_compared and not (changed & manifests):
        for path in sorted(changed & locks):
            findings.append(
                finding(
                    "lockfile_drift",
                    f"{path} changed but no manifest did",
                    path,
                    [
                        Evidence(
                            path=path,
                            kind="lockfile",
                            locator=f"sha256 differs from baseline {baseline_ref}",
                        )
                    ],
                    "medium",
                    "Locked versions or sources changed without a declared dependency change",
                    ["`npm update` / `uv lock --upgrade` change lockfiles legitimately"],
                    None,
                    f"lockfile:{path}",
                )
            )
    return findings


def load_baseline(baseline: Baseline) -> tuple[DependencyDocument, dict[str, str] | None] | None:
    try:
        document = DependencyDocument.model_validate_json(
            (baseline.directory / "normalized.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return None
    try:
        files = json.loads((baseline.directory / SNAPSHOT_FILE).read_text(encoding="utf-8"))
        hashes = files.get("files")
        files_map = hashes if isinstance(hashes, dict) else None
    except (OSError, ValueError):
        files_map = None
    return document, files_map

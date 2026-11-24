"""Read-only view of one completed scan's saved artifacts, plus the per-analysis evidence store.

Everything the AI analyst sees comes from here or from a registered tool. Artifacts
are read with size limits and never written.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import networkx as nx

from app.graph.builder import make_networkx_graph
from app.schemas.ai import EvidenceItem
from app.schemas.dependency import DependencyComponent, DependencyDocument
from app.schemas.findings import Finding, FindingsDocument

MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_SUMMARY = 600

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|authorization)\s*[:=]\s*\S+"),
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]


def redact(text: str) -> str:
    """Remove secret-looking values before anything reaches the model or the audit log."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def clip(text: str, limit: int = MAX_SUMMARY) -> str:
    text = redact(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


class BundleError(RuntimeError):
    """The scan's artifacts are missing or unreadable."""


def _load_json(path: Path, required: bool = True) -> dict | None:
    if not path.is_file():
        if required:
            raise BundleError(f"{path.name} is missing")
        return None
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise BundleError(f"{path.name} is too large")
    return json.loads(path.read_text(encoding="utf-8"))


@dataclass
class ScanBundle:
    scan_id: str
    commit_sha: str | None
    repository_url: str
    resolved_ref: str | None
    app_name: str
    findings: FindingsDocument
    document: DependencyDocument
    graph_json: dict
    osv: dict | None
    grype: dict | None
    nvd: dict | None
    changes: dict | None
    snapshot: dict | None
    digest: str
    graph: nx.DiGraph = field(init=False)

    def __post_init__(self) -> None:
        self.graph = make_networkx_graph(self.document, self.app_name)
        self._components = {c.component_id: c for c in self.document.components}
        self._findings = {f.finding_id: f for f in self.findings.findings}
        self._edges = {
            (e["data"]["source"], e["data"]["target"])
            for e in self.graph_json.get("edges", [])
            if e.get("data", {}).get("type") == "DEPENDS_ON"
        }

    @classmethod
    def load(
        cls,
        scan_dir: Path,
        *,
        scan_id: str,
        commit_sha: str | None,
        repository_url: str,
        resolved_ref: str | None,
        app_name: str,
    ) -> "ScanBundle":
        try:
            findings_bytes = (scan_dir / "findings.json").read_bytes()
            normalized_bytes = (scan_dir / "normalized.json").read_bytes()
            findings = FindingsDocument.model_validate_json(findings_bytes)
            document = DependencyDocument.model_validate_json(normalized_bytes)
            graph_json = _load_json(scan_dir / "graph.json") or {}
        except (OSError, ValueError) as exc:
            raise BundleError(f"Scan artifacts could not be read: {type(exc).__name__}") from exc
        if findings.scan_id != scan_id or document.scan_id != scan_id:
            raise BundleError("Artifact scan ID does not match the scan")
        digest = hashlib.sha256(findings_bytes + b"\0" + normalized_bytes).hexdigest()
        return cls(
            scan_id=scan_id,
            commit_sha=commit_sha,
            repository_url=repository_url,
            resolved_ref=resolved_ref,
            app_name=app_name,
            findings=findings,
            document=document,
            graph_json=graph_json,
            osv=_load_json(scan_dir / "osv.json", required=False),
            grype=_load_json(scan_dir / "grype.json", required=False),
            nvd=_load_json(scan_dir / "nvd.json", required=False),
            changes=_load_json(scan_dir / "changes.json", required=False),
            snapshot=_load_json(scan_dir / "supply_chain.json", required=False),
            digest=digest,
        )

    def finding(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def component(self, component_id: str) -> DependencyComponent | None:
        return self._components.get(component_id)

    def has_edge(self, source: str, target: str) -> bool:
        return (source, target) in self._edges

    def osv_record(self, advisory_id: str) -> dict | None:
        records = (self.osv or {}).get("records") or {}
        if advisory_id in records:
            return records[advisory_id]
        for record in records.values():
            if advisory_id in (record.get("aliases") or []):
                return record
        return None

    def nvd_record(self, cve_id: str) -> dict | None:
        entry = ((self.nvd or {}).get("records") or {}).get(cve_id)
        return entry.get("cve") if isinstance(entry, dict) else None

    def declared_ranges(self, component: DependencyComponent) -> list[tuple[str, str, str]]:
        """(manifest path, section, range) for this package in its own project's manifests."""
        declarations = (self.snapshot or {}).get("declarations") or {}
        out = []
        wanted = component.name.lower()
        project = component.project_path.strip("/")
        for path, entry in sorted(declarations.items()):
            if entry.get("ecosystem") != component.ecosystem:
                continue
            parent = str(PurePosixPath(path).parent)
            if (parent if parent != "." else "") != project:
                continue  # another project's manifest (e.g. an example app)
            for section, deps in (entry.get("sections") or {}).items():
                for name, spec in deps.items():
                    if name.lower() == wanted:
                        out.append((path, section, spec))
        return out


class EvidenceStore:
    """Numbered facts for one analysis. Claims may only cite IDs that exist here."""

    def __init__(self) -> None:
        self.items: list[EvidenceItem] = []
        self._keys: dict[str, str] = {}

    def add(self, key: str, kind: str, source: str, summary: str, external: bool = False) -> str:
        if key in self._keys:
            return self._keys[key]
        evidence_id = f"ev-{len(self.items) + 1}"
        self.items.append(
            EvidenceItem(
                id=evidence_id, kind=kind, source=source, summary=clip(summary), external=external
            )
        )
        self._keys[key] = evidence_id
        return evidence_id

    def ids(self) -> set[str]:
        return {item.id for item in self.items}

    def key(self, evidence_id: str) -> str | None:
        return next((k for k, v in self._keys.items() if v == evidence_id), None)

    def get(self, evidence_id: str) -> EvidenceItem | None:
        return next((i for i in self.items if i.id == evidence_id), None)

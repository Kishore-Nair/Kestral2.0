"""Stable lazy adapters for the three independently owned backend modules."""

from pathlib import Path

from app.schemas.dependency import DependencyDocument
from app.schemas.graph import GraphDocument
from app.schemas.inventory import Inventory


class PipelineComponentUnavailable(RuntimeError):
    pass


def discover_repository(repo_dir: Path, scan_id: str) -> Inventory:
    try:
        from app.discovery.engine import discover_repository as implementation
    except ImportError as exc:
        raise PipelineComponentUnavailable("M2 discovery module is not installed") from exc
    return implementation(repo_dir, scan_id)


def generate_dependency_document(
    repo_dir: Path,
    inventory: Inventory,
    scan_id: str,
    scan_dir: Path,
) -> DependencyDocument:
    try:
        from app.sbom.pipeline import generate_dependency_document as implementation
    except ImportError as exc:
        raise PipelineComponentUnavailable("M3 SBOM module is not installed") from exc
    return implementation(repo_dir, inventory, scan_id, scan_dir)


def build_graph(document: DependencyDocument, app_name: str) -> GraphDocument:
    try:
        from app.graph.builder import build_graph as implementation
    except ImportError as exc:
        raise PipelineComponentUnavailable("M4 graph module is not installed") from exc
    return implementation(document, app_name)


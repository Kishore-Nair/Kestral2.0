"""Cytoscape-compatible graph contract produced by M4 and consumed by M5."""

from typing import Annotated, Literal

from pydantic import Field

from app.schemas.base import StrictModel
from app.schemas.dependency import UnresolvedTarget
from app.schemas.inventory import Evidence


class ApplicationNodeData(StrictModel):
    id: str
    label: str
    type: Literal["application"]
    directness: Literal["not_applicable"]
    depth: None = None


class ProjectNodeData(StrictModel):
    id: str
    label: str
    type: Literal["project"]
    directness: Literal["not_applicable"]
    depth: Literal[0]
    project_path: str


class PackageNodeData(StrictModel):
    id: str
    label: str
    type: Literal["package"]
    directness: Literal["direct", "transitive", "unknown"]
    depth: int | None = Field(default=None, ge=1)
    name: str
    version: str | None
    ecosystem: str
    purl: str | None
    project_path: str | None = None
    install_path: str | None = None
    evidence: list[Evidence]


class UnresolvedNodeData(StrictModel):
    id: str
    label: str
    type: Literal["unresolved"]
    directness: Literal["direct", "transitive", "unknown"]
    depth: int | None = Field(default=None, ge=1)
    unresolved_target: UnresolvedTarget
    resolution_status: Literal["unresolved", "ambiguous"]
    evidence: list[Evidence] = Field(min_length=1)


NodeData = Annotated[
    ApplicationNodeData | ProjectNodeData | PackageNodeData | UnresolvedNodeData,
    Field(discriminator="type"),
]


class GraphNode(StrictModel):
    data: NodeData


class ContainsEdgeData(StrictModel):
    id: str
    source: str
    target: str
    type: Literal["CONTAINS"]


class DependencyEdgeData(StrictModel):
    id: str
    source: str
    target: str
    type: Literal["DEPENDS_ON"]
    resolution_status: Literal["resolved", "unresolved", "ambiguous"]
    evidence: list[Evidence] = Field(min_length=1)


EdgeData = Annotated[ContainsEdgeData | DependencyEdgeData, Field(discriminator="type")]


class GraphEdge(StrictModel):
    data: EdgeData


class GraphStats(StrictModel):
    applications: int = Field(ge=0)
    projects: int = Field(ge=0)
    packages: int = Field(ge=0)
    unresolved: int = Field(ge=0)
    depends_on_edges: int = Field(ge=0)
    max_depth: int = Field(ge=0)
    cycles: int = Field(ge=0)


class GraphMeta(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    partial: bool
    stats: GraphStats
    warnings: list[str]


class GraphDocument(StrictModel):
    meta: GraphMeta
    nodes: list[GraphNode]
    edges: list[GraphEdge]


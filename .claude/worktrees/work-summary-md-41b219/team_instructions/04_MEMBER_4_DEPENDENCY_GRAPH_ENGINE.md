# Member 4 — Directed Dependency Graph and Graph Intelligence

**Branch:** `feature/graph-engine` · **Review:** Member 3 (M5 reviews graph payload consumption) · **Primary outcome:** consume a canonical normalized dependency document and export a deterministic, Cytoscape-compatible directed graph containing project roots, real package instances, relationships, evidence and transparent unknowns.

> Graph correctness is more important than visual density. Never connect packages simply because their names, versions or PURLs appear related. Read [`README.md`](../README.md) for the **normative** `DependencyDocument` and `GraphDocument` contracts; [`SETUP.md`](../SETUP.md) for Python tests. You can develop **entirely from mocked normalized JSON before Syft is available**.

## Ownership and boundaries

**Own exclusively:** `backend/app/graph/**` and `backend/tests/graph/**`, including `backend/tests/graph/fixtures/**`. Suggested files:

```text
backend/app/graph/
├── __init__.py
├── builder.py       # exported build_graph()
├── traversal.py     # depth, dependents, ancestors, root paths
├── anomalies.py     # cyclic SCCs and invalid edge validation
├── serialization.py # Cytoscape elements, JSON-stable ordering
└── filtering.py     # pure in-memory selected-node subgraph helper
backend/tests/graph/
├── test_builder.py
├── test_depth.py
├── test_cycles.py
├── test_unresolved.py
├── test_identity.py
├── test_serialization.py
└── fixtures/{chain.json,diamond.json,two_versions.json,cycle.json,unresolved.json,empty.json,multi_project.json}
```

**Do not edit** `app/schemas/**` (M1), M2 discovery, M3 SBOM, M1 database/routes, `backend/pyproject.toml` or M5 frontend. NetworkX dependency already belongs in `backend/pyproject.toml`. This module never opens a DB connection; M1 persists `graph.json` and serves it to M5.

## Contract and exact semantics

```python
from app.schemas.dependency import DependencyDocument
from app.schemas.graph import GraphDocument

def build_graph(document: DependencyDocument, app_name: str) -> GraphDocument:
    """Pure deterministic transformation. No filesystem, network or database I/O."""
```

Input fields (M3): `schema_version`, `scan_id`, `roots[]`, `components[]`, `relationships[]`, `partial`, `warnings`. Each relationship goes **`from_id` depends on `to_id`**, except unresolved has `to_id=null` and named `unresolved_target`. Output fields: `meta:{schema_version,scan_id,partial,stats,warnings}`, `nodes:[{data:{...}}]`, `edges:[{data:{...}}]`. No `elements` wrapper, no alternate `links` property. See README for exact sample.

### Graph node and edge vocabulary

| Node type | ID | Purpose |
|---|---|---|
| `application` | always `app:root` | top-level scanned GitHub repository, one per scan |
| `project` | M3 `root_id` | specific npm/Python manifest project, possibly many per repo |
| `package` | M3 `component_id` | one evidence-distinct package occurrence/installation instance |
| `unresolved` | `unresolved:<stable-hash>` | intentionally unknown / ambiguous dependency declaration |

| Edge type | Direction | Semantics |
|---|---|---|
| `CONTAINS` | `app:root → root_id` | application includes a manifest project (not dependency) |
| `DEPENDS_ON` | `root_id → component_id` | project directly declares an evidenced dependency |
| `DEPENDS_ON` | `component_id → component_id` | resolved package depends on package |
| `DEPENDS_ON` | `root_id|component_id → unresolved:<hash>` | dependency declared but target not safely resolved |

Each node `data` always includes `id`, `label`, `type`, `directness`, `depth` (nullable). **Unresolved** node data must include `unresolved_target:{name,specifier,ecosystem}`, `resolution_status:"unresolved"|"ambiguous"` and `evidence[]` to preserve the original requested dependency. Package nodes additionally include `name`, `version` nullable, `ecosystem`, `purl` nullable, and `evidence`; add `project_path` and `install_path` where available. Each edge includes `id`, `source`, `target`, `type`; dependency edges also carry `resolution_status` and `evidence`. All evidence items are `{path,kind,locator}`. Other optional fields must be proposed to M1 as an additive schema PR; avoid requiring them in M5 until approved.

**Identity:** use M3's already stable `component_id`/`root_id`; **never rehash PURLs**. IDs that differ by install path remain distinct. `unresolved` placeholders derive a stable hash of `(from_id, name, specifier, ecosystem, normalized evidence locators)`; different parent declarations don't silently merge. Edge IDs derive from `(type, source, target)` using a stable hash; if two relationship evidence items point to same pair, **merge evidence arrays** rather than emitting duplicated Cytoscape edge IDs.

## Step 1 — Write graph fixtures first

Write fixtures conforming to `DependencyDocument.model_validate` so they can be consumed before Member 3 merges. Use synthetic clearly named `alpha`, `beta`, `gamma` packages with **actual fixture evidence** as strings, not fictitious claims about scanned public repos.

| Fixture | Shape | What it proves |
|---|---|---|
| `chain.json` | project→alpha→beta→gamma | depths 1/2/3; direct vs transitive |
| `diamond.json` | root→alpha & root→beta; alpha→gamma & beta→gamma | shared package has two parents, not duplicated |
| `two_versions.json` | two install locations for `gamma@1.0.0`, or gamma 1 & 2 | distinct package nodes remain distinct |
| `cycle.json` | alpha→beta→alpha | no infinite traversal; cycle warning/stat |
| `unresolved.json` | root→unknown `requests>=2` | unresolved placeholder + dashed-eligible edge |
| `empty.json` | no roots/no components | only app node; zero stats; no crash |
| `multi_project.json` | npm root and Python root | single application contains both projects |

For test convenience, ID strings like `cmp:alpha` are acceptable **only** inside explicit synthetic fixtures; production M3 IDs use stable SHA-based identities. Use `scan_id` from README sample. Freeze fixtures as golden payloads in your own folder, not shared M3-owned paths.

## Step 2 — Build NetworkX directed graph

`nx.DiGraph()` is adequate: a dependency pair is a logical unique edge, while multiple evidence records merge into `edge['evidence']`. `nx.MultiDiGraph` would complicate Cytoscape IDs unnecessarily. Create nodes first, then apply edges, then compute classifications. Validate unique IDs and references; no dangling edges or accidental implicit NetworkX nodes.

```python
import networkx as nx

def make_networkx_graph(doc: DependencyDocument, app_name: str) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node("app:root", id="app:root", label=app_name,
                   type="application", directness="not_applicable", depth=None)

    for root in doc.roots:
        if root.root_id in graph:
            raise ValueError(f"Duplicate root id: {root.root_id}")
        graph.add_node(root.root_id, id=root.root_id,
                       label=f"{root.name} ({root.ecosystem})", type="project",
                       project_path=root.path, depth=0, directness="not_applicable")
        graph.add_edge("app:root", root.root_id, type="CONTAINS", evidence=[])

    for c in doc.components:
        if c.component_id in graph:
            raise ValueError(f"Duplicate component id: {c.component_id}")
        graph.add_node(c.component_id, id=c.component_id, type="package",
                       label=c.name, name=c.name, version=c.version,
                       ecosystem=c.ecosystem, purl=c.purl,
                       project_path=c.project_path, install_path=c.install_path,
                       evidence=[e.model_dump() for e in c.evidence],
                       directness="unknown", depth=None)

    for rel in doc.relationships:
        if rel.from_id not in graph:
            raise ValueError(f"Unknown dependency source: {rel.from_id}")
        # implement unresolved placeholders, validated to_id and merging evidence
        add_validated_relationship(graph, rel)

    return graph
```

`add_validated_relationship` is deliberately **a function to implement**; do not paste this alone and expect it to run. M1's Pydantic schemas may use `Optional[str]` for fields; preserve nulls exactly. Don't use `graph.add_edge` on a non-existing target: NetworkX would create a node with missing `type` and break export. Duplicate relationship IDs should either be rejected or, if exactly duplicate evidence, normalized once with a warning.

### Validation rules

1. `root_id` and `component_id` must be unique and disjoint; neither may equal `app:root`.
2. Every resolved relationship: `to_id` non-null and exists in components; every unresolved/ambiguous one: `to_id=null` and non-empty `unresolved_target`.
3. Only project/package nodes may be dependency sources; application only has `CONTAINS` edges.
4. Every source/target pair is a known node; every graph edge ID unique.
5. Manifest/lockfile evidence paths are repo-relative POSIX, while `kind="syft-sbom"` uses scan-artifact-relative `sbom.cdx.json`; no absolute paths. Validate or preserve warnings if malformed; avoid filesystem access here.
6. Empty input → valid graph with one `app:root` node and zero packages.
7. Component disconnected from roots remains visible with `depth:null`, `directness:'unknown'`; never claim it is transitive.

## Step 3 — Compute depth and directness correctly

**Definition:** a package's `depth` is the **shortest number of DEPENDS_ON edges from any project root**. Direct = depth 1 from *at least one* root; transitive = depth ≥2; unreachable/unknown = null/unknown. `CONTAINS` is **not** counted as a dependency edge. A component can be **both** root-direct and a descendant through another path; classify `direct` using minimum depth.

```python
from collections import deque

def dependency_depths(g: nx.DiGraph) -> dict[str, int]:
    roots = sorted(n for n, d in g.nodes(data=True) if d["type"] == "project")
    depth: dict[str, int] = {root: 0 for root in roots}
    queue = deque(roots)
    while queue:
        src = queue.popleft()
        for dst in sorted(g.successors(src)):
            if g.edges[src, dst]["type"] != "DEPENDS_ON":
                continue
            proposed = depth[src] + 1
            if dst not in depth or proposed < depth[dst]:
                depth[dst] = proposed
                queue.append(dst)
    return depth
```

Set `depth=null` for unreachable packages (and app); project depth=0. For unresolved placeholders, you **may** expose known declaration depth (root→unknown = 1) while `resolution_status` clearly says unresolved. `directness` for an unresolved placeholder can be `direct` if root-declared, or `unknown` if parent unreachable; **never treat it as a resolved package**.

### Graph size and complexity

- BFS O(V+E) for reachable nodes; stable sorting makes repeatable output.
- Use `nx.strongly_connected_components` for cycle detection, not unbounded enumeration of all simple cycles (can be exponential). A cyclic SCC is one with >1 node, or a single self-loop. Count **cyclic SCCs** as `meta.stats.cycles`; add a warning such as `Dependency graph contains 1 cyclic component`.
- For large graphs (> ~3,000 visible nodes), M5 should display a focused subset/cluster instead of mounting all labels at once. Keep the full graph artifact; no fabricated edge pruning. Trimming a UI graph does not change underlying evidence.

## Step 4 — Additional graph queries (pure functions)

Implement these as **local functions**; separate HTTP endpoints are optional and not required for the first demo:

```python

def direct_dependencies(g: nx.DiGraph, root_id: str) -> set[str]: ...

def transitive_dependencies(g: nx.DiGraph, root_id: str) -> set[str]: ...

def reverse_dependents(g: nx.DiGraph, package_id: str) -> set[str]: ...

def shortest_dependency_path(g: nx.DiGraph, root_id: str, package_id: str) -> list[str] | None: ...

def neighborhood(g: nx.DiGraph, selected_ids: set[str], hops: int = 2) -> nx.DiGraph: ...
```

**Key directionality:** graph arrows go **depender → dependency**. `g.successors(node)` lists packages it depends on; `g.predecessors(node)` lists upstream dependents. Reverse-dependency impact uses `nx.ancestors(graph, package_id)` and filters project/package nodes. Shortest path should operate on the `DEPENDS_ON`-only view and avoid walking `CONTAINS` edges. For app-root lineage, use a separate `CONTAINS` path.

## Step 5 — Build the Cytoscape payload

`graph.json` must use exactly:

```json
{
  "meta": {
    "schema_version": "1.0",
    "scan_id": "scan_550e8400e29b41d4a716446655440000",
    "partial": false,
    "stats": {"applications": 1, "projects": 1, "packages": 2,
              "unresolved": 0, "depends_on_edges": 2,
              "max_depth": 2, "cycles": 0},
    "warnings": []
  },
  "nodes": [
    {"data": {"id": "app:root", "label": "demo-app", "type": "application",
              "directness": "not_applicable", "depth": null}},
    {"data": {"id": "root:demo", "label": "demo-app (npm)", "type": "project",
              "project_path": "", "directness": "not_applicable", "depth": 0}},
    {"data": {"id": "cmp:alpha", "label": "alpha", "type": "package", "name": "alpha",
              "version": "1.0.0", "ecosystem": "npm", "purl": "pkg:npm/alpha@1.0.0",
              "directness": "direct", "depth": 1,
              "evidence": [{"path":"package-lock.json","kind":"lockfile","locator":"packages.node_modules/alpha"}]}},
    {"data": {"id": "cmp:beta", "label": "beta", "type": "package", "name": "beta",
              "version": "2.0.0", "ecosystem": "npm", "purl": "pkg:npm/beta@2.0.0",
              "directness": "transitive", "depth": 2,
              "evidence": [{"path":"package-lock.json","kind":"lockfile","locator":"packages.node_modules/beta"}]}}
  ],
  "edges": [
    {"data": {"id":"edge:app-demo", "source":"app:root", "target":"root:demo", "type":"CONTAINS"}},
    {"data": {"id":"edge:demo-alpha", "source":"root:demo", "target":"cmp:alpha", "type":"DEPENDS_ON", "resolution_status":"resolved", "evidence":[{"path":"package.json","kind":"manifest","locator":"dependencies.alpha"}]}},
    {"data": {"id":"edge:alpha-beta", "source":"cmp:alpha", "target":"cmp:beta", "type":"DEPENDS_ON", "resolution_status":"resolved", "evidence":[{"path":"package-lock.json","kind":"lockfile","locator":"packages.node_modules/alpha.dependencies.beta"}]}}
  ]
}
```

This **is a fixture shape**; both fixture and production edge `evidence` arrays should identify actual evidence in their corresponding fixture/repository. Populate `evidence` from M3. Sort nodes by `(type,id)` with `application` first and edges by `(type,source,target)` before export. Empty collections should be `[]`, not `null`. `max_depth=0` when no reachable package; `cycles` counts cyclic SCCs, not all backedges. `meta.partial` is `document.partial` or new structural incompleteness; pass original warnings and append cycle/graph consistency notices.

**Stable output:** M4 returns `GraphDocument` from Pydantic; M1 writes to `data/scans/<scan_id>/graph.json`. Do **not** write PostgreSQL graph tables in Phase 1. Graph JSON + preserved normalized document are sufficient; design models so future temporal scans can compare IDs and edges after reading artifacts.

## Step 6 — Future change intelligence and trust lineage (design, not code)

- **Supply Chain Change Intelligence:** stable `root_id`, `component_id`, relationship identities and M1 commit SHA allow a future diff comparing `added`, `removed`, `version_changed`, `edge_changed`. Version changes usually alter IDs; match logical package identity `(project_path, install_path, ecosystem, name)` and compare version to identify an upgrade instead of reporting only removed+added. **Do not implement graph diff until after Phase 1.**
- **Trust Lineage:** reserve new node types and edge families for `repository`, `commit`, `workflow`, `build_artifact`, `container_image`, `vulnerability` in a future schema version, with provenance/evidence. Avoid adding these as fake nodes now.
- **Security:** no vulnerability/cyber-risk scores computed in graph module during Phase 1. Depth is a graph measurement, not vulnerability reachability.

## Step 7 — Tests and correctness checks

| Test | Assertions |
|---|---|
| Chain | exact app→project→alpha→beta→gamma edges, depths 1/2/3 |
| Diamond | gamma single node with two parent edges |
| Multiple copies/versions | separate IDs and correct edges; no merge on PURL alone |
| Root direct + transitive | if both paths exist, minimum depth 1 and `direct` |
| Cycle | no hang; cyclic SCC count; repeatable result |
| Unresolved | placeholder node, truthful `resolution_status`, no guessed target |
| Dangling ID | reject `to_id` not present in normalized components |
| Syft-only orphan | package visible, `depth=null`, `directness=unknown` |
| Empty data | `app:root` only; zero stats and valid graph |
| Multi-project | one app and two project nodes; no unrelated root mapping |
| Deterministic | same input yields same nodes/edges order and IDs |
| Cytoscape validation | all edge endpoints exist, unique element IDs, Pydantic validates |

```bash
# from backend/ (see SETUP.md for OS-specific .venv Python)
python -m pytest tests/graph -q
python -m ruff check app/graph tests/graph
```

A useful invariant test:

```python
ids = [n["data"]["id"] for n in graph.model_dump()["nodes"]]
assert len(ids) == len(set(ids))
assert all(e["data"]["source"] in ids and e["data"]["target"] in ids
           for e in graph.model_dump()["edges"])
```

**Do not** test NetworkX itself; test your input validation, depth classification, deduplication, metadata and schema compatibility.

## Parallel Development and Collaboration

**Start immediately:** author normalized JSON fixtures in `backend/tests/graph/fixtures`, the NetworkX builder, depth, cycle detection, serialization, Pydantic validation and golden tests. **No dependency on GitHub clone, Syft, PostgreSQL, M1 worker or M5 UI** for these steps. If `app.schemas` has not yet landed, use an isolated small test dataclass or JSON fixture locally and replace with M1's shared Pydantic model immediately after the bootstrap PR (do not commit competing canonical models).

| Member | Interface | What you can do while blocked |
|---|---|---|
| M1 | Exports `build_graph(doc,app_name)`; M1 owns `/graph` route | run builder directly with fixtures and validate graph JSON |
| M3 | Supplies `DependencyDocument`; you review their PR | use `chain.json`, `diamond.json`, `unresolved.json` first |
| M5 | Consumes `nodes`/`edges` data | share mock graph output JSON on day one; UI can render it now |
| M2 | No direct dependency | no wait needed |

**Must not modify:** M1 schemas/routes/DB, M3 normalized implementation, M2 discovery, frontend and shared dependencies. **PR order:** builder/fixtures; depth/cycles; export and contract tests; M3 integration review. **Reviewers:** M3 primary, M5 validates UI contract. **Blockers:** invalid/missing `from_id/to_id`, ambiguous relationship mapping, duplicate IDs, unexpected schema fields, graph too dense for UI. Resolve by a **small reproducible fixture and reviewed contract issue**; render a focused view in M5 without deleting actual relationships. Do not invent edges to make the picture attractive.

## Acceptance checklist

- [ ] `build_graph()` callable on mock normalized JSON before live SBOM pipeline exists.
- [ ] Directed NetworkX graph honors **depender → dependency** and app/project containment.
- [ ] Multi-project, multi-parent, duplicated installation, cycles and unresolved dependencies correct.
- [ ] Minimum rooted dependency depth and direct/transitive/unknown classification correct.
- [ ] Graph stats consistent with nodes/edges; partial/warnings preserved.
- [ ] Cytoscape JSON stable, endpoint-safe and validated; all edges point to existing nodes.
- [ ] No guessed relationships, no vulnerability findings, no graph DB or HTTP coupling.
- [ ] Unit tests pass on Windows/macOS; member-owned branch merges via reviewed PR.

**Handoff:** commit at least `chain`, `diamond`, `unresolved` fixture outputs; supply M5 with one graph JSON it can render without an API; provide M1 the exact import/signature and green `pytest tests/graph` output.

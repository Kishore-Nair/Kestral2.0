# Member 3 — Syft SBOM, Package Normalization and Real Dependency Edges

**Branch:** `feature/sbom-extraction` · **Review:** Member 4 (M2 also reviews inventory handoff) · **Primary outcome:** convert one safely cloned repository and a canonical `Inventory` into (1) a real CycloneDX JSON artifact and (2) a deterministic, **evidence-backed** `DependencyDocument` containing resolved and explicitly unresolved relationships.

> **Most important technical rule:** a list of packages is **not** necessarily a dependency tree. Never invent package versions, transitive edges, installation locations, environments or source evidence. Read [`README.md`](../README.md) for the canonical `DependencyDocument` schema, and [`SETUP.md`](../SETUP.md) for Syft installation and OS commands.

## Scope and ownership

You own **only** `backend/app/sbom/**`, `backend/tests/sbom/**` and fixtures under `backend/tests/sbom/fixtures/**`. Suggested layout:

```text
backend/app/sbom/
├── __init__.py
├── pipeline.py         # exported generate_dependency_document()
├── syft_runner.py      # safe subprocess, timeout, raw SBOM artifact
├── cyclonedx_parser.py # validate bomFormat, component extraction, bom-ref map
├── identities.py       # stable instance/root/relationship hashing
├── normalization.py    # merge records without ambiguous matches
├── npm_lock.py         # npm lockfileVersion 2/3 hierarchy resolver
├── python_reqs.py      # requirements + pyproject direct declarations
├── poetry_lock.py      # conservative Poetry lock extraction
└── uv_lock.py          # conservative uv lock extraction
backend/tests/sbom/
├── test_syft_runner.py
├── test_cyclonedx.py
├── test_npm_lock.py
├── test_python_reqs.py
├── test_poetry_uv.py
├── test_identity.py
├── test_pipeline.py
└── fixtures/{npm_v3_simple,npm_duplicate,npm_v2,python_requirements,python_poetry,python_uv,cyclonedx}/
```

Do not change shared schema files, ingestion, discovery, graph, SQL/database or frontend in your feature branch. Request a scoped dependency change to M1 (e.g., `packaging`, `packageurl-python` are already in shared `pyproject.toml`). **Never add `syft` to Python dependencies:** Syft is an external executable installed per OS in `SETUP.md`.

## Fixed integration interface

```python
from pathlib import Path
from app.schemas.inventory import Inventory
from app.schemas.dependency import DependencyDocument

def generate_dependency_document(
    repo_dir: Path, inventory: Inventory, scan_id: str, scan_dir: Path
) -> DependencyDocument:
    """Write scan_dir/sbom.cdx.json; return normalized document v1.0.

    No GitHub fetch. No pip/npm/uv/Poetry install, build or script execution.
    scan_dir is provided by Member 1 and must be outside repo_dir.
    """
```

Member 1 orchestrates `DISCOVERING` → `GENERATING_SBOM` → `BUILDING_GRAPH`. You **do not update scan states** or write `normalized.json` (M1 persists the returned Pydantic object). You **do write only** `<scan_dir>/sbom.cdx.json` as a **raw, validated CycloneDX artifact**. Member 4 consumes the typed `DependencyDocument` directly. Every output uses `schema_version='1.0'`, `scan_id`, `roots`, `components`, `relationships`, `partial`, `warnings` (exact field names in README).

## Step 1 — Install and verify Syft on Windows/macOS

Official documentation: https://oss.anchore.com/docs/installation/syft/ and https://oss.anchore.com/docs/guides/sbom/getting-started/ .

**Windows PowerShell:**

```powershell
winget install Anchore.syft
syft version
New-Item -ItemType Directory -Force -Path data\smoke | Out-Null
syft "dir:backend" -o "cyclonedx-json=data/smoke/test.cdx.json"
```

**macOS:**

```bash
brew install syft
syft version
mkdir -p data/smoke
syft dir:backend -o cyclonedx-json=data/smoke/test.cdx.json
```

Run from project root; `backend/` must exist. If the directory has no resolved package metadata, Syft may produce an empty/limited SBOM, **not a failure by itself**. **Do not run it against a production filesystem/image**; input is the team's isolated local checkout.

### Safe Syft invocation

`syft dir:<absolute-repo-path> -o cyclonedx-json=<absolute-output-path>` scans the filesystem/source metadata without installing or building the application. Use `subprocess.run([...], shell=False, timeout=..., cwd=..., stdin=DEVNULL, capture_output=True, check=True)`. Set `SYFT_CHECK_FOR_APP_UPDATE=false` if supported by the installed release, or use documented CLI configuration; confirm against `syft help` instead of assuming every environment switch is stable. Do not use remote Syft source schemes, registry credentials, `syft <untrusted-image>`, or command interpolation.

```python
import json
import os
import subprocess
from pathlib import Path

def run_syft(repo_dir: Path, scan_dir: Path, timeout: int) -> dict:
    output = scan_dir / "sbom.cdx.json"
    temp = scan_dir / "sbom.cdx.json.tmp"
    safe_vars = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR",
                 "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {key: os.environ[key] for key in safe_vars if key in os.environ}
    env["HOME"] = str(scan_dir)  # isolate tool's user configuration/cache
    result = subprocess.run(
        ["syft", f"dir:{repo_dir.resolve()}", "-o", f"cyclonedx-json={temp}"],
        shell=False, cwd=scan_dir, stdin=subprocess.DEVNULL, env=env,
        capture_output=True, text=True, check=True, timeout=timeout,
    )
    if not temp.is_file() or temp.stat().st_size > 40 * 1024 * 1024:
        raise ValueError("Missing or oversized Syft SBOM")
    data = json.loads(temp.read_text(encoding="utf-8"))
    if data.get("bomFormat") != "CycloneDX" or not isinstance(data.get("components", []), list):
        raise ValueError("Unexpected Syft SBOM format")
    temp.replace(output)
    return data
```

`result` is captured to avoid noisy stdout; don't log raw stderr indiscriminately. Protect against Syft output/file parsing errors and incomplete scans; bound source/manifest size. **Security note:** scanning untrusted input with a native binary is not a formal sandbox; M1 should use isolated/limited execution when possible.

## Step 2 — Parse CycloneDX only as far as it proves facts

Parse documented CycloneDX fields: `components[]` (`bom-ref`, `name`, `version`, `purl`, `licenses`, `hashes`, `properties` when available) and optional `dependencies[]` (`ref`, `dependsOn`). Preserve package `bom-ref` internally for mapping **only when unique**; `bom-ref` is an SBOM-scoped reference, **not** a cross-scan stable package ID. Keep the raw CycloneDX JSON unchanged on disk. Missing `version`, `purl`, `licenses`, hashes and relationship section are **valid limitations**.

Example CycloneDX fixture (synthetic, test-only):

```json
{
  "bomFormat":"CycloneDX", "specVersion":"1.6", "version":1,
  "components":[
    {"type":"library","bom-ref":"pkg:npm/alpha@1.0.0","name":"alpha","version":"1.0.0","purl":"pkg:npm/alpha@1.0.0"},
    {"type":"library","bom-ref":"pkg:npm/beta@2.0.0","name":"beta","version":"2.0.0","purl":"pkg:npm/beta@2.0.0"}
  ],
  "dependencies":[{"ref":"pkg:npm/alpha@1.0.0","dependsOn":["pkg:npm/beta@2.0.0"]}]
}
```

Only `alpha → beta` is proven in that **fixture**. Nothing says the application directly depends on `alpha`; root direct edges must come from `package.json` or a supported Python declaration. If `bom-ref` maps to multiple installed instances, retain an `ambiguous` unresolved relationship with evidence rather than choosing one.

**PURLs:** parse with `packageurl.PackageURL.from_string` and use standard types (`npm`, `pypi`); normalize Python names using `packaging.utils.canonicalize_name` (e.g., `Foo_Bar`→`foo-bar`), preserve original presentation for UI. No PURL is preferable to a guessed PURL for an unpinned range.

## Step 3 — Stable identities that survive scans

**Must not use** PURL as the sole node ID, nor include the scan UUID in component IDs. Create deterministic IDs (full 64-hex or an agreed collision-safe prefix, e.g., 20+ hex) via SHA-256 of a canonical ordered tuple (serialize with `json.dumps(...,separators=(',',':'),ensure_ascii=True)`). This is an implementation detail behind common prefixes; M1's example abbreviated IDs are illustrative.

```python
from hashlib import sha256
import json

def stable_id(prefix: str, *fields: object) -> str:
    payload = json.dumps(fields, separators=(",", ":"), ensure_ascii=True)
    return prefix + ":" + sha256(payload.encode("utf-8")).hexdigest()[:24]

# example: node version and installation both matter
component_id = stable_id("cmp", "npm", "alpha", "1.0.0",
                         project_path, "package-lock.json", "node_modules/alpha")
root_id = stable_id("root", "npm", project_path, manifest_path)
```

For two package copies at `node_modules/alpha` and `node_modules/beta/node_modules/alpha`, IDs **differ even if PURLs match**. For a Syft-only package with no trustworthy installation context, include stable available CycloneDX identity/provenance in a separate, explicit `unknown`-location namespace and **do not** merge with two candidate lockfile instances. Relationship IDs include source, target (or unresolved specification), resolution status and evidence locator. Stable identity permits future **Supply Chain Change Intelligence** comparison but does not itself implement diffing.

## Step 4 — npm package-lock v2/v3 parser (highest initial priority)

Official npm lock semantics: https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json . Prefer lockfileVersion `2` and `3` with `packages` mapping; `packages[""]` describes the project root; each other key (e.g., `node_modules/alpha`, `node_modules/a/node_modules/b`) describes an **installed location**. Some entries lack name; derive it **only** from the last `node_modules/` segment, including `@scope/name`. Lockfile locations are relative to the directory containing the lockfile (monorepo-safe).

**Algorithm** (implement in `npm_lock.py`):

1. For every npm manifest in inventory, pair with nearest **same-directory** `package-lock.json` or `npm-shrinkwrap.json`; don't borrow unrelated parent locks unless workspace metadata proves association. Create `root_id` for each manifest.
2. Parse lockfile JSON with bounded size. Require `lockfileVersion in {2,3}` and a `packages` dictionary. If v1 or malformed, `partial=true` + warning (optionally preserve declarations from `package.json` as unresolved).
3. Create normalized component instances **per installed location** (`packages` key, except the root `""`). Read name/version/link/dev/optional and integrity if present; preserve evidence `{path:'package-lock.json',kind:'lockfile',locator:'packages.node_modules/a'}`. Skip or mark workspaces/link entries as local/unsupported rather than treating them as packages from npm registry.
4. Read direct dependency declarations from root `package.json` and/or lock root `packages[""]` under `dependencies`, `devDependencies`, `optionalDependencies`. Do not label a root dev dependency `runtime`.
5. For each declared `name`, resolve target by **Node module location lookup** in the lock's `packages` map. From a package at `node_modules/a`, first try `node_modules/a/node_modules/<name>`, then ancestor `node_modules/<name>`. For nested paths, walk upward one containing `node_modules` level at a time. **Only create resolved edge if exactly one installed location is found by this documented search.**
6. For every installed package's declared `dependencies` object, repeat the same resolution algorithm and add directed `package → dependency` edges. `peerDependencies` are **requirements, not necessarily installed children**; model separately as unresolved/unsupported evidence unless a verified installed resolution exists and the team explicitly chooses to include it.
7. If version/range cannot be resolved unambiguously, store `to_id:null`, `unresolved_target` and `resolution_status='unresolved'|'ambiguous'`, plus evidence locator. Do not silently drop the declaration.
8. Sort all records by `root_id`, `component_id` and `relationship_id` for repeatability, then deduplicate **exact** same evidence edge only.

Pseudo-resolver illustrating the core search (implement full scoped/nested path support and tests):

```python
def npm_candidate_locations(parent_location: str, dependency: str) -> list[str]:
    # parent_location: "" or e.g. "node_modules/a/node_modules/b"
    # Yield nearest first; validate dependency name before interpolation.
    segments = parent_location.split("/node_modules/")
    result: list[str] = []
    current = parent_location
    while True:
        result.append(f"{current}/node_modules/{dependency}".lstrip("/"))
        if not current:
            break
        marker = current.rfind("/node_modules/")
        if marker == -1:
            current = ""  # top-level package: next candidate is root node_modules/
        else:
            current = current[:marker]
    return list(dict.fromkeys(result))
```

**Implementation caution:** for `parent_location='node_modules/a'`, its nearest `node_modules/a/node_modules/dep` then root `node_modules/dep`. The pseudo-resolver's string-splitting is **not a complete implementation for nested roots/scoped workspace paths**; tests must verify the exact candidate order and use normalized path segments. Test multiple installed versions, hoisted packages, nested `node_modules`, npm scopes, optional/development dependencies, aliases and workspace links. If you cannot verify an npm alias target/version, mark unresolved with a warning instead of inventing a package link.

### npm example (synthetic, tests only)

```text
root app ─DEPENDS_ON─> alpha@1.0.0 [node_modules/alpha]
alpha@1.0.0 ─DEPENDS_ON─> beta@2.0.0 [node_modules/beta]
alpha@1.0.0 ─DEPENDS_ON─> nested@3.0.0 [node_modules/alpha/node_modules/nested]
```

Each edge must be traceable to a `package.json` / `package-lock.json` locator. A dependency can have multiple parents; return one component instance with multiple incoming edges, not duplicated nodes per parent.

## Step 5 — Python manifest/direct dependency parsing

**`requirements*.txt`** are declaration lists, not full resolution graphs. Parse supported PEP 508 lines using `packaging.requirements.Requirement`; for `requests==2.31.0` a **declared direct package version** can be recorded, but no transitive packages may be inferred from it. For `requests>=2,<3`, version is **unknown**, relationship `to_id=null`, unresolved target `{"name":"requests","specifier":">=2,<3","ecosystem":"pypi"}`; do not create `requests@2.31.0` merely because it is common.

Handle comments, blank lines, PEP 508 markers, extras, URL/direct references and `-r` includes conservatively. For `-r other.txt`, follow only if path is relative to the repository root, resolves within the checkout, has bounded depth/count and no cycles; otherwise warn. Never resolve remote references, VCS URLs, `-e` builds, `--index-url`, `--extra-index-url`, `--trusted-host`, or install options. A `requirements.txt` inside a subproject creates a root for that subproject. Preserve marker/extras in `unresolved_target.specifier` or evidence locator (do not collapse distinct platform conditions into an unconditional edge).

**`pyproject.toml`**: `tomllib` from Python 3.12; parse `[project].dependencies`, `[project.optional-dependencies]`, supported `[tool.poetry.dependencies]` with explicit scope if available, always preserving the original declaration. Do not assume dependency groups apply to production. Missing project metadata or dynamic dependency definitions → warning, not guessing.

## Step 6 — Poetry and uv lockfiles (bounded, explicit support)

- `poetry.lock`: parse as TOML package records with name/version and declared package dependencies when available. Map dependency names to locked package records **only if a single compatible target is proven for the relevant project/marker**. If multi-version/environment resolution is ambiguous, emit `to_id:null` with `resolution_status='ambiguous'`. Parse declared direct roots from `pyproject.toml`, not every package as direct.
- `uv.lock`: parse TOML package entries and their locked dependency references (e.g., name/version/source if provided by the file format). **uv format can evolve:** support the explicit fixture format/version tested, issue a warning for unsupported variants. Never call `uv sync`, `uv run` or commands that might resolve, build or install untrusted packages. See https://docs.astral.sh/uv/concepts/projects/sync/ .
- If both Poetry and uv locks exist for a project, do **not** arbitrarily merge conflicting resolutions; prefer the manifest's declared manager only when unambiguous, otherwise produce separate rooted evidence or report `ambiguous` with a warning for integration review.
- `Pipfile.lock`, requirements without full pins, unrecognized Python lock schema: discover and preserve but label completeness accordingly. The first milestone should correctly support **basic** npm v2/v3 and Python declared/locked dependencies; not complete all Python ecosystem edge cases.

## Step 7 — Reconcile Syft components with lockfile records

Merge on **strong identity** where possible: exact ecosystem + normalized name + exact version + known project/install context. A Syft component matching one unambiguous lock instance may enrich it (license/hash/PURL), but if it matches two instances, enrich shared fields conservatively **without collapsing their instance IDs**. If Syft reports a component absent from lock parsing, keep it as a Syft-only component with `directness` later `unknown`, valid evidence and warning as appropriate. If lockfile contains dependencies Syft omits, keep lockfile-evidenced components and report SBOM coverage discrepancy; never drop verified edges to mimic Syft.

**Data quality invariants:**

- Every `relationship.from_id` must reference `roots[]` or `components[]`.
- Every non-null `relationship.to_id` must reference `components[]`.
- A `resolved` relationship must have non-null `to_id`; `unresolved`/`ambiguous` have null `to_id` and filled `unresolved_target`.
- Every `component_id` and `root_id` unique in document; no scan UUID in stable identities.
- `version` and `purl` nullable; no synthetic versions; `scope` in `runtime|dev|optional|unknown`.
- Every component and edge has at least one actual `{path,kind,locator}` evidence item from repo files or SBOM. For Syft-only provenance, use `{path:"sbom.cdx.json",kind:"syft-sbom",locator:"components[<index>]"}`: the one allowed evidence-path exception is **relative to the scan artifact directory**, not the repository. M1 stores it outside repo. All manifest/lockfile paths remain repo-relative.
- `partial=true` whenever unsupported/ambiguous/missing relationship evidence prevents claiming a full graph; UI receives warnings instead of an apparently complete security map.

## Step 8 — Representative normalized output

For a fixture with `package.json` declaring `alpha`, `package-lock.json` pinning `alpha` and a **verified** nested dependency `beta`, output like below. IDs are **illustrative abbreviations**; real stable IDs are derived from deterministic hash.

```json
{
  "schema_version":"1.0","scan_id":"scan_550e8400e29b41d4a716446655440000",
  "roots":[{"root_id":"root:6d7e","name":"demo-app","path":"","manifest_path":"package.json","ecosystem":"npm"}],
  "components":[
    {"component_id":"cmp:alpha","name":"alpha","version":"1.0.0","ecosystem":"npm","purl":"pkg:npm/alpha@1.0.0","install_path":"node_modules/alpha","project_path":"","scope":"runtime","licenses":[],"hashes":[],"evidence":[{"path":"package-lock.json","kind":"lockfile","locator":"packages.node_modules/alpha"}],"resolved":true},
    {"component_id":"cmp:beta","name":"beta","version":"2.0.0","ecosystem":"npm","purl":"pkg:npm/beta@2.0.0","install_path":"node_modules/beta","project_path":"","scope":"runtime","licenses":[],"hashes":[],"evidence":[{"path":"package-lock.json","kind":"lockfile","locator":"packages.node_modules/beta"}],"resolved":true}
  ],
  "relationships":[
    {"relationship_id":"rel:root-alpha","from_id":"root:6d7e","to_id":"cmp:alpha","unresolved_target":null,"resolution_status":"resolved","type":"DEPENDS_ON","evidence":[{"path":"package.json","kind":"manifest","locator":"dependencies.alpha"}]},
    {"relationship_id":"rel:alpha-beta","from_id":"cmp:alpha","to_id":"cmp:beta","unresolved_target":null,"resolution_status":"resolved","type":"DEPENDS_ON","evidence":[{"path":"package-lock.json","kind":"lockfile","locator":"packages.node_modules/alpha.dependencies.beta"}]}
  ],
  "partial":false,"warnings":[]
}
```

In tests, create the *actual matching fixture* before asserting the JSON, and use genuine hash IDs. If an unresolved declaration exists, add `unresolved_target`, mark the doc `partial=true`, and do not synthesize the missing target. A fully resolved graph of a toy fixture is not a promise that all real repos are complete.

## Step 9 — Test matrix and commands

| Test | Fixture | Required assertion |
|---|---|---|
| CycloneDX valid/missing fields | synthetic SBOM | optional metadata accepted; wrong bomFormat rejected |
| Syft exit/timeouts | monkeypatch subprocess | no shell, bounded timeout, no raw credential leakage |
| npm v3 direct + nested | lockfile v3 | project→direct→transitive edges exactly grounded |
| npm v2 | lockfile v2 | same accurate location resolution |
| npm duplicate install | two install paths | two component IDs, appropriate parent edges |
| npm ambiguity | alias, missing lock entry | unresolved target, partial warning, no guessed edge |
| requirements pin | `requests==...` | direct declaration, **zero invented** transitives |
| requirements range | `requests>=...` | unknown version, unresolved target |
| requirements includes | valid/escaping/cyclic includes | safe bounded traversal; escape rejected |
| pyproject groups | optional and dev | scopes preserved, no unconditional extra edges |
| Poetry/uv | deliberately versioned fixtures | only unambiguous verified edges created |
| merge conflicts | Syft one PURL, lock two paths | no accidental identity collapse |
| stable IDs | same fixture twice | byte-identical normalized JSON except `scan_id` |
| failing Syft | timeout/nonzero | typed error to M1, no fabricated success |

```bash
# from backend/ with venv available
python -m pytest tests/sbom -q
python -m ruff check app/sbom tests/sbom
```

Use controlled synthetic CycloneDX data and lockfiles for unit tests; **one real Syft scan** on a small authored local fixture as integration test. Tests must not access package registries or run install scripts. Include golden assertions for exact `from_id→to_id` pairs after resolving hash IDs via display metadata.

## Parallel Development and Collaboration

**Start immediately:** Syft runner wrapper, CycloneDX parser, npm v2/v3 test fixtures, Python requirements parser, deterministic IDs, model-validation tests using README JSON. Use M2's *example inventory JSON* with fixture repo paths if their module isn't merged; create a local `Inventory.model_validate()` test object. Do not wait for M1 API, Postgres or M4 graph.

| Owner | Depend on | Mock/stub while blocked | Contract review point |
|---|---|---|---|
| M1 | scan-dir/repo-dir + canonical schemas | supply local `tmp_path` directories and minimal models | M1 owns schema and worker interface |
| M2 | exact inventory manifest/lock paths | mocked `Inventory` for fixture tree | M2 confirms file categories, no new JSON keys |
| M4 | consumes normalized doc and identities | give a sample `normalized.json` on day one | M4 verifies relationships and IDs |
| M5 | eventually gets normalized data via `/sbom` | give README normalized example | M1 serves route; M5 only consumes |

**Own-only files** as above; **must not modify** `app/schemas`, discovery, graph, ingestion, frontend or shared deps. **Reviewer:** M4 for normalized graph semantics, M2 for inventory handoff. Merge paths: `PR-1` Syft + CycloneDX + fixtures, `PR-2` npm resolver/identities, `PR-3` Python parsers, `PR-4` reconciliation, edge integrity, integration. **Blocker definition:** missing Syft executable, unsupported lockfile version, ambiguous resolution, mismatch with `DependencyDocument`, unsafe path, non-deterministic IDs. Workaround: mock SBOM or preserve a transparent unresolved edge; request M1-owned contract change if needed, but **never stall another workstream**.

## Acceptance checklist

- [ ] Syft is invoked locally with no source code execution; `sbom.cdx.json` is well-formed and persisted in scan output folder.
- [ ] CycloneDX components/licenses/hashes/PURLs parsed when genuinely present; absent values remain null/empty.
- [ ] npm package-lock v2/v3 direct and resolved transitive relationships are correct for fixtures, including duplicates and multiple parents.
- [ ] Python `requirements.txt`, `pyproject.toml`, basic Poetry/uv lock support uses cautious evidence rules.
- [ ] Unpinned, unsupported or ambiguous dependencies explicitly unresolved; never made-up transitive relationships.
- [ ] Stable per-installation component IDs and per-root IDs, evidence on components and edges, deterministic ordering.
- [ ] Output passes M1 Pydantic validation and M4 graph tests on Windows/macOS.
- [ ] Dedicated PRs merge without touching other owners' files.

**Handoff:** provide real Syft CLI version, one raw CycloneDX fixture, one normalized JSON fixture, exact tests, limitations table (unsupported npm/Python lock features) and any warnings that M5 must display.

# Member 3 handoff — SBOM & dependency extraction

Files in this folder:

| File | What it is |
|---|---|
| `sbom.cdx.json` | **Real** Syft output for `../npm_v3_simple` (Syft 1.57.2, CycloneDX 1.6). Only `metadata.component.name` (absolute host path), `serialNumber` and `timestamp` were replaced with placeholders so the fixture is reproducible. |
| `normalized.json` | The `DependencyDocument` v1.0 produced from `../npm_v3_simple` + that SBOM. Real SHA-256-derived IDs. Guarded by `test_handoff_golden_normalized_document`. |

## Integration interface (for M1)

```python
from app.sbom import generate_dependency_document, SyftError

doc = generate_dependency_document(repo_dir, inventory, scan_id, scan_dir)  # -> DependencyDocument
```

* Writes **only** `<scan_dir>/sbom.cdx.json` (temporary file, then atomic `os.replace`). It doesn't write `normalized.json` or update scan state.
* Raises `ValueError` when `scan_dir` is inside `repo_dir` or `repo_dir` is missing.
* Raises a `SyftError` subclass on tool failure: `SyftNotFoundError`, `SyftTimeoutError`, `SyftExecutionError`, `SyftOutputError`. Messages are sanitized (no stderr, no host paths) and safe to show.
* Optional keyword `syft_timeout` (default 300 s).
* `build_document(repo_dir, inventory, scan_id, sbom_dict_or_None)` is the pure part, for tests that don't need Syft.
* **Security note for M1:** the raw `sbom.cdx.json` contains the absolute checkout path in `metadata.component.name`. Do not serve the raw file through the API (`/sbom` serves the normalized document).

## Output conventions (for M4 / M5)

| Field | Value |
|---|---|
| IDs | `root:` / `cmp:` / `rel:` + 24 hex (SHA-256 of a canonical JSON tuple). No scan ID inside. Identical repo state gives identical IDs. |
| `ecosystem` | `npm`, `pypi`, `github-actions` (Syft-only), `unknown` (Syft-only, no PURL). Python roots also use `pypi`. |
| `hashes[]` | `{"alg": "SHA-512", "content": "<hex>"}`, matching M1's `ComponentHash`. |
| `licenses[]` | M1's `License` objects: `{"id": "MIT", "name": null, "url": null}`. A bare SPDX-like token goes in `id`; free text and SPDX expressions go in `name`. |
| evidence `kind` | `manifest`, `lockfile`, `syft-sbom` (`path` is always `sbom.cdx.json` for syft-sbom). |
| npm locators | `dependencies.alpha` (package.json), `packages[''].dependencies.alpha`, `packages.node_modules/a`, `packages.node_modules/a.dependencies.b` |
| Python locators | `line:N` (+ ` [marker: …]`), `project.dependencies[0]`, `tool.poetry.dependencies.x`, `package[name==ver]`, `package[name==ver].dependencies.dep` |
| Syft-only components | `install_path: null`, `scope: "unknown"`, no edges unless Syft's own `dependencies[]` links two Syft-only packages. |

## Limitations (what is deliberately *not* resolved)

| Area | Behavior |
|---|---|
| npm lockfileVersion 1 / missing lock | Root declarations become `unresolved`; `partial=true`. |
| npm workspaces / `link: true` entries | Not modeled as components; edges to them become `unresolved`; warning. |
| npm `peerDependencies` | Not modeled as edges (they're requirements, not proven children); one warning, doesn't set partial. |
| npm alias `npm:x@…` | Resolved only if the installed entry's `name` equals `x`; otherwise `unresolved`. |
| npm optional deps not installed (e.g. `fsevents`) | `unresolved` (truthfully not in the lock). |
| yarn.lock, pnpm-lock.yaml, Pipfile, Pipfile.lock, setup.cfg, go.mod, … | Not parsed; one warning per file; `partial=true`. |
| `requirements*.txt` | Direct declarations only. Exact pins (`==`/`===`, no wildcard) become components. Ranges become `unresolved`. **No transitive packages.** `-e`, `-c`, URLs/VCS refs and index options aren't resolved (option values are never echoed). `-r` is followed only inside the repo (depth ≤ 5, ≤ 20 files, cycle-safe). |
| `requirements.txt` scope | `runtime`; every other requirements file → `unknown` (no guessing from the file name). |
| `pyproject.toml` | PEP 621 deps/extras, PEP 735 `[dependency-groups]`, Poetry tables. `dynamic` deps produce a warning. Tool-only pyprojects create no root. |
| `poetry.lock` | lock-version 1.1/2.0/2.1. Poetry doesn't record a dependency's target version, so if several versions are locked the edge is `ambiguous`. |
| `uv.lock` | `version = 1` only. Versioned references are matched exactly. Local/workspace packages aren't modeled. |
| poetry.lock **and** uv.lock in one project | Used only if `[tool.poetry]` xor `[tool.uv]` declares the manager; otherwise neither is used (warning). |
| Syft ↔ lock merge | Needs ecosystem + normalized name + exact version **and** Syft's `syft:location` = that lockfile/manifest. Without a location: kept separate (Syft-only). |
| Syft `dependencies[]` | Ignored for any package a lockfile/manifest describes. Real Syft 1.57 links a parent to *every* same-name copy, so the lockfile is authoritative. |

## Warnings M5 should display

These come from `document.warnings` verbatim. When `partial=true`, show a "graph may be incomplete" banner.

* `…: no package-lock.json or npm-shrinkwrap.json in the same directory; direct dependencies left unresolved`
* `…: lockfileVersion 1 is not supported (only 2 and 3); …`
* `…: N dependency declarations could not be resolved to exactly one installed lockfile location`
* `…: N workspace/link entries are local packages and are not modeled as registry components`
* `…: N peerDependencies are requirements, not proven installed children; …`
* `…: N declarations are not pinned exactly; their versions are unknown and left unresolved`
* `…: no supported lockfile; transitive dependencies are unknown (declarations only)`
* `Syft reported N packages with no lockfile/manifest evidence; kept as Syft-only components with unknown directness`
* `SBOM coverage discrepancy: N lockfile/manifest components were not reported by Syft …`
* `Repository inventory is partial; dependency extraction may be incomplete`

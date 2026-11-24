# Member 2 — Repository Discovery and Supply Chain Inventory

**Branch:** `feature/repository-discovery` · **Review:** Member 1 (M3 signs off the inventory handoff) · **Primary outcome:** a safe, deterministic, evidence-based `Inventory` identifying source languages, dependency declaration files, lockfiles, Docker/CI/IaC artifacts and source folders in a local checkout.

**First action:** read [`README.md`](../README.md) (especially the `Inventory` contract) and [`SETUP.md`](../SETUP.md). You **do not need a running API, database or Syft** to begin.

## Scope and ownership

**You own** `backend/app/discovery/**` and `backend/tests/discovery/**`, including tests/fixtures in that subtree. Create:

```text
backend/app/discovery/
├── __init__.py
├── engine.py          # exported discover_repository()
├── rules.py           # artifact and language classification tables
├── paths.py           # safe POSIX relative paths and exclusions
└── git_metadata.py    # optional local-only verification helpers
backend/tests/discovery/
├── test_engine.py
├── test_security_limits.py
└── fixtures/
    ├── npm_simple/              # tiny benign fabricated repository
    ├── python_requirements/
    ├── python_uv/
    ├── multi_project/
    ├── empty/
    └── strange_paths/
```

**Do not change** `backend/app/schemas/**`, `backend/app/ingestion/**`, database/migrations, M3/M4 code, `backend/pyproject.toml`, or `frontend/**` without a reviewed owner PR. If `Inventory` needs new fields, request a schema v1.1 contract PR from M1; do not invent them inside JSON.

## Interface contract (fixed)

```python
from pathlib import Path
from app.schemas.inventory import Inventory

def discover_repository(repo_dir: Path, scan_id: str) -> Inventory:
    """Inspect a checked-out, trusted *path* without executing its code.

    repo_dir: existing directory supplied by Member 1, never a URL.
    Returns: Pydantic Inventory v1.0; raises DiscoveryLimitError on hard caps.
    """
```

Input is an **already cloned** repository at `data/workspaces/<scan_id>/repo`; output is **one** `Inventory` instance. M1 saves it atomically to `data/scans/<scan_id>/inventory.json`; M2 does not open database connections, create scan IDs or write to shared scan artifact paths. Return `partial` and warnings for deliberately skipped categories or incomplete inspection; throw typed errors for path escapes/exceeded hard limits.

**Exactly these JSON keys**, defined in `README.md`: `schema_version`, `scan_id`, `languages`, `manifests`, `lockfiles`, `dockerfiles`, `ci_files`, `iac_files`, `existing_sboms`, `source_directories`, `file_count`, `partial`, `warnings`. A manifest/lock entry has `{path,kind,ecosystem}`. `languages` entries have `{name,file_count}`. Lists must be sorted for deterministic tests. No absolute host paths or secret contents in output.

## Step 1 — Make fixture repositories before the ingestion pipeline exists

Create all fixture directories under **your owned** `backend/tests/discovery/fixtures/`. Example benign fixture `npm_simple`:

```text
npm_simple/
├── package.json
├── package-lock.json        # v2/v3 sample; minimal syntactically valid fixture
├── src/index.js
├── Dockerfile
├── .github/workflows/ci.yml
├── infra/main.tf
└── README.md
```

`python_requirements`: `requirements.txt`, `src/app.py`, optionally `pyproject.toml`. `python_uv`: `pyproject.toml`, `uv.lock`, `src/pkg/__init__.py`. `multi_project`: `backend/pyproject.toml`, `frontend/package.json`, `frontend/package-lock.json` to prove a monorepo has multiple project roots. `empty`: no source/dependency files. `strange_paths`: nested folders, irrelevant/generated dirs and symlinks (create symlink test programmatically; Windows symlink privileges may differ). **No external repo/network needed to run unit tests.**

## Step 2 — Define detection rules, not scattered substring checks

Use `rules.py` with explicit lowercase **filename** patterns, preserving original case in output; treat case-sensitive Git paths correctly. Recommended initial registry:

| Family | Detect | `kind` / `ecosystem` |
|---|---|---|
| npm manifest | `package.json` | `package.json` / `npm` |
| npm lock | `package-lock.json`, `npm-shrinkwrap.json` | literal filename / `npm` |
| Python manifest | `requirements.txt`, `requirements-*.txt`, `pyproject.toml`, `setup.cfg`, `Pipfile` | literal matched category / `python` |
| Python lock | `poetry.lock`, `uv.lock`, `Pipfile.lock` | literal filename / `python` |
| Other ecosystems (discovery only) | `pom.xml`, `build.gradle`, `go.mod`, `Cargo.toml`, `Gemfile`, `composer.json`, etc. | literal filename / appropriate ecosystem |
| Docker | `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `compose.yaml`, `compose.yml`, `docker-compose*.yml/yaml` | path list only |
| GitHub Actions | `.github/workflows/*.yml/yaml` | path list only |
| CI other | `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `.circleci/config.yml` | path list only |
| IaC | `*.tf`, `*.tf.json`, `terragrunt.hcl`, `template.yaml`, `template.yml`, `cdk.json`, `serverless.yml` | path list only |
| Existing SBOM | `bom.json`, `*.cdx.json`, `*.spdx.json`, `bom.xml`, `sbom*.json` | path list only; do not trust unvalidated content |

Do not classify any arbitrary `*.json` as a dependency manifest. `requirements-dev.txt` is a manifest; `requirements/foo.txt` may be supported by a configurable basename rule if you document the match. Keep discovery broad enough to report Java/Go/Rust artifacts, but **MVP dependency parsing is only npm/Python**. Mark unsupported ecosystems in `warnings` only if materially relevant to incomplete graph; discovery itself need not fail.

**Language counts:** source file extensions `.py`→Python, `.js/.mjs/.cjs/.jsx/.ts/.tsx`→JavaScript/TypeScript (count TS separately or use agreed labels), `.java`→Java, `.go`→Go, `.rs`→Rust, `.cs`→C#, `.rb`→Ruby; do not treat lockfile JSON as JavaScript language evidence. For ambiguous extensionless files, report only if reliable. `file_count` is number of **eligible regular files visited**, not number of source files or line counts.

## Step 3 — Safe traversal

Walk the **physical checkout**, not a remote URL, from the root passed by M1. Exclude common third-party/generated folders: `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.next`, `dist`, `build`, `coverage`, `vendor` (be cautious: `vendor/` may contain legitimately vendored components; explicitly record a warning if exclusion affects completeness). Only `lstat` normal regular files, **never follow symlinks or junctions**; ignore FIFOs, device files, sockets. Normalize path using `path.relative_to(repo_dir).parts` joined with `/`, then reject `..`, leading `/`, NUL, backslash and escape.

Skeleton (`app/discovery/engine.py`):

```python
import os
from pathlib import Path
from app.schemas.inventory import Inventory, FileEntry, LanguageCount

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             ".next", "dist", "build", "coverage"}


def discover_repository(repo_dir: Path, scan_id: str) -> Inventory:
    root = repo_dir.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository path must be a directory")
    count = 0
    languages: dict[str, int] = {}
    manifests: list[FileEntry] = []
    lockfiles: list[FileEntry] = []
    dockerfiles: list[str] = []
    ci_files: list[str] = []
    iac_files: list[str] = []
    existing_sboms: list[str] = []
    source_dirs: set[str] = set()
    warnings: list[str] = []

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS
                         and not (current_path / d).is_symlink())
        for filename in sorted(files):
            p = current_path / filename
            if p.is_symlink() or not p.is_file():
                continue
            relative = p.relative_to(root).as_posix()
            count += 1
            if count > MAX_FILE_COUNT:  # supplied from validated shared config
                raise DiscoveryLimitError("Repository file count exceeded")
            # classify_file(...) applies the centralized rules above.
            # Append FileEntry or path to appropriate collections; count source extensions.
            # Never read or execute a repository file merely to classify its filename.

    return Inventory(schema_version="1.0", scan_id=scan_id,
                     languages=[LanguageCount(name=k, file_count=v)
                                for k, v in sorted(languages.items())],
                     manifests=sorted(manifests, key=lambda x: x.path),
                     lockfiles=sorted(lockfiles, key=lambda x: x.path),
                     dockerfiles=sorted(set(dockerfiles)), ci_files=sorted(set(ci_files)),
                     iac_files=sorted(set(iac_files)),
                     existing_sboms=sorted(set(existing_sboms)),
                     source_directories=sorted(source_dirs), file_count=count,
                     partial=False, warnings=warnings)
```

`MAX_FILE_COUNT`, `DiscoveryLimitError` and `classify_file` are **to implement**, not imports that already exist. Obtain limits from shared settings or a read-only argument agreed with M1; avoid circular import to M1's worker. Prefer `os.scandir()` if you need finer-grained inode checks, cross-volume/device enforcement or early abort before file-system traversal. **Security nuance:** `Path.is_file()` can follow links while a path is racing; for a hardened sandbox use `lstat` / directory handles and isolate scanning in a read-only container. For the hackathon, no repo code execution plus explicit link checks/limits are minimum controls.

## Step 4 — Source directories and project boundaries

A repository may have **multiple** manifest roots. Record every manifest/lock with its full relative path; never flatten all manifests to the repository root. M3 derives project `root_id` from the manifest's parent directory. Examples:

- `frontend/package.json` and `frontend/package-lock.json` belong to project path `frontend`.
- `backend/pyproject.toml`, `backend/uv.lock` belong to path `backend`.
- Nested `apps/web/package.json`, `packages/ui/package.json` may both exist, with npm workspace links: record both; do not assert they are independent installs without lock evidence.

`source_directories`: detect actual first-level or nested conventional paths containing source, such as `src`, `app`, `lib`, `backend/src`, `frontend/src`; **do not** treat `.github/workflows` as source. File paths are evidence; do not embed file contents. Preserve `pyproject.toml` even if it contains only tools/build metadata (M3 will determine dependency applicability).

## Step 5 — Git metadata without crossing ownership

M1 is the **single source of truth** for canonical URL, requested/resolved ref and commit SHA in the DB/API. You may verify a checkout locally using safe read-only Git subprocess calls if useful for tests (`git -C <repo_dir> rev-parse HEAD`), but **do not** add undeclared repository fields to `Inventory`; no network calls or fetches here. Compare any local metadata to M1's result in integration testing and raise an error/warning if inconsistent. Avoid shell commands or Git hooks.

## Step 6 — Representative inventory JSON

**Illustrative only** (must match a fixture's actual files in tests):

```json
{
  "schema_version":"1.0",
  "scan_id":"scan_550e8400e29b41d4a716446655440000",
  "languages":[{"name":"JavaScript","file_count":1}],
  "manifests":[{"path":"package.json","kind":"package.json","ecosystem":"npm"}],
  "lockfiles":[{"path":"package-lock.json","kind":"package-lock.json","ecosystem":"npm"}],
  "dockerfiles":["Dockerfile"],
  "ci_files":[".github/workflows/ci.yml"],
  "iac_files":["infra/main.tf"],
  "existing_sboms":[],"source_directories":["src"],
  "file_count":7,"partial":false,"warnings":[]
}
```

If a fixture contains 7 eligible regular files, `file_count=7`; **never hard-code this expected count** if files are added. `kind` and `ecosystem` on each manifest/lock entry are required. Empty repos yield empty arrays, `file_count=0`, `partial=false`, not exceptions.

## Step 7 — Tests and invariants

| Unit test | Input | Expected |
|---|---|---|
| `test_npm_files` | npm_simple fixture | package.json + package-lock classified, JavaScript source counted |
| `test_python_files` | Python fixtures | requirements/pyproject and uv/poetry correctly classified |
| `test_monorepo_paths` | nested apps/backend/frontend | original relative paths and both project roots preserved |
| `test_other_supply_chain_files` | Docker, Actions, Terraform, SBOM file | category paths exact and sorted |
| `test_no_follow_symlinks` | symlink pointing outside fixture | ignored; outside file never inspected |
| `test_file_limit` | many tiny files | controlled `DiscoveryLimitError`; no false complete output |
| `test_generated_directories` | `node_modules`, `.git`, `.venv` | never traversed; no accidental npm metadata from install |
| `test_repeatability` | same tree scanned twice | byte-equivalent canonical JSON after stable sort |
| `test_empty` | empty dir | valid Inventory with empty lists |
| `test_bad_path` | missing/non-directory | typed failure, no data leak |

```bash
# from backend/ (see SETUP.md for OS-specific venv executable)
python -m pytest tests/discovery -q
python -m ruff check app/discovery tests/discovery
```

Use `tmp_path` in pytest for generated fixture trees, symlinks, file-limit scenarios. Windows: `pytest.skip()` symlink-privilege-dependent assertions **only** when symlink creation is genuinely blocked; do not silently skip all traversal security tests.

## Step 8 — Integration with Members 1 and 3

M1 calls:

```python
inventory = discover_repository(repo_dir: Path, scan_id: str)
# M1 validates .model_dump(), atomically persists inventory.json, then calls M3.
```

M3 reads `inventory.manifests` and `inventory.lockfiles` to find exact files under `repo_dir` using safe paths. **Do not open the files for M3, parse versions here or create package nodes here.** If M3 needs an additional artifact category, add rules **without changing inventory JSON schema**; if it needs a new field, request contract review. Name/path casing is preserved; `kind` is normalized known classifier. M1 owns path policy and ensures the checkout cannot be overwritten during discovery.

## Parallel Development and Collaboration

**Can start now:** `rules.py`, `engine.py`, temp fixture repos, inventory Pydantic validation and independent unit tests. Your only logical input dependency is the **signature** `discover_repository(repo_dir,scan_id)` and canonical JSON in the README; no GitHub clone, DB, Docker or Syft service is needed.

| Team member | Interface from/to you | Blocker workaround |
|---|---|---|
| M1 | Receives `Inventory`; supplies an isolated `Path` and scan ID | Use `tmp_path` fixture directly until cloning merged |
| M3 | Consumes manifest/lock entries and root paths | Send fixture inventory JSON + fixture tree immediately; no need to wait for live M1 |
| M4 | Receives graph only through M3, no direct coupling | None; avoid graph work in discovery branch |
| M5 | Shows discovered lists from inventory API | Provide sample JSON from `README.md`/fixture; no API wait |

**Ownership barrier:** don't modify shared schema, SQLAlchemy, Syft parsers, graph code or frontend. **PR sequence:** (1) file rules + tests, (2) safe traversal/limits, (3) source directories/monorepos and integration tests. **Reviewer:** M1, with M3 checking inventory consumption if classification fields change. **Integration blocker:** M3 cannot locate a listed path, `file_count` lies, path escapes, schema validation fails, categorization drops lockfiles, unsupported ecosystem claims full coverage. Escalate as a reproducible fixture + failing test and **keep developing** other rules; do not stall for pipeline work.

## Acceptance checklist

- [ ] Pure callable `discover_repository(Path,scan_id)` returns canonical `Inventory` Pydantic model.
- [ ] All filesystem evidence is repo-relative POSIX; no following symlinks/unsafe paths or execution.
- [ ] npm + Python manifests/locks, Dockerfiles, CI, IaC, existing SBOMs classified.
- [ ] Nested/monorepo paths retained, `file_count` actual, sorted deterministic output.
- [ ] Limits fail closed; skipped/unsupported discovery paths not silently labeled complete.
- [ ] Empty/unsupported repository valid and clearly represented.
- [ ] M3 can use fixtures before M1 is merged, and M1 can integrate without editing M2 files.
- [ ] Tests pass on Windows/macOS; changes pushed to `feature/repository-discovery` through reviewed PR.

**Handoff:** submit `Inventory` fixture JSON, one test repository tree, import path, and test command in your PR description; announce path/rule changes to M3 before merge.

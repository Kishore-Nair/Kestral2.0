# Member 1 — Platform, Backend, Secure Ingestion and Integration

**Branch:** `feature/ingestion` · **Review:** Member 2; contracts also reviewed by their producer/consumer · **Primary outcome:** `POST /api/v1/scans` asynchronously creates a real scan, clones a permitted GitHub repo safely, invokes modules owned by M2–M4 and serves results consumed by M5.

> Read [`README.md`](../README.md) for **canonical API/data contracts** and [`SETUP.md`](../SETUP.md) for Windows/macOS setup. Do **not** create a second JSON contract. This plan builds the shared skeleton **first** so the other four can commit independently.

## Scope / architectural decisions

- One Python 3.12 FastAPI **modular monolith**; never build five microservices.
- Two data stores: PostgreSQL for **scan metadata/status**; ignored filesystem for clone and immutable scan artifacts. No raw clone in PostgreSQL.
- `BackgroundTasks` is sufficient for a one-process demo **only**; never imply durability, multi-worker coordination, retries or production-grade isolation. On startup mark interrupted nonterminal statuses `FAILED` with `SCAN_INTERRUPTED`; users can resubmit.
- Public GitHub **HTTPS** only, ref limited to a named branch/tag; deny SSH, credentials, custom ports, arbitrary hosts, IPs, query/fragment and submodules.
- No `pip install`, `npm install`, `git submodule update`, execution of repository CI/hooks/scripts, Docker builds or unsandboxed user code.
- `http://127.0.0.1:8000/docs` exposes OpenAPI; API version is `/api/v1`, artifact schema `1.0`.

## Ownership

**Own exclusively:** `README.md`, `SETUP.md`, `.gitignore`, `.env.example`, `docker-compose.yml`, `backend/pyproject.toml`, `backend/alembic.ini`, `backend/migrations/**`, `backend/app/main.py`, `backend/app/config.py`, `backend/app/api/**`, `backend/app/database/**`, `backend/app/ingestion/**`, `backend/app/schemas/**`, `backend/tests/ingestion/**`, and backend package `__init__.py` files. **Do not edit** `backend/app/discovery/**` (M2), `backend/app/sbom/**` (M3), `backend/app/graph/**` (M4), `frontend/**` (M5). For dependencies requested by another member, you amend the single `backend/pyproject.toml` in a focused PR.

## Deliverable file checklist

```text
backend/
├── pyproject.toml
├── alembic.ini
├── migrations/{env.py,versions/xxxx_create_scans.py}
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── schemas/{__init__.py,scan.py,inventory.py,dependency.py,graph.py,error.py}
│   ├── api/routes/{__init__.py,scans.py}
│   ├── database/{__init__.py,base.py,models.py,session.py}
│   └── ingestion/{__init__.py,url_validation.py,cloner.py,workspace.py,worker.py,artifacts.py}
└── tests/ingestion/{test_urls.py,test_cloner.py,test_api.py,test_pipeline.py}
```

**Do not wait for implementation:** publish the typed schemas and placeholder route responses as the **bootstrap PR**. Stub functions may raise `NotImplementedError` only on a clearly marked local test path; they must not claim completed scans.

## Step 1 — Bootstrap, Python, DB and environment

Follow [`SETUP.md`](SETUP.md): root `.gitignore`, `.env.example`, Compose PostgreSQL 16, `backend/pyproject.toml`, Python venv, pip `-e '.[dev]'`. Create package folders and `__init__.py` files; register FastAPI in `app/main.py`:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes.scans import router as scans_router
from app.config import settings

app = FastAPI(title="Software Supply Chain Guardian", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin],
                   allow_credentials=False, allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type"])
app.include_router(scans_router, prefix="/api/v1")

@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
```

In `app/config.py`, use `pydantic_settings.BaseSettings` and `SettingsConfigDict(env_file=PROJECT_ROOT / '.env')`, where `PROJECT_ROOT = Path(__file__).resolve().parents[2]` for `backend/app/config.py`. Resolve `workspace_root` and `scan_output_root` *under project root* using `Path.resolve()`. Define `database_url`, `frontend_origin`, `git_clone_timeout_seconds`, `syft_timeout_seconds`, `max_repository_size_mb`, `max_file_count`, `max_manifest_size_mb`, `max_active_scans`, and validate positive limits. Do **not** expose `database_url` in API/errors/logs.

## Step 2 — Publish shared Pydantic models (contract freeze)

At minimum, implement the following in `app/schemas/*.py`; make names, required/nullable fields agree **exactly** with `README.md`. The example defines shapes; give each model `extra='forbid'` so accidental field divergence fails tests.

```python
from datetime import datetime
from enum import StrEnum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    CLONING = "CLONING"
    DISCOVERING = "DISCOVERING"
    GENERATING_SBOM = "GENERATING_SBOM"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class ScanCreate(StrictModel):
    repository_url: str = Field(min_length=1, max_length=400)
    ref: str | None = Field(default=None, max_length=120)

class ScanCreated(StrictModel):
    scan_id: str
    status: Literal["QUEUED"]
    repository_name: str

class Repository(StrictModel):
    url: str
    owner: str
    name: str
    requested_ref: str | None
    resolved_ref: str | None
    commit_sha: str | None

class ScanState(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    status: ScanStatus
    current_stage: ScanStatus | None  # Never COMPLETED as an active stage
    repository: Repository
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None  # sanitized human-readable error, not traceback
    warnings: list[str] = Field(default_factory=list)

class Evidence(StrictModel):
    path: str
    kind: str
    locator: str

class FileEntry(StrictModel):
    path: str
    kind: str
    ecosystem: str

class LanguageCount(StrictModel):
    name: str
    file_count: int = Field(ge=0)

class Inventory(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: str
    languages: list[LanguageCount]
    manifests: list[FileEntry]
    lockfiles: list[FileEntry]
    dockerfiles: list[str]
    ci_files: list[str]
    iac_files: list[str]
    existing_sboms: list[str]
    source_directories: list[str]
    file_count: int = Field(ge=0)
    partial: bool
    warnings: list[str]
```

**Remaining models** in `dependency.py` and `graph.py` must follow the normative examples in `README.md`. Minimum `DependencyDocument`: `schema_version`, `scan_id`, `roots`, `components`, `relationships`, `partial`, `warnings`; `Relationship.to_id` nullable, `unresolved_target` nullable, `resolution_status='resolved|unresolved|ambiguous'`. Graph `meta` has stats/warnings/partial and elements `nodes`/`edges` with Cytoscape `data`. **No `Any` except optional controlled metadata dictionaries**; update M3/M4 immediately if you change a field and require two-owner review.

Suggested public functions and their tests:

```python
# M2: app.discovery.engine
def discover_repository(repo_dir: Path, scan_id: str) -> Inventory: ...
# M3: app.sbom.pipeline
def generate_dependency_document(repo_dir: Path, inventory: Inventory,
                                  scan_id: str, scan_dir: Path) -> DependencyDocument: ...
# M4: app.graph.builder
def build_graph(document: DependencyDocument, app_name: str) -> GraphDocument: ...
```

## Step 3 — Validate GitHub URL and named ref **before** subprocess

The validator belongs in `app/ingestion/url_validation.py` and returns a structured `ValidatedRepository(owner, name, canonical_url, requested_ref)`. **Do not** allow generic `urlparse()` + arbitrary clone. Implement strictly:

```python
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
REF = re.compile(r"^[A-Za-z0-9._/-]{1,120}$")

@dataclass(frozen=True)
class ValidatedRepository:
    owner: str
    name: str
    canonical_url: str
    requested_ref: str | None

def validate_repo_url(url: str, ref: str | None) -> ValidatedRepository:
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname != "github.com"
        or parts.netloc != "github.com" or parts.username or parts.password
        or parts.port is not None or parts.query or parts.fragment):
        raise ValueError("Only public https://github.com/owner/repo URLs are supported")
    tokens = parts.path.strip("/").split("/")
    if len(tokens) != 2:
        raise ValueError("Expected a GitHub owner and repository")
    owner, name = tokens
    if name.endswith(".git"):
        name = name[:-4]
    if not OWNER.fullmatch(owner) or not REPO.fullmatch(name) or name in {".", ".."}:
        raise ValueError("Invalid GitHub owner/repository")
    if "%" in parts.path or "\\" in parts.path or "//" in parts.path:
        raise ValueError("Encoded or ambiguous paths are not allowed")
    if ref is not None and (not REF.fullmatch(ref) or ref.startswith(("-", "/", "."))
                            or ".." in ref or "//" in ref or ref.endswith(("/", ".", ".lock"))):
        raise ValueError("Invalid branch/tag")
    return ValidatedRepository(owner, name, f"https://github.com/{owner}/{name}", ref)
```

**Additional required hardening:** reject trailing slash ambiguity if desired; reject double-encoded URLs and non-ASCII homograph hosts (the strict `netloc` check does); run `git check-ref-format --branch <ref>` with `shell=False` for optional ref names (tag names may need a different Git ref check; document/refuse unsupported unusual tags). `urlsplit` `.port` may throw `ValueError`; convert to 422. Reject GitHub `/tree`, `/blob`, `/pull`, `/archive` paths. A `.git` suffix is normalized away and re-added only internally if preferred. Test `https://github.com.evil.test/...`, `https://github.com@evil.test/...`, embedded newlines, `file://`, `localhost`, `http://`, and `https://github.com:443/...`.

**Network security:** canonical host validation is necessary but **not enough** if an upstream proxy/DNS is compromised. Set Git `http.followRedirects=false`, disable alternate transport protocols, and put the scanner on a restricted network with GitHub-only egress and no access to localhost/RFC1918/link-local/metadata addresses where feasible. Document that local dev without egress controls is **not hardened against all SSRF**.

## Step 4 — Workspace and secure clone

Directory layout is fixed: `<root>/data/workspaces/<scan_id>/repo` for checkout and `<root>/data/scans/<scan_id>` for JSON. `scan_id = 'scan_' + uuid.uuid4().hex` (random, filesystem-safe). Create with `mkdir(parents=True, exist_ok=False)`, resolve under configured root, reject traversal, own cleanup, no user-supplied directory names. Git works on a fresh empty scan workspace, and the repo output directory must **not** exist before `git clone`.

```python
import os, subprocess
from pathlib import Path

def clone_public_repo(repo, scan_workspace: Path, timeout: int) -> Path:
    # scan_workspace already allocated safely by workspace.py
    target = scan_workspace / "repo"
    hooks = scan_workspace / "disabled-hooks"
    hooks.mkdir(exist_ok=False)
    # Allowlist basic process variables: do NOT inherit cloud/Git tokens or SSH_AUTH_SOCK.
    safe_vars = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG",
                 "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR")
    env = {key: os.environ[key] for key in safe_vars if key in os.environ}
    empty_config = scan_workspace / "empty.gitconfig"
    empty_config.write_text("", encoding="utf-8")
    env.update({"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "Never",
                "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": str(empty_config), "HOME": str(scan_workspace)})
    args = ["git", "-c", f"core.hooksPath={hooks}",
            "-c", "credential.helper=", "-c", "protocol.file.allow=never",
            "-c", "protocol.ext.allow=never", "-c", "http.followRedirects=false",
            "clone", "--depth", "1", "--single-branch", "--no-recurse-submodules"]
    if repo.requested_ref:
        args.extend(["--branch", repo.requested_ref])
    args.extend(["--", repo.canonical_url, str(target)])
    subprocess.run(args, shell=False, env=env, cwd=scan_workspace,
                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, text=True, timeout=timeout, check=True)
    return target
```

The snippet is a **starting point**, not a complete sandbox: global Git config can still affect helpers/filters; on macOS/Windows arrange a clean `GIT_CONFIG_GLOBAL` (empty file), no inherited Git-specific secret environment variables, and allowlisted subprocess executable path. Disable configurable smudge filters; don't enable `core.symlinks` behavior globally. After checkout verify the actual path, `git rev-parse HEAD` is 40 hex characters (Git repositories may use SHA-256; for MVP reject/flag unsupported object formats explicitly rather than assume), read `git symbolic-ref --short -q HEAD` if branch, and never trust checkout file names as host paths. Subprocess stderr may contain private data: **redact/summarize** in API.

Limits: clone timeout, max concurrent scans 1, post-clone walk with `followlinks=False` and max file count/bytes, max lockfile read size, Syft timeout, max output JSON size. **OS-level CPU/memory/disk/egress boundaries are strongly recommended before accepting arbitrary public input.** A timeout + post-clone size check alone does not prevent a transient oversized download; a production-grade service requires isolated containers/VMs with storage/network quotas and durable jobs.

**Security test matrix:** valid URL, invalid scheme/host/credentials, malicious ref beginning `-`, Git failure, repo not found/private, Git timeout, huge repo, symlink outside root, concurrent scan IDs, no submodules, path traverse, leftover workspace cleanup. Monkeypatch `subprocess.run` for unit tests; never invoke Git on malicious test URLs.

## Step 5 — PostgreSQL model, migrations and scan status

`app/database/models.py` (SQLAlchemy 2):

| Column | Type | Notes |
|---|---|---|
| `scan_id` | `String(40)` PK | `scan_<32 hex>` |
| `repository_url` | `Text` NOT NULL | canonical public HTTPS URL |
| `owner`, `repository_name` | `String(150)` | normalized |
| `requested_ref`, `resolved_ref` | `String(150)` nullable | branch/tag; HEAD resolution |
| `commit_sha` | `String(64)` nullable | SHA storage allows future formats |
| `status` | `String(40)` NOT NULL | enum validated in application |
| `current_stage` | `String(40)` nullable | last processing stage |
| `inventory_path`, `sbom_path`, `normalized_path`, `graph_path` | `Text` nullable | **relative** artifact locations |
| `warnings_json` | `JSON` | default empty array |
| `error_code`, `error_message` | `String/Text` nullable | sanitized |
| `created_at`, `started_at`, `finished_at` | `DateTime(timezone=True)` | UTC |

Use `create_engine(settings.database_url, pool_pre_ping=True)` and `sessionmaker(expire_on_commit=False)` in `session.py`; each worker owns its own DB session. Create an Alembic initial migration; do not call `Base.metadata.create_all()` on each API startup. Write `set_status(scan_id, stage)` and `finish(scan_id, status, ...)` with commits per stage so UI polling sees progress. Atomicity: create row before scheduling task; write artifact file fully, then update path/status in a DB commit. Never record `COMPLETED` without graph artifact validation.

`GET /api/v1/scans/{id}` returns scan state, even if `FAILED` (200 with status). `GET /inventory`, `/sbom`, `/graph` returns 409 when missing, 404 for unknown IDs. Prevent arbitrary disk file serving by resolving **only stored relative** paths under configured `scan_output_root`. Stage data readiness: inventory 200 once written; normalized SBOM 200 once written; graph 200 only once written (even if later failure), with `partial` as appropriate.

## Step 6 — Implement routes and scheduling

Use `BackgroundTasks` in the POST handler and return 202 instantly; don't await clone in request handler. Define an `ApiProblem(status,code,message)` exception and register a FastAPI handler returning the exact README `{error:{code,message,details},scan_id}` shape; never rely on FastAPI's default `{detail:...}` response for your contract errors. Prefer an ordinary `def` worker for subprocess and filesystem IO; if using async endpoint + blocking routines, dispatch through the framework's threadpool rather than blocking event loop.

```python
@router.post("/scans", response_model=ScanCreated, status_code=202)
def create_scan(body: ScanCreate, background_tasks: BackgroundTasks,
                db: Session = Depends(get_db)):
    try:
        repo = validate_repo_url(body.repository_url, body.ref)
    except ValueError as exc:
        raise ApiProblem(status=422, code="INVALID_REPOSITORY", message=str(exc)) from None
    scan_id = "scan_" + uuid.uuid4().hex
    row = create_scan_row(db, scan_id=scan_id, repo=repo, status="QUEUED")
    background_tasks.add_task(run_scan, scan_id)  # opens its OWN Session
    return ScanCreated(scan_id=scan_id, status="QUEUED", repository_name=repo.name)
```

Implement per-process concurrency limits (`threading.BoundedSemaphore`) and return **429** or queue with a documented cap; for a demo, `MAX_ACTIVE_SCANS=1` and one Uvicorn worker. If process dies after 202, queued tasks may be lost; on startup reconcile orphaned `QUEUED/CLONING/...` to `FAILED/SCAN_INTERRUPTED`. This is a conscious hackathon trade-off, not production reliability.

**REST contract:** exactly the methods, status codes and error JSON specified in `README.md`. Do not add an unversioned `/scan` endpoint. Use a Pydantic `ErrorResponse` or exception handler with `{error:{code,message,details},scan_id}`; sanitize Git/Syft stderr and record internal correlation IDs in logs.

## Step 7 — Worker orchestration (stable typed boundaries)

`app/ingestion/worker.py` must be a linear state machine. Use temporary artifact file and `os.replace`, ensuring every stage either publishes a validated artifact or transitions to `FAILED`.

```python
def run_scan(scan_id: str) -> None:
    with session_factory() as db:
        row = load_scan(db, scan_id)
        try:
            workspace, outdir = allocate_scan_dirs(scan_id)
            set_status(db, row, "CLONING")
            repo_dir = clone_public_repo(as_validated_repo(row), workspace,
                                         settings.git_clone_timeout_seconds)
            enforce_workspace_limits(repo_dir)
            record_commit_info(db, row, repo_dir)

            set_status(db, row, "DISCOVERING")
            inventory = discover_repository(repo_dir, scan_id)
            save_validated_json(outdir / "inventory.json", inventory)
            record_artifact(db, row, "inventory_path", scan_id, "inventory.json")

            set_status(db, row, "GENERATING_SBOM")
            doc = generate_dependency_document(repo_dir, inventory, scan_id, outdir)
            save_validated_json(outdir / "normalized.json", doc)
            record_artifact(db, row, "normalized_path", scan_id, "normalized.json")
            # M3 also writes original outdir / "sbom.cdx.json" after Syft succeeds.
            record_artifact(db, row, "sbom_path", scan_id, "sbom.cdx.json")

            set_status(db, row, "BUILDING_GRAPH")
            graph = build_graph(doc, app_name=row.repository_name)
            save_validated_json(outdir / "graph.json", graph)
            record_artifact(db, row, "graph_path", scan_id, "graph.json")
            finish_completed(db, row, warnings=[*inventory.warnings,
                                                 *doc.warnings, *graph.meta.warnings])
        except Exception as exc:
            # One job-boundary catch; to_safe_error maps known failures to stable codes.
            finish_failed(db, row, to_safe_error(exc))
            logger.exception("scan failed: scan_id=%s", scan_id)
        finally:
            apply_workspace_retention_policy(scan_id)
```

Use `except Exception` **once** at the job boundary, with precise error-category mapping inside `to_safe_error`; do not disguise broad catches inside exception tuples. Preserve traceback **only in restricted local logs** and never emit secrets/source file contents. Test cleanup even when Syft fails. `record_artifact` should never accept a path from request JSON. If `Inventory.partial=True`, decide policy: continue to graph but mark result `partial` and explain missing evidence; if security limits indicate malicious/oversized input, stop and fail instead.

**Important**: M3 writes CycloneDX to `sbom.cdx.json` inside the scan artifact directory, **not** to the cloned repo. M4 must not assume all components have PURLs. UI receives normalized `/sbom`, not the raw CycloneDX file.

## Step 8 — Test it in layers

| Test | Fixture/setup | Assertion |
|---|---|---|
| `test_valid_urls` | URLs and branch names | valid normalized; invalid 422 |
| `test_clone_args` | monkeypatched `subprocess.run` | `shell=False`, redirect disabled, no submodule, timeout and isolated path |
| `test_scan_create_202` | FastAPI `TestClient`, fake DB | immediate scan ID, queued |
| `test_unknown_scan` | fake DB | 404 |
| `test_graph_not_ready` | queued scan | 409 structured error |
| `test_worker_happy_path` | fake M2/3/4 modules | stage order, all artifact writes, `COMPLETED` |
| `test_worker_syft_failure` | M3 throws | `FAILED`, safe error, no graph path |
| `test_db_migration` | local test PostgreSQL | migrates fresh DB and scans table |
| `test_end_to_end` | permitted small public test repo | SHA + inventory + real CycloneDX + graph 200 |

Avoid external GitHub network in unit tests. Mock module return values using `model_validate` from canonical JSON fixtures. Use real `syft` only in marked integration smoke tests; pin fixture input to a chosen Git **commit** in your test script so expected results do not float with a branch.

```bash
# In backend/ with venv configured
python -m pytest tests/ingestion -q
python -m ruff check app/ingestion app/api app/database app/schemas
python -m alembic upgrade head
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

For Windows use `.\.venv\Scripts\python.exe -m ...`, macOS `.venv/bin/python -m ...`. Once M5 frontend is ready, open `http://localhost:3000`, scan a small authorized repo, poll status and ensure graph is actionable.

## Parallel Development and Collaboration

**Start immediately (even if others write no code):** bootstrap FastAPI/OpenAPI, schema models, migration, security URL tests, a fixture-worker path (pure fake M2/3/4 interfaces), GET artifact routes and worker status tests. Put two sample payloads under your own `tests/ingestion/fixtures/`; for JSON structure copy `README.md` **exactly**. Do **not** edit other members' implementation modules to make imports pass: publish `__init__.py` and an explicit interface stub in the schema/adapter location you own; have teammates supply implementation behind it.

| Member | Dependency on your work | You need from them | Fallback while blocked |
|---|---|---|---|
| 2 | `repo_dir`, `scan_id`, Inventory model | `discover_repository()` | fake `Inventory` typed fixture |
| 3 | DependencyDocument model, `scan_dir`, inventory contract | `generate_dependency_document()` | normalized fake document + Syft fixture |
| 4 | graph schema, `app_name` | `build_graph()` | saved `GraphDocument` fixture |
| 5 | 202/status/inventory/sbom/graph REST contracts | UI smoke test | curl + TestClient |

**Review** M2's PR and ask M2 to review ingestion PR. Contract changes require M1 + producer/consumer approval, update both fixture sides and OpenAPI. **Integration blocker:** mismatched field shape, unsafe clone path, inability to import one module, wrong status codes, missing verified evidence, or a secret leak. Raise a focused issue and proceed with mocks; no teammate is asked to idle. You integrate in order **bootstrap → modules imported → worker E2E → UI E2E**. Do not merge to `main` if smoke tests or security regressions fail.

### Day-one task slices / PR sequence

1. `PR-1` (immediately): repository skeleton, pyproject, Compose, env, Pydantic schema 1.0, health/stub route, CI/test instructions; **merge early**.
2. `PR-2`: URL/ref validator + secure clone + negative tests.
3. `PR-3`: SQLAlchemy scan row, Alembic migration, status transitions, ready/not-ready endpoints.
4. `PR-4`: fixture-backed worker orchestration and output files (still no real module imports until merge).
5. `PR-5`: wire M2/M3/M4 modules, real authorized sample scan, CORS frontend integration and failure cases.
6. Before demo: replay scan after process restart, test unavailable GitHub, eliminate credentials/absolute paths from logs/response, verify every output file valid JSON.

## Acceptance checklist

- [ ] Bootstrap PR permits all four other members to import canonical schema models and develop without blockers.
- [ ] Public GitHub URL only; malicious URLs/refs fail before clone; repo code never executed.
- [ ] Unique workspaces, timeout, no recursive submodules, resource bounds, no cross-scan artifacts.
- [ ] POST 202 + polling progresses; typed errors 404/409/422/503; interrupted scans fail on restart.
- [ ] Git SHA/ref stored; DB migrations clean; artifacts written atomically and served through fixed endpoints.
- [ ] Worker invokes exactly M2 → M3 → M4, validates typed outputs, keeps warnings and partial accuracy.
- [ ] Both Windows and macOS teammates can run backend and tests using `SETUP.md`.
- [ ] Member 5 can post a URL and retrieve/render actual graph JSON; no risk/CVE claims in Phase 1.

**Handoff to team:** M1 merges the schema/API skeleton quickly, posts `/openapi.json` plus a fixture scan ID/response contract, and owns final integration. Members 2–5 never need to wait for the entire pipeline.

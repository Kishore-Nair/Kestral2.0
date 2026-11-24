# Team Setup — Windows 11 and macOS

> Applies to **all five members**. Read [`README.md`](README.md) first. OS-specific commands are labeled. The initial document pack is a **blueprint**, not an already running application: commands that start services work after Member 1 and Member 5 land the scaffold files.

## 0. Team-wide rules (read before installing)

- Use the same shared GitHub repository and the `feature/<workstream>` branch assigned in `README.md`. Never commit `data/`, `.env`, `.venv/`, `node_modules/`, PostgreSQL volumes or sampled repository contents.
- Backend: **Python 3.12** and `pyproject.toml` with pip editable installation. Frontend: **current supported Node.js LTS** and `package-lock.json` using `npm ci` after setup. Do not introduce Poetry, Conda, pnpm or a second lockfile for the Guardian application.
- Docker Desktop is **for the team's PostgreSQL database** (not running untrusted downloaded code). Install Syft locally on the backend developer's machine; all members should preferably install it so reproductions work.
- Two environment files: repo root `.env` is backend/Compose configuration; `frontend/.env.local` is Next.js public browser configuration. Neither contains real cloud credentials.
- Use only deliberately chosen benign public/authorized repositories for tests; scanning a public repo is **not permission to execute scripts or attack services**.

## 1. Install prerequisite software

| Tool | Windows 11 | macOS | Verify in new terminal |
|---|---|---|---|
| Git | https://git-scm.com/download/win (Git for Windows) | `xcode-select --install` or https://git-scm.com/download/mac | `git --version` |
| Python 3.12 | https://www.python.org/downloads/windows/ (choose Python 3.12; enable PATH/launcher if offered) | `brew install python@3.12` with Homebrew or Python.org installer | `py -3.12 --version` / `python3.12 --version` |
| Node.js LTS + npm | https://nodejs.org/en/download | https://nodejs.org/en/download or `brew install node` (confirm it is an LTS line) | `node --version`, `npm --version` |
| Docker Desktop + Compose | https://docs.docker.com/desktop/setup/install/windows-install/ ; enable WSL 2 as documented | https://docs.docker.com/desktop/setup/install/mac-install/ (choose Apple Silicon/Intel) | `docker version`, `docker compose version` |
| Syft | PowerShell: `winget install Anchore.syft` | Terminal: `brew install syft` | `syft version` |
| Grype (risk stage) | PowerShell: `winget install Anchore.grype`, then `grype db update` | Terminal: `brew install grype`, then `grype db update` | `grype db status` |
| VS Code | https://code.visualstudio.com/ | https://code.visualstudio.com/ | `code --version` (optional PATH) |
| HTTP client | VS Code REST Client, curl or Postman | `curl` or Postman | `curl --version` |

**Homebrew (macOS) if missing:** https://brew.sh/ (follow their current installer instructions; avoid pasting unverified third-party installers). **Syft official guide:** https://oss.anchore.com/docs/installation/syft/ . On Windows, close/reopen PowerShell after `winget` installation to update `PATH`. On Apple Silicon use arm64 binaries as directed by the vendor.

**Grype and OSV (risk stage):** scans never update Grype's database, so run `grype db update` before a demo; each scan records the database build date. OSV is queried over the internet at `https://api.osv.dev`. If Grype is missing or offline OSV fails, the scan still completes and `findings.json` marks vulnerabilities as not assessed (`partial=true`). Set `GRYPE_ENABLED=false` or `OSV_ENABLED=false` in `.env` to turn a source off.

**NVD (CVE details, CWEs, CVSS):** each CVE is looked up once in the NVD CVE API 2.0 and cached in `data/nvd/` for `NVD_CACHE_DAYS`. Without a key NVD allows 5 requests per 30 s, so the first scan of a large project can spend many minutes in *Analyzing risk* (about 6 s per new CVE; NodeGoat's 181 CVEs take ~18 min). A free key (`NVD_API_KEY` in your local `.env`, never committed) makes it ~10x faster. CVEs not reached within `NVD_BUDGET_SECONDS` are reported as not looked up, and the next scan continues from the cache.

### Windows PowerShell check

```powershell
Get-Command git, node, npm, docker, syft
py -3.12 --version
node --version
npm --version
git --version
syft version
docker compose version
```

If `py` is missing but `python --version` says 3.12.x, use `python` in subsequent Windows instructions. If PowerShell blocks `.venv\Scripts\Activate.ps1`, **do not change machine execution policy**: use `.venv\Scripts\python.exe` explicitly instead. If Docker cannot start, verify WSL 2/virtualization using the official Docker Desktop checklist. Avoid `sudo` or admin shells for normal app development.

### macOS check

```bash
python3.12 --version
node --version
npm --version
git --version
syft version
docker compose version
```

If your terminal cannot find `brew` or `python3.12`, follow Homebrew's `shellenv` guidance or use the Python.org installer; don't overwrite the system Python.

## 2. Create the repository, clone it, branch (everyone)

**Only the repository owner/M1:** Create an empty **private team GitHub repository** for *our application source code* (can remain private); add five collaborators with push access; enable branch protection on `main` (PR required and checks where available). Commit `README.md` and `SETUP.md` at the root plus the five plans in `team_instructions/` before coding. Do **not** add the internal Bosch PDF to a public repo.

Every developer then uses **their actual repo URL** (placeholder below is not a functioning address):

```bash
git clone https://github.com/ORG/software-supply-chain-guardian.git
cd software-supply-chain-guardian
git switch main
git pull --ff-only origin main
```

Replace `ORG` with your GitHub organization/account. Use a GitHub credential manager/SSH **for pushing your own code**; the Guardian scanner itself will accept **HTTPS public GitHub URLs only**, with no credentials.

Create your feature branch, one of:

```bash
git switch -c feature/ingestion                  # Member 1
git switch -c feature/repository-discovery      # Member 2
git switch -c feature/sbom-extraction           # Member 3
git switch -c feature/graph-engine              # Member 4
git switch -c feature/frontend                  # Member 5
```

**Run exactly one** command above, matching your workstream. If the branch already exists remotely, use `git fetch origin` then `git switch --track origin/feature/YOUR-WORKSTREAM` rather than creating a duplicate.

## 3. Root application files to be committed by Member 1

**Ownership:** M1 creates and merges these files **once**; others should not rewrite them. `SETUP.md` includes the authoritative starting contents so a missing scaffold is not a blocker.

### `.gitignore`

```gitignore
.env
.env.*
!.env.example
!frontend/.env.local.example
.venv/
__pycache__/
.pytest_cache/
.ruff_cache/
*.py[cod]
*.egg-info/
node_modules/
.next/
out/
coverage/
data/
.DS_Store
Thumbs.db
```

### `.env.example` (root)

```dotenv
# Local-only PostgreSQL development credentials; change for any shared server.
POSTGRES_USER=guardian
POSTGRES_PASSWORD=guardian_dev_only
POSTGRES_DB=guardian
POSTGRES_PORT=5432
DATABASE_URL=postgresql+psycopg://guardian:guardian_dev_only@127.0.0.1:5432/guardian

# Resolved relative to the PROJECT ROOT by app/config.py, not working directory.
WORKSPACE_ROOT=data/workspaces
SCAN_OUTPUT_ROOT=data/scans
MAX_REPOSITORY_SIZE_MB=200
MAX_FILE_COUNT=30000
MAX_MANIFEST_SIZE_MB=8
MAX_ARTIFACT_SIZE_MB=100
GIT_CLONE_TIMEOUT_SECONDS=120
SYFT_TIMEOUT_SECONDS=120
OSV_ENABLED=true
OSV_TIMEOUT_SECONDS=20
GRYPE_ENABLED=true
GRYPE_TIMEOUT_SECONDS=180
NVD_ENABLED=true
NVD_API_KEY=
NVD_TIMEOUT_SECONDS=20
NVD_BUDGET_SECONDS=1200
NVD_CACHE_DAYS=7
NVD_CACHE_ROOT=data/nvd
MAX_ACTIVE_SCANS=1

API_HOST=127.0.0.1
API_PORT=8000
FRONTEND_ORIGIN=http://localhost:3000
LOG_LEVEL=INFO
```

**Important:** `MAX_REPOSITORY_SIZE_MB` is a post-clone on-disk limit; by itself it does not stop oversized Git downloads. For the MVP also use process timeouts, filesystem quota/resource limits where possible, and reject/discard oversized clones promptly. Never claim full DoS resistance based on this environment variable.

### `docker-compose.yml` (root)

```yaml
services:
  postgres:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-guardian}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-guardian_dev_only}
      POSTGRES_DB: ${POSTGRES_DB:-guardian}
    ports:
      - "127.0.0.1:${POSTGRES_PORT:-5432}:5432"
    volumes:
      - guardian_postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-guardian} -d ${POSTGRES_DB:-guardian}"]
      interval: 5s
      timeout: 5s
      retries: 10

volumes:
  guardian_postgres:
```

PostgreSQL **16** is a deliberate dev baseline, not a promise of the latest version. The DB port binds to loopback only; Docker Desktop still runs containers under your local machine account. Never run `docker compose down -v` unless you intend to erase your local DB.

### `backend/pyproject.toml` (M1)

```toml
[build-system]
requires = ["setuptools>=70", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "software-supply-chain-guardian-backend"
version = "0.1.0"
requires-python = ">=3.12,<3.13"
dependencies = [
  "fastapi>=0.115,<1",
  "uvicorn[standard]>=0.30,<1",
  "pydantic>=2.7,<3",
  "pydantic-settings>=2.3,<3",
  "sqlalchemy>=2.0,<3",
  "alembic>=1.13,<2",
  "psycopg[binary]>=3.2,<4",
  "networkx>=3.3,<4",
  "packaging>=24,<27",
  "packageurl-python>=0.16,<2",
]

[project.optional-dependencies]
dev = ["pytest>=8,<10", "pytest-cov>=5,<8", "httpx>=0.27,<1", "ruff>=0.8,<1"]

[tool.setuptools.packages.find]
include = ["app*"]

[tool.ruff]
line-length = 100

[tool.pytest.ini_options]
testpaths = ["tests"]
```

Use this as a **starter version range**, not a reproducible pinned lock. For the hackathon, M1 should test an installation and freeze resolved versions in a reviewed constraints/lock strategy if reproducibility becomes an issue. Other members submit dependency requests to M1; avoid unreviewed `pip install <whatever>` and avoid divergent files.

### `frontend/.env.local.example` (M5)

```dotenv
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000/api/v1
```

No secret belongs in a `NEXT_PUBLIC_` variable: its value is shipped to browsers. Frontend `package.json`, `package-lock.json`, `components.json`, `tailwind` configuration and React files are **owned only by M5**.

## 4. Start PostgreSQL (every backend developer)

Run from **repository root** on Windows PowerShell **or** macOS Terminal:

```bash
# First time, create root .env from tracked example as detailed below.
docker compose up -d postgres
docker compose ps
docker compose logs --tail=50 postgres
```

**Windows:**

```powershell
Copy-Item .env.example .env
docker compose up -d postgres
```

**macOS:**

```bash
cp .env.example .env
docker compose up -d postgres
```

Only copy if no personal `.env` exists; never overwrite a teammate's secrets or commit the file.

```bash
docker compose stop postgres       # stop, keep data
docker compose start postgres      # restart, keep data
docker compose down                # remove container/network, keep named volume
# DANGEROUS: docker compose down -v  # permanently deletes your local DB volume
```

If `5432` is occupied, set `POSTGRES_PORT=5433` and adjust `DATABASE_URL` in **your** `.env` to `127.0.0.1:5433`. On Windows Docker Desktop must be running, not merely installed.

## 5. Backend Python environment

`backend/` and `backend/pyproject.toml` must exist (from M1's bootstrap). The following commands assume you are in `backend/`.

**Windows PowerShell:**

```powershell
Set-Location backend
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If `py -3.12` doesn't exist but `python` is 3.12, replace first invocation accordingly. Keeping the `.venv` Python explicit avoids PowerShell activation/execution-policy issues.

**macOS Terminal:**

```bash
cd backend
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Alembic migrations** (once M1 adds config/migration):

```bash
# From backend/; activate the venv or use its Python (-m alembic)
python -m alembic upgrade head
# First migration creation is ONLY Member 1's responsibility:
# python -m alembic revision --autogenerate -m "create scans"
```

On Windows replace `python` in this example with `.\.venv\Scripts\python.exe`, on macOS with `.venv/bin/python`, unless activated. M1 must load root `.env` in configuration and Alembic `env.py`. `alembic upgrade head` is not usable **until migrations have been implemented**.

Check service when available: `http://127.0.0.1:8000/docs` and `http://127.0.0.1:8000/api/v1/health`.

## 6. Frontend environment

**Only Member 5 on their feature branch creates the initial app**, once, from **repository root**:

```bash
npx create-next-app@latest frontend --typescript --tailwind --eslint --app --src-dir --use-npm --import-alias "@/*"
cd frontend
npm install axios cytoscape cytoscape-dagre lucide-react
npm install --save-dev @types/cytoscape @types/cytoscape-dagre vitest jsdom @testing-library/react @testing-library/jest-dom
npx shadcn@latest init
npx shadcn@latest add button card input badge skeleton sheet separator
```

If `frontend/` already exists in `main`, **do not re-scaffold**; everyone runs:

```bash
cd frontend
npm ci
```

**M5 adds scripts** in `frontend/package.json`: `"lint":"eslint ."`, `"typecheck":"tsc --noEmit"`, `"test":"vitest run"` (alongside Next's `dev`, `build`, `start`). Commit `package-lock.json` after installations. Next.js App Router and Tailwind are created by the scaffold; shadcn adds UI components to the app, not a separate runtime server. If shadcn's CLI offers configuration prompts, select an existing Next.js project and keep `src/`/`@/*` aliases.

**Windows PowerShell:**

```powershell
Copy-Item .env.local.example .env.local
npm run dev
```

**macOS Terminal:**

```bash
cp .env.local.example .env.local
npm run dev
```

Visit `http://localhost:3000`. Member 5 must use `"use client"` and a client-only dynamic import for the Cytoscape component to avoid SSR `window` errors.

## 7. Verify Syft scans a local directory (no execution)

From **repository root** after `backend/` exists:

**Windows PowerShell:**

```powershell
New-Item -ItemType Directory -Force -Path data\smoke | Out-Null
syft "dir:backend" -o "cyclonedx-json=data/smoke/self-test.cdx.json"
Get-Content data\smoke\self-test.cdx.json -TotalCount 8
```

**macOS:**

```bash
mkdir -p data/smoke
syft dir:backend -o cyclonedx-json=data/smoke/self-test.cdx.json
head -n 8 data/smoke/self-test.cdx.json
```

A nonzero exit code, missing `bomFormat: "CycloneDX"` or malformed JSON is a **setup failure**. A small/no-component SBOM is possible if the input lacks resolved dependency files and is not proof of an implementation bug. Syft scans files/manifests locally; it does **not** need `npm install`, `pip install`, a Docker build or execution of submitted repository code.

## 8. Run tests and full demo after integration

Open **three terminals** (PostgreSQL background; backend; frontend). Run DB migrations before backend. Make sure M1 has merged API and modules and M5 has merged frontend. Use a test repository your team is permitted to clone.

**Both OS (from repo root; adapt venv Python path):**

```bash
docker compose up -d postgres
cd backend
python -m alembic upgrade head
python -m pytest -q
python -m ruff check .
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Frontend terminal:**

```bash
cd frontend
npm ci
npm run lint
npm run typecheck
npm run test
npm run dev
```

**API smoke (macOS or PowerShell with curl.exe; replace repository URL):**

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"repository_url":"https://github.com/OWNER/PUBLIC_TEST_REPO","ref":null}'
```

The example above is **bash syntax**. For **PowerShell**, prefer native JSON instead of copied Bash quoting:

```powershell
$body = @{ repository_url = "https://github.com/OWNER/PUBLIC_TEST_REPO"; ref = $null } | ConvertTo-Json
$result = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/scans" -ContentType "application/json" -Body $body
$result.scan_id
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scans/$($result.scan_id)"
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/scans/$($result.scan_id)/graph"
```

**macOS**: copy the returned `scan_id` and poll until `COMPLETED`:

```bash
curl http://127.0.0.1:8000/api/v1/scans/YOUR_SCAN_ID
curl http://127.0.0.1:8000/api/v1/scans/YOUR_SCAN_ID/graph
```

If `/graph` returns HTTP **409**, it is not yet available; inspect the scan status and retry only after successful completion. An HTTP **404** means wrong scan ID, and **FAILED** must show a sanitized message. Finally open `http://localhost:3000`, submit the same URL and click a dependency node.

## 9. Everyday Git process

```bash
git status
git add <only-your-owned-files>           # replace placeholder with actual paths
git commit -m "feat(graph): add rooted depth computation"
git push -u origin feature/graph-engine     # replace with YOUR branch
```

Open PR into `main`, get assigned reviewer approval, fix feedback, merge. To sync:

```bash
git fetch origin
git rebase origin/main                      # on your feature branch, if no one else shares it
# Resolve conflicts only in files you own; coordinate shared files with M1.
```

Never run `git push --force` on `main`. If rebase changes pushed feature history, use `--force-with-lease` **only on your own branch** with team agreement.

## 10. Common setup blockers

| Symptom | Likely cause | Safe remedy |
|---|---|---|
| `syft: command not found` | New PATH not loaded | Reopen terminal; use Syft official platform install instructions |
| `py -3.12` missing | Windows launcher not installed | Use `python` only if it reports Python 3.12; otherwise install 3.12 |
| `uvicorn`/`pytest` not found | Venv not used / package not installed | Use explicit `.venv` Python to run modules |
| `psycopg` database connection refused | Docker isn't running, bad port, DB not healthy | `docker compose ps`, `docker compose logs postgres`, check `.env` |
| Alembic says no config/script directory | M1 hasn't merged migration scaffold | Do independent module tests; do not invent parallel migrations |
| CORS error | frontend origin mismatch | Set `FRONTEND_ORIGIN=http://localhost:3000`, restart backend |
| Next.js `window is not defined` | Cytoscape SSR import | Render Cytoscape only on client via dynamic `ssr:false` |
| Windows file path in API evidence | Host OS path leaked | Convert relative paths to `PurePosixPath`; reject symlink escape |
| Syft returns few packages | No lockfile, unsupported ecosystem, scanner coverage | Surface `partial/warnings`; don't guess versions or edges |
| Scans always QUEUED after restart | `BackgroundTasks` is not a durable queue | M1 marks interrupted scans FAILED at startup; manually resubmit |
| Network/proxy blocking GitHub | Corporate restrictions | Develop from local fixtures, confirm policy with team; do not bypass controls |

## 11. Official sources (recheck when upgrading tools)

- Python: https://www.python.org/downloads/ ; Windows: https://docs.python.org/3/using/windows.html
- Git: https://git-scm.com/downloads
- Node: https://nodejs.org/en/download
- Next.js CLI: https://nextjs.org/docs/app/api-reference/cli/create-next-app
- shadcn: https://ui.shadcn.com/docs/installation/next
- Docker Windows: https://docs.docker.com/desktop/setup/install/windows-install/
- Docker Mac: https://docs.docker.com/desktop/setup/install/mac-install/
- Syft: https://oss.anchore.com/docs/installation/syft/
- PostgreSQL image: https://hub.docker.com/_/postgres

**Ready to begin:** M1 first lands a minimal scaffold and 1.0 schema contracts; Members 2–5 begin with fixtures **without waiting**; all five push reviewed PRs to the same repo.

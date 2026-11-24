# Live NodeGoat sandbox pipeline

Branch: `feat/sandbox-testing`. This is a real scan and sandbox validation, not generated demo findings.

## Presenting the running application

Open **http://localhost:3001**. The API is **http://127.0.0.1:8001/api/v1**.
Ports 3001/8001 avoid interfering with existing services on this workstation.

1. Open http://localhost:3001/?scan=scan_5a21801856924114b38d22f36fcc3037 to load the saved real scan.
2. Inspect the graph and the body-parser finding for **CVE-2024-45590**.
3. Open its remediation proposal and inspect the recorded human decision.
4. In sandbox validation, open the completed body-parser 1.18.3 → 1.20.3 run.
5. Expand build/test output, the exact manifest/lockfile diff, comparison, and remaining risks.
6. Use **Validate again** to repeat the actual checkout, resolution, container tests and rescan.
   Completed stages appear while it runs. This uses the existing exact-version approval.
7. Download the HTML/JSON report. Do not describe the whole application as secure.

For a fresh full presentation, scan `https://github.com/DXVNX/NodeGoat`, review the new
proposal and explicitly approve it, then validate. New scans require their own approval.
No API keys or AI provider are needed for this deterministic route.

## Actual source and approval

- Repository: `https://github.com/DXVNX/NodeGoat`
- Scanned commit: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`
- Proposal: `rem_195f9b7245b992b37616d9d9d42e02ae`
- Proposal digest: `195f9b7245b992b37616d9d9d42e02ae45540e76a23cab67871c787384225565`
- User explicitly approved **sandbox validation only**, recorded through the normal decision API.
- First validation: `val_40f2e28065374bfd936cd798863edf70`, **NOT_FIXED**. Direct pinning
  left Express's nested body-parser 1.18.3 present. This failed result is preserved.
- Retry: `val_5e8cab31b2124eaebe047999d41a6c96`, **FIXED** for the selected advisory.
  Exact direct pin plus npm override fixes nested copies at the same approved version.
- Final rehearsal: `val_98124f89bf704ca6894089e363f9fe4e`, **FIXED**, completed in
  **110.096 seconds**. Six baseline and six patched regressions passed. Original scan hashes
  were unchanged; no validation checkout, test container or test volume remained.

## Verified release evidence (2026-11-24)

- Full offline backend suite: **495 passed, 2 skipped**, container exit code 0.
  The two skips require Syft inside the test image. The real host pipeline ran Syft 1.57.2
  and Grype 0.122.1 successfully, with Grype DB built 2026-11-23T06:28:32Z.
- Frontend suite: **77 passed** across 10 test files; production build passed.
- Ruff on changed validation code/tests: passed. `git diff --check`: passed.
- Real Chrome UI: graph (1,485 package instances, 2,289 dependency edges), findings,
  recorded approval, final FIXED result, test output, exact patch, remaining risks and
  report links were all present. The original scan has explicit partial-coverage warnings.
- HTML/JSON report endpoints: HTTP 200. Frontend: HTTP 200. CORS allows the actual frontend origin.
- Source NodeGoat checkout remains clean at the scanned SHA.
- Earlier failures are preserved in the local evidence: direct-only remediation was NOT_FIXED;
  the first regression harness had one assertion failure, then was corrected; the initial
  full test image omitted Git and policy files. None was reported as a successful run.

Artifacts are under `data/scans/<scan_id>/validations/<validation_id>/`:
`sbom.cdx.json`, `normalized.json`, `graph.json`, `findings.json`, `osv.json`, `grype.json`,
`progress.json`, and the exact files in `patch/`. Database records hold the decision,
test output, verdict and comparison. Local rehearsal API captures are in
`backend/data/live-evidence/`. These generated files are intentionally ignored by Git.

## Implementation and boundaries

- `service.py` checks the human decision, proposal digest, finding digest and scanned commit
  again before execution. A changed/absent approval is refused.
- `patching.py` pins the selected npm version and uses an override for nested copies.
- Lock resolution runs in a bounded container with lifecycle scripts disabled. Only the
  resulting parsed lockfile is written back to the disposable checkout.
- The reviewed NodeGoat recipe is selected by application source hashes, not repository name.
  Other projects retain their existing generic recipes; arbitrary repositories are not
  automatically covered by the NodeGoat tests.
- Installation and execution are separate containers. Tests have **no network**, no host
  secrets/socket, read-only root filesystem, dropped capabilities, and CPU/memory/PID/time limits.
- NodeGoat has no `test/unit` suite at this commit. Kestral therefore runs six explicit
  integration regressions against its real Express/body-parser/contribution-handler code.
  Harmless numeric requests test successful form/JSON handling, negative contributions,
  total contribution bounds, malformed JSON and body size limits. MongoDB is represented by
  an in-memory adapter. Syntax checks are the separate build check; this app has no compilation step.
- Baseline and patched copies run the same recipe. This is focused compatibility coverage,
  not full browser, database, exploit, reachability or application security testing.
- A failed/skipped advisory source cannot establish target resolution. Passing tests are
  required for FIXED and for PR eligibility. Original source and scan artifacts are preserved.
- Temporary containers/volumes and checkouts are cleaned; cleanup failures are errors.
- OSV and Grype ran in the rehearsal. NVD enrichment was explicitly disabled. Original scan
  coverage warnings remain visible, including unsupported/unassessed components.
- The targeted fix does **not** remove newer body-parser advisories. The report lists them,
  and the changed qs version's additional findings. FIXED refers to the selected advisory.
- OSV is a live service; advisory data can change between runs. The report is an observed
  before/after delta, not proof that every new finding was caused by the patch.
- No upstream patch, PR, merge or deployment was performed. Opening a PR is a separate human
  action requiring a configured GitHub token. The sandbox approval does not authorize it.

## Restart on this Windows workstation

Open PowerShell in this checkout, with Docker Desktop running:

Kestral loads secrets from the repository-root `.env`, beside `docker-compose.yml`.
For GitHub PR creation, set `GITHUB_TOKEN` in that file. Do not put it in `backend/.env`.

```powershell
powershell -ExecutionPolicy Bypass -File backend/scripts/start-live.ps1
```

Leave that terminal running. In another terminal:

```powershell
docker build -f frontend/Dockerfile.live -t kestral-live-frontend frontend
docker start kestral-live-frontend
```

For a first launch where the container does not exist:

```powershell
docker run -d --name kestral-live-frontend --label kestral.live=true --memory=1g --cpus=2 -p 127.0.0.1:3001:3000 kestral-live-frontend
```

If replacing an old frontend image, remove only this disposable frontend container
(`docker rm -f kestral-live-frontend`) and run the launch command again. PostgreSQL's volume
contains your history and approval records; do not delete it.

The Python environment is `backend/.venv` (Python 3.12). On another machine create it using
your installed Python 3.12, then install `backend[dev]` using that environment's pip.
Syft, Grype, Git and Docker must be installed. The helper discovers Windows WinGet scanner paths.

## Verification commands

```powershell
docker build -f backend/Dockerfile.validation-tests -t kestral-validation-tests backend
docker run --rm --network none --memory=3g --cpus=2 --mount "type=bind,source=$PWD/backend,target=/work,readonly" --mount "type=bind,source=$PWD/policies,target=/policies,readonly" kestral-validation-tests python -m pytest -q -p no:cacheprovider
docker run --rm --network none --memory=2g --cpus=2 kestral-live-frontend npm test -- --reporter=dot
backend/.venv/Scripts/python.exe -m ruff check backend/app/validation backend/tests/validation
```

The backend test image needs Git and the policy mount. Without these, eight environment
failures were observed in an earlier broad test run. Windows also cannot create symlinks
without the appropriate OS privilege; the Linux suite exercises those negative tests.

# Sandbox pipeline PR handoff

Target branch: `feat/sandbox-testing` only. No main merge or upstream NodeGoat change.
Base commit: `33b8ba4a82a9a201d798b9f959849fc04882eadf`.
Actual application source: `DXVNX/NodeGoat@c5cb68a7084e4ae7dcc60e6a98768720a81841e8`.

The previous validator could report FIXED without passing tests, resolve an already-allowed
npm range to the old locked version, retain vulnerable nested copies, and lose a timed-out
container. This change pins the approved version across package occurrences, binds execution
to the actual human approval/evidence, uses bounded disposable containers, runs the reviewed
NodeGoat application regression recipe offline, requires scanner coverage, exposes live
progress and checks cleanup. Before/after comparison now indexes identities instead of
repeatedly walking the full component inventory.

Actual run directory:
`data/scans/scan_5a21801856924114b38d22f36fcc3037/validations/val_98124f89bf704ca6894089e363f9fe4e/`.
Result: FIXED for CVE-2024-45590, six baseline + six patched regressions passed, 110.096 seconds.
Newer body-parser advisories and qs findings remain explicitly reported. No reachability or
full application security claim. MongoDB is an in-memory adapter in this focused recipe.

Reviewed files: `backend/app/validation/{compare,patching,profiles,sandbox,service}.py`,
`backend/app/validation/nodegoat_regression.cjs`, `backend/app/api/routes/validation.py`,
`backend/app/schemas/validation.py`, `backend/pyproject.toml`,
`backend/scripts/start-live.ps1`, `backend/Dockerfile.validation-tests`, changed/new files
in `backend/tests/validation/`, `frontend/src/components/validation/ValidationPanel.tsx`,
`frontend/src/types/validation.ts`, `frontend/src/test/validation.test.tsx`,
`frontend/{Dockerfile.live,.dockerignore}`, and the two sandbox handoff documents.

Exact build/test/restart commands and judge walkthrough are in `SANDBOX_LIVE_PIPELINE.md`.
Full backend: 495 passed, 2 Syft-only skips. Frontend: 77 passed. Production frontend build,
Ruff, real API/report/CORS requests and Chrome UI verification passed. Local actual outputs:
`backend/data/live-evidence/`. These generated artifacts and approval records are not committed.

Limitations: network access is required for fresh clone, resolution and advisory queries;
OSV is not a frozen advisory snapshot; generic repository testing is not guaranteed;
the UI runs on localhost only; no production authentication or deployment is asserted.
PR publication of a validated patch still requires a separate human action and configured
GitHub access. The user authorized sandbox validation only for the NodeGoat proposal.

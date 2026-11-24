# Proposed integration for owner review

## Scan worker

After inventory and risk complete and before the worker deletes the checkout, extract any approved provenance candidates and verify them with platform-owned trust settings. Use the existing artifact helper to validate and save a standalone `provenance.json` with the scan ID. Evaluate the shipped OPA policy using that artifact and `findings.json`, then save the typed `policy-results.json` separately. Apply candidate limits and preserve evidence references. Keep scan completion separate from the release decision. A BLOCK is a successful assessment that denies release. Record tool and evaluation errors explicitly.

## Platform and frontend ownership

The platform owner decides artifact registration, migrations if needed, settings, and the new API routes `GET /api/v1/scans/{scan_id}/provenance` and `GET /api/v1/scans/{scan_id}/policy`. The frontend owner can use those separately versioned contracts to display provenance evidence, assessment status, and the policy decision. Keep `FindingKind` and `SourceName` as they are. Route contract changes through normal owner review.

## Day 2 and CI

A future agent can read verified evidence and propose a fix for human review. After approval, build, test, and rescan in a sandbox. Rerun provenance verification and OPA on the exact new artifact digest. Make the gate exit code the input to a future required CI check. Preserve human control of fixes and releases and keep policy enforcement mandatory, with no agent override, automatic merge, or deployment. Worker, API, frontend, CI, and Day 2 changes are proposals.

# Proposed shared integration for owner approval

Phase 4 accepts current suspicious findings in the standalone release gate. `POL-007` is review-only. The package intelligence report remains a separate artifact with its own evidence and coverage.

## Risk analyzer and worker

- In `backend/app/risk/analyzer.py`, add an optional, typed package intelligence input to `analyze_risk`. For enabled scans, map eligible observations to `Finding(kind="suspicious")` just before the existing `suspicious = escalate(suspicious)` call. Preserve normalized component IDs and scan IDs, attach existing graph context, and deduplicate local, historical, and registry signals before running escalation once. Update `FindingStats.suspicious`, the registry `SourceRun`, and warnings with the real counts and failure/skip reasons. Keep partial coverage explicit and preserve default-disabled output.
- In `backend/app/ingestion/worker.py`, call the standalone engine after normalized dependency extraction and graph construction, immediately before `analyze_risk`, while the checkout is still available. Pass the normalized document, checkout as lock root, and the operator-approved per-scan name allowlist. Save `package-intelligence.json` using `save_validated_json` in the scan artifact directory. Feed the validated result to the analyzer. Keep the existing cleanup and status transitions. Coordinate typed artifact registration and any database or artifact API exposure as a separate owner-reviewed change.
- In `backend/app/config.py` and the scan request contract, propose a default-disabled capability and per-scan authorization with server-side ceilings. Never derive lookup authorization from a scanned lockfile, an arbitrary URL, or package names supplied by the AI.

## Shared findings and policy contracts

- In `backend/app/schemas/findings.py`, extend the closed `SourceName` union with `package-registry`. Use `FindingSource.record_id` for the stable signal ID and retain the existing `category`, `risk_level`, `risk_reason`, and `uncertainty` fields. Keep existing findings documents readable. Represent external registry references using an approved typed reference to the persisted report and its hash. Keep lockfile evidence as an existing repo-relative evidence item and avoid overloading evidence paths with URLs.
- If a registry mismatch block is proposed later, require an explicitly enabled, default-off gate and independent evidence validation that binds scan, component, exact artifact, strongest comparable algorithm, both digest sets, and trusted registry record. Any missing or malformed link stays inconclusive. A string category, a caller-provided confidence value, or a high heuristic score is insufficient to block. Keep registry metadata comparisons separate from Cosign signatures and preserve the existing six rules and `POL-007`.

## AI analyst and frontend

- In `backend/app/ai/bundle.py`, load the optional package report with existing artifact path and size safeguards, validate its scan ID, index it by component ID, and include its bytes in the analysis input digest so cached analyses cannot reuse stale registry evidence.
- In `backend/app/ai/tools.py`, add a read-only registered tool that returns bounded persisted observations for the current finding's component, with signal IDs and explicit unknowns. Cite them through `EvidenceStore`. Keep live advisory lookups, existing AI metadata tools, and the human approval and validation workflow separate. Never add execution or remediation authority.
- In `frontend/src/types/findings.ts`, mirror the new source label and any approved evidence or coverage fields. In `frontend/src/lib/findings.ts`, add the display label for `package-registry`. In `frontend/src/components/risk/FindingsPanel.tsx`, use the existing Suspicious changes view and SourceStatus to show coverage, references, and confidence. Keep disabled, unavailable and partial states distinct from an assessed result with no indicators.

After owner approval, verify default-off parity, enabled public and denied/private cases, cleanup and artifact access, mixed findings in OPA, AI evidence scoping, and frontend states. Scanner, worker, database, API, configuration and frontend changes are pending approval.

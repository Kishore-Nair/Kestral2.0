# Advanced Package Risk Intelligence review

The retained feature branch is `feature/provenance-policy`. It was clean at `77b2d23`; fetching advanced `origin/main` to `69179dc`, nine commits ahead. The branch was fast-forwarded to that SHA. The implementation and test changes are standalone and untracked.

## Phase 4 review and genuine npm integrity replay

The public fixture is the npm CLI v11.6.2 release at commit `072253549d774893a3689341dbc660cb845ebcfe`. Only its manifest and genuine lockfile are downloaded. Kestral discovers those files and statically generates the normalized dependency document without invoking Syft, installing dependencies, or running package scripts. The full document has 1,206 components. The demo projects the exact `b4a@1.7.3` component into a partial assessment to keep the public lookups scoped to one package. [Public lockfile](https://github.com/npm/cli/blob/072253549d774893a3689341dbc660cb845ebcfe/package-lock.json)

| Local evidence | Registry integrity result | Evidence |
| --- | --- | --- |
| Unchanged public lockfile | Match, assessed | SHA-512, `cmp:1d95cc7e9c346342ad38c5a7`, `packages.node_modules/b4a` |
| **Synthetic** lockfile copy with one digest bit flipped | Mismatch, assessed | Same exact package, version, algorithm and artifact URL, with `registry_integrity_mismatch` emitted |
| Genuine normalized component with lock evidence omitted | Unassessed | `unbound_or_missing`, no digest comparison or match verdict |

All three cases used one genuine response from `https://registry.npmjs.org/b4a`, with observed raw metadata SHA-256 `a7251e87e28286b058e8240d67794c4e84078dbbbfde68beecc0279db4b4443a`. The original normalized SHA-512 starts with `e50da67e` and the synthetic value starts with `e40da67e`. Registry metadata comparison does not verify downloaded bytes, runtime behavior, or publisher identity.

Run the following from the repository root with Python 3.12 and the project's declared backend dependencies. The pinned public repo files are data inputs. The only other network request is explicitly scoped to public npm package `b4a`.

```powershell
$ErrorActionPreference = 'Stop'
$d = Join-Path $env:TEMP ('kp-int-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path "$d/original" | Out-Null
$commit = '072253549d774893a3689341dbc660cb845ebcfe'
foreach ($name in 'package.json','package-lock.json') {
  Invoke-WebRequest "https://raw.githubusercontent.com/npm/cli/$commit/$name" -OutFile "$d/original/$name"
}
$expectedLock = 'C90E3C3B1F80CA4B018C225BCD4DC6A3E41711EDE7DE82B0FC1D4B0F05D455A6'
if ((Get-FileHash "$d/original/package-lock.json").Hash -ne $expectedLock) {
  throw 'Public lockfile SHA-256 differs from the observed fixture'
}
Push-Location backend
try {
@'
import base64
import json
import shutil
import sys
from pathlib import Path

from app.discovery import discover_repository
from app.package_intelligence.__main__ import Report
from app.package_intelligence.engine import assess
from app.package_intelligence.registry import Registry
from app.provenance.local import write_json
from app.sbom.pipeline import build_document

root = Path(sys.argv[1]).resolve()
original, synthetic = root / "original", root / "synthetic-mismatch-b4a"
scan_id = "npm_cli_integrity"
package = "b4a"
install_path = f"node_modules/{package}"
synthetic.mkdir()
shutil.copyfile(original / "package.json", synthetic / "package.json")
lock = json.loads((original / "package-lock.json").read_bytes())
entry = lock["packages"][install_path]
algorithm, encoded = entry["integrity"].split("-", 1)
assert algorithm == "sha512"
changed = bytearray(base64.b64decode(encoded, validate=True))
changed[0] ^= 1
entry["integrity"] = algorithm + "-" + base64.b64encode(changed).decode()
(synthetic / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")

registry = Registry({("npm", package)}, enabled=True)
def normalize(directory, label):
    dependencies = build_document(directory, discover_repository(directory, scan_id), scan_id, None)
    (root / f"{label}-normalized.json").write_text(
        dependencies.model_dump_json(indent=2), encoding="utf-8",
    )
    [component] = [c for c in dependencies.components if c.install_path == install_path]
    print(label, "normalized_components", len(dependencies.components), "id", component.component_id,
          "version", component.version, "locator", component.evidence[0].locator,
          "digest", component.hashes[0].content)
    return dependencies.model_copy(update={
        "components": [component], "roots": [], "relationships": [], "partial": True,
    })

genuine = normalize(original, "genuine")
modified = normalize(synthetic, "synthetic-mismatch")
for label, document, lock_root, expected in (
    ("genuine", genuine, original, "match"),
    ("synthetic-mismatch", modified, synthetic, "mismatch"),
    ("missing-evidence", genuine, None, "unbound_or_missing"),
):
    report = assess(document, registry, lock_root=lock_root)
    [row] = report["packages"]
    [comparison] = row["integrity"]
    coverage = row["detectors"]["registry_integrity_mismatch"]
    assert row["registry"]["status"] == "ok", row["registry"]
    assert comparison["status"] == expected, comparison
    assert coverage == ("unassessed" if lock_root is None else "assessed")
    print(label, comparison, "detector", coverage, "registry", row["registry"],
          "signals", [s["category"] for s in row["signals"]])
    write_json(root / f"{label}-report.json", Report.model_validate(report))
assert registry.requests == 1
print("registry_requests", registry.requests)
'@ | python -B - $d
  if ($LASTEXITCODE) { throw 'Integrity demo failed' }
  if ((Get-FileHash "$d/original/package-lock.json").Hash -ne $expectedLock) {
    throw 'Original lockfile changed'
  }
  Get-ChildItem -LiteralPath $d -Filter '*-report.json'
} finally { Pop-Location }
```

### Trust and coverage review

The transport independently validates canonical HTTPS npm/PyPI endpoints, rejects redirects, ignores environment proxies, requests identity encoding, and checks status and response length before bounded reads. Explicit network opt-in, per-name authorization, per-request timeouts, the monotonic network budget, and bounded caches still apply. A timed-out DNS, TLS, or header worker can finish in the background under its socket timeout, but cannot write artifacts, start another lookup, or supply a late result to the assessment. Lockfile binding rejects Windows alternate streams and ambiguous artifact path encodings. Conservative URL matching can leave equivalent URL spellings unassessed. Registry URLs in dependency data are never used for network requests.

This extends the existing scanner's lockfile and historical findings with exact-version registry evidence. The existing local script-presence and scan-diff detectors still own their original behaviors. The new script detector assigns static indicators only. It emits no script body and makes no malware determination. The npm match and synthetic mismatch above compare metadata only.

### Phase 4 validation

Python 3.12.16 and Ruff 0.17.6 ran the full backend lint check with exit 0. OPA 1.22.4 strict validation passed and all 12 Rego tests passed. The focused Python run exited 0 with 53 tests across package intelligence, provenance and policy. The full backend run exited 1 with **488 passed, 4 skipped, and 3 existing Windows symlink failures** (WinError 1314). Those same failures were reproduced on untouched `69179dc` during the Phase 3 baseline check. No newly introduced test failure was observed.

From the repository root with the test environment active:

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:RUFF_NO_CACHE = 'true'
$base = Join-Path $env:TEMP ('kp' + [guid]::NewGuid().ToString('N').Substring(0,6))
$env:PYTEST_ADDOPTS = "-p no:cacheprovider --basetemp `"$base`""
Push-Location backend
python -m ruff check .
python -m pytest -q tests/package_intelligence tests/provenance tests/policy
python -m pytest -q --tb=short
Pop-Location
opa check --strict policies/kestral
opa test policies/kestral -v
git diff --check
```

### OPA compatibility

The policy adapter validates `vulnerability`, `workflow_pin`, and `suspicious` counts independently using the current FindingsDocument. Earlier documents without suspicious findings continue to use the default zero count. Suspicious category and risk level are validated when provided. `POL-007` returns REVIEW for high-risk suspicious findings in both normal and strict mode. A pre-existing blocking rule still takes precedence. A registry integrity mismatch has no dedicated blocking rule and the standalone report is not a policy input. Integrating a configurable integrity block requires a separately validated evidence contract and explicit approval. The six existing rules retain their prior behavior.



## Scope

The CLI accepts a validated normalized dependency document, an optional same-scan findings document, and an optional authorized lockfile root. It writes a standalone JSON report atomically outside the implementation checkout and any supplied lock checkout. The registry lookup is off by default. An operator must authorize each public name and enable networking. Metadata comes from one project request per canonical name on fixed HTTPS hosts. Lockfile URLs are only read as comparison evidence and are never followed.

| Files | Responsibilities |
| --- | --- |
| `backend/app/package_intelligence/__init__.py`, `__main__.py` | Package entry point, bounded inputs, scan IDs, CLI options, and report |
| `backend/app/package_intelligence/registry.py` | Name/version validation, fixed endpoint construction, redirect rejection, time and size budgets, and per-run deduplication |
| `backend/app/package_intelligence/engine.py`, `lock_evidence.py` | Grouping, lock evidence binding, source references, signals, and detector coverage |
| `backend/app/package_intelligence/integrity.py`, `script_analysis.py`, `release_signals.py` | Metadata digest comparison, static script indicators, and release heuristics |
| `backend/tests/package_intelligence/test_package_intelligence.py` | Synthetic offline tests |
| `docs/package-intelligence/REVIEW.md`, `INTEGRATION.md` | Evidence, replay commands, limits, and integration proposal |

## Replay from the repository root

This creates a synthetic normalized input. Only the second invocation contacts public registries, and only for the two named public identities.

```powershell
$d = Join-Path $env:TEMP ('kestral-package-demo-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $d | Out-Null
'{"schema_version":"1.0","scan_id":"package_intelligence_demo","roots":[],"components":[{"component_id":"cmp:express","name":"express","version":"4.21.2","ecosystem":"npm","purl":"pkg:npm/express@4.21.2","install_path":null,"project_path":"","scope":"runtime","licenses":[],"hashes":[],"evidence":[{"path":"normalized.json","kind":"synthetic-demo","locator":"express"}],"resolved":true},{"component_id":"cmp:requests","name":"requests","version":"2.32.5","ecosystem":"pypi","purl":"pkg:pypi/requests@2.32.5","install_path":null,"project_path":"","scope":"runtime","licenses":[],"hashes":[],"evidence":[{"path":"normalized.json","kind":"synthetic-demo","locator":"requests"}],"resolved":true}],"relationships":[],"partial":false,"warnings":[]}' | Set-Content -Encoding ascii "$d/normalized.json"
$env:PYTHONDONTWRITEBYTECODE = '1'
Push-Location backend
try {
  $common = @('--scan-id','package_intelligence_demo','--workspace',$d,'--normalized',"$d/normalized.json")
  python -m app.package_intelligence @common --output "$d/offline.json"
  "offline exit=$LASTEXITCODE"
  python -m app.package_intelligence @common --output "$d/live.json" --enable-network --allow-public npm:express --allow-public pypi:requests
  "live exit=$LASTEXITCODE"
  foreach ($mode in 'offline','live') {
    $r = Get-Content "$d/$mode.json" -Raw | ConvertFrom-Json
    $r.registry_source
    $r.request_budget
    $r.coverage
    $r.packages | Select-Object name,version,assessment_status,released_at,detectors
  }
} finally { Pop-Location }
```

A valid report can contain partial, unassessed, or skipped evidence and still exit 0. Registry failures are status codes in the report. Invalid input, invalid budget, mismatched scan IDs, or unsafe/unwritable outputs exit 1. For a real scan, supply its artifact directory, exact scan ID, normalized artifact, optional findings, and an authorized `--lock-root` containing its lockfiles. Set the allowlist explicitly for that scan.

## Observed evidence

The network-disabled run exited 0 with zero requests and two skipped components. The live run exited 0 with two requests, two partial components, and two successful exact-version metadata lookups.

| Live registry package | Exact release UTC | Published artifacts observed |
| --- | --- | --- |
| npm `express@4.21.2` | 2024-12-05 22:31:40.945Z | One tarball metadata record |
| PyPI `requests@2.32.5` | 2025-08-18 20:46:00.542304Z | Two distribution metadata records |

The synthetic SBOM omitted lock evidence, so both live integrity assessments were unassessed. The Express script metadata was assessable. PyPI lifecycle script checks were inapplicable and Requests release-history coverage was insufficient for a burst verdict. The live reports used actual registry payloads; any mismatch, script, withdrawal, and burst exercises in the unit tests used synthetic data.

## Phase 3 validation history

Use a Python 3.12 environment with the declared backend dependencies for the following commands:

```powershell
$env:RUFF_NO_CACHE = 'true'
$env:PYTHONDONTWRITEBYTECODE = '1'
$base = Join-Path $env:TEMP ('kp' + [guid]::NewGuid().ToString('N').Substring(0,6))
$env:PYTEST_ADDOPTS = "-p no:cacheprovider --basetemp `"$base`""
Push-Location backend
python -V
python -m ruff check .
python -m pytest -q
python -m pytest -q tests/package_intelligence
Pop-Location
opa test policies/kestral -v
git diff --check
git diff --stat
git ls-files --others --exclude-standard
```

The system Python 3.11 baseline hit 19 collection errors. Local Ruff 0.12.0 reported a pre-existing UP038. The final checks used an isolated Python 3.12.16 environment with the declared dependencies. Full Ruff 0.17.6 exited 0 and the existing OPA tests passed 8/8. All 14 new pytest cases passed. The full backend run exited 1 with 476 passed, 4 skipped, and 3 existing failures at Windows symlink creation (WinError 1314), reproduced against a temporary archive of untouched `69179dc`. A shorter temp directory resolved the initial validation artifact path failures. The existing skipped tests required Syft or symlink privileges. Frontend checks were unavailable because frontend dependencies were absent.

## Limits

Metadata digest comparison does not verify downloaded bytes or publisher authenticity. npm integrity binding supports the `packages` layout of npm lockfiles, and PyPI exact comparison supports a bound `uv.lock` v1 source distribution. Unbound PyPI hashes can only show membership, and lack of membership stays ambiguous. Registry script text represents available metadata and is never executed or emitted. Recency defaults are 30 days for a package and 7 days for a release. The configurable burst rule requires five distinct stable versions in seven days after at least 90 days without a stable release, with enough observed history. Earliest observed release is labeled as a proxy when package creation is unavailable. These heuristics are observations, not maliciousness determinations.

Defaults are 20 unique packages, 25 requests, 5 seconds per request, a 30-second network budget, 4 MiB per response, and 512 components. Unsupported ecosystems, nonpublic lock sources, omitted evidence, and failed retrievals remain visible as coverage limitations. This standalone demo has no scanner, graph escalation, AI, UI, report, or policy integration.

[npm package metadata](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md) · [PyPI JSON API](https://docs.pypi.org/api/json/)

# Provenance and policy review

On `feature/provenance-policy` at `3ff4286`, the standalone Cosign CLI verifies local blobs and emits a typed `provenance.json`. The standalone OPA gate validates this report and the existing Kestral findings schema, then applies the six Rego rules. A verified blob signature establishes integrity and authenticity under the chosen signer constraints. The demo does not verify a build attestation.

## Observed live demo

Cosign v3.1.4 verified the official v3.1.4 release checksums file using the v0.3 Sigstore bundle, which contained one Rekor inclusion proof, a trusted root populated through Sigstore TUF, and the exact release signer identity and issuer. Both file variants used the same original bundle and trust settings. [Release assets](https://github.com/sigstore/cosign/releases/expanded_assets/v3.1.4) · [Sigstore verification instructions](https://docs.sigstore.dev/cosign/system_config/installation/)

| Evidence | Direct Cosign exit | Provenance CLI exit / signature | OPA enforcement |
| --- | --- | --- | --- |
| Original checksums file | 0 | 0 / verified | REVIEW, exit 2 |
| Tampered copy | 1 | 2 / failed | BLOCK, exit 2, POL-002 |
| Bundle omitted | — | 2 / not_assessed | REVIEW, exit 2 |
| Bundle omitted, strict release | — | 2 / not_assessed | BLOCK, exit 2 |

The original printed `Verified OK`. The tampered copy reported `failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature`. The earlier locally signed bundle contained no inclusion proof. Cosign reported `not enough verified log entries from transparency log: 0 < 1`, which the wrapper records as an operational error. The previous policy run on that genuine inconclusive report returned REVIEW, exit 2. All live policy runs above used labeled synthetic findings and real OPA v1.22.4. An earlier ALLOW/0 used fully synthetic provenance and findings.

## PowerShell demo from the repository root

With Cosign v3.1.4 and OPA v1 on a trusted PATH, run this from the repository root. If needed, the session's previously approved temporary tools can be added with `$env:Path = 'C:\Users\Hariprita\AppData\Local\Temp\kestral-tools-5f2440d6e87641f79862bb5d472152dc;' + $env:Path`. The commands download public data and TUF metadata to temporary storage. They neither upload nor execute the release fixture. The clean findings document is synthetic.

```powershell
$ErrorActionPreference = 'Stop'
$d = Join-Path $env:TEMP ('kestral-public-review-' + [guid]::NewGuid().ToString('N'))
$s = Join-Path $d evidence
New-Item -ItemType Directory -Path $s | Out-Null
$url = 'https://github.com/sigstore/cosign/releases/download/v3.1.4'
$original = "$s/cosign_checksums.txt"
$bundle = "$original.sigstore.json"
Invoke-WebRequest "$url/cosign_checksums.txt" -OutFile $original
Invoke-WebRequest "$url/cosign_checksums.txt.sigstore.json" -OutFile $bundle
$previousTufRoot = $env:TUF_ROOT
try {
  $env:TUF_ROOT = "$d/tuf-cache"
  cosign trusted-root create --with-default-services --out "$d/trusted-root.json"
  if ($LASTEXITCODE) { throw 'Could not populate the trusted root' }
} finally {
  $env:TUF_ROOT = $previousTufRoot
}
$tampered = "$s/tampered.txt"
Copy-Item $original $tampered
[IO.File]::AppendAllText($tampered, 'changed')
$signer = @('--bundle', $bundle, '--trusted-root', "$d/trusted-root.json",
  '--certificate-identity', 'keyless@projectsigstore.iam.gserviceaccount.com',
  '--certificate-oidc-issuer', 'https://accounts.google.com')
foreach ($file in $original, $tampered) {
  cosign verify-blob @signer $file
  "Cosign $(Split-Path -Leaf $file) exit=$LASTEXITCODE"
}
@{
  schema_version='1.0';scan_id='demo';partial=$false;findings=@();warnings=@()
  sources=@(@{name='workflow-scan';status='ok'})
  stats=@{vulnerabilities=0;vulnerable_packages=0;confirmed_by_both=0;workflow_pins=0;
    components_total=0;components_assessed=0;components_not_assessed=0}
} | ConvertTo-Json -Depth 8 | Set-Content "$s/findings-synthetic.json"
Push-Location backend
try {
  $common = @('--scan-id','demo','--workspace',$s)
  foreach ($case in 'original','tampered','missing') {
    $file = if ($case -eq 'tampered') { $tampered } else { $original }
    $trust = @()
    if ($case -ne 'missing') { $trust = $signer }
    $p = "$d/provenance-$case.json"
    python -B -m app.provenance @common --artifact $file @trust --output $p
    $verify = $LASTEXITCODE
    Copy-Item $p "$s/provenance-$case.json"
    $report = "$d/policy-$case.json"
    python -B -m app.policy @common --findings "$s/findings-synthetic.json" --provenance "$s/provenance-$case.json" --output $report --enforce
    $gate = $LASTEXITCODE
    $result = Get-Content $report -Raw | ConvertFrom-Json
    "$case verifier=$verify gate=$gate decision=$($result.decision)"
  }
  python -B -m app.policy @common --findings "$s/findings-synthetic.json" --provenance "$s/provenance-missing.json" --output "$d/policy-strict.json" --enforce --strict-release
  "strict gate=$LASTEXITCODE"
} finally {
  Pop-Location
}
```

For enforcement, exit 0 permits ALLOW, exit 2 denies REVIEW or BLOCK, and exit 1 indicates an operational or validation error. Use the current exit code because a validation error may leave an older report at the same output path.

## Scan evidence and regression results

The configured local scan output locations contained no live Kestral scan. The repository has inventory and normalized fixtures and a labeled frontend findings fixture. The standalone policy CLI validated the findings fixture with matching `scan_sample` provenance and returned REVIEW/2. Live worker integration has not been demonstrated.

```powershell
py -3.12 -V
opa check --strict policies/kestral
opa test policies/kestral -v
Push-Location backend
python -B -m pytest -p no:cacheprovider tests/provenance tests/policy tests/ingestion/test_contracts.py -q
Pop-Location
git diff --check
git diff HEAD --name-only
git status --short --branch
git ls-files --others --exclude-standard
```

Python 3.12 was unavailable. Under Python 3.11, 27 new tests and six existing contract tests passed. OPA strict validation and all eight Rego tests passed. The tracked diff was empty and the 14 untracked files were confined to `backend/app/{policy,provenance}`, `backend/tests/{policy,provenance}`, `policies/kestral`, and `docs/provenance-policy`. The inspection found no private keys, downloaded bundles, generated scan outputs, or common credential markers in those files.

Build-attestation verification, OCI verification, and worker, API, frontend and CI integration are outside this demo. See `INTEGRATION.md` for ownership and integration proposals. To roll back, preserve any work you want and remove only the added feature files.

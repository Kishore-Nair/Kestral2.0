param([int]$Port = 8001, [string]$FrontendOrigin = 'http://localhost:3001')
$ErrorActionPreference = 'Stop'
$backend = Split-Path $PSScriptRoot -Parent
Set-Location $backend
$python = Join-Path $backend '.venv/Scripts/python.exe'
if (-not (Test-Path $python)) { throw 'Create backend/.venv with Python 3.12 and install backend[dev] first.' }
foreach ($tool in @('syft', 'grype')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        $packages = Join-Path $env:LOCALAPPDATA 'Microsoft/WinGet/Packages'
        $installed = Get-ChildItem -LiteralPath $packages -Directory -Filter "Anchore.$tool*" |
            Where-Object { Test-Path (Join-Path $_.FullName "$tool.exe") } |
            Select-Object -First 1
        if (-not $installed) { throw "$tool is missing. Install it from Anchore before starting." }
        $env:PATH = $installed.FullName + ';' + $env:PATH
    }
}
& docker info --format '{{.Architecture}}'
if ($LASTEXITCODE) { throw 'Start Docker Desktop and wait for its engine.' }
& docker compose -f ../docker-compose.yml up -d --wait postgres
if ($LASTEXITCODE) { throw 'PostgreSQL startup failed.' }
& $python -m alembic upgrade head
if ($LASTEXITCODE) { throw 'Database migration failed.' }
$env:VALIDATION_CONTAINER_RUNTIME = 'docker'
$env:FRONTEND_ORIGIN = $FrontendOrigin
# NVD enrichment is optional; OSV and Grype remain enabled for the live run.
$env:NVD_ENABLED = 'false'
$env:OSV_ENABLED = 'true'
$env:GRYPE_ENABLED = 'true'
& $python -m uvicorn app.main:app --host 127.0.0.1 --port $Port

# Validate locally before push - mirrors GitHub Actions workflow
# Run: .\scripts\validate-ci-local.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $root

Write-Host "=== 1. npm ci ===" -ForegroundColor Cyan
npm ci
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`n=== 2. npm run build ===" -ForegroundColor Cyan
npm run build --if-present
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`n=== 3. npm test ===" -ForegroundColor Cyan
npm test --if-present
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`n=== 4. Python build (uv or pip) ===" -ForegroundColor Cyan
if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv build
} else {
    python -m pip install build hatchling -q | Out-Null
    python -m build --no-isolation
}
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`n=== 5. Python tests ===" -ForegroundColor Cyan
$env:PYTHONPATH = "src"
pytest tests/ -v --tb=short
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`n=== All CI checks passed ===" -ForegroundColor Green

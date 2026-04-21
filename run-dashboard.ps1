# Starts the MCP-Bastion metrics dashboard on this PC.
# Usage: right-click -> Run with PowerShell, or:
#   powershell -ExecutionPolicy Bypass -File .\run-dashboard.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path "dashboard\app.py")) {
    Write-Host "dashboard\app.py not found. Run this script from the MCP-Bastion repo folder." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python is not on PATH. Install Python 3.10+ and retry." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host ""
Write-Host "Dashboard URL: http://127.0.0.1:7000/" -ForegroundColor Cyan
Write-Host "Leave this window open while you use the browser. Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""
python dashboard/app.py
Write-Host ""
if ($LASTEXITCODE -ne 0) {
    Write-Host "Python exited with code $LASTEXITCODE" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}

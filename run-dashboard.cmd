@echo off
REM Same as run-dashboard.ps1: bind 127.0.0.1:7000 from repo root (double-click safe).
cd /d "%~dp0"
if not exist "dashboard\app.py" (
  echo Run this from the MCP-Bastion repo folder. Missing dashboard\app.py
  pause
  exit /b 1
)
set PYTHONPATH=src
set MCP_BASTION_DASHBOARD_HOST=0.0.0.0
set MCP_BASTION_DASHBOARD_PORT=7000
set MCP_BASTION_DEMO=1
echo.
echo Dashboard: http://127.0.0.1:7000/
echo Leave this window open. Ctrl+C to stop.
echo.
python dashboard\app.py
if errorlevel 1 pause

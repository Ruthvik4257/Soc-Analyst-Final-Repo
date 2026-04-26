# SOC Analyst — run API + Streamlit on Windows (PowerShell)
# Usage: right-click "Run with PowerShell" or:  cd here ; .\run_local.ps1

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root
$env:PYTHONPATH = $Root
$env:SOC_API_BASE = "http://127.0.0.1:8000"

if (Test-Path "$Root\.venv\Scripts\Activate.ps1") {
    & "$Root\.venv\Scripts\Activate.ps1"
}

$py = "python"
try { & $py --version | Out-Null } catch { $py = "py" }

Write-Host ""
Write-Host "=== Starting FastAPI: http://127.0.0.1:8000  (API docs: /docs) ===" -ForegroundColor Cyan
Start-Process powershell -ArgumentList @(
    "-NoExit", "-NoProfile", "-Command",
    "Set-Location '$Root'; `$env:PYTHONPATH='$Root'; $py -m uvicorn server.app:app --host 127.0.0.1 --port 8000"
)

Start-Sleep -Seconds 2

Write-Host "=== Starting Streamlit: http://127.0.0.1:8501  (open this in the browser) ===" -ForegroundColor Cyan
Start-Process powershell -ArgumentList @(
    "-NoExit", "-NoProfile", "-Command",
    "Set-Location '$Root'; `$env:PYTHONPATH='$Root'; `$env:SOC_API_BASE='http://127.0.0.1:8000'; $py -m streamlit run streamlit_app.py --server.port 8501"
)

Start-Sleep -Seconds 1
Write-Host ""
Write-Host "Two blue PowerShell windows should open (API + UI)." -ForegroundColor Green
Write-Host "1) Wait until the first shows 'Uvicorn running'" -ForegroundColor Green
Write-Host "2) Open: http://127.0.0.1:8501" -ForegroundColor Green
Write-Host "3) In the sidebar, API base URL should be: http://127.0.0.1:8000" -ForegroundColor Green
Write-Host ""

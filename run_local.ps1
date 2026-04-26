# SOC Analyst — run FastAPI (serves the HTML console + API) on Windows
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root
$env:PYTHONPATH = $Root

if (Test-Path "$Root\.venv\Scripts\Activate.ps1") {
    & "$Root\.venv\Scripts\Activate.ps1"
}

$py = "python"
try { & $py --version | Out-Null } catch { $py = "py" }

Write-Host ""
Write-Host "Open in your browser: http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "API docs: http://127.0.0.1:8000/docs" -ForegroundColor Cyan
Write-Host "First start may take 1-2 min while the model stack loads. Press Ctrl+C to stop." -ForegroundColor Green
Write-Host ""
Start-Process powershell -ArgumentList @(
    "-NoExit", "-NoProfile", "-Command",
    "Set-Location '$Root'; `$env:PYTHONPATH='$Root'; $py -m uvicorn server.app:app --host 127.0.0.1 --port 8000"
)

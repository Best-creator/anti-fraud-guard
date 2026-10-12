param(
    [int]$ImportPort = 8000,
    [int]$QueryPort = 8001
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    throw "Virtual environment not found. Run scripts\setup-delivery.ps1 first."
}
if (-not (Test-Path ".env")) {
    throw ".env not found. Copy .env.example to .env and fill required values first."
}

$python = (Resolve-Path ".venv\Scripts\python.exe").Path
Start-Process -FilePath $python -ArgumentList "-m","app.import_process.api.file_import_service" -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput "runtime_8000.out.log" -RedirectStandardError "runtime_8000.err.log"
Start-Process -FilePath $python -ArgumentList "-m","app.query_process.api.query_service" -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput "runtime_8001.out.log" -RedirectStandardError "runtime_8001.err.log"

Write-Host "Services starting..."
Write-Host "Import page: http://127.0.0.1:$ImportPort/import.html"
Write-Host "Chat page:   http://127.0.0.1:$QueryPort/chat.html"
Write-Host "Admin page:  http://127.0.0.1:$QueryPort/admin/review.html"

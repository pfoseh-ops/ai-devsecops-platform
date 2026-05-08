# Bootstrap development environment on Windows PowerShell
# Creates or activates a virtualenv, installs requirements and common tools.
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptRoot

if (-Not (Test-Path ".venv")) {
    Write-Host ".venv not found, creating virtualenv..."
    python -m venv .venv
} else {
    Write-Host ".venv found"
}

Write-Host "Activating virtualenv..."
# Use the PowerShell activation script
. .\.venv\Scripts\Activate.ps1

Write-Host "Upgrading pip and installing requirements..."
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-dev.txt

if (-Not (Test-Path "reports")) { New-Item -ItemType Directory -Path "reports" | Out-Null }

Write-Host "Bootstrap complete. Run 'pytest -q' to run tests."

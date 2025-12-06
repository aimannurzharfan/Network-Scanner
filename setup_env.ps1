# Setup script for Network-Scanner
# Creates a virtual environment in `.venv` and installs requirements

param(
    [string]$venvName = ".venv"
)

python -m venv $venvName
# Upgrade pip
& "$venvName\Scripts\python.exe" -m pip install --upgrade pip
# Install requirements
& "$venvName\Scripts\python.exe" -m pip install -r requirements.txt

Write-Host "Virtual environment created in $venvName and dependencies installed." -ForegroundColor Green
Write-Host "To activate the venv run: .\$venvName\Scripts\Activate.ps1" -ForegroundColor Yellow

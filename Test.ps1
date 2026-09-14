$ErrorActionPreference = 'Stop'
$ChekerPython = Join-Path (Split-Path $PSScriptRoot -Parent) 'app\runtime\python.exe'
$env:PYTHONPATH = Join-Path $PSScriptRoot 'backend'
Push-Location (Join-Path $PSScriptRoot 'backend')
try {
    & $ChekerPython -m pytest
    exit $LASTEXITCODE
} finally { Pop-Location }

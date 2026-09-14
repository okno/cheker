$ErrorActionPreference = 'Stop'
$ChekerDev = $PSScriptRoot
$ChekerPython = Join-Path (Split-Path $ChekerDev -Parent) 'app\runtime\python.exe'
$ChekerNode = Join-Path $ChekerDev '.tools\node-win'
$env:PATH = "$ChekerNode;$env:PATH"
Push-Location (Join-Path $ChekerDev 'frontend')
try {
    & (Join-Path $ChekerNode 'npm.cmd') ci
    if ($LASTEXITCODE -ne 0) { throw 'Installazione frontend fallita' }
    & (Join-Path $ChekerNode 'npm.cmd') run build
    if ($LASTEXITCODE -ne 0) { throw 'Build frontend fallita' }
} finally { Pop-Location }
& $ChekerPython (Join-Path $ChekerDev 'package_app.py')
if ($LASTEXITCODE -ne 0) { throw 'Packaging fallito' }

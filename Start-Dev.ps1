$ErrorActionPreference = 'Stop'
$ChekerDev = $PSScriptRoot
$ChekerApp = Join-Path (Split-Path $ChekerDev -Parent) 'app'
$ChekerPython = Join-Path $ChekerApp 'runtime\python.exe'
$ChekerNode = Join-Path $ChekerDev '.tools\node-win'
$env:PYTHONPATH = Join-Path $ChekerDev 'backend'
$env:PATH = "$ChekerNode;$env:PATH"
$ChekerData = Join-Path $ChekerDev '.dev-data'
# Separate development state from the installed application's approvals and keys.
New-Item -ItemType Directory -Force $ChekerData | Out-Null
$env:MCP_GUARD_DATA = $ChekerData
$env:GUARD_API_TARGET = 'http://127.0.0.1:8766'
$ChekerBackend = $null
Push-Location $ChekerDev
try {
    if (-not (Test-Path (Join-Path $ChekerDev 'frontend\node_modules\.bin\vite.cmd'))) {
        Push-Location (Join-Path $ChekerDev 'frontend')
        try { & (Join-Path $ChekerNode 'npm.cmd') ci; if ($LASTEXITCODE -ne 0) { throw 'npm ci fallito' } }
        finally { Pop-Location }
    }
    $ChekerBackend = Start-Process $ChekerPython -ArgumentList @('-m','uvicorn','integrity_guard.devserver:app','--host','127.0.0.1','--port','8766','--reload','--reload-dir',(Join-Path $ChekerDev 'backend')) -PassThru
    & $ChekerPython -c "import os, pathlib, webbrowser; from integrity_guard.api import ensure_token; webbrowser.open('http://127.0.0.1:5173/#token='+ensure_token(pathlib.Path(os.environ['MCP_GUARD_DATA'])))"
    Push-Location (Join-Path $ChekerDev 'frontend')
    try { & (Join-Path $ChekerNode 'node.exe') 'node_modules\vite\bin\vite.js' --host 127.0.0.1 --port 5173 --strictPort }
    finally { Pop-Location }
} finally {
    if ($ChekerBackend -and -not $ChekerBackend.HasExited) { & taskkill.exe /PID $ChekerBackend.Id /T /F | Out-Null }
    Pop-Location
}

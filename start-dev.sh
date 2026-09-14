#!/usr/bin/env bash
set -euo pipefail
umask 077
CHEKER_DEV_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$CHEKER_DEV_DIR/.tools/node/bin:$PATH"
export PYTHONPATH="$CHEKER_DEV_DIR/backend${PYTHONPATH:+:$PYTHONPATH}"
export MCP_GUARD_DATA="$CHEKER_DEV_DIR/.dev-data-linux"
export GUARD_API_TARGET="http://127.0.0.1:8766"
mkdir -p "$MCP_GUARD_DATA"
chmod 700 "$MCP_GUARD_DATA"
cd "$CHEKER_DEV_DIR/frontend"
if [[ ! -f node_modules/vite/bin/vite.js ]]; then npm ci; fi
"$CHEKER_DEV_DIR/.venv/bin/python" -m uvicorn integrity_guard.devserver:app --host 127.0.0.1 --port 8766 --reload --reload-dir "$CHEKER_DEV_DIR/backend" &
CHEKER_BACKEND_PID=$!
trap 'kill "$CHEKER_BACKEND_PID" 2>/dev/null || true' EXIT INT TERM
printf '%s\n' 'Sviluppo UI: http://127.0.0.1:5173' "Token: $MCP_GUARD_DATA/api-token"
npm run dev -- --port 5173 --strictPort

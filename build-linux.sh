#!/usr/bin/env bash
set -euo pipefail
CHEKER_DEV_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$CHEKER_DEV_DIR/.tools/node/bin:$PATH"
cd "$CHEKER_DEV_DIR/frontend"
npm ci
npm run build
mkdir -p "$CHEKER_DEV_DIR/../app/wheels"
"$CHEKER_DEV_DIR/.venv/bin/python" -m pip wheel --no-deps "$CHEKER_DEV_DIR/backend" -w "$CHEKER_DEV_DIR/../app/wheels"
"$CHEKER_DEV_DIR/.venv/bin/python" "$CHEKER_DEV_DIR/package_app.py"
if [[ -x "$CHEKER_DEV_DIR/../app/runtime-linux/bin/python" ]]; then
  "$CHEKER_DEV_DIR/../app/runtime-linux/bin/python" -m pip install --no-deps --force-reinstall "$CHEKER_DEV_DIR/../app/wheels/"mcp_integrity_guard-*.whl
fi

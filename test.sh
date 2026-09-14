#!/usr/bin/env bash
set -euo pipefail
CHEKER_DEV_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$CHEKER_DEV_DIR/backend"
exec "$CHEKER_DEV_DIR/.venv/bin/python" -m pytest "$@"

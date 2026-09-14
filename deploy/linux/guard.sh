#!/usr/bin/env bash
set -euo pipefail
umask 077
CHEKER_APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$CHEKER_APP_DIR/runtime-linux/bin/python" -I -m integrity_guard --data-dir "${MCP_GUARD_DATA:-$CHEKER_APP_DIR/data-linux}" "$@"

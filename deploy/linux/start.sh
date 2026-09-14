#!/usr/bin/env bash
set -euo pipefail
umask 077
CHEKER_APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CHEKER_DATA_DIR="${MCP_GUARD_DATA:-$CHEKER_APP_DIR/data-linux}"
if [[ ! -x "$CHEKER_APP_DIR/runtime-linux/bin/python" ]]; then
  printf '%s\n' 'Eseguire prima: bash install-linux.sh' >&2
  exit 2
fi
mkdir -p -- "$CHEKER_DATA_DIR"
chmod 700 -- "$CHEKER_DATA_DIR"
if [[ "${GUARD_NO_BROWSER:-0}" == 1 ]]; then
  exec "$CHEKER_APP_DIR/runtime-linux/bin/python" -I -m integrity_guard --data-dir "$CHEKER_DATA_DIR" serve --ui-dir "$CHEKER_APP_DIR/ui" "$@"
fi
exec "$CHEKER_APP_DIR/runtime-linux/bin/python" -I -m integrity_guard --data-dir "$CHEKER_DATA_DIR" serve --ui-dir "$CHEKER_APP_DIR/ui" --open "$@"

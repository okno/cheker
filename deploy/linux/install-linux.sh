#!/usr/bin/env bash
set -euo pipefail
umask 077
CHEKER_APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$CHEKER_APP_DIR"
chmod 700 -- "$CHEKER_APP_DIR"
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ richiesto"'
python3 verify-release.py
python3 -m venv runtime-linux
runtime-linux/bin/python -m pip install -r requirements-linux.lock
runtime-linux/bin/python -m pip install --no-deps --force-reinstall ./wheels/mcp_integrity_guard-*.whl
mkdir -p data-linux
chmod 700 data-linux
runtime-linux/bin/python -I -m integrity_guard.diagnostics
printf '%s\n' 'Installazione completata. Avvio: bash start.sh'

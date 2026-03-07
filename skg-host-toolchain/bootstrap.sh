#!/usr/bin/env bash
# bootstrap.sh — Set up the skg-host-toolchain virtualenv
set -euo pipefail
TC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -d "$TC_DIR/.venv" ]; then
    python3 -m venv "$TC_DIR/.venv"
fi
"$TC_DIR/.venv/bin/pip" install --no-cache-dir --quiet --upgrade pip
"$TC_DIR/.venv/bin/pip" install --no-cache-dir --quiet -r "$TC_DIR/requirements.txt"
echo "[OK] skg-host-toolchain bootstrapped"
echo "     python: $TC_DIR/.venv/bin/python"

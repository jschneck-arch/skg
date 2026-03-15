#!/usr/bin/env bash
# bootstrap.sh — Set up the skg-data-toolchain virtualenv
set -euo pipefail
TC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -d "$TC_DIR/.venv" ]; then
    python3 -m venv "$TC_DIR/.venv"
fi
"$TC_DIR/.venv/bin/pip" install --no-cache-dir --quiet --upgrade pip
"$TC_DIR/.venv/bin/pip" install --no-cache-dir --quiet -r "$TC_DIR/requirements.txt"
# Create state directory
mkdir -p /var/lib/skg/data_state
echo "[OK] skg-data-toolchain bootstrapped"
echo "     python: $TC_DIR/.venv/bin/python"
echo "     SQLAlchemy: $("$TC_DIR/.venv/bin/python" -c 'import sqlalchemy; print(sqlalchemy.__version__)' 2>/dev/null || echo 'not installed')"

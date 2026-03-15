#!/usr/bin/env bash
# bootstrap.sh — set up venv for skg-container-escape-toolchain
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$DIR/.venv"

if [ ! -d "$VENV" ]; then
    echo "[*] Creating venv..."
    python3 -m venv "$VENV"
fi

"$VENV/bin/pip" install --upgrade pip --quiet
"$VENV/bin/pip" install -r "$DIR/requirements.txt" --quiet
echo "[*] Running golden test..."
cd "$DIR"
"$VENV/bin/python" tests/test_golden.py
echo "[OK] skg-container-escape-toolchain bootstrapped"

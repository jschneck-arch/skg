#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

echo "[*] Bootstrapping skg-aprs-toolchain $(cat VERSION) in: $ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERR] python3 not found" >&2
  exit 2
fi

if [ ! -d ".venv" ]; then
  echo "[*] Creating venv (.venv)"
  python3 -m venv .venv
fi

echo "[*] Activating venv"
# shellcheck disable=SC1091
source .venv/bin/activate

echo "[*] Installing requirements"
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt >/dev/null

echo "[*] Running golden test (projection sanity)"
python tests/test_golden.py

echo "[*] Done."
echo "    Try: ./skg project aprs --in tests/golden/events/sample.ndjson --out /tmp/interp.ndjson"

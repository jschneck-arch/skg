#!/usr/bin/env bash
set -euo pipefail
TC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ ! -d "$TC_DIR/.venv" ] && python3 -m venv "$TC_DIR/.venv"
"$TC_DIR/.venv/bin/pip" install --no-cache-dir --quiet --upgrade pip
"$TC_DIR/.venv/bin/pip" install --no-cache-dir --quiet -r "$TC_DIR/requirements.txt"
echo "[OK] skg-iot_firmware-toolchain bootstrapped"

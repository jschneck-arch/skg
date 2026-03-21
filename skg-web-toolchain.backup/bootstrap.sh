#!/usr/bin/env bash
# bootstrap.sh — skg-web-toolchain
set -euo pipefail
TC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -d "$TC_DIR/.venv" ]; then python3 -m venv "$TC_DIR/.venv"; fi
"$TC_DIR/.venv/bin/pip" install --no-cache-dir --quiet --upgrade pip
"$TC_DIR/.venv/bin/pip" install --no-cache-dir --quiet requests beautifulsoup4 lxml
echo "[OK] skg-web-toolchain bootstrapped"

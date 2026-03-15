#!/usr/bin/env bash
# bootstrap.sh — skg-binary-toolchain
# Tools installed system-wide via pacman; this just verifies availability.
set -euo pipefail
MISSING=()
for tool in checksec rabin2 ROPgadget ltrace; do
    command -v "$tool" &>/dev/null || MISSING+=("$tool")
done
if [ ${#MISSING[@]} -gt 0 ]; then
    echo "[WARN] Missing binary analysis tools: ${MISSING[*]}"
    echo "       Install: sudo pacman -S checksec radare2 python-ropgadget ltrace"
else
    echo "[OK] skg-binary-toolchain: all tools present"
fi

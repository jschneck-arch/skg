"""
skg.cli — entry point shim for pip-installed console_scripts.

The authoritative CLI lives in bin/skg (run directly or via /usr/local/bin/skg
after setup_arch.sh).  This module lets `pip install -e .` wire the same
`main()` function via the pyproject.toml console_scripts entry point so SKG
works without the shell symlink.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path


def main() -> None:
    # Locate bin/skg relative to the installed package tree
    _here = Path(__file__).resolve().parent.parent   # repo root
    _bin  = _here / "bin" / "skg"

    if not _bin.exists():
        print(f"[skg.cli] bin/skg not found at {_bin} — cannot start CLI", file=sys.stderr)
        sys.exit(1)

    namespace = runpy.run_path(str(_bin), run_name="skg_cli_main")
    entrypoint = namespace.get("main")
    if not callable(entrypoint):
        print(f"[skg.cli] main() missing in {_bin}", file=sys.stderr)
        sys.exit(1)
    entrypoint()

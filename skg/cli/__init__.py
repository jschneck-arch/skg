"""
skg.cli — importable command layer for the SKG CLI.

All commands live in skg/cli/commands/*.  bin/skg is now a thin shim
that imports from here and provides the argparse frontend.
"""
from __future__ import annotations


def main():
    """Entry point used by pyproject.toml: skg = 'skg.cli:main'"""
    import runpy
    import sys
    from pathlib import Path

    bin_skg = Path(__file__).resolve().parents[2] / "bin" / "skg"
    if not bin_skg.exists():
        print(f"[skg.cli] bin/skg not found at {bin_skg} — cannot start CLI", file=sys.stderr)
        sys.exit(1)

    namespace = runpy.run_path(str(bin_skg), run_name="skg_bin_main")
    entrypoint = namespace.get("main")
    if not callable(entrypoint):
        print(f"[skg.cli] main() missing in {bin_skg}", file=sys.stderr)
        sys.exit(1)
    entrypoint()

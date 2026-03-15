"""
skg-binary-toolchain adapters.
Primary analysis is handled by gravity_field._exec_binary_analysis()
which runs checksec/rabin2/ROPgadget/ltrace locally.
This module exposes the standalone analyze_binary() callable for
direct use from exploit_dispatch and the CLI.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "skg-gravity"))

try:
    from exploit_dispatch import analyze_binary
except ImportError:
    def analyze_binary(binary_path: str, **kwargs):
        raise ImportError("exploit_dispatch not found; run from /opt/skg")

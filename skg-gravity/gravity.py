"""
skg :: gravity.py

Compatibility shim for the legacy gravity entrypoint.

The canonical gravity runtime is skg-gravity/gravity_field.py.
This module delegates all behavior there so the repo no longer carries
two independent gravity engines.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_GRAVITY_FIELD = Path(__file__).with_name("gravity_field.py")
_MODULE = None


def _load():
    global _MODULE
    if _MODULE is not None:
        return _MODULE

    spec = importlib.util.spec_from_file_location("skg_gravity_field_shim", _GRAVITY_FIELD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _MODULE = module
    return module


def __getattr__(name: str):
    return getattr(_load(), name)


def main() -> int:
    print(
        "[SKG-GRAVITY] gravity.py is a compatibility shim; delegating to gravity_field.py",
        file=sys.stderr,
    )
    _load().main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

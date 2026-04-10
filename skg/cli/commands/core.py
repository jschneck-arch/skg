from __future__ import annotations

from skg.core import coupling as coupling_module


def cmd_core(a):
    if getattr(a, "core_cmd", None) == "coupling":
        return coupling_module.run(a)
    print("Usage: skg core coupling [--show|--validate|--learn|--apply]")
    return 1

"""Compatibility shim for older imports that expected ``skg/cli.py``."""
from __future__ import annotations

from skg.cli.app import main

__all__ = ["main"]

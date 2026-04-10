"""
Importable command layer for the SKG CLI.

The authoritative parser and dispatch live in ``skg.cli.app``. ``bin/skg`` is
only a repository-local bootstrap shim.
"""
from __future__ import annotations

from .app import build_parser, dispatch_command, main

__all__ = ["build_parser", "dispatch_command", "main"]

"""
conftest.py — pytest configuration for the SKG test suite.

Adds /opt/skg to sys.path so that `import skg` works without
needing PYTHONPATH to be set manually.
"""
import sys
from pathlib import Path

# Ensure the repo root is on the path for all test modules
repo_root = str(Path(__file__).resolve().parents[1])
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

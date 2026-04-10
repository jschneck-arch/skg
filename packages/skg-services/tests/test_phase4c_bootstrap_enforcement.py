from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def _read(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8")


def test_wave1_projector_fallbacks_removed() -> None:
    banned = {
        "skg/cli/commands/derived.py": ["from skg.sensors.projector"],
        "skg/cli/commands/exploit.py": ["from skg.sensors.projector"],
        "skg/core/daemon.py": ["from skg.sensors.projector"],
        "skg/forge/generator.py": ["from skg.sensors.projector"],
        "skg/sensors/__init__.py": ["from skg.sensors.projector"],
    }

    for relpath, patterns in banned.items():
        text = _read(relpath)
        for pattern in patterns:
            assert pattern not in text, f"{relpath} still contains legacy fallback import: {pattern}"


def test_wave2_registry_fallbacks_removed() -> None:
    banned = {
        "skg/core/daemon.py": ["from skg.core.domain_registry"],
        "skg/core/coupling.py": ["from skg.core.domain_registry"],
        "skg/sensors/dark_hypothesis_sensor.py": ["from skg.core.domain_registry"],
        "skg/sensors/projector.py": ["from skg.core.domain_registry"],
    }

    required = {
        "skg/core/daemon.py": ["from skg_registry import DomainRegistry", "from skg_services.gravity.domain_runtime import"],
        "skg/core/coupling.py": ["from skg_registry import DomainRegistry"],
        "skg/sensors/dark_hypothesis_sensor.py": ["from skg_registry import DomainRegistry"],
        "skg/sensors/projector.py": ["from skg_registry import DomainRegistry"],
    }

    for relpath, patterns in banned.items():
        text = _read(relpath)
        for pattern in patterns:
            assert pattern not in text, f"{relpath} still contains legacy registry fallback import: {pattern}"

    for relpath, patterns in required.items():
        text = _read(relpath)
        for pattern in patterns:
            assert pattern in text, f"{relpath} is missing canonical import: {pattern}"

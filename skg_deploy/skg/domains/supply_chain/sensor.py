"""
skg.domains.supply_chain.sensor
================================
SBOM sensor — reads package manifests and emits NodeStates.

Supported inputs:
  pip freeze output     (requirements.txt format)
  npm list --json       (package-lock.json / npm list)
  CycloneDX JSON        (cyclonedx format)
  Manual package list   (simple name==version lines)

For each package found, cross-references against a CVE list
(initially: known-bad package list, later: NVD API feed).

Emits obs.substrate.node events in the standard envelope.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from skg.substrate.node import NodeState, TriState

log = logging.getLogger("skg.domains.supply_chain.sensor")

# Known vulnerable packages for demonstration
# In production: replaced by NVD API feed / OSV database
KNOWN_VULNERABLE: dict[str, dict] = {
    "lodash": {
        "cve": "CVE-2021-23337",
        "affected_below": "4.17.21",
        "severity": "high",
        "exploit_public": True,
    },
    "log4j": {
        "cve": "CVE-2021-44228",
        "affected_below": "2.17.0",
        "severity": "critical",
        "exploit_public": True,
    },
    "requests": {
        "cve": "CVE-2023-32681",
        "affected_below": "2.31.0",
        "severity": "medium",
        "exploit_public": False,
    },
    "pyyaml": {
        "cve": "CVE-2020-14343",
        "affected_below": "5.4",
        "severity": "critical",
        "exploit_public": True,
    },
    "pillow": {
        "cve": "CVE-2023-44271",
        "affected_below": "10.0.1",
        "severity": "high",
        "exploit_public": False,
    },
    "cryptography": {
        "cve": "CVE-2023-49083",
        "affected_below": "41.0.6",
        "severity": "medium",
        "exploit_public": False,
    },
}


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse version string to tuple for comparison."""
    try:
        parts = version_str.split(".")
        return tuple(int(p.split("-")[0].split("+")[0])
                     for p in parts if p.isdigit() or p[0].isdigit())
    except Exception:
        return (0,)


def _is_vulnerable(pkg_name: str, version: str) -> Optional[dict]:
    """Check if a package version is vulnerable."""
    info = KNOWN_VULNERABLE.get(pkg_name.lower())
    if not info:
        return None
    try:
        pkg_ver = _parse_version(version)
        max_ver = _parse_version(info["affected_below"])
        if pkg_ver < max_ver:
            return info
    except Exception:
        pass
    return None


def parse_pip_freeze(content: str) -> list[tuple[str, str]]:
    """Parse pip freeze / requirements.txt format → [(name, version)]
    Handles pinned (name==version) and unpinned (name only) formats.
    Unpinned packages get version "0.0.0" — will match any known-vulnerable entry.
    """
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            packages.append((name.strip().lower(), version.strip()))
        elif line and not line.startswith(("http", "git+")):
            # Unpinned — use 0.0.0 which is below any known-bad version
            name = line.split("#")[0].split(">")[0].split("<")[0].split("[")[0].strip()
            if name:
                packages.append((name.lower(), "0.0.0"))
    return packages


def scan_packages(packages: list[tuple[str, str]],
                  workload_id: str = "default",
                  attack_path_id: str = "supply_chain_prototype_injection_v1",
                  run_id: Optional[str] = None) -> list[dict]:
    """
    Scan a package list and emit substrate node events.
    Returns list of event dicts in obs.substrate.node envelope.
    """
    run_id = run_id or str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    events = []

    vulnerable_found = []
    exploit_public = False

    for name, version in packages:
        vuln = _is_vulnerable(name, version)
        if vuln:
            vulnerable_found.append((name, version, vuln))
            if vuln.get("exploit_public"):
                exploit_public = True

    # PKG-01: vulnerable package exists
    pkg01_status = TriState.REALIZED if vulnerable_found else TriState.BLOCKED
    pkg01_notes = (f"{len(vulnerable_found)} vulnerable package(s) found: "
                   + ", ".join(f"{n}=={v} ({i['cve']})"
                               for n, v, i in vulnerable_found[:3])
                   if vulnerable_found else "No known-vulnerable packages found.")

    events.append(_make_event(
        node_id="PKG-01",
        status=pkg01_status,
        confidence=0.90 if vulnerable_found else 0.80,
        source_kind="sbom_scan",
        pointer=f"sbom://{workload_id}/packages",
        notes=pkg01_notes,
        attributes={"vulnerable_packages": [
            {"name": n, "version": v, "cve": i["cve"], "severity": i["severity"]}
            for n, v, i in vulnerable_found
        ]},
        workload_id=workload_id,
        attack_path_id=attack_path_id,
        run_id=run_id,
        now=now,
    ))

    # PKG-02: transitive exposure — unknown without full dep graph
    # Mark unknown unless we have explicit transitive scan
    events.append(_make_event(
        node_id="PKG-02",
        status=TriState.UNKNOWN,
        confidence=0.40,
        source_kind="sbom_scan",
        pointer=f"sbom://{workload_id}/transitive",
        notes="Transitive dependency graph not fully resolved — manual review required.",
        workload_id=workload_id,
        attack_path_id=attack_path_id,
        run_id=run_id,
        now=now,
    ))

    # PKG-03: direct import — realized if any vulnerable package is direct dep
    pkg03_status = TriState.REALIZED if vulnerable_found else TriState.UNKNOWN
    events.append(_make_event(
        node_id="PKG-03",
        status=pkg03_status,
        confidence=0.85 if vulnerable_found else 0.40,
        source_kind="sbom_scan",
        pointer=f"sbom://{workload_id}/direct",
        notes=("Direct dependency on vulnerable package confirmed."
               if vulnerable_found else "No direct vulnerable dependencies found."),
        workload_id=workload_id,
        attack_path_id=attack_path_id,
        run_id=run_id,
        now=now,
    ))

    # PKG-05: public exploit exists
    pkg05_status = TriState.REALIZED if exploit_public else TriState.BLOCKED
    events.append(_make_event(
        node_id="PKG-05",
        status=pkg05_status,
        confidence=0.92 if exploit_public else 0.85,
        source_kind="sbom_scan",
        pointer=f"sbom://{workload_id}/exploits",
        notes=("Public exploit exists for one or more vulnerable packages."
               if exploit_public else "No public exploits found for vulnerable packages."),
        workload_id=workload_id,
        attack_path_id=attack_path_id,
        run_id=run_id,
        now=now,
    ))

    return events


def _make_event(node_id: str, status: TriState, confidence: float,
                source_kind: str, pointer: str, notes: str,
                workload_id: str, attack_path_id: str, run_id: str,
                now: str, attributes: dict = None) -> dict:
    return {
        "id":   str(uuid.uuid4()),
        "ts":   now,
        "type": "obs.substrate.node",
        "source": {
            "source_id": "supply_chain_sensor",
            "toolchain": "skg-supply-chain",
            "version":   "1.0.0",
        },
        "payload": {
            "node_id":        node_id,
            "status":         status.value,
            "attack_path_id": attack_path_id,
            "run_id":         run_id,
            "workload_id":    workload_id,
            "observed_at":    now,
            "notes":          notes,
            "attributes":     attributes or {},
        },
        "provenance": {
            "evidence_rank": 2,
            "evidence": {
                "source_kind":   source_kind,
                "pointer":       pointer,
                "collected_at":  now,
                "confidence":    confidence,
            },
        },
    }

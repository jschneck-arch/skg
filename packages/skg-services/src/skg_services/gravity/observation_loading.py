from __future__ import annotations

import glob
import json
import re
from pathlib import Path
from typing import Callable, TypeVar

T = TypeVar("T")

MAX_RECENT_BROAD_EVENT_FILES = 64


def _candidate_patterns(node_key: str, discovery_dir: Path, cve_dir: Path | None) -> list[str]:
    ip_dot = node_key
    ip_us = node_key.replace(".", "_")

    patterns = [
        str(discovery_dir / f"gravity_http_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_http_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_auth_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_auth_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_nmap_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_nmap_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_pcap_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_pcap_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_ssh_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_ssh_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_sysaudit_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_sysaudit_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_binary_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_binary_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_ce_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_ce_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_iot_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_iot_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_sc_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_sc_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_data_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_data_{ip_us}_*.ndjson"),
        str(discovery_dir / f"msf_exec_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"msf_exec_{ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_events_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_events_{ip_us}_*.ndjson"),
        str(discovery_dir / f"web_events_{ip_dot}.ndjson"),
        str(discovery_dir / f"gravity_postexp_{ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_postexp_{ip_us}_*.ndjson"),
    ]

    if cve_dir is not None:
        patterns.extend(
            [
                str(cve_dir / f"cve_events_{ip_dot}_*.ndjson"),
                str(cve_dir / f"cve_events_{ip_us}_*.ndjson"),
            ]
        )

    return patterns


def _discover_candidate_files(node_key: str, discovery_dir: Path, events_dir: Path, cve_dir: Path | None) -> list[str]:
    seen: set[str] = set()
    files: list[str] = []

    for pattern in _candidate_patterns(node_key, discovery_dir, cve_dir):
        for path in glob.glob(pattern):
            if path not in seen:
                seen.add(path)
                files.append(path)

    if events_dir.exists():
        for path in sorted(
            glob.glob(str(events_dir / "*.ndjson")),
            key=lambda item: Path(item).stat().st_mtime,
            reverse=True,
        )[:MAX_RECENT_BROAD_EVENT_FILES]:
            if path not in seen:
                seen.add(path)
                files.append(path)

    is_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", node_key))
    if (not is_ip) and discovery_dir.exists():
        for path in sorted(
            glob.glob(str(discovery_dir / "*.ndjson")),
            key=lambda item: Path(item).stat().st_mtime,
            reverse=True,
        )[:MAX_RECENT_BROAD_EVENT_FILES]:
            if path not in seen:
                seen.add(path)
                files.append(path)

    return files


def load_observations_for_node(
    node_key: str,
    discovery_dir: Path,
    events_dir: Path,
    mapper: Callable[[dict, str], T | None],
    cve_dir: Path | None = None,
) -> list[T]:
    """Service-owned event-file scanning and mapping for gravity runtime."""

    observations: list[T] = []
    seen_event_ids: set[str] = set()

    for filepath in _discover_candidate_files(node_key, discovery_dir, events_dir, cve_dir):
        cycle_id = Path(filepath).stem
        try:
            with open(filepath, encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue

                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    event_id = event.get("id")
                    if event_id and event_id in seen_event_ids:
                        continue
                    if event_id:
                        seen_event_ids.add(event_id)

                    mapped = mapper(event, cycle_id)
                    if mapped is not None:
                        observations.append(mapped)
        except OSError:
            continue

    return observations

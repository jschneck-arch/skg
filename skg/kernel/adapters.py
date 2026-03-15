"""
skg.kernel.adapters
===================
Converts raw NDJSON event files into kernel Observation objects.

This is the bridge between the adapter layer (instruments that emit
obs.attack.precondition events) and the kernel (SupportEngine,
StateEngine, EnergyEngine).

Each event has:
  payload.wicket_id    — the node being observed (WB-09, CE-01, etc.)
  payload.status       — "realized" | "blocked" | "unknown"
  payload.target_ip    — which host this applies to
  provenance.evidence.confidence — how confident the instrument is

The kernel needs Observation with support_mapping:
  support_mapping[target_ip][context] = {"R": phi_R, "B": phi_B}

Mapping:
  status=realized  → phi_R = confidence, phi_B = 0.0
  status=blocked   → phi_R = 0.0,        phi_B = confidence
  status=unknown   → phi_R = 0.0,        phi_B = 0.0  (contributes nothing)

Decay class assignment:
  evidence_rank 1 (runtime)    → operational (moderate decay)
  evidence_rank 2 (config)     → structural  (slow decay)
  evidence_rank 3+ (inferred)  → operational
  ephemeral instruments (pcap) → ephemeral   (fast decay)

Support thresholds (CollapseThresholds):
  We set realized=0.5, blocked=0.5.
  A single high-confidence (≥0.95) observation realizes immediately.
  Two moderate (0.7) observations together also realize (1.4 > 0.5).
  Conflicting observations cancel and stay UNKNOWN.
"""
from __future__ import annotations

import glob
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .observations import Observation

log = logging.getLogger("skg.kernel.adapters")

# Instruments whose evidence decays quickly
EPHEMERAL_INSTRUMENTS = {"pcap", "net_sensor", "tshark"}

# Default decay class by instrument
INSTRUMENT_DECAY = {
    "bloodhound":       "structural",
    "nvd_feed":         "structural",
    "supply_chain":     "structural",
    "nmap":             "structural",
    "auth_scanner":     "operational",
    "http_collector":   "operational",
    "ssh_sensor":       "operational",
    "sysaudit":         "operational",
    "container_inspect":"operational",
    "msf_sensor":       "operational",
    "pcap":             "ephemeral",
}


def _decay_class(instrument: str, evidence_rank: int) -> str:
    if instrument in EPHEMERAL_INSTRUMENTS:
        return "ephemeral"
    if evidence_rank == 2:
        return "structural"
    return INSTRUMENT_DECAY.get(instrument, "operational")


def _phi_from_event(status: str, confidence: float) -> Tuple[float, float]:
    """Convert (status, confidence) → (phi_R, phi_B) support vector."""
    if status == "realized":
        return (confidence, 0.0)
    if status == "blocked":
        return (0.0, confidence)
    return (0.0, 0.0)


def event_to_observation(event: dict) -> Optional[Observation]:
    """
    Convert a single NDJSON event dict to a kernel Observation.
    Returns None if the event lacks required fields.
    """
    payload = event.get("payload", {})
    provenance = event.get("provenance", {})
    evidence = provenance.get("evidence", {})
    source = event.get("source", {})

    wicket_id = payload.get("wicket_id")
    status = payload.get("status")
    if not wicket_id or not status:
        return None

    # Resolve target IP
    target_ip = (
        payload.get("target_ip")
        or payload.get("workload_id", "").split("::")[-1]
    )
    if not target_ip:
        return None

    # Confidence: from provenance, fallback to payload, fallback 0.8
    confidence = float(
        evidence.get("confidence")
        or payload.get("confidence")
        or 0.8
    )

    # Evidence rank
    rank = int(provenance.get("evidence_rank") or evidence.get("rank") or 3)

    # Instrument name from source_id
    source_id = source.get("source_id", "")
    instrument = source_id.split(".")[-1] if "." in source_id else source_id

    decay = _decay_class(instrument, rank)

    phi_r, phi_b = _phi_from_event(status, confidence)

    # Parse timestamp
    ts_str = event.get("ts") or evidence.get("collected_at") or ""
    try:
        event_time = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        event_time = datetime.now(timezone.utc)
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    return Observation(
        instrument=instrument,
        targets=[target_ip],
        context=wicket_id,          # context = the wicket being observed
        payload=payload,
        event_time=event_time,
        decay_class=decay,
        support_mapping={target_ip: {"R": phi_r, "B": phi_b}},
    )


def load_observations_for_target(
    target_ip: str,
    discovery_dir: Path,
    events_dir: Path,
    cve_dir: Optional[Path] = None,
) -> List[Observation]:
    """
    Load all Observation objects for a target from all event files.
    Replaces load_wicket_states() + _load_events_file() in gravity_field.py.
    """
    observations = []

    # Normalised forms of the IP (dots and underscores) for file matching
    _ip_dot = target_ip          # 192.168.254.7
    _ip_us  = target_ip.replace(".", "_")  # 192_168_254_7

    patterns = [
        # Web / auth
        str(discovery_dir / f"gravity_http_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_http_{_ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_auth_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_auth_{_ip_us}_*.ndjson"),
        # Network
        str(discovery_dir / f"gravity_nmap_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_nmap_{_ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_pcap_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_pcap_{_ip_us}_*.ndjson"),
        # Host
        str(discovery_dir / f"gravity_ssh_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_ssh_{_ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_sysaudit_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_sysaudit_{_ip_us}_*.ndjson"),
        str(discovery_dir / f"gravity_binary_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_binary_{_ip_us}_*.ndjson"),
        # Container escape
        str(discovery_dir / f"gravity_ce_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_ce_{_ip_us}_*.ndjson"),
        # IoT firmware
        str(discovery_dir / f"gravity_iot_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_iot_{_ip_us}_*.ndjson"),
        # Supply chain
        str(discovery_dir / f"gravity_sc_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_sc_{_ip_us}_*.ndjson"),
        # Data profiler
        str(discovery_dir / f"gravity_data_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_data_{_ip_us}_*.ndjson"),
        # MSF execution
        str(discovery_dir / f"msf_exec_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"msf_exec_{_ip_us}_*.ndjson"),
        # Generic gravity events
        str(discovery_dir / f"gravity_events_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_events_{_ip_us}_*.ndjson"),
        str(discovery_dir / f"web_events_{_ip_dot}_*.ndjson"),
    ]
    if cve_dir:
        patterns.append(str(cve_dir / "cve_events_*.ndjson"))
    patterns.append(str(events_dir / "*.ndjson"))

    seen_event_ids = set()

    for pattern in patterns:
        for filepath in glob.glob(pattern):
            try:
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        # Dedup by event id
                        ev_id = event.get("id")
                        if ev_id and ev_id in seen_event_ids:
                            continue
                        if ev_id:
                            seen_event_ids.add(ev_id)

                        # Filter by target for broad files (events_dir)
                        payload = event.get("payload", {})
                        ev_target = (
                            payload.get("target_ip")
                            or payload.get("workload_id", "").split("::")[-1]
                        )
                        if ev_target and ev_target != target_ip:
                            continue

                        obs = event_to_observation(event)
                        if obs is not None:
                            observations.append(obs)
            except Exception as e:
                log.debug(f"Failed to read {filepath}: {e}")

    return observations

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
  support_mapping[subject_key][context] = {"R": phi_R, "B": phi_B, "U": phi_U}

  subject_key = identity_key = the stable host anchor (never target_ip directly).

Mapping:
  status=realized  → phi_R = confidence, phi_B = 0.0,        phi_U = 0.0
  status=blocked   → phi_R = 0.0,        phi_B = confidence, phi_U = 0.0
  status=unknown   → phi_R = 0.0,        phi_B = 0.0,        phi_U = confidence

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

from skg.core.assistant_contract import classify_assistant_event
from skg.identity import canonical_observation_subject

from .observations import Observation

try:
    from skg_protocol.observation_mapping import (
        decay_class_for_event as _protocol_decay_class_for_event,
        map_event_to_observation_mapping as _protocol_map_event_to_observation_mapping,
        phi_from_status as _protocol_phi_from_status,
    )
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    _protocol_decay_class_for_event = None
    _protocol_map_event_to_observation_mapping = None
    _protocol_phi_from_status = None

try:
    from skg_services.gravity.observation_loading import (
        load_observations_for_node as _service_load_observations_for_node,
    )
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    _service_load_observations_for_node = None

log = logging.getLogger("skg.kernel.adapters")

MAX_RECENT_BROAD_EVENT_FILES = 64

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
    if _protocol_decay_class_for_event is not None:
        return _protocol_decay_class_for_event(instrument, evidence_rank)
    if instrument in EPHEMERAL_INSTRUMENTS:
        return "ephemeral"
    if evidence_rank == 2:
        return "structural"
    return INSTRUMENT_DECAY.get(instrument, "operational")


def _phi_from_event(status: str, confidence: float) -> Tuple[float, float, float]:
    """Convert (status, confidence) → (phi_R, phi_B, phi_U) support vector."""
    if _protocol_phi_from_status is not None:
        return _protocol_phi_from_status(status, confidence)
    if status == "realized":
        return (confidence, 0.0, 0.0)
    if status == "blocked":
        return (0.0, confidence, 0.0)
    return (0.0, 0.0, confidence)


def event_to_observation(event: dict, cycle_id: str = "") -> Optional[Observation]:
    """
    Convert a single NDJSON event dict to a kernel Observation.
    Returns None if the event lacks required fields.

    cycle_id: the gravity cycle execution identifier — typically the NDJSON
    file stem that contained this event (e.g. "gravity_nmap_192_168_1_1_20260322T143022").
    Used by SupportEngine to count distinct cycle runs (n) for the decoherence criterion.
    Falls back to payload.gravity_cycle_id if set, then to the caller-supplied value.
    """
    if _protocol_map_event_to_observation_mapping is not None:
        mapped = _protocol_map_event_to_observation_mapping(event, cycle_id=cycle_id)
        if mapped is None:
            return None
        return Observation(
            instrument=mapped.instrument,
            targets=list(mapped.targets),
            context=mapped.context,
            payload=dict(mapped.payload),
            event_time=mapped.event_time,
            decay_class=mapped.decay_class,
            support_mapping=dict(mapped.support_mapping),
            cycle_id=mapped.cycle_id,
        )

    payload = event.get("payload", {})
    provenance = event.get("provenance", {})
    evidence = provenance.get("evidence", {})
    source = event.get("source", {})

    admissibility = classify_assistant_event(event)
    if not admissibility.get("observation_admissible", True):
        log.debug(
            "[adapters] dropped inadmissible observation event from %s: %s",
            source.get("source_id", ""),
            admissibility.get("reason", "assistant boundary"),
        )
        return None

    wicket_id = payload.get("wicket_id")
    status = payload.get("status")
    if not wicket_id or not status:
        return None

    subject = canonical_observation_subject(payload)
    subject_key = subject["subject_key"]
    if not subject_key:
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

    phi_r, phi_b, phi_u = _phi_from_event(status, confidence)

    # Parse timestamp
    ts_str = event.get("ts") or evidence.get("collected_at") or ""
    try:
        event_time = datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        event_time = datetime.now(timezone.utc)
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    # Resolve cycle_id: prefer payload field, then caller-supplied value
    resolved_cycle_id = (
        str(payload.get("gravity_cycle_id") or "").strip()
        or cycle_id
    )

    return Observation(
        instrument=instrument,
        targets=[subject_key],
        context=wicket_id,          # context = the wicket being observed
        payload=payload,
        event_time=event_time,
        decay_class=decay,
        support_mapping={subject_key: {"R": phi_r, "B": phi_b, "U": phi_u}},
        cycle_id=resolved_cycle_id,
    )


def load_observations_for_node(
    node_key: str,
    discovery_dir: Path,
    events_dir: Path,
    cve_dir: Optional[Path] = None,
) -> List[Observation]:
    """
    Load all Observation objects for a node from all event files.

    node_key is the stable identity anchor for the node — the identity_key
    resolved by canonical_observation_subject().  For IP-only hosts this equals
    the IP address, but for workload-identified nodes (e.g. "web::10.0.0.1:8080")
    it is the host portion of the workload_id.  node_key is never the operator
    target label.

    Replaces load_wicket_states() + _load_events_file() in gravity_field.py.
    """
    if _service_load_observations_for_node is not None:
        def _map_and_filter(event: dict, file_cycle_id: str) -> Observation | None:
            payload = event.get("payload", {})
            subject = canonical_observation_subject(payload)
            candidates = {
                str(subject.get("subject_key") or "").strip(),
                str(subject.get("identity_key") or "").strip(),
                str(subject.get("target_ip") or "").strip(),
            }
            candidates.discard("")
            if candidates and node_key not in candidates:
                return None
            return event_to_observation(event, cycle_id=file_cycle_id)

        return _service_load_observations_for_node(
            node_key=node_key,
            discovery_dir=discovery_dir,
            events_dir=events_dir,
            mapper=_map_and_filter,
            cve_dir=cve_dir,
        )

    observations = []

    # Normalised forms for file-name matching.
    # For non-IP node_keys we try both the key as-is and a sanitised form.
    _ip_dot = node_key
    _ip_us  = node_key.replace(".", "_")

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
        # Post-exploitation session output
        str(discovery_dir / f"gravity_postexp_{_ip_dot}_*.ndjson"),
        str(discovery_dir / f"gravity_postexp_{_ip_us}_*.ndjson"),
    ]
    if cve_dir:
        patterns.extend([
            str(cve_dir / f"cve_events_{_ip_dot}_*.ndjson"),
            str(cve_dir / f"cve_events_{_ip_us}_*.ndjson"),
        ])

    seen_event_ids = set()
    candidate_files: list[str] = []
    seen_files = set()

    for pattern in patterns:
        for filepath in glob.glob(pattern):
            if filepath not in seen_files:
                seen_files.add(filepath)
                candidate_files.append(filepath)

    broad_event_files = []
    if events_dir.exists():
        broad_event_files = sorted(
            glob.glob(str(events_dir / "*.ndjson")),
            key=lambda p: Path(p).stat().st_mtime,
            reverse=True,
        )[:MAX_RECENT_BROAD_EVENT_FILES]
    for filepath in broad_event_files:
        if filepath not in seen_files:
            seen_files.add(filepath)
            candidate_files.append(filepath)

    # If node_key looks like a hostname (not a bare IP), the discovery files may
    # be named after the IP rather than the hostname.  Add a broad discovery scan
    # so content-based filtering (line 295) can match hostname identity payloads
    # in IP-named files (MED-58 fix).
    import re as _re
    _is_ip = bool(_re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", node_key))
    if not _is_ip and discovery_dir.exists():
        broad_disc = sorted(
            glob.glob(str(discovery_dir / "*.ndjson")),
            key=lambda p: Path(p).stat().st_mtime,
            reverse=True,
        )[:MAX_RECENT_BROAD_EVENT_FILES]
        for filepath in broad_disc:
            if filepath not in seen_files:
                seen_files.add(filepath)
                candidate_files.append(filepath)

    for filepath in candidate_files:
        # The file stem is the natural gravity cycle ID: each instrument run
        # writes its own NDJSON file with a unique timestamp-stamped name.
        # This gives SupportEngine the "distinct cycle executions" count (n).
        file_cycle_id = Path(filepath).stem
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

                    payload = event.get("payload", {})
                    subject = canonical_observation_subject(payload)
                    candidates = {
                        str(subject.get("subject_key") or "").strip(),
                        str(subject.get("identity_key") or "").strip(),
                        str(subject.get("target_ip") or "").strip(),
                    }
                    candidates.discard("")
                    if candidates and node_key not in candidates:
                        continue

                    obs = event_to_observation(event, cycle_id=file_cycle_id)
                    if obs is not None:
                        observations.append(obs)
        except Exception as e:
            log.debug(f"Failed to read {filepath}: {e}")

    return observations


# Backward-compatibility alias — callers that still pass target_ip as positional arg
# continue to work; new callers should use load_observations_for_node directly.
load_observations_for_target = load_observations_for_node

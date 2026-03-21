"""
skg.topology.energy
===================
Computes G(t) — the information field coherence observable — per domain sphere.

Current observable:
    G(sphere) = Σᵢⱼ Aᵢ Aⱼ cos(φᵢ - φⱼ) / n²

Where:
  A = amplitude derived from confidence structure
  φ = phase derived from substrate state:
        realized → 0.0
        blocked  → π
        unknown  → π/2
      or explicit substrate phase if provided.

Interpretation:
- G increasing after new realizations = attack surface becoming coherent
- G decreasing under defensive controls = energy/coherence draining
- unknown states remain orthogonal and resist premature collapse

Backward-compatibility:
This module preserves the original public API and observable, but is now
aware of richer substrate state:
- confidence_vector
- explicit phase
- local_energy
- latent flags

This is still an observable, not the full canonical SKG energy functional.
"""
from __future__ import annotations

import json
import math
import logging
import os
from glob import glob
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from skg.identity import parse_workload_ref
from skg.kernel.pearls import Pearl, PearlLedger

log = logging.getLogger("skg.topology.energy")

# Phase encoding — tri-state as angle on the unit circle
PHASE = {
    "realized": 0.0,
    "blocked":  math.pi,
    "unknown":  math.pi / 2,
}

# Domain sphere membership — which prefixes belong to which sphere
SPHERE_MAP = {
    "host":         ["HO-", "PI-", "LI-"],
    "container":    ["CE-"],
    "ad":           ["AD-"],
    "network":      ["NE-"],
    "web":          ["WE-", "WB-"],
    "data":         ["DP-"],
    "binary":       ["BA-"],
    "ai_target":    ["AI-"],
    "iot_firmware": ["IF-"],
    "supply_chain": ["SC-"],
    "aprs":         ["AP-"],
}

FIELD_DOMAIN_TO_SPHERE = {
    "host": "host",
    "sysaudit": "host",
    "binary_analysis": "host",
    "web": "web",
    "data": "data",
    "data_pipeline": "data",
    "container_escape": "container",
    "ad_lateral": "ad",
    "ai_target": "ai_target",
    "iot_firmware": "iot_firmware",
    "supply_chain": "supply_chain",
    "aprs": "aprs",
}


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return float(value)


def _mean(values: list[float], default: float = 0.0) -> float:
    if not values:
        return default
    return float(sum(values) / len(values))


def _surface_score(path: str) -> tuple[int, int, float]:
    try:
        data = json.loads(Path(path).read_text())
        targets = data.get("targets", []) or []
        target_count = sum(1 for t in targets if t.get("ip") or t.get("host"))
        service_count = sum(len(t.get("services", []) or []) for t in targets)
        return (target_count + service_count, target_count, os.path.getmtime(path))
    except Exception:
        return (0, 0, os.path.getmtime(path))


def _select_surface_path() -> str | None:
    surfaces = glob("/var/lib/skg/discovery/surface_*.json")
    if not surfaces:
        return None
    return max(surfaces, key=_surface_score)


def _default_pearls_path() -> Path:
    return Path("/var/lib/skg/pearls.jsonl")


def field_spheres_for_domains(domains: set[str] | list[str] | tuple[str, ...]) -> list[str]:
    spheres: list[str] = []
    for domain in domains:
        sphere = FIELD_DOMAIN_TO_SPHERE.get(str(domain or "").strip())
        if sphere and sphere not in spheres:
            spheres.append(sphere)
    return spheres


def anchored_field_pull(
    anchor: str,
    domains: set[str] | list[str] | tuple[str, ...],
    sphere_pulls: dict[str, float],
    fiber_clusters_by_anchor: dict[str, object],
    sphere_persistence: dict[str, float] | None = None,
) -> float:
    sphere_persistence = sphere_persistence or {}
    target_spheres = field_spheres_for_domains(domains)
    cluster = fiber_clusters_by_anchor.get(anchor)
    cluster_spheres = set(getattr(cluster, "spheres", []) or []) if cluster else set()
    active_spheres = [s for s in target_spheres if s in cluster_spheres] or target_spheres
    active_pulls = [
        float(sphere_pulls.get(s, 0.0) or 0.0)
        for s in active_spheres
        if sphere_pulls.get(s) is not None
    ]
    sphere_pull = (sum(active_pulls) / len(active_pulls)) if active_pulls else 0.0
    active_persistence = [
        float(sphere_persistence.get(s, 0.0) or 0.0)
        for s in active_spheres
        if sphere_persistence.get(s) is not None
    ]
    persistence_pull = (sum(active_persistence) / len(active_persistence)) if active_persistence else 0.0

    cluster_tension = float(getattr(cluster, "total_tension", 0.0) or 0.0) if cluster else 0.0
    cluster_coherence = float(getattr(cluster, "total_coherence", 0.0) or 0.0) if cluster else 0.0
    cluster_member_count = float(getattr(cluster, "member_count", 0.0) or 0.0) if cluster else 0.0
    overlap = float(len(set(target_spheres) & cluster_spheres)) if cluster else 0.0
    pearl_fibers = [
        fiber for fiber in getattr(cluster, "fibers", []) or []
        if getattr(fiber, "kind", "") == "pearl_memory"
    ] if cluster else []
    pearl_count = float(len(pearl_fibers))
    pearl_coherence = sum(float(getattr(fiber, "coherence", 0.0) or 0.0) for fiber in pearl_fibers)

    raw_pull = (
        (0.04 * sphere_pull)
        + (0.18 * persistence_pull)
        + (0.55 * math.log1p(cluster_tension))
        + (0.12 * math.log1p(cluster_coherence))
        + (0.03 * math.log1p(cluster_member_count))
        + (0.08 * math.log1p(pearl_count))
        + (0.05 * math.log1p(pearl_coherence))
        + (0.08 * overlap)
    )
    return round(min(4.0, max(0.0, raw_pull)), 4)


def _pearl_identity_key(pearl: Pearl) -> str:
    energy = pearl.energy_snapshot or {}
    target = pearl.target_snapshot or {}
    return (
        str(energy.get("identity_key") or target.get("identity_key") or "")
        or parse_workload_ref(
            str(energy.get("workload_id") or target.get("workload_id") or "")
        ).get("identity_key", "")
        or str(energy.get("target_ip") or target.get("target_ip") or "")
    )


def _pearl_spheres(pearl: Pearl) -> list[str]:
    spheres: list[str] = []

    def _add(sphere: str) -> None:
        if sphere and sphere not in spheres:
            spheres.append(sphere)

    energy = pearl.energy_snapshot or {}
    target = pearl.target_snapshot or {}
    parsed = parse_workload_ref(str(energy.get("workload_id") or target.get("workload_id") or ""))

    domain = str(target.get("domain") or energy.get("domain") or parsed.get("domain_hint") or "")
    if domain:
        mapped = FIELD_DOMAIN_TO_SPHERE.get(domain)
        if mapped:
            _add(mapped)

    instrument_to_sphere = {
        "http_collector": "web",
        "auth_scanner": "web",
        "data_profiler": "data",
        "sysaudit": "host",
        "ssh_sensor": "host",
        "nmap": "host",
        "pcap": "host",
        "container_inspect": "container",
        "supply_chain": "supply_chain",
        "ai_probe": "ai_target",
        "iot_firmware": "iot_firmware",
        "bloodhound": "ad",
    }
    for reason in pearl.reason_changes or []:
        mapped = instrument_to_sphere.get(str(reason.get("instrument") or "").strip())
        if mapped:
            _add(mapped)

    for change in pearl.projection_changes or []:
        for item in list(change.get("added", []) or []) + list(change.get("removed", []) or []):
            mapped = FIELD_DOMAIN_TO_SPHERE.get(str(item or "").strip())
            if mapped:
                _add(mapped)

    refs = [str(ref).lower() for ref in pearl.observation_refs or []]
    for ref in refs:
        if "gravity_http_" in ref or "gravity_auth_" in ref:
            _add("web")
        if "gravity_data_" in ref or "mysql" in ref or "postgresql" in ref:
            _add("data")
        if "gravity_audit_" in ref or "gravity_ssh_" in ref or "gravity_nmap_" in ref or "gravity_pcap_" in ref:
            _add("host")
        if "gravity_iot_" in ref:
            _add("iot_firmware")
        if "gravity_sc_" in ref:
            _add("supply_chain")

    return spheres


@dataclass
class WicketState:
    wicket_id: str
    status: str                    # realized / blocked / unknown
    confidence: float              # scalar compatibility layer
    observed_at: str = ""

    # richer substrate-aware optional fields
    confidence_vector: list[float] = field(default_factory=list)
    explicit_phase: Optional[float] = None
    local_energy: float = 0.0
    decoherence: float = 0.0
    compatibility_score: float = 0.0
    is_latent: bool = False

    @property
    def phase(self) -> float:
        if self.explicit_phase is not None:
            return float(self.explicit_phase)
        return PHASE.get(self.status, math.pi / 2)

    @property
    def amplitude(self) -> float:
        """
        Amplitude derives from richer confidence if available, otherwise scalar confidence.
        """
        if self.confidence_vector:
            return _clamp01(_mean(self.confidence_vector, default=self.confidence))
        return _clamp01(self.confidence)


@dataclass
class SphereEnergy:
    """G(t) for a single domain sphere at a point in time."""
    sphere: str
    G: float                       # raw coherence observable
    G_norm: float                  # normalized [0, 1]
    n_wickets: int
    n_realized: int
    n_blocked: int
    n_unknown: int
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # richer optional observables
    unknown_mass: float = 0.0
    total_local_energy: float = 0.0
    mean_local_energy: float = 0.0
    n_latent: int = 0

    def as_dict(self) -> dict:
        return {
            "sphere":             self.sphere,
            "G":                  round(self.G, 6),
            "G_norm":             round(self.G_norm, 6),
            "n_wickets":          self.n_wickets,
            "n_realized":         self.n_realized,
            "n_blocked":          self.n_blocked,
            "n_unknown":          self.n_unknown,
            "unknown_mass":       round(self.unknown_mass, 6),
            "computed_at":        self.computed_at,
            "total_local_energy": round(self.total_local_energy, 6),
            "mean_local_energy":  round(self.mean_local_energy, 6),
            "n_latent":           self.n_latent,
        }


@dataclass
class SphereField:
    sphere: str
    self_energy: float
    coupling_energy: float
    dissipation: float
    pearl_persistence: float
    fiber_tension: float
    curvature: float
    gravity_pull: float
    protected_state: bool
    protected_reason: str = ""

    def as_dict(self) -> dict:
        return {
            "sphere": self.sphere,
            "self_energy": round(self.self_energy, 6),
            "coupling_energy": round(self.coupling_energy, 6),
            "dissipation": round(self.dissipation, 6),
            "pearl_persistence": round(self.pearl_persistence, 6),
            "fiber_tension": round(self.fiber_tension, 6),
            "curvature": round(self.curvature, 6),
            "gravity_pull": round(self.gravity_pull, 6),
            "protected_state": bool(self.protected_state),
            "protected_reason": self.protected_reason,
        }


@dataclass
class FieldTopology:
    spheres: dict[str, SphereField]
    total_self_energy: float
    total_coupling_energy: float
    total_dissipation: float
    global_curvature: float
    protected_spheres: list[str]
    h1_obstruction_count: int
    beta_1: int
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict:
        return {
            "spheres": {k: v.as_dict() for k, v in self.spheres.items()},
            "total_self_energy": round(self.total_self_energy, 6),
            "total_coupling_energy": round(self.total_coupling_energy, 6),
            "total_dissipation": round(self.total_dissipation, 6),
            "global_curvature": round(self.global_curvature, 6),
            "protected_spheres": list(self.protected_spheres),
            "h1_obstruction_count": int(self.h1_obstruction_count),
            "beta_1": int(self.beta_1),
            "computed_at": self.computed_at,
        }


@dataclass
class Fiber:
    fiber_id: str
    sphere: str
    kind: str
    anchor: str
    members: list[str]
    coherence: float
    tension: float

    def as_dict(self) -> dict:
        return {
            "fiber_id": self.fiber_id,
            "sphere": self.sphere,
            "kind": self.kind,
            "anchor": self.anchor,
            "members": list(self.members),
            "coherence": round(self.coherence, 6),
            "tension": round(self.tension, 6),
        }


@dataclass
class FiberCluster:
    cluster_id: str
    anchor: str
    spheres: list[str]
    kinds: list[str]
    member_count: int
    total_coherence: float
    total_tension: float
    fibers: list[Fiber]

    def as_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "anchor": self.anchor,
            "spheres": list(self.spheres),
            "kinds": list(self.kinds),
            "member_count": int(self.member_count),
            "total_coherence": round(self.total_coherence, 6),
            "total_tension": round(self.total_tension, 6),
            "fibers": [f.as_dict() for f in self.fibers],
        }


def _sphere_for_wicket(wicket_id: str) -> str:
    for sphere, prefixes in SPHERE_MAP.items():
        for prefix in prefixes:
            if wicket_id.startswith(prefix):
                return sphere
    return "unknown"


def _compute_G(states: list[WicketState]) -> float:
    """
    Pairwise coherence observable over a sphere.

    G = Σᵢⱼ Aᵢ Aⱼ cos(φᵢ - φⱼ) / n²

    Notes:
    - This is not yet the full SKG energy functional.
    - It remains useful as a phase/coherence observable for the sphere.
    """
    n = len(states)
    if n == 0:
        return 0.0
    if n == 1:
        return states[0].amplitude ** 2

    total = 0.0
    for si in states:
        for sj in states:
            total += si.amplitude * sj.amplitude * math.cos(si.phase - sj.phase)

    return total / (n * n)


def compute_sphere_energy(states: list[WicketState], sphere: str) -> SphereEnergy:
    """Compute G(t) for a single sphere given a list of wicket states."""
    if not states:
        return SphereEnergy(
            sphere=sphere,
            G=0.0,
            G_norm=0.0,
            n_wickets=0,
            n_realized=0,
            n_blocked=0,
            n_unknown=0,
            unknown_mass=0.0,
            total_local_energy=0.0,
            mean_local_energy=0.0,
            n_latent=0,
        )

    G = _compute_G(states)

    # Normalize against maximum coherent amplitude for this sphere snapshot.
    G_max = sum(s.amplitude ** 2 for s in states) / len(states)
    G_norm = min(G / G_max, 1.0) if G_max > 0 else 0.0

    counts = {"realized": 0, "blocked": 0, "unknown": 0}
    for s in states:
        counts[s.status] = counts.get(s.status, 0) + 1

    # Unknown is not a flat count. It is unresolved field mass:
    # orthogonal phase support that has not collapsed, plus its retained local energy.
    unknown_states = [s for s in states if s.status == "unknown"]
    unknown_mass = sum(
        float(s.amplitude)
        + (0.5 * float(getattr(s, "local_energy", 0.0) or 0.0))
        + (0.5 * float(getattr(s, "decoherence", 0.0) or 0.0))
        + (0.25 * max(0.0, 1.0 - float(getattr(s, "compatibility_score", 0.0) or 0.0)))
        for s in unknown_states
    )

    total_local_energy = sum(float(getattr(s, "local_energy", 0.0) or 0.0) for s in states)
    n_latent = sum(1 for s in states if bool(getattr(s, "is_latent", False)))
    mean_local_energy = (total_local_energy / len(states)) if states else 0.0

    return SphereEnergy(
        sphere=sphere,
        G=G,
        G_norm=G_norm,
        n_wickets=len(states),
        n_realized=counts["realized"],
        n_blocked=counts["blocked"],
        n_unknown=counts["unknown"],
        unknown_mass=unknown_mass,
        total_local_energy=total_local_energy,
        mean_local_energy=mean_local_energy,
        n_latent=n_latent,
    )


def _wicket_id_from_payload(payload: dict) -> str:
    """
    Backward-compatible id extraction:
    topology historically used wicket_id, but the substrate now also uses node_id.
    """
    return payload.get("wicket_id") or payload.get("node_id", "")


def load_states_from_events(events_file: Path) -> dict[str, list[WicketState]]:
    """
    Load wicket/node states from an events NDJSON file.
    Returns dict keyed by sphere name.
    Latest state per id wins by observed_at timestamp.
    """
    latest: dict[str, WicketState] = {}

    for line in events_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue

        if ev.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
            continue

        payload = ev.get("payload", {})
        prov = ev.get("provenance", {})
        evidence = prov.get("evidence", {})

        wid = _wicket_id_from_payload(payload)
        if not wid:
            continue

        status = payload.get("status", "unknown")
        observed_at = payload.get("observed_at") or ev.get("ts", "")

        existing = latest.get(wid)
        if existing and observed_at and existing.observed_at and observed_at <= existing.observed_at:
            continue

        confidence = evidence.get("confidence", 0.5)
        confidence_vector = evidence.get("confidence_vector", []) or []
        explicit_phase = evidence.get("phase", None)
        local_energy = evidence.get("local_energy", 0.0)
        decoherence = evidence.get("decoherence", payload.get("decoherence", 0.0))
        compatibility_score = evidence.get("compatibility_score", payload.get("compatibility_score", 0.0))
        is_latent = payload.get("is_latent", False)

        try:
            confidence = float(confidence)
        except Exception:
            confidence = 0.5

        try:
            confidence_vector = [float(x) for x in confidence_vector]
        except Exception:
            confidence_vector = []

        try:
            explicit_phase = float(explicit_phase) if explicit_phase is not None else None
        except Exception:
            explicit_phase = None

        try:
            local_energy = float(local_energy or 0.0)
        except Exception:
            local_energy = 0.0
        try:
            decoherence = float(decoherence or 0.0)
        except Exception:
            decoherence = 0.0
        try:
            compatibility_score = float(compatibility_score or 0.0)
        except Exception:
            compatibility_score = 0.0

        latest[wid] = WicketState(
            wicket_id=wid,
            status=status,
            confidence=confidence,
            observed_at=observed_at,
            confidence_vector=confidence_vector,
            explicit_phase=explicit_phase,
            local_energy=local_energy,
            decoherence=decoherence,
            compatibility_score=compatibility_score,
            is_latent=bool(is_latent),
        )

    by_sphere: dict[str, list[WicketState]] = {}
    for ws in latest.values():
        sphere = _sphere_for_wicket(ws.wicket_id)
        by_sphere.setdefault(sphere, []).append(ws)

    return by_sphere


def compute_field_energy(events_file: Path) -> dict[str, SphereEnergy]:
    """
    Compute G(t) for all domain spheres from a single events file.
    Returns dict keyed by sphere name.
    """
    by_sphere = load_states_from_events(events_file)
    result: dict[str, SphereEnergy] = {}

    for sphere, states in by_sphere.items():
        result[sphere] = compute_sphere_energy(states, sphere)
        log.debug(
            f"G({sphere}) = {result[sphere].G_norm:.4f} "
            f"[{result[sphere].n_realized}R/{result[sphere].n_blocked}B/{result[sphere].n_unknown}U] "
            f"Ē={result[sphere].mean_local_energy:.4f} latent={result[sphere].n_latent}"
        )

    return result


def compute_field_energy_from_dir(events_dir: Path,
                                  latest_only: bool = True) -> dict[str, SphereEnergy]:
    """
    Compute G(t) across all events files in a directory.
    If latest_only=True, uses only the most recent file.
    Merges states across files — latest observation per wicket/node wins.
    """
    files = sorted(events_dir.glob("*.ndjson"))
    if not files:
        return {}

    if latest_only:
        files = [files[-1]]

    merged: dict[str, WicketState] = {}
    for f in files:
        by_sphere = load_states_from_events(f)
        for states in by_sphere.values():
            for ws in states:
                existing = merged.get(ws.wicket_id)
                if not existing or ws.observed_at > existing.observed_at:
                    merged[ws.wicket_id] = ws

    by_sphere: dict[str, list[WicketState]] = {}
    for ws in merged.values():
        sphere = _sphere_for_wicket(ws.wicket_id)
        by_sphere.setdefault(sphere, []).append(ws)

    return {
        sphere: compute_sphere_energy(states, sphere)
        for sphere, states in by_sphere.items()
    }


def compute_energy_timeseries(events_dir: Path,
                              sphere: str = "host") -> list[dict]:
    """
    Compute G(t) for a single sphere across all historical event files.
    Returns list of snapshots sorted chronologically.
    """
    files = sorted(events_dir.glob("*.ndjson"))
    series = []

    for f in files:
        by_sphere = load_states_from_events(f)
        states = by_sphere.get(sphere, [])
        if not states:
            continue

        e = compute_sphere_energy(states, sphere)

        ts_raw = f.stem.split("_")[0]
        try:
            ts = datetime.strptime(ts_raw, "%Y%m%dT%H%M%S").replace(
                tzinfo=timezone.utc
            ).isoformat()
        except ValueError:
            ts = e.computed_at

        series.append({
            "ts":                 ts,
            "file":               f.name,
            "G":                  round(e.G, 6),
            "G_norm":             round(e.G_norm, 6),
            "n_realized":         e.n_realized,
            "n_blocked":          e.n_blocked,
            "n_unknown":          e.n_unknown,
            "unknown_mass":       round(e.unknown_mass, 6),
            "n_wickets":          e.n_wickets,
            "total_local_energy": round(e.total_local_energy, 6),
            "mean_local_energy":  round(e.mean_local_energy, 6),
            "n_latent":           e.n_latent,
        })

    return series


# Default confidence by status when no evidence confidence is available
DEFAULT_CONFIDENCE = {"realized": 0.90, "blocked": 0.75, "unknown": 0.40}


def load_states_from_interp(interp_file: Path) -> dict[str, list[WicketState]]:
    """
    Load wicket states from an interp NDJSON file (projection summary format).
    Uses default confidence values since interp files do not carry per-wicket confidence.
    """
    latest: dict[str, WicketState] = {}

    for line in interp_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue

        payload = d.get("payload", {})
        latest_status = payload.get("latest_status", {})
        observed_at = d.get("ts", "")

        for wid, status in latest_status.items():
            confidence = DEFAULT_CONFIDENCE.get(status, 0.40)
            latest[wid] = WicketState(
                wicket_id=wid,
                status=status,
                confidence=confidence,
                observed_at=observed_at,
                decoherence=0.0,
                compatibility_score=0.0,
            )

    by_sphere: dict[str, list[WicketState]] = {}
    for ws in latest.values():
        sphere = _sphere_for_wicket(ws.wicket_id)
        by_sphere.setdefault(sphere, []).append(ws)

    return by_sphere


def _world_states_from_surface(surface_path: Path) -> dict[str, list[WicketState]]:
    """
    Build supplementary field states from the richer world/surface layer.
    These are not wicket collapses; they are direct observed-world contributions
    that let the field representation see domains and services before or beyond
    path projection.
    """
    try:
        data = json.loads(surface_path.read_text())
    except Exception:
        return {}

    by_sphere: dict[str, list[WicketState]] = {}
    seen: set[str] = set()
    targets = data.get("targets", []) or []

    def _add(sphere: str, obs_id: str, confidence: float = 0.85, local_energy: float = 0.1) -> None:
        if obs_id in seen:
            return
        seen.add(obs_id)
        by_sphere.setdefault(sphere, []).append(
            WicketState(
                wicket_id=obs_id,
                status="realized",
                confidence=confidence,
                observed_at="",
                local_energy=local_energy,
                decoherence=0.0,
                compatibility_score=1.0,
                is_latent=False,
            )
        )

    for target in targets:
        host = str(target.get("ip") or target.get("host") or target.get("hostname") or "")
        if not host:
            continue

        for domain in target.get("domains", []) or []:
            if domain == "host":
                _add("host", f"world::{host}::domain::host", 0.8, 0.05)
            elif domain == "web":
                _add("web", f"world::{host}::domain::web", 0.8, 0.05)
            elif domain == "data":
                _add("data", f"world::{host}::domain::data", 0.8, 0.05)
            elif domain == "container_escape":
                _add("container", f"world::{host}::domain::container", 0.8, 0.05)
            elif domain == "ai_target":
                _add("ai_target", f"world::{host}::domain::ai", 0.85, 0.05)
            elif domain == "supply_chain":
                _add("supply_chain", f"world::{host}::domain::supply_chain", 0.75, 0.05)
            elif domain == "iot_firmware":
                _add("iot_firmware", f"world::{host}::domain::iot", 0.75, 0.05)
            elif domain == "ad_lateral":
                _add("ad", f"world::{host}::domain::ad", 0.75, 0.05)

        for svc in target.get("services", []) or []:
            service = str(svc.get("service") or svc.get("name") or "").lower()
            banner = str(svc.get("banner") or "").lower()
            port = str(svc.get("port") or "")
            obs_base = f"world::{host}::service::{service or 'unknown'}::{port or 'na'}"

            if service in {"http", "https", "ajp13", "ajp"} or port in {"80", "443", "8000", "8080", "8009", "8443"} or "http" in banner:
                _add("web", obs_base, 0.9, 0.1)
            if service in {"mysql", "postgresql", "postgres", "mssql", "redis", "mongodb"}:
                _add("data", obs_base, 0.9, 0.1)
            if service in {"ssh", "ftp", "telnet", "smb", "netbios-ssn", "vnc"}:
                _add("host", obs_base, 0.85, 0.1)
            if service in {"ollama"} or "ollama" in banner:
                _add("ai_target", obs_base, 0.95, 0.1)

    return by_sphere


def _world_states_from_snapshot(world: dict) -> dict[str, list[WicketState]]:
    """
    Convert a canonical world snapshot into field observations.
    This supplements path-derived states with observed world structure:
    credentials, datastores, runtime/process findings, relations, and access paths.
    """
    by_sphere: dict[str, list[WicketState]] = {}
    seen: set[str] = set()
    identity_key = str(world.get("identity_key") or "")

    def _add(sphere: str, obs_id: str, confidence: float = 0.8, local_energy: float = 0.1) -> None:
        if not sphere or obs_id in seen:
            return
        seen.add(obs_id)
        by_sphere.setdefault(sphere, []).append(
            WicketState(
                wicket_id=obs_id,
                status="realized",
                confidence=confidence,
                observed_at="",
                local_energy=local_energy,
                decoherence=0.0,
                compatibility_score=1.0,
                is_latent=False,
            )
        )

    def _sphere_for_service(service: str) -> str:
        service = str(service or "").lower()
        if service in {"http", "https", "ajp13", "ajp"}:
            return "web"
        if service in {"mysql", "postgresql", "postgres", "mssql", "redis", "mongodb"}:
            return "data"
        if service in {"ollama"}:
            return "ai_target"
        if service in {"ssh", "ftp", "telnet", "smb", "netbios-ssn", "vnc", "rdp"}:
            return "host"
        return "host"

    for binding in world.get("credentials", {}).get("bindings", []) or []:
        service = str(binding.get("service") or "")
        creds = list(binding.get("credentials") or [])
        if creds:
            _add(_sphere_for_service(service), f"world::{identity_key}::cred::{service}", 0.85, 0.12)

    for row in world.get("datastore_access", []) or []:
        _add("data", f"world::{identity_key}::datastore_access::{str(row)[:48]}", 0.9, 0.15)
    for row in world.get("datastore_observations", []) or []:
        service = str(row.get("service") or "data")
        workload_id = str(row.get("workload_id") or service)
        _add(_sphere_for_service(service), f"world::{identity_key}::datastore_obs::{workload_id}", 0.9, 0.12)

    runtime = world.get("runtime", {}) or {}
    if runtime.get("process_count"):
        _add("host", f"world::{identity_key}::runtime::processes", 0.75, 0.1)
    for finding in runtime.get("process_findings", []) or []:
        wid = str(finding.get("wicket_id") or "process")
        _add("host", f"world::{identity_key}::runtime::{wid}", 0.8, 0.12)
    if runtime.get("container"):
        _add("container", f"world::{identity_key}::runtime::container", 0.8, 0.1)
    if runtime.get("docker_access"):
        _add("container", f"world::{identity_key}::runtime::docker_access", 0.85, 0.15)

    for relation in world.get("relations", []) or []:
        relation_name = str(relation.get("relation") or "relation")
        other = str(relation.get("other_identity") or "")
        strength = float(relation.get("strength") or 0.5)
        _add("host", f"world::{identity_key}::relation::{relation_name}::{other}", max(0.6, min(0.95, strength)), 0.1)

    for row in world.get("access_paths", []) or []:
        kind = str(row.get("kind") or "")
        service = str(row.get("service") or "")
        sphere = _sphere_for_service(service)
        if kind == "runtime_control":
            sphere = "container"
        _add(sphere, f"world::{identity_key}::access::{kind}::{service or 'runtime'}::{row.get('port') or 'na'}", 0.85, 0.1)

    return by_sphere


def _world_states_from_runtime() -> dict[str, list[WicketState]]:
    """
    Load supplementary field states from the canonical daemon world snapshot.
    This keeps topology aligned with the runtime's world formation instead of
    inventing a parallel model.
    """
    try:
        from skg.core import daemon as daemon_mod
        all_targets_index = getattr(daemon_mod, "_all_targets_index", None)
        identity_world = getattr(daemon_mod, "_identity_world", None)
        if not callable(all_targets_index) or not callable(identity_world):
            return {}
        by_sphere: dict[str, list[WicketState]] = {}
        for target in all_targets_index():
            identity_key = str(target.get("ip") or target.get("host") or target.get("workload_id") or "")
            if not identity_key:
                continue
            world = identity_world(identity_key, target)
            snapshot_states = _world_states_from_snapshot(world)
            for sphere, states in snapshot_states.items():
                by_sphere.setdefault(sphere, []).extend(states)
        return by_sphere
    except Exception:
        return {}


def _pearl_states_from_ledger(pearls_path: Path | None = None) -> dict[str, list[WicketState]]:
    pearls_path = pearls_path or _default_pearls_path()
    if not pearls_path.exists():
        return {}

    by_sphere: dict[str, list[WicketState]] = {}
    aggregates: dict[tuple[str, str], dict[str, float | set[str] | str]] = {}
    try:
        ledger = PearlLedger(pearls_path)
    except Exception:
        return {}

    for pearl in ledger.all():
        identity_key = _pearl_identity_key(pearl)
        if not identity_key:
            continue
        spheres = _pearl_spheres(pearl)
        if not spheres:
            continue

        refs = list(pearl.observation_refs or [])
        reasons = list(pearl.reason_changes or [])
        projections = list(pearl.projection_changes or [])
        state_changes = list(pearl.state_changes or [])
        fold_context = list(pearl.fold_context or [])
        decay_class = str((pearl.energy_snapshot or {}).get("decay_class") or "").strip().lower()

        for sphere in spheres:
            key = (identity_key, sphere)
            row = aggregates.setdefault(key, {
                "refs": 0.0,
                "reasons": 0.0,
                "projections": 0.0,
                "states": 0.0,
                "folds": 0.0,
                "structural": 0.0,
                "ts": "",
            })
            row["refs"] = float(row["refs"]) + len(refs)
            row["reasons"] = float(row["reasons"]) + len(reasons)
            row["projections"] = float(row["projections"]) + len(projections)
            row["states"] = float(row["states"]) + len(state_changes)
            row["folds"] = float(row["folds"]) + len(fold_context)
            row["structural"] = float(row["structural"]) + (1.0 if decay_class in {"structural", "temporal"} else 0.0)
            row["ts"] = max(str(row["ts"] or ""), pearl.timestamp.isoformat())

    for (identity_key, sphere), row in aggregates.items():
        refs = float(row["refs"])
        reasons = float(row["reasons"])
        projections = float(row["projections"])
        states = float(row["states"])
        folds = float(row["folds"])
        structural = float(row["structural"])
        local_energy = min(
            0.85,
            0.06 * math.log1p(refs)
            + 0.05 * math.log1p(reasons)
            + 0.04 * math.log1p(projections)
            + 0.05 * math.log1p(states)
            + 0.05 * math.log1p(folds),
        )
        confidence = min(0.97, 0.72 + 0.05 * math.log1p(refs) + 0.03 * math.log1p(reasons))
        decoherence = min(0.22, 0.04 + 0.03 * math.log1p(structural))
        by_sphere.setdefault(sphere, []).append(
            WicketState(
                wicket_id=f"pearl::{identity_key}::{sphere}",
                status="realized",
                confidence=confidence,
                observed_at=str(row["ts"] or ""),
                local_energy=local_energy,
                decoherence=decoherence,
                compatibility_score=0.92,
                is_latent=False,
            )
        )

    return by_sphere


def _world_snapshot_fibers(world: dict) -> list[Fiber]:
    identity_key = str(world.get("identity_key") or "")
    if not identity_key:
        return []

    fibers: list[Fiber] = []

    def _add(kind: str, sphere: str, anchor: str, members: list[str], coherence: float, tension: float) -> None:
        members = [m for m in members if m]
        if not members:
            return
        fibers.append(
            Fiber(
                fiber_id=f"{identity_key}::{kind}::{anchor}",
                sphere=sphere,
                kind=kind,
                anchor=anchor,
                members=members,
                coherence=max(0.0, min(1.0, float(coherence))),
                tension=max(0.0, float(tension)),
            )
        )

    for binding in world.get("credentials", {}).get("bindings", []) or []:
        service = str(binding.get("service") or "")
        creds = [str(c) for c in binding.get("credentials", []) or []]
        if service and creds:
            sphere = "host" if service in {"ssh", "ftp", "telnet", "smb", "netbios-ssn", "vnc", "rdp"} else "data"
            _add("credential_binding", sphere, service, creds, 0.82, 0.12)

    for row in world.get("access_paths", []) or []:
        kind = str(row.get("kind") or "")
        service = str(row.get("service") or row.get("port") or kind)
        members = []
        for key in ("credential_candidates", "confirmed_access", "network_constraints"):
            members.extend([str(v) for v in row.get(key, []) or []])
        sphere = "container" if kind == "runtime_control" else ("data" if kind == "datastore" else "host")
        if service:
            _add("access_path", sphere, service, members or [kind], 0.78, 0.18 if row.get("network_constraints") else 0.08)

    for row in world.get("datastore_observations", []) or []:
        service = str(row.get("service") or "data")
        wid = str(row.get("workload_id") or service)
        detail = str(row.get("detail") or "")
        _add("datastore", "data", service, [wid, detail], 0.88, 0.1)

    runtime = world.get("runtime", {}) or {}
    process_members = [str(item.get("wicket_id") or "") for item in runtime.get("process_findings", []) or []]
    if process_members:
        _add("runtime_process", "host", "process", process_members, 0.76, 0.16)
    if runtime.get("container"):
        _add("container_runtime", "container", "container", [json.dumps(runtime.get("container") or {}, sort_keys=True)], 0.8, 0.1)

    for relation_row in world.get("relations", []) or []:
        relation_name = str(relation_row.get("relation") or "relation")
        other = str(relation_row.get("other_identity") or "")
        strength = float(relation_row.get("strength") or 0.5)
        _add("relation", "host", relation_name, [other], max(0.6, strength), 1.0 - max(0.6, strength))

    return fibers


def _pearl_fibers_from_ledger(pearls_path: Path | None = None) -> list[Fiber]:
    pearls_path = pearls_path or _default_pearls_path()
    if not pearls_path.exists():
        return []

    try:
        ledger = PearlLedger(pearls_path)
    except Exception:
        return []

    aggregates: dict[tuple[str, str], dict[str, object]] = {}
    for pearl in ledger.all():
        identity_key = _pearl_identity_key(pearl)
        if not identity_key:
            continue
        spheres = _pearl_spheres(pearl)
        if not spheres:
            continue

        members: list[str] = []
        members.extend(Path(ref).name for ref in (pearl.observation_refs or []) if ref)
        members.extend(str(r.get("instrument") or "") for r in (pearl.reason_changes or []) if r.get("instrument"))
        members.extend(str(c.get("wicket_id") or c.get("node_id") or "") for c in (pearl.state_changes or []) if (c.get("wicket_id") or c.get("node_id")))
        members.extend(str(item) for change in (pearl.projection_changes or []) for item in (change.get("added", []) or []))
        members = [m for m in members if m]
        if not members:
            members = [f"pearl::{pearl.id}"]

        for sphere in spheres:
            key = (identity_key, sphere)
            row = aggregates.setdefault(key, {
                "members": set(),
                "projection_count": 0.0,
                "fold_count": 0.0,
                "state_count": 0.0,
            })
            row["members"].update(members)
            row["projection_count"] = float(row["projection_count"]) + len(pearl.projection_changes or [])
            row["fold_count"] = float(row["fold_count"]) + len(pearl.fold_context or [])
            row["state_count"] = float(row["state_count"]) + len(pearl.state_changes or [])

    fibers: list[Fiber] = []
    for (identity_key, sphere), row in aggregates.items():
        members = sorted(set(str(m) for m in row["members"] if m))
        coherence = min(0.98, 0.56 + 0.06 * math.log1p(len(members)) + 0.03 * math.log1p(float(row["projection_count"])))
        tension = min(0.65, 0.06 + 0.05 * math.log1p(float(row["fold_count"])) + 0.04 * math.log1p(float(row["state_count"])))
        fibers.append(
            Fiber(
                fiber_id=f"pearl::{identity_key}::{sphere}",
                sphere=sphere,
                kind="pearl_memory",
                anchor=identity_key,
                members=members or [f"pearl::{identity_key}::{sphere}"],
                coherence=coherence,
                tension=tension,
            )
        )

    return fibers


def compute_field_fibers() -> list[FiberCluster]:
    """
    Build overlapping field fibers from canonical world snapshots.
    Fibers are preserved strands of structure anchored in one identity but
    participating across multiple domains and relation types.
    """
    try:
        from skg.core import daemon as daemon_mod
    except Exception:
        return []
    all_targets_index = getattr(daemon_mod, "_all_targets_index", None)
    identity_world = getattr(daemon_mod, "_identity_world", None)
    if not callable(all_targets_index) or not callable(identity_world):
        return []

    fibers_by_anchor: dict[str, list[Fiber]] = {}
    for target in all_targets_index():
        identity_key = str(target.get("ip") or target.get("host") or target.get("workload_id") or "")
        if not identity_key:
            continue
        world = identity_world(identity_key, target)
        fibers = _world_snapshot_fibers(world)
        if not fibers:
            continue
        fibers_by_anchor.setdefault(identity_key, []).extend(fibers)

    for fiber in _pearl_fibers_from_ledger():
        fibers_by_anchor.setdefault(fiber.anchor, []).append(fiber)

    clusters: list[FiberCluster] = []
    for identity_key, fibers in fibers_by_anchor.items():
        if not fibers:
            continue
        clusters.append(
            FiberCluster(
                cluster_id=f"cluster::{identity_key}",
                anchor=identity_key,
                spheres=sorted({f.sphere for f in fibers}),
                kinds=sorted({f.kind for f in fibers}),
                member_count=sum(len(f.members) for f in fibers),
                total_coherence=sum(f.coherence for f in fibers),
                total_tension=sum(f.tension for f in fibers),
                fibers=fibers,
            )
        )
    return clusters


def fiber_coupling_matrix(clusters: list[FiberCluster]) -> dict[str, dict[str, float]]:
    """
    Derive inter-sphere coupling from overlapping fiber structure.

    This supplements manifold edge coupling with preserved world strands.
    Two spheres couple when fibers in the same cluster share members or form
    a coherent mixed bundle under one anchor identity.
    """
    totals: dict[str, dict[str, float]] = {}
    counts: dict[str, dict[str, int]] = {}

    def _acc(sa: str, sb: str, value: float) -> None:
        if sa == sb:
            return
        totals.setdefault(sa, {}).setdefault(sb, 0.0)
        counts.setdefault(sa, {}).setdefault(sb, 0)
        totals[sa][sb] += float(value)
        counts[sa][sb] += 1

    for cluster in clusters:
        fibers = list(cluster.fibers or [])
        for i, a in enumerate(fibers):
            members_a = set(a.members or [])
            for b in fibers[i + 1:]:
                if a.sphere == b.sphere:
                    continue
                members_b = set(b.members or [])
                overlap = len(members_a & members_b)
                union = len(members_a | members_b) or 1
                overlap_score = overlap / union
                bundle_score = 0.15 if a.anchor == b.anchor else 0.0
                coherence_score = (float(a.coherence) + float(b.coherence)) / 2.0
                tension_penalty = min(0.5, (float(a.tension) + float(b.tension)) / 4.0)
                weight = max(0.0, min(1.0, overlap_score + bundle_score + coherence_score * 0.35 - tension_penalty))
                if weight <= 0.0:
                    continue
                _acc(a.sphere, b.sphere, weight)
                _acc(b.sphere, a.sphere, weight)

    result: dict[str, dict[str, float]] = {}
    for sa, row in totals.items():
        result[sa] = {}
        for sb, total in row.items():
            result[sa][sb] = round(total / max(1, counts[sa][sb]), 4)
    return result


def merge_coupling_matrices(*matrices: dict[str, dict[str, float]]) -> dict[str, dict[str, float]]:
    """
    Merge coupling sources into one bounded matrix.
    Later matrices supplement earlier ones; coupling is additive but clipped.
    """
    merged: dict[str, dict[str, float]] = {}
    for matrix in matrices:
        for sa, row in (matrix or {}).items():
            merged.setdefault(sa, {})
            for sb, value in row.items():
                merged[sa][sb] = round(min(1.0, float(merged[sa].get(sb, 0.0)) + float(value)), 4)
    return merged


def fiber_tension_by_sphere(clusters: list[FiberCluster]) -> dict[str, float]:
    """
    Aggregate fiber tension per sphere and normalize it into a bounded field term.

    We preserve all contributing strands, but compress raw accumulation so a
    dense sphere does not dominate purely by count. The field should respond to
    sustained tension, not explode with strand multiplicity.
    """
    tension: dict[str, float] = {}
    for cluster in clusters:
        for fiber in cluster.fibers:
            tension[fiber.sphere] = tension.get(fiber.sphere, 0.0) + float(fiber.tension or 0.0)
    return {sphere: round(math.log1p(value), 6) for sphere, value in tension.items()}


def pearl_persistence_by_sphere(clusters: list[FiberCluster]) -> dict[str, float]:
    """
    Aggregate pearl-memory fibers into a bounded persistence term.
    This captures preserved transformed structure across time as its own
    contribution, separate from ordinary strand tension.
    """
    persistence: dict[str, float] = {}
    for cluster in clusters:
        for fiber in cluster.fibers:
            if fiber.kind != "pearl_memory":
                continue
            contribution = (0.6 * float(fiber.coherence or 0.0)) + (0.4 * float(fiber.tension or 0.0))
            persistence[fiber.sphere] = persistence.get(fiber.sphere, 0.0) + contribution
    return {sphere: round(min(2.5, math.log1p(value)), 6) for sphere, value in persistence.items()}


def compute_field_energy_all(events_dir: Path,
                             interp_dir: Path) -> dict[str, SphereEnergy]:
    """
    Compute G(t) for all spheres from both events and interp directories.
    Events files take precedence — interp fills in spheres not covered by events.
    """
    merged: dict[str, WicketState] = {}

    for f in sorted(events_dir.glob("*.ndjson"))[-5:]:
        by_sphere = load_states_from_events(f)
        for states in by_sphere.values():
            for ws in states:
                existing = merged.get(ws.wicket_id)
                if not existing or ws.observed_at > existing.observed_at:
                    merged[ws.wicket_id] = ws

    covered = {_sphere_for_wicket(w) for w in merged}
    for f in sorted(interp_dir.glob("*_interp.ndjson"))[-10:]:
        by_sphere = load_states_from_interp(f)
        for sphere, states in by_sphere.items():
            if sphere not in covered:
                for ws in states:
                    existing = merged.get(ws.wicket_id)
                    if not existing or ws.observed_at > existing.observed_at:
                        merged[ws.wicket_id] = ws

    by_sphere: dict[str, list[WicketState]] = {}
    for ws in merged.values():
        sphere = _sphere_for_wicket(ws.wicket_id)
        by_sphere.setdefault(sphere, []).append(ws)

    surface_path = _select_surface_path()
    if surface_path:
        world_states = _world_states_from_surface(Path(surface_path))
        for sphere, states in world_states.items():
            by_sphere.setdefault(sphere, []).extend(states)
    runtime_world_states = _world_states_from_runtime()
    for sphere, states in runtime_world_states.items():
        by_sphere.setdefault(sphere, []).extend(states)
    pearl_states = _pearl_states_from_ledger()
    for sphere, states in pearl_states.items():
        by_sphere.setdefault(sphere, []).extend(states)

    return {
        sphere: compute_sphere_energy(states, sphere)
        for sphere, states in by_sphere.items()
    }


def decompose_field_topology(
    sphere_energies: dict[str, SphereEnergy],
    coupling: dict[str, dict[str, float]],
    fiber_tension: dict[str, float],
    pearl_persistence: dict[str, float],
    beta_1: int,
    h1_obstruction_count: int,
) -> FieldTopology:
    """
    Decompose the current field into self-energy, coupling energy, dissipation,
    and curvature terms.

    This is a pragmatic SKG field decomposition:
    - self_energy: local unresolved mass and local energy retained in a sphere
    - coupling_energy: cross-sphere influence via the simplicial coupling matrix
    - dissipation: incoherence/latency within the sphere
    - curvature: local instability concentration from unresolved mass and H¹ load
    """
    spheres: dict[str, SphereField] = {}
    protected: list[str] = []
    total_self = 0.0
    total_coupling = 0.0
    total_dissipation = 0.0

    for sphere, energy in sphere_energies.items():
        measured_unresolved = float(energy.unknown_mass)
        count_floor = 1.0 if energy.n_unknown > 0 and measured_unresolved <= 0.0 else 0.0
        unresolved_mass = measured_unresolved + count_floor
        latent_mass = float(energy.n_latent) * 0.5
        local_mass = float(energy.total_local_energy)
        self_energy = unresolved_mass + latent_mass + local_mass

        neighbors = coupling.get(sphere, {}) or {}
        coupling_energy = 0.0
        for other, weight in neighbors.items():
            other_e = sphere_energies.get(other)
            if not other_e:
                continue
            other_measured_unresolved = float(other_e.unknown_mass)
            other_count_floor = 1.0 if other_e.n_unknown > 0 and other_measured_unresolved <= 0.0 else 0.0
            other_unresolved_mass = other_measured_unresolved + other_count_floor
            coupling_energy += float(weight or 0.0) * (
                float(other_e.total_local_energy) + other_unresolved_mass
            )

        dissipation = (1.0 - float(energy.G_norm)) * max(1.0, unresolved_mass)
        dissipation += float(energy.n_latent) * 0.25

        local_fiber_tension = float(fiber_tension.get(sphere, 0.0) or 0.0)
        local_pearl_persistence = float(pearl_persistence.get(sphere, 0.0) or 0.0)
        curvature = unresolved_mass + float(energy.mean_local_energy)
        curvature += 0.35 * float(len(neighbors))
        curvature += 0.5 * local_fiber_tension
        curvature += 0.4 * local_pearl_persistence
        curvature += 0.5 * float(beta_1 > 0)

        gravity_pull = (
            self_energy
            + coupling_energy
            + dissipation
            + curvature
            + local_fiber_tension
            + 0.5 * local_pearl_persistence
        )

        protected_state = bool(
            (
                energy.G_norm >= 0.72
                and unresolved_mass <= 1.25
                and energy.n_latent == 0
                and dissipation <= 0.5
            )
            or (
                energy.G_norm >= 0.64
                and local_pearl_persistence >= 0.7
                and dissipation <= 0.9
            )
        )
        protected_reason = ""
        if protected_state:
            protected_reason = (
                "persistent preserved structure stabilizes the sphere under current coupling"
                if local_pearl_persistence >= 0.7
                else "high coherence with low dissipation under current coupling"
            )
            protected.append(sphere)

        spheres[sphere] = SphereField(
            sphere=sphere,
            self_energy=self_energy,
            coupling_energy=coupling_energy,
            dissipation=dissipation,
            pearl_persistence=local_pearl_persistence,
            fiber_tension=local_fiber_tension,
            curvature=curvature,
            gravity_pull=gravity_pull,
            protected_state=protected_state,
            protected_reason=protected_reason,
        )
        total_self += self_energy
        total_coupling += coupling_energy
        total_dissipation += dissipation

    global_curvature = float(beta_1) + float(h1_obstruction_count)
    if spheres:
        global_curvature += sum(s.curvature for s in spheres.values()) / len(spheres)

    return FieldTopology(
        spheres=spheres,
        total_self_energy=total_self,
        total_coupling_energy=total_coupling,
        total_dissipation=total_dissipation,
        global_curvature=global_curvature,
        protected_spheres=protected,
        h1_obstruction_count=h1_obstruction_count,
        beta_1=beta_1,
    )


def compute_field_topology(events_dir: Path, interp_dir: Path) -> FieldTopology:
    """
    Compute the current field decomposition from sphere energies and the
    simplicial coupling manifold.
    """
    from skg.topology.manifold import (
        build_full_complex,
        sphere_coupling_matrix,
        find_h1_obstructions,
    )

    sphere_energies = compute_field_energy_all(events_dir, interp_dir)
    sc = build_full_complex(events_dir)
    fibers = compute_field_fibers()
    manifold_coupling = sphere_coupling_matrix(sc)
    fiber_coupling = fiber_coupling_matrix(fibers)
    fiber_tension = fiber_tension_by_sphere(fibers)
    pearl_persistence = pearl_persistence_by_sphere(fibers)
    coupling = merge_coupling_matrices(manifold_coupling, fiber_coupling)
    obstructions = find_h1_obstructions(sc)
    beta_1 = int(sc.betti_1())
    return decompose_field_topology(
        sphere_energies=sphere_energies,
        coupling=coupling,
        fiber_tension=fiber_tension,
        pearl_persistence=pearl_persistence,
        beta_1=beta_1,
        h1_obstruction_count=len(obstructions),
    )

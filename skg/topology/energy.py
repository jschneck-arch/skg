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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("skg.topology.energy")

# Phase encoding — tri-state as angle on the unit circle
PHASE = {
    "realized": 0.0,
    "blocked":  math.pi,
    "unknown":  math.pi / 2,
}

# Domain sphere membership — which prefixes belong to which sphere
SPHERE_MAP = {
    "host":      ["HO-"],
    "container": ["CE-"],
    "ad":        ["AD-"],
    "network":   ["NE-"],
    "web":       ["WE-"],
    "aprs":      ["AP-"],
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
            "computed_at":        self.computed_at,
            "total_local_energy": round(self.total_local_energy, 6),
            "mean_local_energy":  round(self.mean_local_energy, 6),
            "n_latent":           self.n_latent,
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

        latest[wid] = WicketState(
            wicket_id=wid,
            status=status,
            confidence=confidence,
            observed_at=observed_at,
            confidence_vector=confidence_vector,
            explicit_phase=explicit_phase,
            local_energy=local_energy,
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
            )

    by_sphere: dict[str, list[WicketState]] = {}
    for ws in latest.values():
        sphere = _sphere_for_wicket(ws.wicket_id)
        by_sphere.setdefault(sphere, []).append(ws)

    return by_sphere


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

    return {
        sphere: compute_sphere_energy(states, sphere)
        for sphere, states in by_sphere.items()
    }

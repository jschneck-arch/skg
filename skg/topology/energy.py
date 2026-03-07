"""
skg.topology.energy
===================
Computes G(t) — the information field energy — per domain sphere.

G(sphere) = Σᵢⱼ Aᵢ Aⱼ cos(φᵢ - φⱼ)

Where:
  A = confidence (amplitude)
  φ = tri-state encoded as phase angle:
        realized → 0.0        (fully coherent, in phase)
        blocked  → π          (anti-phase, possibility eliminated)
        unknown  → π/2        (orthogonal, maximum uncertainty)

G(t) decreasing under defensive controls = energy draining from attack surface.
G(t) increasing after new realizations = attack surface becoming coherent.

This is the experimental observable the final paper needs.
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

# Domain sphere membership — which wicket prefixes belong to which sphere
SPHERE_MAP = {
    "host":      ["HO-"],
    "container": ["CE-"],
    "ad":        ["AD-"],
    "network":   ["NE-"],
    "web":       ["WE-"],
    "aprs":      ["AP-"],
}


@dataclass
class WicketState:
    wicket_id:  str
    status:     str        # realized / blocked / unknown
    confidence: float      # [0, 1]
    observed_at: str = ""

    @property
    def phase(self) -> float:
        return PHASE.get(self.status, math.pi / 2)

    @property
    def amplitude(self) -> float:
        return self.confidence


@dataclass
class SphereEnergy:
    """G(t) for a single domain sphere at a point in time."""
    sphere:      str
    G:           float          # raw Kuramoto order parameter
    G_norm:      float          # normalized [0, 1]
    n_wickets:   int
    n_realized:  int
    n_blocked:   int
    n_unknown:   int
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict:
        return {
            "sphere":      self.sphere,
            "G":           round(self.G, 6),
            "G_norm":      round(self.G_norm, 6),
            "n_wickets":   self.n_wickets,
            "n_realized":  self.n_realized,
            "n_blocked":   self.n_blocked,
            "n_unknown":   self.n_unknown,
            "computed_at": self.computed_at,
        }


def _sphere_for_wicket(wicket_id: str) -> str:
    for sphere, prefixes in SPHERE_MAP.items():
        for prefix in prefixes:
            if wicket_id.startswith(prefix):
                return sphere
    return "unknown"


def _compute_G(states: list[WicketState]) -> float:
    """
    Kuramoto order parameter on the wicket graph.
    G = Σᵢⱼ Aᵢ Aⱼ cos(φᵢ - φⱼ) / n²

    For a fully realized sphere (all in phase): G → 1.0
    For maximum disorder (mixed states):        G → 0.0
    For fully blocked sphere (all anti-phase):  G → 1.0 (coherent but inverted)
    """
    n = len(states)
    if n == 0:
        return 0.0
    if n == 1:
        return states[0].amplitude ** 2

    total = 0.0
    for i, si in enumerate(states):
        for j, sj in enumerate(states):
            total += si.amplitude * sj.amplitude * math.cos(si.phase - sj.phase)

    return total / (n * n)


def compute_sphere_energy(states: list[WicketState], sphere: str) -> SphereEnergy:
    """Compute G(t) for a single sphere given a list of wicket states."""
    if not states:
        return SphereEnergy(sphere=sphere, G=0.0, G_norm=0.0,
                            n_wickets=0, n_realized=0, n_blocked=0, n_unknown=0)

    G = _compute_G(states)

    # Normalize: max G occurs when all states are identical (fully coherent)
    # G_max = mean(A²) for identical phases
    G_max = sum(s.amplitude ** 2 for s in states) / len(states)
    G_norm = min(G / G_max, 1.0) if G_max > 0 else 0.0

    counts = {"realized": 0, "blocked": 0, "unknown": 0}
    for s in states:
        counts[s.status] = counts.get(s.status, 0) + 1

    return SphereEnergy(
        sphere=sphere,
        G=G,
        G_norm=G_norm,
        n_wickets=len(states),
        n_realized=counts["realized"],
        n_blocked=counts["blocked"],
        n_unknown=counts["unknown"],
    )


def load_states_from_events(events_file: Path) -> dict[str, list[WicketState]]:
    """
    Load wicket states from an events NDJSON file.
    Returns dict keyed by sphere name.
    Latest state per wicket_id wins (last-write).
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

        payload = ev.get("payload", {})
        prov = ev.get("provenance", {})
        wid = payload.get("wicket_id", "")
        if not wid:
            continue

        status = payload.get("status", "unknown")
        confidence = prov.get("evidence", {}).get("confidence", 0.5)
        observed_at = payload.get("observed_at", "")

        latest[wid] = WicketState(
            wicket_id=wid,
            status=status,
            confidence=confidence,
            observed_at=observed_at,
        )

    # Group by sphere
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
    result = {}
    for sphere, states in by_sphere.items():
        result[sphere] = compute_sphere_energy(states, sphere)
        log.debug(f"G({sphere}) = {result[sphere].G_norm:.4f} "
                  f"[{result[sphere].n_realized}R/{result[sphere].n_blocked}B/{result[sphere].n_unknown}U]")
    return result


def compute_field_energy_from_dir(events_dir: Path,
                                   latest_only: bool = True) -> dict[str, SphereEnergy]:
    """
    Compute G(t) across all events files in a directory.
    If latest_only=True, uses only the most recent file per host.
    Merges states across files — latest observation per wicket wins.
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

    return {sphere: compute_sphere_energy(states, sphere)
            for sphere, states in by_sphere.items()}


def compute_energy_timeseries(events_dir: Path,
                               sphere: str = "host") -> list[dict]:
    """
    Compute G(t) for a single sphere across all historical event files.
    Returns list of {ts, G, G_norm, n_realized, n_blocked, n_unknown}
    sorted chronologically — the energy trajectory over engagement time.
    """
    files = sorted(events_dir.glob("*.ndjson"))
    series = []

    for f in files:
        by_sphere = load_states_from_events(f)
        states = by_sphere.get(sphere, [])
        if not states:
            continue
        e = compute_sphere_energy(states, sphere)
        # Extract timestamp from filename e.g. 20260307T040935
        ts_raw = f.stem.split("_")[0]
        try:
            ts = datetime.strptime(ts_raw, "%Y%m%dT%H%M%S").replace(
                tzinfo=timezone.utc).isoformat()
        except ValueError:
            ts = e.computed_at
        series.append({
            "ts":         ts,
            "file":       f.name,
            "G":          round(e.G, 6),
            "G_norm":     round(e.G_norm, 6),
            "n_realized": e.n_realized,
            "n_blocked":  e.n_blocked,
            "n_unknown":  e.n_unknown,
            "n_wickets":  e.n_wickets,
        })

    return series


# Default confidence by status when no evidence confidence is available
DEFAULT_CONFIDENCE = {"realized": 0.90, "blocked": 0.75, "unknown": 0.40}


def load_states_from_interp(interp_file: Path) -> dict[str, list[WicketState]]:
    """
    Load wicket states from an interp NDJSON file (projection summary format).
    Uses default confidence values since interp files don't carry per-wicket confidence.
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
    # Start with events (highest fidelity)
    merged: dict[str, WicketState] = {}

    for f in sorted(events_dir.glob("*.ndjson"))[-5:]:
        by_sphere = load_states_from_events(f)
        for states in by_sphere.values():
            for ws in states:
                existing = merged.get(ws.wicket_id)
                if not existing or ws.observed_at > existing.observed_at:
                    merged[ws.wicket_id] = ws

    # Fill in from interp ndjson files for spheres not covered
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

    return {sphere: compute_sphere_energy(states, sphere)
            for sphere, states in by_sphere.items()}

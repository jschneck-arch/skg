"""
skg.topology.kuramoto
=====================
Kuramoto oscillator dynamics wired to the live SKG wicket graph.

Each wicket is an oscillator:
  - Natural frequency ω derived from evidence rank (rank 1 = fast, rank 4 = slow)
  - Phase φ initialized from tri-state (realized=0, blocked=π, unknown=π/2)
  - Amplitude A = confidence

The Kuramoto equation on the wicket graph:
  dφᵢ/dt = ωᵢ + (K/n) Σⱼ Aⱼ sin(φⱼ - φᵢ)

Where K is the coupling strength derived from the coupling matrix.

The order parameter R(t) = |Σⱼ Aⱼ exp(iφⱼ)| / Σⱼ Aⱼ
measures global synchronization — equivalent to G_norm from energy.py
but now evolving continuously under the dynamics.

R(t) → 1.0: full synchronization (all wickets in phase = fully realized)
R(t) → 0.0: incoherence (mixed states, maximum uncertainty)

This is the bridge between the static snapshot (energy.py) and
the dynamical system (the engagement unfolding over time).
"""
from __future__ import annotations

import json
import math
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("skg.topology.kuramoto")

# Natural frequencies by evidence rank
# Rank 1 (runtime/live) oscillates fastest — highest information density
# Rank 4 (network/external) oscillates slowest
NATURAL_FREQ = {1: 1.00, 2: 0.75, 3: 0.50, 4: 0.25}
DEFAULT_FREQ  = 0.50

# Global coupling strength — calibrated to archbox engagement data
K_DEFAULT = 2.0

# Phase encoding
PHASE_INIT = {"realized": 0.0, "blocked": math.pi, "unknown": math.pi / 2}


@dataclass
class Oscillator:
    wicket_id:   str
    phase:       float    # current phase φ [0, 2π]
    amplitude:   float    # confidence A [0, 1]
    freq:        float    # natural frequency ω
    status:      str      # realized / blocked / unknown
    sphere:      str      # which domain sphere

    @property
    def phasor(self) -> complex:
        """Complex phasor: A * exp(iφ)"""
        return self.amplitude * complex(math.cos(self.phase), math.sin(self.phase))


@dataclass
class KuramotoState:
    """Snapshot of the dynamical system at time t."""
    t:           float              # simulation time
    R:           float              # global order parameter
    R_per_sphere: dict[str, float]  # R per domain sphere
    oscillators: list[dict]         # per-oscillator state
    computed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict:
        return {
            "t":            round(self.t, 4),
            "R":            round(self.R, 6),
            "R_per_sphere": {k: round(v, 6) for k, v in self.R_per_sphere.items()},
            "n_oscillators": len(self.oscillators),
            "computed_at":  self.computed_at,
        }


def _order_parameter(oscillators: list[Oscillator]) -> float:
    """R = |Σ A exp(iφ)| / Σ A — amplitude-weighted synchronization."""
    if not oscillators:
        return 0.0
    total_amp = sum(o.amplitude for o in oscillators)
    if total_amp == 0:
        return 0.0
    phasor_sum = sum(o.phasor for o in oscillators)
    return abs(phasor_sum) / total_amp


def _order_parameter_per_sphere(
        oscillators: list[Oscillator]) -> dict[str, float]:
    by_sphere: dict[str, list[Oscillator]] = {}
    for o in oscillators:
        by_sphere.setdefault(o.sphere, []).append(o)
    return {s: _order_parameter(osc) for s, osc in by_sphere.items()}


def _step(oscillators: list[Oscillator],
          adj: dict[str, list[tuple[str, float]]],
          dt: float,
          K: float) -> None:
    """Single Euler step of the Kuramoto equations."""
    n = len(oscillators)
    if n == 0:
        return

    idx = {o.wicket_id: o for o in oscillators}
    dphi = {}

    for o in oscillators:
        coupling_sum = 0.0
        neighbors = adj.get(o.wicket_id, [])
        for nb_id, weight in neighbors:
            nb = idx.get(nb_id)
            if nb:
                coupling_sum += weight * nb.amplitude * math.sin(nb.phase - o.phase)
        dphi[o.wicket_id] = o.freq + (K / max(n, 1)) * coupling_sum

    for o in oscillators:
        o.phase = (o.phase + dphi[o.wicket_id] * dt) % (2 * math.pi)


def build_oscillators(events_dir: Path,
                      interp_dir: Optional[Path] = None) -> list[Oscillator]:
    """
    Build oscillator list from current wicket states in events/interp dirs.
    """
    from skg.topology.energy import (load_states_from_events,
                                      load_states_from_interp,
                                      _sphere_for_wicket,
                                      DEFAULT_CONFIDENCE)

    merged = {}

    # Events files — highest fidelity, carry evidence rank
    rank_map = {}
    for f in sorted(events_dir.glob("*.ndjson"))[-5:]:
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            p = ev.get("payload", {})
            prov = ev.get("provenance", {})
            wid = p.get("wicket_id", "")
            if not wid:
                continue
            status = p.get("status", "unknown")
            conf = prov.get("evidence", {}).get("confidence", 0.5)
            rank = prov.get("evidence_rank", 3)
            merged[wid] = (status, conf, p.get("observed_at", ""))
            rank_map[wid] = rank

    # Interp files — fill in spheres not covered by events
    if interp_dir:
        covered_spheres = {_sphere_for_wicket(w) for w in merged}
        for f in sorted(interp_dir.glob("*_interp.ndjson"))[-10:]:
            by_sphere = load_states_from_interp(f)
            for sphere, states in by_sphere.items():
                if sphere not in covered_spheres:
                    for ws in states:
                        if ws.wicket_id not in merged:
                            merged[ws.wicket_id] = (
                                ws.status,
                                DEFAULT_CONFIDENCE.get(ws.status, 0.4),
                                ws.observed_at)

    oscillators = []
    for wid, (status, conf, _) in merged.items():
        sphere = _sphere_for_wicket(wid)
        rank = rank_map.get(wid, 3)
        oscillators.append(Oscillator(
            wicket_id=wid,
            phase=PHASE_INIT.get(status, math.pi / 2),
            amplitude=conf,
            freq=NATURAL_FREQ.get(rank, DEFAULT_FREQ),
            status=status,
            sphere=sphere,
        ))

    return oscillators


def build_adjacency(events_dir: Path) -> dict[str, list[tuple[str, float]]]:
    """Build adjacency list from manifold edges."""
    from skg.topology.manifold import build_full_complex
    sc = build_full_complex(events_dir)
    adj: dict[str, list[tuple[str, float]]] = {}
    for e in sc.edges.values():
        adj.setdefault(e.source, []).append((e.target, e.weight))
        adj.setdefault(e.target, []).append((e.source, e.weight))
    return adj


def run_dynamics(events_dir: Path,
                 interp_dir: Optional[Path] = None,
                 steps: int = 200,
                 dt: float = 0.05,
                 K: float = K_DEFAULT) -> list[KuramotoState]:
    """
    Run Kuramoto dynamics on the current wicket graph.
    Returns time series of order parameter snapshots.

    steps=200, dt=0.05 → t ∈ [0, 10] engagement time units
    """
    oscillators = build_oscillators(events_dir, interp_dir)
    adj = build_adjacency(events_dir)

    if not oscillators:
        log.warning("No oscillators — empty wicket graph")
        return []

    log.info(f"Kuramoto: {len(oscillators)} oscillators, K={K}, steps={steps}")

    history = []
    for step in range(steps):
        t = step * dt
        if step % 20 == 0:
            R = _order_parameter(oscillators)
            R_sphere = _order_parameter_per_sphere(oscillators)
            history.append(KuramotoState(
                t=t, R=R, R_per_sphere=R_sphere,
                oscillators=[{"wicket_id": o.wicket_id,
                               "phase": round(o.phase, 4),
                               "amplitude": round(o.amplitude, 4),
                               "sphere": o.sphere}
                              for o in oscillators]
            ))
        _step(oscillators, adj, dt, K)

    # Final state
    R = _order_parameter(oscillators)
    R_sphere = _order_parameter_per_sphere(oscillators)
    history.append(KuramotoState(
        t=steps * dt, R=R, R_per_sphere=R_sphere,
        oscillators=[{"wicket_id": o.wicket_id,
                       "phase": round(o.phase, 4),
                       "amplitude": round(o.amplitude, 4),
                       "sphere": o.sphere}
                     for o in oscillators]
    ))

    return history


def steady_state(events_dir: Path,
                 interp_dir: Optional[Path] = None,
                 K: float = K_DEFAULT) -> KuramotoState:
    """Run to steady state and return final snapshot."""
    history = run_dynamics(events_dir, interp_dir, steps=400, dt=0.05, K=K)
    return history[-1] if history else None

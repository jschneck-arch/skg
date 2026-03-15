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
DEFAULT_FREQ = 0.50

# Global coupling strength — calibrated to engagement data
K_DEFAULT = 2.0

# Phase encoding
PHASE_INIT = {"realized": 0.0, "blocked": math.pi, "unknown": math.pi / 2}


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
class Oscillator:
    wicket_id: str
    phase: float                 # current phase φ [0, 2π]
    amplitude: float             # confidence-derived amplitude A [0, 1]
    freq: float                  # natural frequency ω
    status: str                  # realized / blocked / unknown
    sphere: str                  # which domain sphere

    # richer substrate-aware fields
    local_energy: float = 0.0
    damping: float = 0.0
    is_latent: bool = False
    confidence_vector: list[float] = field(default_factory=list)

    @property
    def phasor(self) -> complex:
        """Complex phasor: A * exp(iφ)"""
        return self.amplitude * complex(math.cos(self.phase), math.sin(self.phase))


@dataclass
class KuramotoState:
    """Snapshot of the dynamical system at time t."""
    t: float
    R: float
    R_per_sphere: dict[str, float]
    oscillators: list[dict]
    computed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def as_dict(self) -> dict:
        return {
            "t": round(self.t, 4),
            "R": round(self.R, 6),
            "R_per_sphere": {k: round(v, 6) for k, v in self.R_per_sphere.items()},
            "n_oscillators": len(self.oscillators),
            "computed_at": self.computed_at,
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


def _order_parameter_per_sphere(oscillators: list[Oscillator]) -> dict[str, float]:
    by_sphere: dict[str, list[Oscillator]] = {}
    for o in oscillators:
        by_sphere.setdefault(o.sphere, []).append(o)
    return {s: _order_parameter(osc) for s, osc in by_sphere.items()}


def _step(oscillators: list[Oscillator],
          adj: dict[str, list[tuple[str, float]]],
          dt: float,
          K: float) -> None:
    """
    Single Euler step of the Kuramoto equations.

    Current form preserves the original coupling law while allowing optional
    per-node damping:
        dφ_i = ω_i + (K/n) Σ_j w_ij A_j sin(φ_j - φ_i) - d_i
    """
    n = len(oscillators)
    if n == 0:
        return

    idx = {o.wicket_id: o for o in oscillators}
    dphi: dict[str, float] = {}

    for o in oscillators:
        coupling_sum = 0.0
        neighbors = adj.get(o.wicket_id, [])
        for nb_id, weight in neighbors:
            nb = idx.get(nb_id)
            if nb:
                coupling_sum += weight * nb.amplitude * math.sin(nb.phase - o.phase)

        dphi[o.wicket_id] = o.freq + (K / max(n, 1)) * coupling_sum - float(o.damping or 0.0)

    for o in oscillators:
        o.phase = (o.phase + dphi[o.wicket_id] * dt) % (2 * math.pi)


def _id_from_payload(payload: dict) -> str:
    return payload.get("wicket_id") or payload.get("node_id", "")


def _amplitude_from_event(evidence: dict, fallback_conf: float) -> tuple[float, list[float]]:
    """
    Derive oscillator amplitude from richer confidence structure when available.
    """
    confidence_vector = evidence.get("confidence_vector", []) or []
    try:
        confidence_vector = [float(x) for x in confidence_vector]
    except Exception:
        confidence_vector = []

    if confidence_vector:
        return _clamp01(_mean(confidence_vector, default=fallback_conf)), confidence_vector

    try:
        conf = float(fallback_conf)
    except Exception:
        conf = 0.5

    return _clamp01(conf), []


def build_oscillators(events_dir: Path,
                      interp_dir: Optional[Path] = None) -> list[Oscillator]:
    """
    Build oscillator list from current wicket/node states in events/interp dirs.

    Events files are preferred because they carry richer substrate hints:
    - evidence_rank
    - confidence_vector
    - local_energy
    - phase
    - latent status
    """
    from skg.topology.energy import (
        load_states_from_interp,
        _sphere_for_wicket,
        DEFAULT_CONFIDENCE,
    )

    merged: dict[str, dict] = {}
    rank_map: dict[str, int] = {}

    # Events files — highest fidelity
    for f in sorted(events_dir.glob("*.ndjson"))[-5:]:
        for line in f.read_text().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            if ev.get("type") not in ("obs.attack.precondition", "obs.substrate.node"):
                continue

            p = ev.get("payload", {})
            prov = ev.get("provenance", {})
            evidence = prov.get("evidence", {})

            wid = _id_from_payload(p)
            if not wid:
                continue

            status = p.get("status", "unknown")
            observed_at = p.get("observed_at") or ev.get("ts", "")
            conf = evidence.get("confidence", 0.5)
            rank = prov.get("evidence_rank", 3)

            amplitude, confidence_vector = _amplitude_from_event(evidence, conf)

            explicit_phase = evidence.get("phase", None)
            try:
                explicit_phase = float(explicit_phase) if explicit_phase is not None else None
            except Exception:
                explicit_phase = None

            local_energy = evidence.get("local_energy", 0.0)
            try:
                local_energy = float(local_energy or 0.0)
            except Exception:
                local_energy = 0.0

            damping = evidence.get("damping", 0.0)
            try:
                damping = float(damping or 0.0)
            except Exception:
                damping = 0.0

            merged[wid] = {
                "status": status,
                "amplitude": amplitude,
                "observed_at": observed_at,
                "explicit_phase": explicit_phase,
                "local_energy": local_energy,
                "damping": damping,
                "is_latent": bool(p.get("is_latent", False)),
                "confidence_vector": confidence_vector,
            }
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
                            merged[ws.wicket_id] = {
                                "status": ws.status,
                                "amplitude": DEFAULT_CONFIDENCE.get(ws.status, 0.4),
                                "observed_at": ws.observed_at,
                                "explicit_phase": None,
                                "local_energy": 0.0,
                                "damping": 0.0,
                                "is_latent": False,
                                "confidence_vector": [],
                            }

    oscillators: list[Oscillator] = []
    for wid, data in merged.items():
        status = data["status"]
        sphere = _sphere_for_wicket(wid)
        rank = rank_map.get(wid, 3)

        phase = data["explicit_phase"]
        if phase is None:
            phase = PHASE_INIT.get(status, math.pi / 2)

        oscillators.append(Oscillator(
            wicket_id=wid,
            phase=phase,
            amplitude=float(data["amplitude"]),
            freq=NATURAL_FREQ.get(rank, DEFAULT_FREQ),
            status=status,
            sphere=sphere,
            local_energy=float(data["local_energy"]),
            damping=float(data["damping"]),
            is_latent=bool(data["is_latent"]),
            confidence_vector=list(data["confidence_vector"]),
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

    history: list[KuramotoState] = []
    for step in range(steps):
        t = step * dt

        if step % 20 == 0:
            R = _order_parameter(oscillators)
            R_sphere = _order_parameter_per_sphere(oscillators)
            history.append(KuramotoState(
                t=t,
                R=R,
                R_per_sphere=R_sphere,
                oscillators=[
                    {
                        "wicket_id": o.wicket_id,
                        "phase": round(o.phase, 4),
                        "amplitude": round(o.amplitude, 4),
                        "sphere": o.sphere,
                        "local_energy": round(o.local_energy, 6),
                        "damping": round(o.damping, 6),
                        "is_latent": o.is_latent,
                    }
                    for o in oscillators
                ],
            ))

        _step(oscillators, adj, dt, K)

    # Final state
    R = _order_parameter(oscillators)
    R_sphere = _order_parameter_per_sphere(oscillators)
    history.append(KuramotoState(
        t=steps * dt,
        R=R,
        R_per_sphere=R_sphere,
        oscillators=[
            {
                "wicket_id": o.wicket_id,
                "phase": round(o.phase, 4),
                "amplitude": round(o.amplitude, 4),
                "sphere": o.sphere,
                "local_energy": round(o.local_energy, 6),
                "damping": round(o.damping, 6),
                "is_latent": o.is_latent,
            }
            for o in oscillators
        ],
    ))

    return history


def steady_state(events_dir: Path,
                 interp_dir: Optional[Path] = None,
                 K: float = K_DEFAULT) -> KuramotoState:
    """Run to steady state and return final snapshot."""
    history = run_dynamics(events_dir, interp_dir, steps=400, dt=0.05, K=K)
    if not history:
        return KuramotoState(t=0.0, R=0.0, R_per_sphere={}, oscillators=[])
    return history[-1]

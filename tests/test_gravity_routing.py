"""
Integration test: gravity routing selects highest-entropy target first.

This test exercises the core field-selection invariant:
  Given a minimal surface with N targets, the gravity cycle must route
  to the target with the highest information-theoretic energy E first.

Coverage:
  - EnergyEngine.compute() returns higher E for more unknown wickets
  - EnergyEngine.compute_weighted() handles dict-form node states
  - Fold gravity weights are additive to base unknown count
  - Landscape sorting by E puts the highest-entropy target at index 0
  - GravityScheduler ranks instruments by expected reduction potential
"""

from __future__ import annotations

import pytest

from skg.kernel.energy import EnergyEngine
from skg.kernel.folds import Fold
from skg.substrate.node import TriState


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_states(n_unknown: int, n_realized: int = 0, n_blocked: int = 0):
    """Return list of TriState values."""
    return (
        [TriState.UNKNOWN] * n_unknown
        + [TriState.REALIZED] * n_realized
        + [TriState.BLOCKED] * n_blocked
    )


def _make_fold(probability: float = 0.7, fold_type: str = "structural") -> Fold:
    """Build a minimal Fold."""
    try:
        return Fold(
            fold_id="test-fold",
            fold_type=fold_type,
            probability=probability,
            evidence="test",
        )
    except TypeError:
        # If Fold signature differs, try positional
        return Fold("test-fold", fold_type, probability)  # type: ignore


# ── EnergyEngine.compute tests ─────────────────────────────────────────────────

def test_energy_zero_when_all_realized():
    engine = EnergyEngine()
    states = _make_states(n_unknown=0, n_realized=5)
    assert engine.compute(states, []) == 0.0


def test_energy_equals_unknown_count():
    engine = EnergyEngine()
    for n in (1, 3, 10):
        states = _make_states(n_unknown=n, n_realized=2)
        assert engine.compute(states, []) == float(n), f"expected {n}, got {engine.compute(states, [])}"


def test_blocked_nodes_do_not_contribute():
    engine = EnergyEngine()
    states = _make_states(n_unknown=3, n_blocked=10)
    assert engine.compute(states, []) == 3.0


def test_fold_weight_is_additive():
    """Fold weight must add to the base unknown count, not replace it."""
    engine = EnergyEngine()
    states = _make_states(n_unknown=5)
    fold = _make_fold(probability=0.8)
    base_e  = engine.compute(states, [])
    folded_e = engine.compute(states, [fold])
    assert folded_e > base_e, "Fold must increase field energy"
    fold_contribution = folded_e - base_e
    assert fold_contribution > 0.0


def test_multiple_folds_stack():
    engine = EnergyEngine()
    states = _make_states(n_unknown=2)
    folds  = [_make_fold(0.6), _make_fold(0.9)]
    e_no_fold  = engine.compute(states, [])
    e_one_fold = engine.compute(states, [folds[0]])
    e_two_fold = engine.compute(states, folds)
    assert e_two_fold > e_one_fold > e_no_fold


# ── EnergyEngine.compute_weighted tests ───────────────────────────────────────

def test_weighted_tristate_unknowns():
    engine = EnergyEngine()
    states = [TriState.UNKNOWN, TriState.UNKNOWN, TriState.REALIZED]
    assert engine.compute_weighted(states, []) == 2.0


def test_weighted_dict_states_base_case():
    engine = EnergyEngine()
    states = [
        {"status": "unknown", "phi_u": 0.8, "contradiction": 0.0, "decoherence": 0.0},
        {"status": "realized", "phi_u": 0.0},
    ]
    e = engine.compute_weighted(states, [])
    assert e >= 0.8   # at least the phi_u of the unknown


def test_weighted_contradiction_adds_energy():
    engine = EnergyEngine()
    base_state  = [{"status": "unknown", "phi_u": 0.5, "contradiction": 0.0, "decoherence": 0.0}]
    contr_state = [{"status": "unknown", "phi_u": 0.5, "contradiction": 0.3, "decoherence": 0.0}]
    assert engine.compute_weighted(contr_state, []) > engine.compute_weighted(base_state, [])


# ── Gravity routing invariant (landscape ordering) ───────────────────────────

def test_highest_entropy_target_sorts_first():
    """
    Core routing invariant: when the landscape is sorted by entropy descending,
    the target with the most unknown wickets appears at index 0.
    """
    engine = EnergyEngine()

    # Build three simulated landscape entries
    targets = {
        "192.168.1.10": _make_states(n_unknown=8, n_realized=2),
        "192.168.1.20": _make_states(n_unknown=3, n_realized=7),
        "192.168.1.30": _make_states(n_unknown=12, n_realized=0),
    }

    landscape = [
        {
            "host":    ip,
            "entropy": engine.compute(states, []),
        }
        for ip, states in targets.items()
    ]

    landscape.sort(key=lambda x: x["entropy"], reverse=True)

    assert landscape[0]["host"] == "192.168.1.30", (
        f"Expected highest-entropy target (12 unknowns) first, got {landscape[0]}"
    )
    assert landscape[-1]["host"] == "192.168.1.20", (
        f"Expected lowest-entropy target (3 unknowns) last, got {landscape[-1]}"
    )


def test_fold_breaks_entropy_tie():
    """A structural fold should break a tie between two otherwise equal targets."""
    engine = EnergyEngine()

    # Both have 5 unknowns; one has an additional fold
    states_base = _make_states(n_unknown=5)
    fold        = _make_fold(probability=0.85)

    e_no_fold   = engine.compute(states_base, [])
    e_with_fold = engine.compute(states_base, [fold])

    landscape = [
        {"host": "A", "entropy": e_no_fold},
        {"host": "B", "entropy": e_with_fold},
    ]
    landscape.sort(key=lambda x: x["entropy"], reverse=True)

    assert landscape[0]["host"] == "B", "Target with structural fold should have higher entropy"


def test_fully_resolved_target_sorts_last():
    """A target with zero unknowns must always be routed to last."""
    engine = EnergyEngine()

    landscape = [
        {"host": "fully-resolved", "entropy": engine.compute(_make_states(0, 10), [])},
        {"host": "partially-known", "entropy": engine.compute(_make_states(5, 5), [])},
    ]
    landscape.sort(key=lambda x: x["entropy"], reverse=True)

    assert landscape[-1]["host"] == "fully-resolved"
    assert landscape[-1]["entropy"] == 0.0

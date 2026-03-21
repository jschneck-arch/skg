from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skg.identity import parse_workload_ref
from skg.kernel.pearls import Pearl, PearlLedger


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _matches_wavelength(wicket_id: str, wavelength: list[str]) -> bool:
    for item in wavelength or []:
        if item.endswith("*"):
            if wicket_id.startswith(item[:-1]):
                return True
        elif wicket_id == item:
            return True
    return False


def _pearl_workload_id(pearl: Pearl) -> str:
    energy = pearl.energy_snapshot or {}
    target = pearl.target_snapshot or {}
    return (
        str(energy.get("workload_id") or target.get("workload_id") or "")
        or f"gravity::{energy.get('target_ip', '')}".rstrip(":")
    )


def _pearl_identity_key(pearl: Pearl) -> str:
    energy = pearl.energy_snapshot or {}
    target = pearl.target_snapshot or {}
    return (
        str(energy.get("identity_key") or target.get("identity_key") or "")
        or parse_workload_ref(_pearl_workload_id(pearl)).get("identity_key", "")
    )


def _pearl_domain(pearl: Pearl) -> str:
    target = pearl.target_snapshot or {}
    energy = pearl.energy_snapshot or {}
    workload_id = _pearl_workload_id(pearl)
    parsed = parse_workload_ref(workload_id)
    return str(target.get("domain") or energy.get("domain") or parsed.get("domain_hint") or "")


def _state_change_wickets(pearl: Pearl) -> set[str]:
    wickets = set()
    for change in pearl.state_changes:
        wicket = str(change.get("wicket_id") or change.get("node_id") or "")
        if wicket:
            wickets.add(wicket)
    for confirm in getattr(pearl, "observation_confirms", []) or []:
        wicket = str(confirm.get("wicket_id") or confirm.get("node_id") or "")
        status = str(confirm.get("status") or "")
        if wicket and status in {"realized", "blocked"}:
            wickets.add(wicket)
    return wickets


@dataclass(slots=True)
class PearlNeighborhood:
    identity_key: str
    domain: str
    pearl_count: int
    reinforced_wickets: list[str]
    reinforced_reasons: list[str]
    transition_density: float
    mean_energy: float
    manifestation_keys: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity_key": self.identity_key,
            "domain": self.domain,
            "pearl_count": self.pearl_count,
            "reinforced_wickets": self.reinforced_wickets,
            "reinforced_reasons": self.reinforced_reasons,
            "transition_density": self.transition_density,
            "mean_energy": self.mean_energy,
            "manifestation_keys": self.manifestation_keys,
        }


class PearlManifold:
    """
    Derived structural memory over the append-only pearl ledger.

    The ledger remains the source of truth. This class computes reinforced
    neighborhoods over pearls so recall can use repeated structure rather
    than only individual records.
    """

    def __init__(self, ledger: PearlLedger):
        self.ledger = ledger

    def neighborhoods(self) -> list[PearlNeighborhood]:
        groups: dict[tuple[str, str], list[Pearl]] = {}
        for pearl in self.ledger.all():
            identity_key = _pearl_identity_key(pearl)
            domain = _pearl_domain(pearl)
            groups.setdefault((identity_key, domain), []).append(pearl)

        results: list[PearlNeighborhood] = []
        for (identity_key, domain), pearls in groups.items():
            wicket_counts = Counter()
            reason_counts = Counter()
            manifestation_keys = set()
            energy_total = 0.0
            transition_total = 0

            for pearl in pearls:
                wickets = _state_change_wickets(pearl)
                wicket_counts.update(wickets)
                for reason in pearl.reason_changes or []:
                    kind = str(reason.get("kind") or "")
                    name = str(reason.get("reason") or "")
                    if kind == "proposal_lifecycle" and name:
                        reason_counts.update([name])
                manifestation_keys.add(
                    str((pearl.energy_snapshot or {}).get("manifestation_key")
                        or (pearl.target_snapshot or {}).get("manifestation_key")
                        or _pearl_workload_id(pearl))
                )
                energy_total += _safe_float((pearl.energy_snapshot or {}).get("E"))
                transition_total += len(pearl.state_changes or [])

            reinforced = sorted(
                [w for w, count in wicket_counts.items() if count >= 2]
            )
            reinforced_reasons = sorted(
                [r for r, count in reason_counts.items() if count >= 1]
            )
            pearl_count = len(pearls)
            results.append(PearlNeighborhood(
                identity_key=identity_key,
                domain=domain,
                pearl_count=pearl_count,
                reinforced_wickets=reinforced,
                reinforced_reasons=reinforced_reasons,
                transition_density=round(transition_total / pearl_count, 6) if pearl_count else 0.0,
                mean_energy=round(energy_total / pearl_count, 6) if pearl_count else 0.0,
                manifestation_keys=sorted(manifestation_keys),
            ))

        return sorted(results, key=lambda item: (item.identity_key, item.domain))

    def recall_adjustment(self, domain: str, hosts: list[str] | None = None) -> dict[str, Any]:
        hosts = hosts or []
        host_keys = {parse_workload_ref(h).get("identity_key", h) for h in hosts if h}
        neighborhoods = [
            n for n in self.neighborhoods()
            if (not domain or n.domain == domain)
            and (not host_keys or n.identity_key in host_keys)
        ]

        if not neighborhoods:
            return {
                "delta": 0.0,
                "reinforced_wickets": [],
                "matched_neighborhoods": 0,
            }

        reinforced = sorted({w for n in neighborhoods for w in n.reinforced_wickets})
        avg_density = sum(n.transition_density for n in neighborhoods) / len(neighborhoods)
        delta = min(0.05, 0.01 * len(reinforced) + 0.01 * avg_density)
        return {
            "delta": round(delta, 4),
            "reinforced_wickets": reinforced,
            "matched_neighborhoods": len(neighborhoods),
        }

    def growth_adjustment(self, domain: str, hosts: list[str] | None = None) -> dict[str, Any]:
        hosts = hosts or []
        host_keys = {parse_workload_ref(h).get("identity_key", h) for h in hosts if h}
        neighborhoods = [
            n for n in self.neighborhoods()
            if (not domain or n.domain == domain)
            and (not host_keys or n.identity_key in host_keys)
        ]
        if not neighborhoods:
            return {
                "delta": 0.0,
                "matched_neighborhoods": 0,
                "proposal_reasons": [],
            }

        reasons = sorted({r for n in neighborhoods for r in n.reinforced_reasons})
        created = sum(1 for r in reasons if r.startswith("proposal_created"))
        superseded = sum(1 for r in reasons if r == "clustered_catalog_growth")
        delta = min(0.05, 0.01 * created + 0.01 * superseded)
        return {
            "delta": round(delta, 4),
            "matched_neighborhoods": len(neighborhoods),
            "proposal_reasons": reasons,
        }

    def wavelength_boost(self, hosts: list[str] | None = None, wavelength: list[str] | None = None) -> float:
        """
        Memory-reinforced gravity boost for an instrument's wavelength on a target.

        Physics:
          The pearl ledger records what collapsed in prior sweeps. When an
          instrument's wavelength matches previously-reinforced wickets, the
          manifold adds curvature toward that instrument — the field has been
          informative here before.

          boost = len(matches) × transition_scale × energy_scale
          capped at 10.0 (meaningful against potentials of 5–25)

        Previously capped at 2.0 with weak scaling — raised to reflect actual
        coupling energy semantics from SKG_FIELD_FUNCTIONAL.md:
          E_couple(i, j) = K(i, j) × (E_local(j) + U_m(j))
        """
        hosts = hosts or []
        wavelength = wavelength or []
        host_keys = {parse_workload_ref(h).get("identity_key", h) for h in hosts if h}
        neighborhoods = [
            n for n in self.neighborhoods()
            if (not host_keys or n.identity_key in host_keys)
        ]
        if not neighborhoods or not wavelength:
            return 0.0

        reinforced = sorted({w for n in neighborhoods for w in n.reinforced_wickets})
        matches = [w for w in reinforced if _matches_wavelength(w, wavelength)]
        if not matches:
            return 0.0

        # Transition density: how active were past sweeps on this identity?
        avg_density = sum(n.transition_density for n in neighborhoods) / len(neighborhoods)
        # Mean energy: how much unresolved energy existed in past observations?
        avg_energy = sum(n.mean_energy for n in neighborhoods) / len(neighborhoods)

        # Each matching reinforced wicket contributes 1.0 base boost
        match_boost = float(len(matches))

        # Scale by transition density — 0.5..2.0 range
        # High density = prior sweeps were informative = stronger coupling
        transition_scale = min(2.0, max(0.5, avg_density + 0.5))

        # Scale by prior energy — higher historical energy = more unresolved
        # structure existed = this instrument was needed here
        energy_scale = min(2.0, max(0.5, avg_energy / 5.0 + 0.5)) if avg_energy > 0 else 1.0

        return round(min(10.0, match_boost * transition_scale * energy_scale), 4)


def load_pearl_manifold(pearls_path: str | Path) -> PearlManifold:
    return PearlManifold(PearlLedger(pearls_path))

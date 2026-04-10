"""
skg.kernel.field_functional
===========================
Canonical runtime field-functional semantics for a single target.

This module closes the split between the older local-only functional in
``skg.kernel.field_local`` and the newer topology/fiber decomposition in
``skg.topology.energy``.

The runtime semantics here are intentionally explicit:

* ``self_energy`` comes from target-local ``FieldLocal`` objects.
* ``coupling_energy`` is computed over directed domain couplings so it is not
  sensitive to list ordering.
* ``dissipation`` is the accumulated decoherence/contradiction load.
* ``curvature`` is the target-local curvature approximation induced by actual
  fiber clusters plus optional topology context.

This does not claim to be the final paper-proof form of Work 4. It is the
single canonical implementation that the rest of the runtime can call.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable, Optional

from .field_local import FieldLocal, coupling_constant

if TYPE_CHECKING:
    from skg.topology.energy import FiberCluster, FieldTopology


_DOMAIN_TO_SPHERE = {
    "host": "host",
    "sysaudit": "host",
    "web": "web",
    "data": "data",
    "container": "container",
    "container_escape": "container",
    "ad": "ad",
    "ad_lateral": "ad",
    "lateral": "ad",
    "binary": "binary",
    "binary_analysis": "binary",
    "ai_target": "ai_target",
    "supply_chain": "supply_chain",
    "iot_firmware": "iot_firmware",
    "aprs": "aprs",
}


@dataclass
class FieldFunctionalBreakdown:
    self_energy: float
    coupling_energy: float
    dissipation: float
    curvature: float
    total: float
    protected_locals: list[str] = field(default_factory=list)
    relevant_spheres: list[str] = field(default_factory=list)
    fiber_cluster_id: str = ""

    def as_dict(self) -> dict:
        return {
            "self_energy": round(self.self_energy, 6),
            "coupling_energy": round(self.coupling_energy, 6),
            "dissipation": round(self.dissipation, 6),
            "curvature": round(self.curvature, 6),
            "total": round(self.total, 6),
            "protected_locals": list(self.protected_locals),
            "relevant_spheres": list(self.relevant_spheres),
            "fiber_cluster_id": self.fiber_cluster_id,
        }


@dataclass
class FiberPotentialBreakdown:
    tension: float
    coupling: float
    decoherence: float
    cost: float
    total: float
    reachable_locals: list[str] = field(default_factory=list)
    reachable_spheres: list[str] = field(default_factory=list)
    fiber_cluster_id: str = ""

    def as_dict(self) -> dict:
        return {
            "tension": round(self.tension, 6),
            "coupling": round(self.coupling, 6),
            "decoherence": round(self.decoherence, 6),
            "cost": round(self.cost, 6),
            "total": round(self.total, 6),
            "reachable_locals": list(self.reachable_locals),
            "reachable_spheres": list(self.reachable_spheres),
            "fiber_cluster_id": self.fiber_cluster_id,
        }


def domain_to_sphere(domain: str) -> str:
    normalized = str(domain or "").strip()
    return _DOMAIN_TO_SPHERE.get(normalized, normalized or "unknown")


def spheres_for_locals(locals_: Iterable[FieldLocal]) -> list[str]:
    spheres: list[str] = []
    for loc in locals_:
        sphere = domain_to_sphere(loc.domain)
        if sphere and sphere not in spheres:
            spheres.append(sphere)
    return spheres


def _directed_coupling_energy(locals_: list[FieldLocal]) -> float:
    total = 0.0
    for source in locals_:
        for target in locals_:
            if source.local_id == target.local_id:
                continue
            k = coupling_constant(source.domain, target.domain)
            if k <= 0.0:
                continue
            total += source.coupling_energy(target, k)
    return total


def _cluster_fiber_load(cluster: "FiberCluster" | None, relevant_spheres: set[str]) -> tuple[float, float]:
    if cluster is None:
        return 0.0, 0.0

    tension_load = 0.0
    persistence_load = 0.0
    for fiber in cluster.fibers or []:
        if relevant_spheres and fiber.sphere not in relevant_spheres:
            continue
        tension_load += float(fiber.tension or 0.0) * float(fiber.coherence or 0.0)
        if fiber.kind == "pearl_memory":
            persistence_load += (0.6 * float(fiber.coherence or 0.0)) + (0.4 * float(fiber.tension or 0.0))

    # Match the bounded scale used in topology.energy while staying target-local.
    return math.log1p(max(0.0, tension_load)), min(2.5, math.log1p(max(0.0, persistence_load)))


def _topology_curvature(topology: "FieldTopology" | None, relevant_spheres: list[str]) -> tuple[float, float]:
    if topology is None or not relevant_spheres:
        return 0.0, 0.0

    rows = [topology.spheres[s] for s in relevant_spheres if s in topology.spheres]
    if not rows:
        return 0.0, 0.0

    mean_curvature = sum(float(row.curvature or 0.0) for row in rows) / len(rows)
    h1_term = 0.5 if int(getattr(topology, "beta_1", 0) or 0) > 0 else 0.0
    return mean_curvature, h1_term


def field_functional_breakdown(
    locals_: list[FieldLocal],
    *,
    fiber_cluster: "FiberCluster" | None = None,
    topology: "FieldTopology" | None = None,
) -> FieldFunctionalBreakdown:
    if not locals_:
        return FieldFunctionalBreakdown(
            self_energy=0.0,
            coupling_energy=0.0,
            dissipation=0.0,
            curvature=0.0,
            total=0.0,
        )

    relevant_spheres = spheres_for_locals(locals_)
    relevant_sphere_set = set(relevant_spheres)

    self_energy = sum(loc.E_self for loc in locals_)
    coupling_energy = _directed_coupling_energy(locals_)
    dissipation = sum(loc.decoherence_load() for loc in locals_)

    unresolved_mass = sum(loc.U_m for loc in locals_)
    mean_local_energy = sum(loc.E_local for loc in locals_) / len(locals_)
    fiber_load, pearl_persistence = _cluster_fiber_load(fiber_cluster, relevant_sphere_set)
    topology_curvature, h1_term = _topology_curvature(topology, relevant_spheres)

    curvature = unresolved_mass + mean_local_energy
    curvature += 0.5 * fiber_load
    curvature += 0.4 * pearl_persistence
    curvature += 0.25 * topology_curvature
    curvature += h1_term

    total = self_energy + coupling_energy + dissipation + curvature
    return FieldFunctionalBreakdown(
        self_energy=self_energy,
        coupling_energy=coupling_energy,
        dissipation=dissipation,
        curvature=curvature,
        total=total,
        protected_locals=[loc.local_id for loc in locals_ if loc.is_protected()],
        relevant_spheres=relevant_spheres,
        fiber_cluster_id=getattr(fiber_cluster, "cluster_id", "") or "",
    )


def field_functional(
    locals_: list[FieldLocal],
    *,
    fiber_cluster: "FiberCluster" | None = None,
    topology: "FieldTopology" | None = None,
) -> float:
    return field_functional_breakdown(
        locals_,
        fiber_cluster=fiber_cluster,
        topology=topology,
    ).total


def phi_fiber_breakdown(
    instrument_wavelength: list[str],
    instrument_cost: float,
    locals_: list[FieldLocal],
    *,
    other_locals: Optional[list[FieldLocal]] = None,
    fiber_cluster: "FiberCluster" | None = None,
) -> FiberPotentialBreakdown:
    from skg.topology.energy import fiber_coupling_matrix

    wave_set = set(instrument_wavelength or [])
    cost = max(float(instrument_cost or 0.0), 1e-9)

    wicket_to_local: dict[str, FieldLocal] = {}
    all_locals = list(locals_ or []) + list(other_locals or [])
    for loc in all_locals:
        for wid in loc.wicket_states:
            wicket_to_local[wid] = loc

    reachable_ids: set[str] = set()
    for wid in wave_set:
        loc = wicket_to_local.get(wid)
        if loc is not None:
            reachable_ids.add(loc.local_id)

    reachable_set = [loc for loc in all_locals if loc.local_id in reachable_ids]
    reachable_spheres = spheres_for_locals(reachable_set)
    reachable_sphere_set = set(reachable_spheres)

    matched_fibers = [
        fiber
        for fiber in (getattr(fiber_cluster, "fibers", None) or [])
        if fiber.sphere in reachable_sphere_set
    ]
    cluster_driven = bool(matched_fibers)

    if cluster_driven:
        # When real cross-expression fiber structure is present, it is the
        # primary carrier of reach/tension in selection. Do not add a second
        # generic coupling bonus on top of that.
        tension = sum(
            float(fiber.tension or 0.0) * float(fiber.coherence or 0.0)
            for fiber in matched_fibers
        )
        coupling = 0.0
    else:
        tension = sum(loc.tension_times_coherence() for loc in reachable_set)
        coupling = 0.0
        cluster_matrix = fiber_coupling_matrix([fiber_cluster]) if fiber_cluster is not None else {}
        for loc_i in all_locals:
            if loc_i.local_id in reachable_ids:
                continue

            target_sphere = domain_to_sphere(loc_i.domain)
            weight = 0.0
            for source_sphere in reachable_spheres:
                weight = max(weight, float(cluster_matrix.get(source_sphere, {}).get(target_sphere, 0.0) or 0.0))

            if weight <= 0.0:
                for reachable in reachable_set:
                    weight = max(weight, coupling_constant(reachable.domain, loc_i.domain))

            if weight > 0.0:
                coupling += weight * loc_i.U_m

    decoherence = sum(loc.decoherence_load() for loc in reachable_set)
    total = (tension + coupling + decoherence) / cost
    return FiberPotentialBreakdown(
        tension=tension,
        coupling=coupling,
        decoherence=decoherence,
        cost=cost,
        total=total,
        reachable_locals=[loc.local_id for loc in reachable_set],
        reachable_spheres=reachable_spheres,
        fiber_cluster_id=getattr(fiber_cluster, "cluster_id", "") or "",
    )


def phi_fiber(
    instrument_wavelength: list[str],
    instrument_cost: float,
    locals_: list[FieldLocal],
    *,
    other_locals: Optional[list[FieldLocal]] = None,
    fiber_cluster: "FiberCluster" | None = None,
) -> float:
    return phi_fiber_breakdown(
        instrument_wavelength,
        instrument_cost,
        locals_,
        other_locals=other_locals,
        fiber_cluster=fiber_cluster,
    ).total

# SKG Field Functional

Purpose: define the canonical SKG field law in operational mathematical terms.

This document is the reference for how SKG should treat:

- measurement
- preserved information/energy
- unresolved structure
- coupling
- dissipation
- curvature
- protected states
- fibers and fiber clusters

It does not claim that SKG is a literal physical quantum system.
It defines the field quantities that SKG is allowed to compute and expose.

## Core Principle

SKG does not begin from wickets.

SKG begins from observed information/energy:

1. an observation is recorded
2. the observation contributes local field structure
3. the observation contributes coupling structure
4. preserved history transforms that structure over time
5. projections such as wickets, paths, folds, and reports are derived from the field

The field is primary.
Wickets are one projection of it.

## Canonical Objects

The canonical field is built from five object classes.

### 1. Field Observation

A field observation is a bounded measured contribution:

- source instrument
- manifestation / anchor identity
- local support
- temporal placement
- confidence structure
- compatibility context
- dissipation class

It is not yet a wicket.

### 2. Field Local

A field local is a persistent localized concentration of observed structure.

Examples:

- a service surface
- a credential binding
- a datastore access condition
- a process/runtime integrity condition
- a relation to another identity

### 3. Field Coupling

A field coupling expresses inter-local influence.

Examples:

- credential -> ssh service
- credential -> datastore service
- host -> container boundary
- relation -> lateral potential
- web surface -> host foothold precondition

### 4. Field Fiber

A fiber is an overlapping strand of preserved structure through one anchor identity.

Fibers are not simple edges.
They preserve:

- multi-membership
- directional relevance
- repeated measured coherence
- local tension

### 5. Field Cluster

A fiber cluster is a bundle of related fibers for one anchor identity.

This is the right level for operator-readable ribbon-like structure.

## Canonical Quantities

The field functional is expressed through these terms.

### Local self-energy

For a local or sphere `s`:

`E_self(s) = U_m(s) + E_local(s) + E_latent(s)`

Where:

- `U_m(s)` = unresolved measured mass
- `E_local(s)` = retained local energy from observed conditions
- `E_latent(s)` = latent but preserved contribution

`U_m` is not flat count.
It is measured unresolved structure.

### Unresolved measured mass

Current practical form:

`U_m = A + 0.5 * E_local + 0.5 * D + 0.25 * (1 - C)`

Where:

- `A` = unresolved amplitude/support
- `E_local` = local retained energy
- `D` = decoherence
- `C` = compatibility score

This is allowed to evolve, but the principle must remain:
unknown is unresolved measured structure, not absence.

### Coupling energy

For locals or spheres `i, j`:

`E_couple(i, j) = K(i, j) * (E_local(j) + U_m(j))`

Where:

- `K(i, j)` = measured coupling strength

The next runtime step is to let fibers contribute directly to `K`, not only sphere adjacency.

### Dissipation

For a local or sphere `s`:

`D(s) = decoherence(s) + latency(s) + stale_support_loss(s)`

Operationally this means:

- stale support loses present relevance
- one-basis unresolved structure carries higher fragility
- preserved history remains, but its present coherence decays

### Curvature

Curvature is concentration of unresolved and incompatible structure.

Current practical reading:

`Kappa(s) = U_m(s) + mean_local_energy(s) + coupling_load(s) + obstruction_load(s)`

Folds are explicit curvature concentrations.

### Protected state

A state is protected when repeated measured structure remains coherent under perturbation.

Current practical criterion:

- high coherence
- low dissipation
- low unresolved mass
- repeated reinforcement across manifestations or time

This must remain a persistence criterion, not a mere threshold trick.

## Fiber Law

Fibers are the preferred geometry for overlapping preserved structure.

Each fiber has:

- anchor identity
- sphere/domain participation
- kind
- members
- coherence
- tension

Interpretation:

- coherence = stability of the strand
- tension = unresolved pull within the strand

Fiber clusters are bundles of related strands over one anchor identity.

The next runtime step is:

`fiber -> coupling -> curvature -> gravity`

rather than keeping fibers as representation only.

## Sphere Law

Spheres remain valid as an operator-readable projection.

They are useful for:

- coarse field summaries
- protected basin display
- high-level gravity and report surfaces

But spheres are not the only geometry and not the canonical one.

Spheres are one cut through a richer fibered field.

## Gravity Law

Gravity does not "choose scanners."

Gravity follows regions where observation can most meaningfully transform the field.

Operationally, gravity should follow:

`G_pull ~ unresolved_mass + contradiction + dissipation + fold_curvature + coupling opportunity`

The next runtime step is to let fiber tension and coupling opportunity affect gravity directly.

## Pearl Law

Pearls do not store reports.
Pearls preserve transformed field structure through time.

A pearl should preserve:

- what was measured
- where it localized
- what it coupled to
- what changed
- what remained unresolved

Pearl manifolds are derived memory neighborhoods over that preserved field history.

## What Counts As Correct Physics/Math In SKG

Correct means:

- every field quantity is explicitly defined
- every exposed runtime value maps to a defined term
- no term is presented as more rigorous than the code instantiates
- operator views are projections of the field, not replacements for it

Incorrect means:

- decorative physics language without operational effect
- using counts where measured mass exists
- treating projections as the substrate
- claiming literal quantum equivalence where only measurement analogy is implemented

## Current Runtime Status

Current SKG already instantiates part of this functional:

- support / collapse
- decoherence
- compatibility
- unresolved measured mass
- self-energy
- coupling energy
- curvature
- protected-state heuristics
- fibers and fiber clusters as topology views

What is still incomplete:

- world-first canonical field objects
- fiber-driven coupling law
- fiber-driven gravity
- one unified field object feeding all projections

## Immediate Implementation Order

1. keep field observation primary
2. continue moving topology input from wicket rows to world observations
3. let fibers affect coupling directly
4. let coupling and fiber tension affect curvature and gravity
5. keep wickets, paths, and reports as derived projections

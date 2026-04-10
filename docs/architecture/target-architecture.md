# SKG Target Architecture

Status: canonical target blueprint for repository realignment.

## Layer Map

- `packages/skg-core`
  - Canonical substrate and protocol-neutral mechanics.
  - Owns: kernel/state algebra, graph/topology primitives, identity, provenance, temporal memory, constraints, serialization, config primitives.

- `packages/skg-protocol`
  - Public contracts and validation only.
  - Owns: event contracts, adapter contracts, projector contracts, manifests, compatibility rules, checkpoint contracts.

- `packages/skg-registry`
  - Discovery/loading/resolution layer.
  - Owns: domain registration, adapter discovery, projector discovery, policy loading.

- `packages/skg-services`
  - Runtime and operator services.
  - Owns: `gravity`, `forge`, `cli`, `api`, `reporting`, `assistant`, `harness`.
  - `harness` owns `claw-runtime`, `claw-bridge`, `claw-cli`.

- `packages/skg-domains`
  - First-class domain bundles.
  - Each domain owns its ontology extensions, contracts/catalogs, adapters, projectors, policies, fixtures, examples.

- `packages/skg-reasoning`
  - Higher-order reasoning layer (`SKG-R`).
  - Owns: path/value/usefulness evaluation over canonical domain events and service context contracts.
  - Must not redefine domain semantics and must not emit raw observation events.

- `packages/skg-legacy`
  - Temporary compatibility bridges and migration shims only.

- `archive`
  - Mirrors, backups, stale generated trees, and quarantined historical material.

## Authority Planes

The architecture must keep these planes separate:

1. Declaration/configuration plane
2. Measurement/observation plane
3. Interpretation/projection plane
4. Orchestration/proposal plane

No module may blur these planes by silently mirroring or mutating cross-plane state.

## Dependency Rules

- `skg-core` MUST NOT import domains or services.
- `skg-protocol` MUST NOT depend on domains.
- `skg-registry` may depend on `skg-protocol` and lightweight `skg-core` identity/config primitives.
- `skg-services` consume domains through `skg-registry` + `skg-protocol` contracts only.
- `skg-domains` may depend on `skg-protocol` contracts and selected `skg-core` primitives, but MUST NOT import private service internals.
- `skg-reasoning` may depend on `skg-protocol` contracts and canonical event payloads; it MUST NOT import domain/service internals.

## Non-Negotiable Runtime Rules

- Gravity is a service (`packages/skg-services/gravity`), not core and not an adapter.
- Claw is harness runtime (`packages/skg-services/harness`), not core and not an adapter.
- No hardcoded `/opt/skg` path assumptions in canonical architecture.
- No `sys.path` mutation in canonical architecture.
- No private-import bypass around registry/projector boundaries.

## Canonical Package Skeleton

```text
packages/
  skg-core/
  skg-protocol/
  skg-registry/
  skg-services/
    gravity/
    forge/
    cli/
    api/
    reporting/
    assistant/
    harness/
      claw-runtime/
      claw-bridge/
      claw-cli/
  skg-domains/
  skg-reasoning/
  skg-legacy/
archive/
```

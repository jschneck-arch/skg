# Phase 6A Domain Boundaries (host)

Date: 2026-04-02

## Ownership Decisions Applied

1. Domain pack owns semantics.
- Host ontology, mappings, adapter normalization, projector logic, and policies now live in:
  - `packages/skg-domains/host/src/skg_domain_host/ontology/*`
  - `packages/skg-domains/host/src/skg_domain_host/mappings/*`
  - `packages/skg-domains/host/src/skg_domain_host/adapters/host_nmap_profile/run.py`
  - `packages/skg-domains/host/src/skg_domain_host/projectors/host/run.py`
  - `packages/skg-domains/host/src/skg_domain_host/policies/*`

2. Services/runtime remain outside the domain pack.
- No subprocess or scanner execution was migrated into `skg-domain-host`.
- `nmap` process invocation, SSH/WinRM sessions, and runtime transport remain deferred in legacy/service-owned space.

3. Protocol contracts remain the event boundary.
- Adapter emits only canonical `obs.attack.precondition` envelopes using `skg_protocol.events` helpers.
- No legacy envelope builders or ad hoc event shells are used.

4. Projector remains domain-owned but substrate-driven.
- Host projector consumes only public `skg_core.substrate` projection primitives.
- No imports from legacy `skg.kernel.*`, no `sys.path` hacks, no daemon/runtime semantics in projector code.

5. Single manifest authority enforced.
- Canonical manifest: `packages/skg-domains/host/src/skg_domain_host/manifest.yaml`.
- Root `packages/skg-domains/host/domain.yaml` removed to avoid dual authority.

## Boundary Risks Still Open

| Risk | Path | Status |
|---|---|---|
| Runtime/semantic mixing still present in deferred host adapters | `skg-host-toolchain/adapters/ssh_collect/parse.py` | deferred |
| Cross-domain emissions mixed in host toolchain SMB enumeration | `skg-host-toolchain/adapters/smb_collect/enum4linux_adapter.py` | deferred |
| Legacy projector contains optional sheaf coupling not migrated | `skg-host-toolchain/projections/host/run.py` | deferred |

## Net Assessment

Phase 6A host migration preserves the web pilot boundary pattern:
- semantics in domain pack
- runtime outside domain pack
- canonical contracts at boundaries
- no dual execution path introduced for migrated host semantic flows.

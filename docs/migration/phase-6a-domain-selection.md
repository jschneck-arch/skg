# Phase 6A Domain Selection

Date: 2026-04-02

## Selected Second Domain

- Selected domain: `host`
- Selection rule: preferred order (`host` -> `ad`), migrate exactly one second domain.

## Why `host` Was Selected

1. `host` is the first preferred second-domain candidate and had only scaffold state under `packages/skg-domains/host`, so extraction value is immediate.
2. `skg-host-toolchain/contracts/catalogs/attack_preconditions_catalog.host.v1.json` contains a usable, explicit ontology authority for wickets and attack paths.
3. `skg-host-toolchain/adapters/nmap_scan/parse.py` had a clean semantic slice (service/exploit-to-wicket mapping) that could be split from runtime subprocess execution.
4. `skg-host-toolchain/projections/host/run.py` had projector logic that could be rewritten to canonical substrate projection without keeping `sys.path` hacks.

## Domain Not Migrated In Phase 6A

- `ad`: deferred by phase scope. No third-domain migration performed.

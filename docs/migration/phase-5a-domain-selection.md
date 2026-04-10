# Phase 5A Domain Selection

Date: 2026-04-01

## Selected Pilot

- Selected domain: `web`
- Selection rule: preferred order (`web` -> `host` -> `ad`), migrate exactly one domain.

## Why `web` Was Selected

1. The `web` toolchain had a usable canonical substrate candidate for projection logic at `skg-web-toolchain/projections/web/run.py`.
2. The `web` adapter space had extractable domain semantics (path-pattern to wicket mapping) in `skg-web-toolchain/adapters/web_active/gobuster_adapter.py`.
3. The domain had explicit ontology material in `skg-web-toolchain/contracts/catalogs/attack_preconditions_catalog.web.v1.json` that could be split into canonical domain-owned ontology and path catalogs.
4. The migration could be done without pulling runtime orchestration (`gravity`, daemon scheduling, subprocess control) into domain code.

## Domains Not Migrated In Phase 5A

- `host`: deferred to a later phase.
- `ad`: deferred to a later phase.

No additional domains were migrated in this phase.

# Phase 7M AD Governance

Date: 2026-04-03

## Canonical AD-22 Sidecar Governance

### Canonical contract location

- Protocol contract module:
  - `packages/skg-protocol/src/skg_protocol/contracts/ad_tiering_input.py`

### Canonical contract identifiers

- Schema: `skg.ad.tiering_input.v1`
- Filename: `ad22_tiering_input.json`
- Wicket semantic target: `AD-22`

### Producer/consumer ownership

1. Producer (service/runtime):
- `skg_services.gravity.ad_runtime.build_ad22_tiering_input`
- `skg_services.gravity.ad_runtime.route_bloodhound_ad22_evidence`

2. Runtime router (service/runtime):
- `skg/sensors/adapter_runner.py` uses protocol filename constant for sidecar lookup

3. Consumer (service/runtime gateway):
- `skg_services.gravity.ad_runtime.map_ad22_sidecar_to_events`
- validates sidecar payload against protocol contract before invoking domain adapter

4. Semantic interpreter (AD domain):
- `skg_domain_ad.adapters.ad_tiering_posture.map_tiering_posture_to_events`
- validates payload contract and emits semantic status with validation metadata

## Governance Tightening Applied In Phase 7M

1. Single protocol contract source of truth added.
- No duplicate schema literals for sidecar id/filename in runtime codepaths.

2. Fail-closed sidecar routing in services.
- Invalid or malformed sidecar payloads now raise in service routing adapter and are skipped by runtime caller handling.

3. Domain-side validation transparency.
- Domain adapter includes validation errors in `AD-TI-01` attributes for observability.

## Explicit Versioning Note

- Any breaking change to sidecar required fields or semantics must:
  1. introduce a new schema id (`skg.ad.tiering_input.v2`),
  2. preserve `v1` compatibility path until callers are migrated,
  3. update protocol contract tests and service/domain adapter validation behavior.

## Guardrail Against Legacy Authority Drift

- `skg-ad-lateral-toolchain/contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json` and `skg-ad-lateral-toolchain/projections/lateral/run.py` remain non-canonical for AD domain slice authority.
- Canonical AD slice semantics must continue to route through:
  - protocol contracts,
  - domain-pack ontology/policies/adapters/projector,
  - service-owned runtime wrappers.

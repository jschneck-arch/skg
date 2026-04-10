# Phase 7A Domain Boundaries

Date: 2026-04-02

## Ownership Decisions

1. Services own runtime and transport (unchanged).
- No runtime execution was migrated into `skg_domain_ad`.
- No LDAP/BloodHound API client code was moved into domain adapters.

2. AD domain pack owns slice semantics.
- Domain-owned semantic mapping:
  - `packages/skg-domains/ad/src/skg_domain_ad/adapters/ad_privileged_membership/run.py`
- Domain-owned ontology/policies/projector:
  - `packages/skg-domains/ad/src/skg_domain_ad/ontology/**`
  - `packages/skg-domains/ad/src/skg_domain_ad/policies/**`
  - `packages/skg-domains/ad/src/skg_domain_ad/projectors/ad/run.py`

3. Core/protocol boundaries preserved.
- Adapter emits canonical envelopes via `skg_protocol.events` contracts.
- Projector uses `skg_core.substrate.projection` substrate mechanics.
- No AD-domain imports in core/protocol packages.

4. Cross-domain contamination explicitly avoided.
- Did not migrate host semantics.
- Did not migrate redteam exploit-path semantics.
- Did not migrate broad ad-lateral ACL/delegation/DCSync chains in this phase.

## Boundary Violations Avoided

- No `sys.path` hacks in canonical AD package.
- No hardcoded layout assumptions (`/opt/skg` style) in canonical AD package.
- No service runtime code placed in AD adapter/projector modules.

## Remaining Boundary Risks

| Path | Risk | Status |
|---|---|---|
| `skg-ad-lateral-toolchain/adapters/bloodhound/parse.py` | Mixed many-slice AD attack semantics still in one legacy file. | deferred |
| `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` | Source-specific parsing plus mixed wicket semantics across multiple slices. | deferred |
| `skg/sensors/bloodhound_sensor.py` | Runtime client + normalization + adapter coupling in one service module. | deferred |
| `skg-gravity/adapters/ldap_enum.py` | Runtime execution mixed with ad_lateral semantics and legacy imports/path handling. | deferred |

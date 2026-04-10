# Phase 5B Web Boundaries

Date: 2026-04-01

## Boundary Hardening Decisions

1. Domain adapters remain mapping-only.
- `packages/skg-domains/web/src/skg_domain_web/adapters/web_surface_fingerprint/run.py`
- `packages/skg-domains/web/src/skg_domain_web/adapters/web_nikto_findings/run.py`
- Both consume pre-collected findings/profiles and emit canonical protocol envelopes.
- Neither executes subprocess scanners, socket transport, or daemon orchestration.

2. Policies are explicit domain artifacts.
- `packages/skg-domains/web/src/skg_domain_web/policies/surface_fingerprint_policy.yaml`
- `packages/skg-domains/web/src/skg_domain_web/policies/nikto_adapter_policy.yaml`
- Confidence and wicket selection logic moved out of hidden adapter conditionals.

3. Mapping artifacts are explicit and domain-owned.
- `packages/skg-domains/web/src/skg_domain_web/mappings/surface_fingerprint_rules.yaml`
- `packages/skg-domains/web/src/skg_domain_web/mappings/nikto_patterns.yaml`
- Pattern/rule ownership is now in domain pack data, not in runtime wrappers.

4. Projector ownership stayed domain-local.
- Existing projector remains under `packages/skg-domains/web/src/skg_domain_web/projectors/web/run.py`.
- No projector execution runtime was moved into domain pack.

5. Protocol emission remains contract-driven.
- New adapters emit through `skg_protocol.events.build_event_envelope` and `build_precondition_payload`.
- No adapter emits bespoke event schema.

6. Registry owns discovery behavior.
- Manifest authority and component path resolution are implemented in `skg-registry`, not in domain package bootstrap code.

## Boundary Violations Prevented In Phase 5B

- No `sys.path` mutation in migrated web domain modules.
- No `/opt/skg` layout assumptions in migrated web domain modules.
- No `subprocess` nikto invocation in domain adapters.
- No transport socket/TLS probing in domain adapters.
- No gravity/claw runtime imports in web domain package.

## Residual Boundary Risks

1. Legacy runtime wrappers still exist in `skg-web-toolchain/adapters/web_active/*` and are still invoked by active callsites:
- `skg/cli/commands/target.py` -> `web_active/collector.py`
- `skg-gravity/gravity_field.py` -> `web_active/collector.py`, `web_active/nikto_adapter.py`
2. Registry legacy fallback (`domain.yaml`) is still enabled for non-migrated packs; this is intentional compatibility, not authority for web.
3. Some legacy operators may still bypass registry and read toolchain files directly.

## Follow-On Requirement

Before Phase 5C/next-domain expansion, migrate remaining live runtime callsites to service-owned runtime modules that invoke domain mapping adapters, then retire direct legacy adapter entrypoints.

# Phase 7K AD-22 Runtime Ledger

Date: 2026-04-02

## Runtime Seam Corrections

| File path | Old behavior | New behavior | Ownership classification | Rationale | Unresolved risk |
|---|---|---|---|---|---|
| `skg/sensors/adapter_runner.py` | `run_bloodhound()` executed legacy BloodHound checks and returned legacy AD-22 static `unknown` output unchanged. No canonical AD-22 input routing happened. | Added `_route_ad22_runtime_evidence()` call inside `run_bloodhound()` to route `sessions.json` + computer inventory into canonical AD-shaped input. Added `_drop_legacy_ad22_events()` so legacy AD-22 output is quarantined from active runtime events. | Service/runtime evidence routing + legacy shim containment | Keeps runtime ownership in services, removes static legacy AD-22 semantics from active output, and prepares canonical AD domain handoff. | AD-22 canonical event emission is still deferred until the dedicated AD-22 slice migration. |
| `packages/skg-services/src/skg_services/gravity/ad_runtime.py` | No canonical AD runtime wrapper existed for AD-22 evidence shaping. | Added service-owned wrapper functions: `load_bloodhound_session_rows()`, `build_ad22_tiering_input()`, `route_bloodhound_ad22_evidence()`. Writes `ad22_tiering_input.json` sidecar with normalized session evidence and tiering summary scaffold. | Service/runtime wrapper consuming AD-domain helpers | Establishes canonical runtime input shape without migrating the full AD-22 slice. | Sidecar artifact is not yet consumed by a canonical AD-22 adapter in production flow. |
| `skg/sensors/bloodhound_sensor.py` | `sessions.json` write path was documented as legacy-only helper usage. | Updated comments to clarify sessions are routed by runtime seam into canonical AD-domain input shape. | Service/runtime collection | Makes active ownership explicit and prevents silent drift back to legacy-only semantics. | Comment-only; behavior change is enforced in `adapter_runner`, not this file. |
| `skg-gravity/adapters/ldap_enum.py` | Emitted `wicket_id="AD-22"` for LDAP account enumeration, conflicting with canonical AD-22 tiering meaning. | Renamed branch to quarantined legacy signal `AD-22-LDAP-LEGACY` with explicit quarantine note; no longer defines canonical AD-22 semantics. | Legacy compatibility (quarantined semantics) | Removes conflicting AD-22 authority from legacy runtime code. | Downstream consumers reading raw legacy AD-22 from this adapter must be updated to the quarantined ID or removed. |

## Tests Added / Updated

| Test file | Coverage added |
|---|---|
| `packages/skg-services/tests/test_ad_runtime_wrappers.py` | Validates canonical AD-22 sidecar generation and proves runtime sessions now reach canonical AD-shaped input path via `run_bloodhound()`. Also validates AD-22 legacy static output is quarantined. |

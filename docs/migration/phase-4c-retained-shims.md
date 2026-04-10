# Phase 4C Retained Shims

Date: 2026-04-01  
Scope: shims intentionally retained after Wave 1–2 deletion.

## Retained Compatibility Branches

| Legacy file | Retained symbol/branch | Reason retained | Expected future removal phase |
|---|---|---|---|
| `skg/sensors/projector.py` | top-level `try/except` around `from skg_services.gravity import projector_runtime as _service_projector_runtime`; fallback local runtime implementation and function rebinding | Runtime callsites were migrated, but legacy tests still import this module directly (`tests/test_runtime_regressions.py`, `tests/test_sensor_projection_loop.py`). | Phase 4C Wave 3 after canonical-only projector tests replace legacy-shim tests. |
| `skg/sensors/__init__.py` | fallback imports for protocol contracts (`_protocol_build_event_envelope`, `_protocol_build_precondition_payload`) and event writer (`_service_emit_events`) | Sensor modules still preserve transitional compatibility when canonical packages are unavailable; Wave 1–2 did not target contract/writer fallback deletion. | Phase 4C Wave 3 (sensor contract/writer fallback removal). |
| `skg/kernel/adapters.py` | optional protocol/service imports and internal fallback logic in `event_to_observation` and `load_observations_for_node` | Legacy kernel adapters still serve compatibility tests and non-canonical paths. | Phase 4C Wave 4 once canonical-only kernel ingestion is enforced. |
| `skg/substrate/projection.py` | optional service collapse imports and fallback implementations of `load_states_from_events*` | Legacy substrate module still used by compatibility tests and transitional callsites. | Phase 4C Wave 4 after canonical substrate imports are universal. |
| `skg/core/domain_registry.py` | compatibility API (`load_domain_inventory`, `load_daemon_domains`, `summarize_domain_inventory`) and fallback logic | Runtime callsites for Wave 2 were removed, but compatibility tests still exercise this module directly. | Final retirement in Phase 5 readiness cleanup after test migration. |
| `skg/core/paths.py` | compatibility constants (`SKG_HOME`, `SKG_STATE_DIR`, `EVENTS_DIR`, etc.) and `ensure_runtime_dirs()` | High-footprint runtime modules still rely on constant imports; broad path-context migration is explicitly out of Wave 1–2 scope. | Phase 4D paths migration (required before aggressive shim deletion). |

## Retained Test Dependencies

| File | Retained dependency | Rationale |
|---|---|---|
| `tests/test_runtime_regressions.py` | imports `skg.kernel.adapters`, `skg.sensors.projector`, `skg.sensors` wrappers | Validates legacy compatibility behavior intentionally. |
| `tests/test_sensor_projection_loop.py` | imports `skg.sensors.projector` and legacy substrate projection loaders | Exercises legacy shim behavior and projection loop compatibility. |

## Notes

- Wave 1–2 deletion removed preferred runtime fallbacks only.
- Remaining shims are explicit and bounded to compatibility surfaces not yet migrated.

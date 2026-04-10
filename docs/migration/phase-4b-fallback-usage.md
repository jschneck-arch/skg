# Phase 4B Remaining Fallback Usage

Date: 2026-04-01  
Scope: residual dependencies on legacy split modules after callsite migration.

## Remaining Fallback Dependencies

| Legacy file | Still-used symbol/path | Who still depends on it | Why it could not yet be removed | Exact future step to eliminate |
|---|---|---|---|---|
| `skg/sensors/projector.py` | `project_events_dir`, `project_event_file`, `project_events` (fallback import branch) | `skg/sensors/__init__.py`, `skg/cli/commands/derived.py`, `skg/cli/commands/exploit.py`, `skg/core/daemon.py` fallback branches | Runtime must continue to work when canonical packages are not on import path. | Make canonical package imports mandatory in runtime bootstrap; remove fallback `except` imports and pin to `skg_services.gravity.projector_runtime`. |
| `skg/sensors/projector.py` | `_discover_toolchain_projector`, `_projector_cache` fallback branch | `skg/forge/generator.py` fallback branch | Forge install path still tolerates legacy-only environments. | Introduce a public projector registration API in `skg-services`; migrate forge to that API; delete private fallback import. |
| `skg/core/domain_registry.py` | `load_daemon_domains`, `summarize_domain_inventory` fallback import branch | `skg/core/daemon.py` fallback branch (`_load_domains_and_inventory`) | Daemon still supports environments without canonical registry/service package availability. | Require canonical package availability at daemon start; remove fallback branch and legacy imports. |
| `skg/core/domain_registry.py` | `load_domain_inventory` fallback import branch | `skg/core/coupling.py`, `skg/sensors/dark_hypothesis_sensor.py`, `skg/sensors/projector.py` fallback paths | These modules now prefer `skg_registry`, but fallback is retained for compatibility. | After package bootstrap is canonical-only, delete fallback branches and import `DomainRegistry` directly. |
| `skg/sensors/__init__.py` | `envelope`, `precondition_payload`, `emit_events` fallback branch | Multiple sensors fallback paths: `gpu_probe`, `boot_probe`, `struct_fetch`, `process_probe`, `net_sensor`, `cve_sensor`, `msf_sensor`, `web_sensor`, `ssh_sensor`, `usb_sensor`, `agent_sensor`, `bloodhound_sensor`, `cognitive_sensor`, and `adapter_runner` | Sensor modules now import canonical protocol/service first, but keep fallback compatibility for legacy runtime packaging. | Remove fallback imports in sensor modules after canonical package availability is enforced and integration tests pass in canonical-only mode. |
| `skg/kernel/adapters.py` | `_decay_class` fallback branch | `skg/kernel/folds.py` fallback branch | Fold detector now prefers protocol decay policy, but fallback retained for non-canonical package path installs. | Remove fallback import and use protocol decay function unconditionally once canonical packages are mandatory. |
| `skg/substrate/projection.py` | legacy `project_path` / event-collapse entrypoints | `skg/intel/redteam_to_data.py` fallback branch; tests that import legacy substrate modules | Some runtime/test paths still import legacy substrate package directly. | Migrate those importers to `skg_core.substrate.*`; update tests; remove legacy import fallback. |
| `skg/core/paths.py` | compatibility constants (`EVENTS_DIR`, `SKG_STATE_DIR`, `SKG_HOME`, etc.) | Broad legacy runtime footprint (`daemon`, `cli`, `intel`, `training`, `resonance`, `assistant`, `sensors`, etc.) | This is the largest unresolved compatibility surface; canonical `skg_core.config.paths` API is object-based and not drop-in for all constants yet. | Phase 4C/5 introduce explicit path-context wiring (`resolve_paths()`/service path policy) in runtime entrypoints, then collapse constant imports module-by-module. |
| `skg/kernel/adapters.py` and `skg/sensors/projector.py` | direct legacy usage in tests | `tests/test_runtime_regressions.py`, `tests/test_sensor_projection_loop.py` | Regression tests intentionally validate legacy shim behavior. | Split test suites into canonical-runtime tests vs legacy-compat tests; gate fallback deletion behind canonical suite parity. |

## Live Legacy-Module Import Footprint (Post-4B)

- `skg.core.paths` remains widely imported in runtime modules and is the highest-volume unresolved legacy dependency.
- Legacy projector and domain-registry fallbacks now exist primarily as guarded compatibility branches, not preferred paths.
- Sensor contract/event-emission callsites now prefer canonical protocol/service modules by default.

## Assessment

- Preferred runtime path is now canonical for migrated callsites.
- Remaining fallback usage is explicit and bounded.
- Fallback removal is feasible, but only after enforcing canonical package import availability and updating broad `skg.core.paths` consumers.

# Phase 4B Callsites Ledger

Date: 2026-04-01  
Scope: migrate active runtime callsites from legacy split modules to canonical package paths, with compatibility fallback only where required.

## Runtime Projector Callsites

| Original file | Original import/call target | New canonical target | Why migration was safe | Remaining compatibility risk |
|---|---|---|---|---|
| `skg/cli/commands/derived.py` | `skg.sensors.projector.project_events_dir` | `skg_services.gravity.projector_runtime.project_events_dir` | Same call signature and output contract (`list[Path]`); module already extracted in Phase 4A. | Fallback retained if `skg-services` import fails in non-canonical runtime env. |
| `skg/cli/commands/exploit.py` | `skg.sensors.projector.project_events` | `skg_services.gravity.projector_runtime.project_events` | Binary-event projection already uses generic projector runtime contract; canonical implementation handles same grouping/output semantics. | Fallback retained for environments not loading canonical package paths. |
| `skg/core/daemon.py` (`/collect`) | `skg.sensors.projector.project_events_dir` | `skg_services.gravity.projector_runtime.project_events_dir` | Daemon single-target collection path only needs directory projection entrypoint; canonical service runtime is authoritative owner. | Fallback retained behind guarded import. |
| `skg/sensors/__init__.py` (`SensorLoop._auto_project_all`) | `skg.sensors.projector.project_events_dir`, `project_event_file` | `skg_services.gravity.projector_runtime.project_events_dir`, `project_event_file` | Sensor loop already passes same `(events_dir, interp_dir, run_id/since_run_id)` data expected by canonical runtime. | Legacy projector fallback still used if canonical service import fails. |
| `skg/forge/generator.py` | `skg.sensors.projector._discover_toolchain_projector`, `_projector_cache` | `skg_services.gravity.projector_runtime._discover_toolchain_projector`, `_projector_cache` | Install-time projector registration logic aligns with service-owned runtime discovery path; avoids re-entering legacy projector module by default. | Uses private symbols; API stability depends on service runtime internals until a public hook is introduced. |

## Registry/Domain Runtime Callsites

| Original file | Original import/call target | New canonical target | Why migration was safe | Remaining compatibility risk |
|---|---|---|---|---|
| `skg/core/daemon.py` (global domain bootstrap) | `skg.core.domain_registry.load_daemon_domains`, `summarize_domain_inventory` | `skg_registry.DomainRegistry.discover` + `skg_services.gravity.domain_runtime.load_daemon_domains_from_inventory` | Canonical registry now owns discovery; service module owns daemon-native runtime policy. Daemon now composes them directly. | Fallback to legacy registry retained when canonical packages are unavailable at import/runtime. |
| `skg/core/coupling.py` (`validate_payload`) | `skg.core.domain_registry.load_domain_inventory` | `skg_registry.DomainRegistry.discover().list_domains()` | Validation only needs known domain names; canonical registry returns authoritative names without service coupling. | Fallback retained for legacy-only environments. |
| `skg/sensors/dark_hypothesis_sensor.py` (`_available_instruments`) | `skg.core.domain_registry.load_domain_inventory` | `skg_registry.DomainRegistry.discover().list_domains()` normalized to instrument rows | Sensor only needs domain/toolchain/catalog descriptors; canonical records provide these directly. | Fallback retained for legacy-only environments. |
| `skg/sensors/projector.py` (legacy fallback module internals) | `skg.core.domain_registry.load_domain_inventory` + `SKG_HOME` existence checks | `skg_registry.DomainRegistry.discover().list_domains()` via `_domain_inventory_rows()` | Even fallback projector now prefers canonical registry rows; removes direct legacy registry/path dependency from preferred path. | Legacy registry import remains in fallback branch if canonical registry package import fails. |

## Protocol/Core Callsites

| Original file | Original import/call target | New canonical target | Why migration was safe | Remaining compatibility risk |
|---|---|---|---|---|
| `skg/kernel/folds.py` (`detect_temporal`) | `skg.kernel.adapters._decay_class` | `skg_protocol.observation_mapping.decay_class_for_event` | Decay classification is protocol mapping policy, not kernel adapter runtime concern. | Fallback to legacy adapter decay kept for package-availability compatibility. |
| `skg/intel/redteam_to_data.py` (`report`) | `skg.substrate.node`, `skg.substrate.path`, `skg.substrate.projection.project_path` | `skg_core.substrate.node`, `skg_core.substrate.path`, `skg_core.substrate.projection.project_path` | Reporting path projection is substrate logic and now points to canonical core substrate implementation. | Legacy substrate fallback retained because some environments/tests still import legacy substrate package directly. |
| `skg/sensors/adapter_runner.py` (`_analyze_aprs_direct`) | `skg.sensors.envelope`, `skg.sensors.precondition_payload` | `skg_protocol.events.build_event_envelope`, `build_precondition_payload` | Event-building is protocol contract logic; callsite was contract-only. | Fallback retained for environments without canonical protocol import path. |

## Sensor Event Contract/Emission Callsites Migrated

| Original file | Original import/call target | New canonical target | Why migration was safe | Remaining compatibility risk |
|---|---|---|---|---|
| `skg/sensors/gpu_probe.py` | `skg.sensors.envelope`, `precondition_payload` | `skg_protocol.events.build_event_envelope`, `build_precondition_payload` | Pure event contract usage; no runtime scheduler dependency. | Fallback to legacy wrapper retained. |
| `skg/sensors/boot_probe.py` | `skg.sensors.envelope`, `precondition_payload` | `skg_protocol.events.*` | Same contract parameters; direct protocol import removes legacy indirection. | Fallback retained. |
| `skg/sensors/struct_fetch.py` | `skg.sensors.envelope`, `precondition_payload` | `skg_protocol.events.*` | Structured fetcher only builds observation envelopes/payloads. | Fallback retained. |
| `skg/sensors/process_probe.py` | `skg.sensors.envelope`, `precondition_payload` | `skg_protocol.events.*` | Probe emits precondition events only; contract path is canonical. | Fallback retained. |
| `skg/sensors/net_sensor.py` | `skg.sensors.envelope`, `precondition_payload` | `skg_protocol.events.*` | Network sensor event generation is contract-level. | Fallback retained. |
| `skg/sensors/cve_sensor.py` | `skg.sensors.envelope`, `precondition_payload` | `skg_protocol.events.*` | CVE sensor emits protocol envelopes; no need for legacy wrapper. | Fallback retained. |
| `skg/sensors/msf_sensor.py` | `skg.sensors.envelope`, `precondition_payload` | `skg_protocol.events.*` | MSF sensor uses envelope contract directly. | Fallback retained. |
| `skg/sensors/web_sensor.py` | `skg.sensors.envelope`, `precondition_payload`; `skg.sensors.emit_events` | `skg_protocol.events.*`; `skg_services.gravity.event_writer.emit_events` | Event creation and event-file emission now point to canonical protocol/service owners. | Fallback retained for both imports. |
| `skg/sensors/ssh_sensor.py` | `skg.sensors.envelope`, `precondition_payload`; `skg.sensors.emit_events` | `skg_protocol.events.*`; `skg_services.gravity.event_writer.emit_events` | Same event contract and emission interface. | Fallback retained for both imports. |
| `skg/sensors/usb_sensor.py` | `skg.sensors.envelope`; `skg.sensors.emit_events` | `skg_protocol.events.build_event_envelope`; `skg_services.gravity.event_writer.emit_events` | USB path only needed envelope creation and write helper. | Fallback retained for both imports. |
| `skg/sensors/bloodhound_sensor.py` | `skg.sensors.emit_events` | `skg_services.gravity.event_writer.emit_events` | Sensor output writing is service runtime concern. | Fallback retained. |
| `skg/sensors/agent_sensor.py` | `skg.sensors.emit_events` | `skg_services.gravity.event_writer.emit_events` | Same semantics for event file emission; service owner now explicit. | Fallback retained. |
| `skg/sensors/cognitive_sensor.py` | `skg.sensors.emit_events` | `skg_services.gravity.event_writer.emit_events` | Cognitive sensor only needs event write helper; canonical service module is the proper owner. | Fallback retained. |

## Validation Snapshot

- Compile: `python -m compileall packages/skg-core/src packages/skg-protocol/src packages/skg-registry/src packages/skg-services/src`.
- Tests: `PYTHONPATH=packages/skg-core/src:packages/skg-protocol/src:packages/skg-registry/src:packages/skg-services/src:$PYTHONPATH pytest packages/skg-core/tests packages/skg-protocol/tests packages/skg-registry/tests packages/skg-services/tests`.
- Legacy shim syntax check: `python -m py_compile skg/kernel/adapters.py skg/substrate/projection.py skg/sensors/__init__.py skg/sensors/projector.py skg/core/domain_registry.py skg/core/paths.py`.

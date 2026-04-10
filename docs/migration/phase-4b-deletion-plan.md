# Phase 4B Deletion Readiness Plan

Date: 2026-04-01  
Scope: controlled preparation for Phase 4C fallback deletion.

## Readiness Summary

- Canonical runtime path is now preferred in migrated callsites.
- Compatibility fallbacks are still required for:
  - environments where canonical package import paths are not guaranteed,
  - broad `skg.core.paths` constant consumers,
  - legacy regression tests that intentionally exercise shim behavior.
- Result: partial deletion readiness. Projector/registry/sensor wrapper fallbacks can be deleted in controlled waves after bootstrap hardening; `skg.core.paths` deprecation requires a later wave.

## Phase 4C Candidate Deletion Waves

### Wave 1: Projector Runtime Fallback Removal (High readiness)

Objective:
- Remove fallback imports to `skg.sensors.projector` in migrated callsites.

Files:
- `skg/sensors/__init__.py`
- `skg/cli/commands/derived.py`
- `skg/cli/commands/exploit.py`
- `skg/core/daemon.py`
- `skg/forge/generator.py`

Delete/replace:
- Remove `except` branches importing `skg.sensors.projector`.
- Keep only `skg_services.gravity.projector_runtime` imports.

Preconditions:
- Canonical package paths are guaranteed at runtime (installed packages or enforced `PYTHONPATH`).

Validation gates:
- Existing package test suite (core/protocol/registry/services).
- Runtime smoke: sensor loop auto-projection, `skg derived rebuild`, binary exploit projection, forge projector registration.

Rollback:
- Reintroduce fallback branches from this phase’s git history; no data migration required.

### Wave 2: Registry Fallback Removal (Medium-high readiness)

Objective:
- Remove fallback imports to `skg.core.domain_registry` where canonical registry/service policy now exists.

Files:
- `skg/core/daemon.py`
- `skg/core/coupling.py`
- `skg/sensors/dark_hypothesis_sensor.py`
- `skg/sensors/projector.py`

Delete/replace:
- Remove fallback branches importing `load_domain_inventory`/`load_daemon_domains`/`summarize_domain_inventory`.
- Use only `skg_registry.DomainRegistry` + `skg_services.gravity.domain_runtime` composition.

Preconditions:
- Domain discovery parity verified between canonical registry and legacy inventory for active domains.

Validation gates:
- Daemon API `/api` domain inventory output sanity.
- Coupling validation command path (if used) covers known domains.
- Dark hypothesis instrument discovery lists same or stricter set.

Rollback:
- Restore fallback import blocks and helper branches.

### Wave 3: Sensor Contract/Writer Fallback Removal (Medium readiness)

Objective:
- Remove fallback imports back to `skg.sensors` wrappers for event contracts and emission.

Files:
- `skg/sensors/{gpu_probe,boot_probe,struct_fetch,process_probe,net_sensor,cve_sensor,msf_sensor,web_sensor,ssh_sensor,usb_sensor,bloodhound_sensor,agent_sensor,cognitive_sensor}.py`
- `skg/sensors/adapter_runner.py`

Delete/replace:
- Remove `except` imports to legacy `skg.sensors` envelope/precondition/emit wrappers.
- Keep only `skg_protocol.events` + `skg_services.gravity.event_writer`.

Preconditions:
- Canonical package availability enforced globally.
- Sensor sweep integration test run across enabled sensors.

Validation gates:
- Sensor sweep smoke run in daemon mode.
- Event file output + projector pass for generated events.

Rollback:
- Re-add fallback imports per file (mechanical revert).

### Wave 4: Kernel/Substrate Fallback Cleanup (Medium readiness)

Objective:
- Remove remaining legacy fallback to adapter/substrate shims in migrated callsites.

Files:
- `skg/kernel/folds.py`
- `skg/intel/redteam_to_data.py`

Delete/replace:
- Remove fallback imports to `skg.kernel.adapters._decay_class` and legacy substrate modules.
- Keep canonical protocol/core imports only.

Preconditions:
- Legacy regression tests updated to canonical-runtime expectations.

Validation gates:
- Fold detection regression tests.
- Redteam-to-data report projection checks.

Rollback:
- Restore fallback imports from git.

### Wave 5: `skg.core.paths` Compatibility Collapse (Low readiness, later than 4C)

Objective:
- Retire broad dependency on `skg.core.paths` constants.

Files:
- High-footprint runtime/cli/intel/resonance/training modules currently importing constants.

Delete/replace:
- Replace constant imports with resolved path context (`skg_core.config.paths.resolve_paths` and/or `skg_services.gravity.path_policy`).
- Remove compatibility constants from `skg.core.paths` only after all consumers migrate.

Preconditions:
- Introduce and adopt a shared runtime path-context injection pattern.

Validation gates:
- Full daemon + CLI smoke tests.
- File-output path invariants across events/interp/discovery/logging.

Rollback:
- Keep `skg.core.paths` compatibility module until parity is proven; do not hard-delete early.

## Explicit No-Delete List for Immediate 4C

Do not delete yet:
- `skg/core/paths.py` compatibility constants.
- Legacy regression tests that validate shim behavior.
- Fallback branches that guard package import availability until canonical bootstrap is enforced.

## Deletion Decision

- Recommended immediate next step: **Phase 4C controlled fallback deletion**, Waves 1-2 first.
- Domain-pack migration (Phase 5) should start only after Waves 1-2 land cleanly and runtime bootstrap is canonical-only.

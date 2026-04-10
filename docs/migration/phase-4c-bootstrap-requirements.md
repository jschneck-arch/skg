# Phase 4C Bootstrap Requirements

Date: 2026-04-01  
Scope: canonical bootstrap enforcement after Wave 1–2 fallback deletion.

## Canonical Package Requirements

Runtime now requires the canonical package stack to be importable:

- `skg-core`
- `skg-protocol`
- `skg-registry`
- `skg-services`

If running from source tree, ensure `PYTHONPATH` includes:

- `packages/skg-core/src`
- `packages/skg-protocol/src`
- `packages/skg-registry/src`
- `packages/skg-services/src`

## Enforced Fail-Fast Paths (No Legacy Fallback)

Wave 1 enforced canonical projector runtime imports in:

- `skg/cli/commands/derived.py`
- `skg/cli/commands/exploit.py`
- `skg/core/daemon.py` (`/collect` path)
- `skg/forge/generator.py`
- `skg/sensors/__init__.py` (`SensorLoop._auto_project_all`)

Wave 2 enforced canonical registry/runtime composition imports in:

- `skg/core/daemon.py`
- `skg/core/coupling.py`
- `skg/sensors/dark_hypothesis_sensor.py`
- `skg/sensors/projector.py` (registry lookup path)

Behavior change:
- Missing canonical package imports now raise immediately (import-time failure) instead of silently falling back to legacy modules.

## Bootstrap Verification

Targeted enforcement test:
- [test_phase4c_bootstrap_enforcement.py](/opt/skg/packages/skg-services/tests/test_phase4c_bootstrap_enforcement.py)

Validation command used in this phase:

```bash
PYTHONPATH=packages/skg-core/src:packages/skg-protocol/src:packages/skg-registry/src:packages/skg-services/src:$PYTHONPATH \
python - <<'PY'
from skg.cli.commands.derived import _rebuild_interp_from_events
from skg.cli.commands.exploit import _project_binary_events
import skg.core.daemon as daemon

print('derived_fn', callable(_rebuild_interp_from_events))
print('exploit_fn', callable(_project_binary_events))
print('domains_loaded', isinstance(daemon.DOMAINS, dict), len(daemon.DOMAIN_INVENTORY))
PY
```

## Not Enforced Yet

These compatibility surfaces are intentionally still allowed and will be handled in later phases:

- `skg/sensors/__init__.py` envelope/event-writer fallback wrappers
- `skg/kernel/adapters.py` compatibility fallback logic
- `skg/substrate/projection.py` compatibility fallback logic
- `skg/core/domain_registry.py` compatibility API (used by legacy tests)
- `skg/core/paths.py` compatibility constants (broad runtime dependency)

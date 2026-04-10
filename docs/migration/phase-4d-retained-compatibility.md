# Phase 4D Retained Compatibility

Date: 2026-04-01  
Scope: explicit compatibility surface left after active-runtime migration off `skg.core.paths`.

## Current State

- Active runtime tree (`skg/`) has `0` live `from skg.core.paths import ...` callsites.
- `skg/core/paths.py` remains as a compatibility shim only.
- Remaining legacy imports are isolated to non-canonical trees and archived/deploy mirrors.

## Retained Compatibility Items

| Legacy symbol/path | Who still depends on it | Why retained | Exact next step for removal |
|---|---|---|---|
| `skg/core/paths.py` module | External/legacy callers and non-canonical trees | Needed as a controlled compatibility boundary while old trees are still present. | Phase 5+: finish migration of remaining live legacy trees; then replace shim with hard-fail import guard and remove exports in Phase 8 cleanup. |
| `TOOLCHAIN_DIR`, `CE_TOOLCHAIN_DIR`, `AD_TOOLCHAIN_DIR`, `HOST_TOOLCHAIN_DIR`, `WEB_TOOLCHAIN_DIR` (exported by shim via service policy) | `skg/core/daemon.py`; legacy mirror `skg_deploy/skg/core/daemon.py` | Transitional support for layout-coupled toolchain execution paths; not canonical architecture. | Phase 5/6: move daemon/toolchain resolution to registry/domain manifests and delete direct toolchain dir constants from daemon. |
| `MSF_DIR`, `BH_DIR` compatibility exports | `skg/core/paths.py` compatibility surface only | No active canonical caller; retained only to avoid breaking external scripts importing old constants. | Phase 6+: remove once no imports remain outside shim; enforce service policy object access instead of globals. |
| `RESONANCE_INDEX`, `RESONANCE_RECORDS`, `RESONANCE_DRAFTS` compatibility exports | `skg/core/paths.py` compatibility surface only | Internal layout constants retained for backward import compatibility. | Phase 6+: replace with `ServicePathPolicy` field access in any remaining consumers, then delete exports. |
| Legacy import callsites in `skg-gravity/*.py` | `skg-gravity/cred_reuse.py`, `skg-gravity/exploit_dispatch.py`, `skg-gravity/exploit_proposals.py`, `skg-gravity/gravity_field.py` | `skg-gravity` is legacy runtime tree and out of canonical package path. | Phase 6: migrate/retire `skg-gravity` into `packages/skg-services/gravity` or archive the tree. |
| Legacy import callsites in `skg_deploy/**` | `skg_deploy/skg/**`, `skg_deploy/skg-gravity/**` | Deploy mirror is non-canonical staging/deploy copy; should not drive architecture decisions. | Phase 8: archive `skg_deploy/` under `archive/` and remove from active validation matrix. |
| Legacy import in `skg-data-toolchain/adapters/db_profiler/profile.py` | DB profiler adapter in legacy toolchain tree | Toolchain tree is not yet domain-packed; still legacy runtime artifact. | Phase 5: move adapter ownership into domain pack and switch to canonical path API, then delete legacy import. |
| Legacy import callsites under `.claude/worktrees/**` | Worktree mirrors only | Generated/staging worktrees are not canonical runtime code. | Immediate: ignore for runtime; archive/prune as workspace artifacts outside migration completion criteria. |

## Explicitly Removed From Active Runtime Path

- `from skg.core.paths import ...` usage in active `skg/` runtime modules.
- Legacy test patch targets pointing at `skg.core.paths` for active runtime paths.

## Compatibility Boundary Rules Going Forward

- New code may not import from `skg.core.paths`.
- Any compatibility-only symbol in `skg_services.gravity.path_policy` must be treated as transitional and documented with removal phase.
- Non-canonical trees (`skg_deploy`, `skg-gravity`, `.claude/worktrees`) are not allowed to block canonical path ownership progression.

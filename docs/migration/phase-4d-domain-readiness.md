# Phase 4D Domain-Pack Readiness

Date: 2026-04-01  
Objective: determine whether path/config ownership normalization is sufficient to begin Phase 5 domain-pack migration.

## Readiness Checks

| Check | Result | Evidence |
|---|---|---|
| Active runtime callsites off legacy `skg.core.paths` | PASS | `rg "from skg\.core\.paths import" skg tests -g'*.py'` returns no active runtime callsites. |
| Core path primitives centralized | PASS | [`packages/skg-core/src/skg_core/config/paths.py`](/opt/skg/packages/skg-core/src/skg_core/config/paths.py) now owns canonical primitives (`SKG_HOME`, `SKG_STATE_DIR`, `EVENTS_DIR`, `INTERP_DIR`, `DISCOVERY_DIR`, `DELTA_DIR`, etc.). |
| Service path policy centralized | PASS | [`packages/skg-services/src/skg_services/gravity/path_policy.py`](/opt/skg/packages/skg-services/src/skg_services/gravity/path_policy.py) now owns service/runtime policy constants and runtime dir creation. |
| Legacy shim reduced to compatibility-only delegation | PASS | [`skg/core/paths.py`](/opt/skg/skg/core/paths.py) no longer resolves paths independently; it delegates to canonical core/service modules. |
| Domain packages depend on legacy path shim | PASS | No `skg.core.paths` references under `packages/skg-domains/**`. |
| Fail-fast/fallback reduction test coverage | PASS | Added tests: [`packages/skg-core/tests/test_config_paths.py`](/opt/skg/packages/skg-core/tests/test_config_paths.py), [`packages/skg-services/tests/test_path_policy.py`](/opt/skg/packages/skg-services/tests/test_path_policy.py). |

## Remaining Risks Before/During Phase 5

| Risk | Severity | Impact | Containment |
|---|---|---|---|
| Toolchain directory constants are still transitional (`TOOLCHAIN_DIR`, `*_TOOLCHAIN_DIR`) | MEDIUM | Can preserve legacy layout coupling in daemon runtime. | Keep constants service-owned only; remove when daemon/toolchain resolution shifts to registry/domain manifests. |
| Legacy non-canonical trees still import `skg.core.paths` (`skg-gravity`, `skg_deploy`, `skg-data-toolchain`) | MEDIUM | Confusing dual authority if treated as live runtime. | Treat these trees as legacy/archival inputs only; do not use as canonical source during domain-pack migration. |
| Module-level constants are import-time resolved | LOW | Tests/runtime that mutate env after import can misread path values. | Use `resolve_paths()` / `build_service_path_policy()` in new code paths requiring dynamic env behavior. |

## Gate Decision

- **Recommendation:** `ready for Phase 5 domain-pack migration`.
- **Condition:** Phase 5 must treat toolchain-dir constants as transitional compatibility and avoid introducing new dependencies on them.
- **Condition:** Domain-pack migration must source code from canonical trees (`packages/*`, active `skg/*` runtime callsites), not from deploy/worktree mirrors.

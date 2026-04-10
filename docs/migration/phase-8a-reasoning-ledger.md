# Phase 8A Reasoning Foundation Ledger

Date: 2026-04-04

## File-Level Changes

| Path | Classification | Action | Rationale | Risk |
|---|---|---|---|---|
| `packages/skg-reasoning/pyproject.toml` | package scaffold | added | New standalone canonical reasoning package with protocol-only dependency surface. | Low |
| `packages/skg-reasoning/README.md` | package scaffold | added | Declares reasoning scope/non-scope to prevent layer drift. | Low |
| `packages/skg-reasoning/src/skg_reasoning/__init__.py` | package API | added | Exposes minimal public API for delegation reasoning pilot. | Low |
| `packages/skg-reasoning/src/skg_reasoning/contracts.py` | reasoning contract | added | Defines `skg.reasoning.delegation_evaluation.v1` output schema + validation. | Medium: contract may evolve as more reasoning slices are added. |
| `packages/skg-reasoning/src/skg_reasoning/delegation_engine.py` | reasoning engine | added | Consumes AD-06/AD-08 canonical events + AD-07 context contract; emits derived-only reasoning output. | Medium: heuristic pressure/usefulness mapping is intentionally minimal for pilot. |
| `packages/skg-reasoning/tests/test_delegation_engine.py` | tests | added | Verifies input consumption, output correctness, and contract enforcement. | Low |
| `packages/skg-reasoning/tests/test_reasoning_boundaries.py` | tests | added | Enforces no domain/service import contamination and no raw event emission helpers. | Low |
| `docs/migration/phase-8a-reasoning-boundaries.md` | boundary evidence | added | Captures authoritative layer ownership and deferred coupling boundaries. | Low |
| `docs/architecture/target-architecture.md` | architecture authority | updated | Added `skg-reasoning` layer and dependency rule. | Low |

## Deferred Items (Intentional)

| Deferred item | Why deferred |
|---|---|
| AD-09 sensitive-target reasoning | Remains outside domain posture-core and outside Phase 8A pilot scope. |
| Attack-path chaining/value graph reasoning | Needs dedicated reasoning graph design beyond first pilot heuristic layer. |
| Runtime/service integration callsites into reasoning layer | Out of scope for Phase 8A; this phase establishes package and contract foundation only. |

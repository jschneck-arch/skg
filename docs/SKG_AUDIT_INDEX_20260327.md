# SKG Codebase Audit — Master Index
**Date:** 2026-03-27
**Scope:** /opt/skg — full codebase
**Method:** Automated deep-read across all subsystems (7 parallel audit agents)

---

## Document Set

| File | Coverage |
|------|----------|
| [SKG_MASTER_REMEDIATION_PLAN_20260328.md](SKG_MASTER_REMEDIATION_PLAN_20260328.md) | **MASTER PLAN** — 134 items across 6 categories, 4-tier prioritized fix queue |
| [SKG_AUDIT_ARCHITECTURE_20260327.md](SKG_AUDIT_ARCHITECTURE_20260327.md) | System-wide architecture, data flows, design principles, math model |
| [SKG_AUDIT_KERNEL_TOPOLOGY_20260327.md](SKG_AUDIT_KERNEL_TOPOLOGY_20260327.md) | `skg/kernel/` (18 modules) + `skg/topology/` (4 modules) |
| [SKG_AUDIT_SENSORS_GRAVITY_FORGE_20260327.md](SKG_AUDIT_SENSORS_GRAVITY_FORGE_20260327.md) | `skg/sensors/` (21 files) + `skg/gravity/` (5 files) + `skg/forge/` (6 files) |
| [SKG_AUDIT_GRAVITY_TOOLCHAIN_20260327.md](SKG_AUDIT_GRAVITY_TOOLCHAIN_20260327.md) | `skg-gravity/` (gravity_field.py ~8000 lines + 5 supporting files) |
| [SKG_AUDIT_CLI_ASSISTANT_20260327.md](SKG_AUDIT_CLI_ASSISTANT_20260327.md) | `skg/cli/` (30+ commands) + `skg/assistant/` |
| [SKG_AUDIT_CORE_INTEL_SUBSTRATE_20260327.md](SKG_AUDIT_CORE_INTEL_SUBSTRATE_20260327.md) | `skg/core/`, `skg/intel/`, `skg/identity/`, `skg/temporal/`, `skg/substrate/` |
| [SKG_AUDIT_TOOLCHAINS_TESTS_20260327.md](SKG_AUDIT_TOOLCHAINS_TESTS_20260327.md) | All 12 domain toolchains + `skg-discovery/` + `tests/` | **COMPLETE** |
| [SKG_AUDIT_CONFIG_DOCS_INFRA_20260327.md](SKG_AUDIT_CONFIG_DOCS_INFRA_20260327.md) | `config/`, `resonance/`, `ui/`, `feeds/`, `scripts/`, deployment, docs index | **COMPLETE** |

---

## Executive Summary

SKG (Spherical Knowledge Graph) is a telemetry-driven, information-theoretic security assessment substrate. It models an environment's attack surface as a physical field in which:

- **Observation** collapses wickets (attack preconditions) from UNKNOWN to REALIZED or BLOCKED
- **Field energy** E is Shannon entropy over the unknown wicket set
- **Gravity** selects which instrument to run next based on expected entropy reduction
- **Proposals** stage Metasploit RC scripts for operator-gated execution
- **The forge** autonomously generates new domain toolchains when coverage gaps are detected

The system has been empirically validated on three live targets (Metasploitable 2, DVWA, Metasploitable 3 Win2k8) realizing 10+ attack paths autonomously including EternalBlue (MS17-010) at 0.95 confidence.

---

## Codebase Metrics

| Metric | Count |
|--------|-------|
| Python source files | ~120+ |
| Kernel submodules | 18 |
| Topology modules | 4 |
| Sensor modules | 21 |
| CLI command modules | 8+ |
| Domain toolchains | 12 |
| Configuration YAML files | 7 |
| Documentation files | 41 |
| UI files | 3 (JS/HTML/CSS) |
| Gravity field engine (gravity_field.py) | ~8,000 lines |
| Total estimated LOC | ~35,000+ |

---

## Key Design Invariants

1. **Tri-state honesty** — REALIZED / BLOCKED / UNKNOWN are first-class; never collapse UNKNOWN to false
2. **Append-only substrate** — Events and identity records never overwritten; full provenance preserved
3. **Operator gating** — No exploit executes without explicit operator approval via `skg proposals trigger`
4. **Domain agnosticism** — Projection engine π has no hardcoded domain logic; toolchains plug in
5. **Physics model** — Energy, gravity, fibers, pearls, manifold are not metaphors; they are the formal model
6. **Evidence ranks** — All observations carry rank 1–5; higher rank = shorter decay TTL

---

## Critical Files

| File | Role |
|------|------|
| `skg-gravity/gravity_field.py` | Main gravity loop (~8000 lines); orchestrates all instruments |
| `skg/kernel/engine.py` | Unified kernel interface; entry point for gravity into state |
| `skg/kernel/support.py` | SupportEngine; aggregates observations with decay |
| `skg/kernel/field_local.py` | Paper 4 FieldLocal; coupling energy, decoherence criterion |
| `skg/topology/energy.py` | G(t) coherence observable; Fiber/FiberCluster |
| `skg/topology/kuramoto.py` | Oscillator dynamics; order parameter R |
| `skg/topology/sheaf.py` | H¹ cohomology obstructions |
| `skg/sensors/__init__.py` | SensorLoop; event envelope factory |
| `skg/forge/pipeline.py` | Gap → generate → validate → propose pipeline |
| `skg/gravity/selection.py` | Instrument ranking algorithm |
| `skg/core/daemon.py` | FastAPI daemon (~50k tokens); REST API + loop manager |
| `bin/skg` | CLI entry point → `skg.cli.main()` |

---

## Known Gaps & Open Items (as of 2026-03-27)

1. **dc01-win2022**: OS installation pending; disk provisioned but empty
2. **K coupling constant calibration**: Currently lab-validated; wider empirical evaluation needed
3. **Kuramoto convergence formal proof**: Open mathematical question (Paper 4)
4. **Decision-theoretic decoherence thresholds**: C=0.7, contradiction<0.15, decoherence<0.20 empirically calibrated
5. **GitHub push + README update**: Needed before Zenodo deposit
6. **Per-sensor rate limiting**: No backpressure if one sensor is slow
7. **Unbounded state files**: MSF audit logs, agent queue state grow indefinitely

---

## Papers Produced

| Paper | File | Status |
|-------|------|--------|
| Paper 1 — Telemetry-First substrate | (inline docs) | Informal |
| Paper 2 — Spherical Knowledge Graph (Kuramoto) | (inline docs) | Informal |
| Paper 3 — Projection over Constrained System State | `SKG_Work3_Final.md` | **Published** |
| Paper 4 — Unified Field Functional: Fiber-Driven Gravity | `SKG_Work4_Final.md` | **Complete** |

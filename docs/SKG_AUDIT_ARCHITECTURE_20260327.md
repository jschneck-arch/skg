# SKG Architecture Audit
**Date:** 2026-03-27
**Scope:** System-wide architecture, formal model, data flows, design principles

---

## 1. What SKG Is

SKG is a **domain-agnostic telemetry-driven observational substrate** for red-team security assessment. It does not operate from a policy table or attack tree. Instead it treats the environment's attack surface as an information field and:

1. Accumulates bounded observations into a tri-state knowledge graph
2. Directs its own measurement via information-theoretic gravity
3. Generates staged (operator-gated) Metasploit proposals when attack paths are realized
4. Autonomously generates new domain toolchains when coverage gaps are detected

The mathematical backbone spans sheaf cohomology, Kuramoto oscillator dynamics, fiber bundle geometry, and support-vector aggregation.

---

## 2. Formal Model Summary

### 2.1 Tri-State Encoding

Every attack precondition (wicket) is in one of three states:

| State | Symbol | Meaning |
|-------|--------|---------|
| REALIZED | R | Evidence confirms precondition present |
| BLOCKED | B | Evidence confirms precondition absent/mitigated |
| UNKNOWN | U | Not yet measured |

UNKNOWN is **not** false. It is a first-class epistemic state. The system never conflates "unmeasured" with "false."

### 2.2 Field Energy

```
E(S, A) = |{ n ∈ A : Σ(n) = U }| + Σ Φ(fold)
```

Where:
- `A` = applicable wicket set for a target
- `Σ(n)` = tri-state of wicket n
- `Φ(fold)` = gravity weight of structural knowledge gaps

Weighted form (Paper 4):
```
E_weighted = Σ_n (max(φ_U, local_energy, 1.0 if unknown else 0.0) + φ_contradiction + φ_decoherence) + Σ Φ(fold)
```

### 2.3 Gravity / Instrument Selection

Instruments are ranked by expected entropy reduction potential:

```
score(instrument) = (ΔE / cost) × penalty × approval_factor
```

Paper 4 extends this with a fiber-driven term:
```
Φ_effective = Φ_base + α × Φ_fiber    (α = 0.35)
```

Where `Φ_fiber` integrates tension, coupling, and decoherence across fiber clusters.

### 2.4 Support Aggregation

Observations decay exponentially by decay class:

| Class | λ (per hour) | TTL |
|-------|-------------|-----|
| structural | 0.001 | ~weeks |
| operational | 0.01 | ~days |
| ephemeral | 0.1 | ~hours |

Support for each wicket:
```
φ_R = Σ w_i × phi_r_i        (decayed realized support)
φ_B = Σ w_i × phi_b_i        (decayed blocked support)
contradiction = min(φ_R, φ_B) (conflicting evidence)
```

Collapse rules:
- REALIZED: φ_R > threshold AND φ_R > φ_B
- BLOCKED: φ_B > threshold AND φ_B ≥ φ_R
- UNKNOWN: otherwise (including high-conflict cases)

### 2.5 Decoherence Criterion (Paper 4 §5)

A FieldLocal is **protected** (stable minimum — no re-observation benefit) iff:
1. compatibility_score C ≥ 0.70
2. φ_contradiction < 0.15
3. φ_decoherence < 0.20
4. compatibility_span n ≥ 2

Where `C = 1.0 − concentration + 0.1×(n−1)` and concentration is the max-instrument-family weight fraction.

### 2.6 Sheaf Cohomology (Paper 3 §4)

Attack path realizability is refined by H¹ obstruction:
- Wickets form a simplicial complex with causal + co-realized edges
- Betti number β₁ = |E| − |V| + |C| counts independent cycles in the constraint graph
- β₁ > 0 → mutual dependency cycle → classification upgrades from "indeterminate" to "indeterminate_h1"
- Interpretation: constraint surface must change (not observation) to resolve

### 2.7 Kuramoto Oscillator Dynamics

Each wicket is modeled as an oscillator:
- Phase φ: realized=0, unknown=π/2, blocked=π
- Amplitude A: confidence-derived
- Natural frequency ω: by evidence decay class (ephemeral=0.80, structural=0.15)

Kuramoto equation:
```
dφ_i/dt = ω_i + (K/n) Σ_j w_ij A_j sin(φ_j − φ_i) − d_i
```

Order parameter R = |Σ A exp(iφ)| / Σ A measures domain synchronization [0, 1].

Phase gradient (torque) drives gravity boosts toward high-uncertainty regions.

### 2.8 Pearl Manifold (Memory Curvature)

Pearls are immutable records of state transitions (decision points). The PearlManifold:
- Groups pearls by (identity_key, domain) → PearlNeighborhood
- Reinforced wickets (appearing ≥2 times) boost gravity toward repeat patterns
- Memory curvature: instruments that previously succeeded get higher potential

### 2.9 Unified Field Functional (Paper 4)

```
L(F) = E_self + E_coupling − Curvature + Dissipation
```

Five canonical objects:
1. Field Observation — events from instruments
2. Field Local — per-wicket state per workload
3. Field Coupling — inter-target prior propagation
4. Field Fiber — fiber-driven Φ opportunity and decoherence load
5. Field Cluster — cross-domain cluster dynamics

---

## 3. Runtime Architecture

### 3.1 Layer Stack

```
┌─────────────────────────────────────────────────────────────────┐
│  Operator Interface                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │  skg CLI     │  │  UI (port    │  │  gravity_field.py      ││
│  │  (bin/skg)   │  │  5055/ui)    │  │  autonomous loop       ││
│  └──────┬───────┘  └──────┬───────┘  └──────────┬─────────────┘│
│         └─────────────────┼──────────────────────┘             │
│                    REST API (FastAPI, port 5055)                 │
│                    core/daemon.py                                │
├─────────────────────────────────────────────────────────────────┤
│  Intelligence Layer                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │  Gravity     │  │  Resonance   │  │  Forge Pipeline        ││
│  │  (selection, │  │  (LLM pool,  │  │  (gap detect →         ││
│  │   ranking)   │  │   embedding) │  │   generate → validate) ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Kernel Layer                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │  Support     │  │  State       │  │  Energy + Gravity      ││
│  │  Engine      │  │  Engine      │  │  Scheduler             ││
│  │  (aggregate, │  │  (collapse,  │  │  (Φ_effective, rank)   ││
│  │   decay)     │  │   TriState)  │  │                        ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │  Folds       │  │  Pearls +    │  │  WicketGraph           ││
│  │  (structural,│  │  Manifold    │  │  (Kuramoto phase,      ││
│  │   temporal,  │  │  (memory     │  │   hypotheses, dark)    ││
│  │   contextual)│  │   curvature) │  │                        ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Topology Layer                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐│
│  │  energy.py   │  │  manifold.py │  │  kuramoto.py           ││
│  │  G(t), Fiber,│  │  Simplicial  │  │  Oscillator dynamics,  ││
│  │  FiberCluster│  │  Complex     │  │  Order parameter R     ││
│  └──────────────┘  └──────────────┘  └────────────────────────┘│
│  ┌──────────────────────────────────────────────────────────────┐│
│  │  sheaf.py — H¹ cohomology obstruction (β₁ computation)     ││
│  └──────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Substrate Layer                                                 │
│  node.py | path.py | projection.py | bond.py | state.py        │
│  (TriState, NodeState, PathScore, BondState, SKGState)          │
├─────────────────────────────────────────────────────────────────┤
│  Sensor Layer                                                    │
│  ssh_sensor | web_sensor | msf_sensor | bloodhound | cve_sensor │
│  usb_sensor | net_sensor | data_sensor | agent_sensor | ...     │
├─────────────────────────────────────────────────────────────────┤
│  Domain Toolchains (12 domains)                                  │
│  skg-host | skg-web | skg-data | skg-ad-lateral                 │
│  skg-container-escape | skg-binary | skg-ai                     │
│  skg-aprs | skg-iot_firmware | skg-supply-chain                 │
│  skg-metacognition | skg-discovery                              │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Gravity Cycle Data Flow

```
Targets (targets.yaml / surface.json)
  │
  ▼
load_wicket_states(ip)              ← KernelStateEngine.states()
  │                                   ← SupportEngine.aggregate()
  ▼                                   ← ObservationStore (NDJSON events)
field_entropy(ip, applicable_wickets)
  │
  ▼
rank_instruments_for_target(ip)     ← Selection + memory boost + Φ_fiber
  │
  ▼
Execute top-k instruments           ← MAX_CONCURRENT = 8 (ThreadPoolExecutor)
  │
  ├─ _exec_nmap()     ─→ discovery NDJSON
  ├─ _exec_ssh_sensor() ─→ events NDJSON
  ├─ _exec_http_collector() ─→ events NDJSON
  ├─ _exec_metasploit() ─→ events NDJSON
  └─ [other instruments] ─→ events NDJSON
  │
  ▼
Auto-project events via SensorLoop.projector
  │
  ▼
Fold detection → dark hypotheses
  │
  ▼
generate_exploit_proposals()        ← exploit_dispatch.py
  │
  ▼
Operator: `skg proposals trigger <id>` ─→ msfconsole -q -r <rc_file>
  │
  ▼
MSF output → parse → EVENTS_DIR ─→ loop closes
```

### 3.3 Event Sourcing Model

All state is derived from NDJSON event files. Nothing is stored in a database. The substrate is:

```
/var/lib/skg/
  discovery/     — nmap + instrument raw output (*.ndjson)
  events/        — obs.attack.precondition events (*.ndjson)
  interp/        — projection results (*.json)
  folds/         — active folds state (*.json)
  pearls/        — pearl ledger (*.ndjson)
  proposals/     — exploit proposals (*.json)
  interp_delta/  — DeltaStore snapshots and transitions
  brain/         — identity journal (append-only *.jsonl)
```

State is reconstructed by replaying events: `skg replay <events_dir>`.

---

## 4. Cross-Target Coupling

Targets are coupled in the gravity web via bonds:

| Bond Type | Strength | Prior Influence |
|-----------|----------|-----------------|
| same_host | 1.00 | 1.00 |
| docker_host | 0.90 | 0.90 |
| same_compose | 0.80 | 0.80 |
| shared_cred | 0.70 | 0.70 |
| same_domain | 0.60 | 0.60 |
| same_subnet | 0.40 | 0.40 |

Prior propagation (discrete Kuramoto approximation):
```
P_B(n, t) = s_ij × SW(t)
```

Where `s_ij` is bond strength and `SW(t)` is the signal weight of the triggering transition. Capped at MAX_PRIOR = 0.85 to prevent unbounded accumulation.

WorkloadGraph propagation weights by relationship type:

| Relationship | Weight |
|-------------|--------|
| same_identity | 0.85 |
| credential_overlap | 0.45 |
| same_domain | 0.35 |
| trust_relationship | 0.25 |
| same_subnet | 0.20 |
| network_adjacent | 0.15 |

---

## 5. Wicket Naming Convention

| Prefix | Domain | Examples |
|--------|--------|----------|
| HO- | Host | HO-01 (reachable), HO-19 (SMB exposed), HO-25 (CVE confirmed) |
| WB- | Web | WB-01 (reachable), WB-05 (admin exposed), WB-10 (default creds) |
| DP- | Data Pipeline | DP-01 (schema present), DP-09 (freshness TTL) |
| AD- | AD Lateral | AD-01 (kerberoastable), AD-06 (unconstrained delegation) |
| CE- | Container Escape | CE-01 (root), CE-02 (privileged), CE-03 (docker socket) |
| BA- | Binary Analysis | BA-01 (NX disabled), BA-06 (exploit chain constructible) |
| AI- | AI/ML | AI-01 (service reachable), AI-06 (prompt injection) |
| AP- | APRS (Log4Shell) | AP-L4 (log4j loaded), AP-L15 (callback egress) |
| IF- | IoT Firmware | IF-01 (reachable), IF-03 (BusyBox buffer overflow) |
| SC- | Supply Chain | SC-01 (reachable), SC-15 (jinja2 RCE) |
| MC- | Metacognition | MC-01 (calibration), MC-08 (overconfidence absence) |
| FI- | System Integrity | FI-01 (binary integrity), FI-08 (deleted file handles) |
| PI- | Process Integrity | PI-01 (manifest match), PI-05 (listening ports) |
| LI- | Log Integrity | LI-01 (logrotate), LI-06 (audit trail) |
| BT- | Boot/UEFI | BT-01 (UEFI mode), BT-02 (Secure Boot disabled) |
| GP- | GPU | GP-01 (GPU present), GP-07 (network-exposed compute API) |
| PR- | Process Exploit | PR-01 (ptrace_scope=0), PR-04 (dangerous SUID) |

---

## 6. Evidence Ranks

| Rank | Source | Decay Class |
|------|--------|-------------|
| 1 | Runtime (SSH exec, live observation) | ephemeral |
| 2 | Harvested (banner, SPN list, dynamic analysis) | structural (override) |
| 3 | Config/Static (file attributes, docker inspect) | operational |
| 4 | Network (port scan, DNS resolution) | structural |
| 5 | Lookup/NVD (no version confirmation) | structural |

---

## 7. Operational Modes

| Mode | Behavior |
|------|----------|
| OPERATE | Normal — gravity runs, proposals generated, some auto-execution |
| ANCHOR | Identity locked read-only; no state updates |
| AUDIT | Read-only projection; no new observations |
| UNIFIED | Full field functional; fiber-driven gravity active |

Mode transitions validated by `skg.modes.valid_transition()`.

---

## 8. Deployment Architecture

```
systemd unit: skg.service
  → /opt/skg/skg/core/daemon.py
  → FastAPI on 0.0.0.0:5055
  → UI at /ui
  → API at /api/...

systemd timer: skg-train.timer
  → skg-train.service
  → confidence calibration + pearl manifold refresh

External services:
  → Metasploit RPC: localhost:55553
  → BloodHound CE: localhost:8080
  → Ollama: localhost:11434 (optional)
  → Anthropic API: cloud (optional, ANTHROPIC_API_KEY)

State directories:
  → /var/lib/skg/   (runtime state)
  → /etc/skg/       (config + targets)
  → /opt/skg/       (source, UI, toolchains)
```

---

## 9. Key Design Principles

### 9.1 Field-First, Not Policy-First
No hardcoded attack trees. Observation directs measurement via gravity; gravity follows entropy gradients. Adding a new domain requires only a toolchain (catalog + adapter + projector).

### 9.2 Immutability and Provenance
Events are never overwritten. Identity journal is append-only. Contradictions are retained, not reconciled. Full history is always available for replay.

### 9.3 Honest Epistemic Modeling
UNKNOWN is a first-class state. The system distinguishes:
- **unmeasured** — no instrument has probed this wicket
- **conflicted** — both realized and blocked evidence present
- **decohered** — evidence has decayed past TTL
- **inconclusive** — evidence present but below threshold
- **single_basis** — only one instrument family has observed this

### 9.4 Operator Gating
All exploit execution is staged. Proposals require explicit `skg proposals trigger <id>`. The `--authorized` flag on individual instruments permits direct test execution (for credential reuse), but exploit proposals never auto-fire.

### 9.5 Domain Agnosticism
The substrate (node, path, projection, bond) has no hardcoded knowledge of "web" or "host." Domain expressions (Δ) are bindings: (Ω, Ι, Α, Π) — observation space, identity, adapter, projection. New domains extend the system without touching the substrate.

---

## 10. Empirical Validation (as of 2026-03-21)

| Target | Result |
|--------|--------|
| DVWA 172.17.0.3 | SQLi + CMDI + XSS confirmed; CMDI reverse shell proposal (0.94 confidence) |
| Metasploitable2 172.17.0.2 | FTP/SSH/HTTP attack surface mapped |
| Metasploitable3 192.168.122.153 | EternalBlue (MS17-010) autonomously realized via HO-01→HO-19→HO-25 coupling (0.95 confidence) |
| Cycles run | 9+ gravity cycles |
| Proposals generated | 643+ pearls, 126+ proposals |
| L(F) values | DVWA: 1277.8, Metasploitable2: 262.9, Win2k8: 207.5 |

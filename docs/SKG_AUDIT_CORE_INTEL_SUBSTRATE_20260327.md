# SKG Core, Intel, Identity, Temporal, and Substrate Audit
**Date:** 2026-03-27
**Scope:** `skg/core/`, `skg/intel/`, `skg/identity/`, `skg/temporal/`, `skg/substrate/`

---

## 1. `skg/core/` — Core Infrastructure

### `paths.py` — Filesystem Constants

Single source of truth for all SKG paths. Environment variables override defaults:

| Variable | Default |
|----------|---------|
| SKG_HOME | /opt/skg |
| SKG_STATE_DIR | /var/lib/skg |
| SKG_CONFIG_DIR | /etc/skg |

Exports 30+ path constants organized by purpose:
- Toolchain dirs: TOOLCHAIN_DIR, CE_TOOLCHAIN_DIR, AD_TOOLCHAIN_DIR, HOST_TOOLCHAIN_DIR, WEB_TOOLCHAIN_DIR
- Resonance memory: RESONANCE_DIR, RESONANCE_INDEX, RESONANCE_RECORDS, RESONANCE_DRAFTS
- Runtime state: BRAIN_DIR, IDENTITY_FILE, EVENTS_DIR, INTERP_DIR, DELTA_DIR, DISCOVERY_DIR
- Logs: LOG_DIR, LOG_FILE, PID_FILE

`ensure_runtime_dirs()`: Creates all required directories on first run.

---

### `__init__.py` — Lazy Module Loading

`__getattr__(name)` → `importlib.import_module()` at attribute access time.

Prevents pulling in heavy dependencies (uvicorn/FastAPI) at import time when only paths.py is needed.

---

### `daemon_registry.py` — Daemon Function Registry

Module-level mutable state (`_all_targets_index`, `_identity_world`) populated at daemon startup.

Allows topology layer to call daemon functions without circular imports. Enables `mock.patch` in tests without daemon dependencies.

---

### `coupling.py` — Coupling Weight Management

**Purpose**: Manage inter-domain, cluster, and intra-target attack coupling weights. Learn intra-target couplings from delta snapshots.

**Tables** (loaded from `/etc/skg/coupling.yaml` or `/opt/skg/config/coupling.yaml`):

- `inter_local_table()`: Dict[(domain_a, domain_b) → float] — cross-domain coupling K
- `cluster_table()`: Dict[(cluster_a, cluster_b) → float] — cluster coupling
- `intra_target_table()`: Dict[(domain_a, domain_b) → float] — within-target coupling

**Default inter-local values:**
```
host → smb: 0.80
smb → vuln: 0.90
web → data: 0.85
cmdi → shell: 0.90
credential → ssh/web: 0.95/0.80
container → host escape: 0.85
```

**Decay TTLs:**
```
ephemeral:  4 hours
operational: 24 hours
structural: 168 hours (7 days)
```

Reverse discount: 0.8 (applied when flipping coupling direction A→B to B→A).

**Learning** (`learn_intra_target_couplings(delta_dir)`):
- Reads delta snapshots from `snapshots/` subdirectory
- Indexes latest per (workload_id, identity) pair
- Counts realized domains per identity
- Computes probability: `hits / total` for domain transitions
- Returns `{"counts": {...}, "estimated": {...}}`

**Validation** (`validate_payload(payload)`):
- All section keys must be dicts
- Domain names validated against known registry
- Values must be in [0, 1]
- TTL hours must be ≥ 0

**CLI**: `--show`, `--validate`, `--learn`, `--apply [--learned-file]`, `--review`, `--backup`, `--yes`

---

### `domain_registry.py` — Domain Inventory

**Toolchain Discovery** (auto-scans `SKG_HOME` for `skg-*-toolchain` directories):
- Loads `forge_meta.json` if present
- Infers domain name from directory pattern (skg-ad-lateral-toolchain → ad_lateral)
- Discovers `projections/run.py` or `projections/*/run.py`
- Counts catalogs in `contracts/catalogs/`
- Checks `.venv/bin/python` for bootstrap status

**Default Registry** (12 domains):

| Domain | daemon_native | Description |
|--------|-------------|-------------|
| aprs | ✓ | Log4Shell / JNDI RCE |
| container_escape | ✓ | Container breakout |
| ad_lateral | ✓ | AD lateral movement |
| host | ✓ | OS-level host |
| data | ✓ | Data pipeline integrity |
| web | — | HTTP/web application |
| nginx | — | Nginx config |
| binary | — | Binary analysis |
| ai_target | — | AI/ML endpoints |
| supply_chain | — | Software dependencies |
| iot_firmware | — | IoT devices |
| metacognition | — | Cognitive capability |

**Merge Strategy**: Discovered toolchains override configured entries by domain name.

---

### `assistant_contract.py` — LLM Output Classification

**Purpose**: Define admissibility rules for LLM assistant output entering the observation plane.

**Output Classes:**
- `OBSERVED_EVIDENCE`: Can enter observation plane; requires custody chain
- `DERIVED_ADVICE`: Cannot enter observation plane; advisory only
- `MUTATION_ARTIFACT`: Generated artifacts (RC scripts, patches)
- `RECONCILIATION_CLAIM`: Reconciliation between conflicting evidence

**Admissibility Criterion:**

```python
observation_admissible = (
    effective_class == OBSERVED_EVIDENCE
    AND (not is_assistant OR custody_chain_complete)
)
```

**Custody Chain Requirements** (all four required):
- `artifact_path` or `artifact_ref`
- `artifact_hash`
- `source_uri` or `source_pointer` or `source_command`
- `collected_at` or `observed_at`

**State Authority:**
- OBSERVED_EVIDENCE: "custody_relay_only"
- Other: "advisory_only"

---

### `daemon.py` — Main SKG Daemon

FastAPI daemon. Entry point at `/opt/skg/skg/core/daemon.py`. ~50k tokens (very large).

**Startup sequence:**
1. Initialize paths, logging, identity journal
2. Boot SensorLoop (sensors registered by config)
3. Boot ResonanceEngine (LLM memory)
4. Boot DeltaStore, WorkloadGraph, FeedbackIngester
5. Load domain inventory, register daemon-native toolchains
6. Start FastAPI on 0.0.0.0:5055
7. Serve UI at /ui

**Key REST endpoints:**
- `GET /api/surface` — Current attack surface
- `POST /api/gravity/run` — Trigger gravity cycle
- `GET /api/proposals` — Proposal queue
- `POST /api/proposals/{id}/trigger` — Execute proposal
- `GET /api/resonance/llm-pool/status` — LLM pool status
- `GET /ui` — Operator UI

---

## 2. `skg/intel/` — Intelligence Layer

### `gap_detector.py` — Coverage Gap Detection

Scans collection output for uncovered services. Returns gap records for forge candidates.

**KNOWN_SERVICES** (83 regex patterns → service_name, attack_surface, forge_ready):
redis, mongodb, postgresql, mysql, nginx, apache, jenkins, jboss, tomcat, elasticsearch, kibana, rabbitmq, consul, vault, etcd, kubernetes, grafana, splunk, gitlab, gitea, samba, nfs, rsync, memcached, zookeeper, kafka, solr, influxdb, prometheus, minio, and more.

**Detection Sources:**
1. Process list (running services with no toolchain)
2. Port scan (open ports not mapped)
3. Package list (installed software with known attack patterns)
4. SSH collection artifacts
5. Agent callbacks

**Gap Record Schema:**
```python
{
    "service": str,
    "category": "network_service|process|package|config|web_fingerprint",
    "hosts": [workload_ids],
    "evidence": str,
    "attack_surface": str,
    "collection_hints": [str],   # SSH commands to collect evidence
    "forge_ready": bool,
}
```

**State file**: `SKG_STATE_DIR/gap_detector.state.json` — persists known gaps, prevents re-detection.

---

### `surface.py` — Operator Intelligence Surface

Synthesizes all SKG state into ranked operator picture.

**Score Keys by Domain:**
```
aprs → "aprs"
container_escape → "escape_score"
ad_lateral → "lateral_score"
host → "host_score"
web → "web_score"
ai_target → "ai_score"
data → "data_score"
```

**Classification Ranking:** realized (0) > indeterminate (1) > not_realized (2) > unknown (3)

**Input Sources:**
- INTERP_DIR: projection results
- EVENTS_DIR: raw observations
- WorkloadGraph: cross-workload topology
- PearlLedger: confirmation rates (memory overlay)

---

### `redteam_to_data.py` — Cross-Domain Inference

Maps red team security findings → data pipeline integrity conditions.

**Core mapping table** (SECURITY_TO_DATA):

| Security Finding | DP Implication |
|-----------------|----------------|
| CE-01 realized (container RCE) | DP-07 blocked (transformation logic untrustworthy) |
| PI-05 blocked (shell from service) | DP-07 blocked (OS-level RCE confirmed) |
| WB-10 realized (SQLi confirmed) | DP-08 blocked (DB integrity violated), DP-04 blocked |
| FI-07 blocked (new UID-0 account) | DP-02 blocked (schema may be altered) |
| LI-05 realized (auditd active) | DP-11 realized (batch completeness verifiable) |

Confidence levels: 0.95 (near-certain), 0.80 (strong), 0.65 (moderate), 0.50 (weak).

**Key insight**: Security observation → data integrity implication via causal mapping. The substrate evaluates both attack realizability and telemetry trustworthiness using the same mechanism.

---

### `engagement_dataset.py` — Engagement Integrity

Converts red team telemetry into SQLite DB, then applies data pipeline toolchain against the telemetry itself.

**Schema tables**: observations, projections, gravity_cycles, proposals, transitions, folds, engagement_meta.

Applies DP-* wicket assessment to the engagement data itself — same substrate evaluates both attack realizability and dataset trustworthiness.

---

### `confidence_calibrator.py` — Calibration Wrapper

Backward-compatible facade around `skg.sensors.confidence_calibrator`. Learns from DeltaStore NDJSON.

Calibration state file managed by parent class; shared with SensorContext at runtime.

---

## 3. `skg/identity/` — Append-Only Identity Journal

### `parse_workload_ref(workload_id)` → dict

Parses workload IDs into components:
```
"host::192.168.1.10" → {
    domain_hint: "host",
    locator: "192.168.1.10",
    host: "192.168.1.10",
    identity_key: "192.168.1.10",
    manifestation_key: "host::192.168.1.10",
}
```

### `canonical_observation_subject(payload, workload_id, target_ip)` → dict

Resolves canonical substrate subject for observation events. Returns stable identity anchor, not trailing workload token.

### `Identity` — Journal Manager

Append-only persistence at IDENTITY_FILE (JSONL). Full snapshot per update; nothing overwrites.

`lock(locked=True)` → raises PermissionError("Identity is read-only in ANCHOR mode...") on update.

### `IdentitySnapshot` — Full State Snapshot

Fields: name, version, mode, coherence, sessions, notes, timestamp, source.

`to_envelope()`: Formats as obs.skg.identity event with formal SKG envelope.

---

## 4. `skg/temporal/` — Temporal Tracking

### `__init__.py` — DeltaStore

**WicketTransition** (dataclass): Single state change
- workload_id, domain, wicket_id, attack_path_id
- from_state → to_state, from_run_id → to_run_id, from_ts → to_ts
- meaning, signal_weight (from TRANSITION_MEANINGS table)
- Optional rich metadata: confidence_delta, local_energy_delta, phase_delta, latent_delta

**Transition Meanings and Signal Weights:**

| Transition | Meaning | Weight |
|-----------|---------|--------|
| unknown → realized | surface_expansion | 1.0 |
| realized → blocked | remediation | 0.8 |
| realized → unknown | evidence_decay | 0.6 |
| blocked → realized | regression | 1.0 |
| unknown → blocked | control_observed | 0.5 |
| blocked → unknown | control_evidence_lost | 0.5 |
| realized → realized | persistence_confirmed | 0.2 |
| blocked → blocked | control_persists | 0.2 |
| unknown → unknown | still_unknown | 0.0 |

**DeltaStore**: Manages snapshots and transitions.

Layout:
```
DELTA_DIR/
  snapshots/<workload_id>.jsonl   — all projection snapshots
  transitions/<workload_id>.jsonl — all state transitions
  index.jsonl                     — cross-workload latest index
```

**Confidence Calibration** (`calibrate_confidence_weights()`):
- Collects all U→R transitions as confirmations
- Groups by evidence_rank
- Precision = confirmed / total
- Calibrated weight = 0.5 + 0.5 × precision (maps [0,1] → [0.5, 1.0])

**Propagation Rule**: Only signal_weight ≥ 0.8 transitions propagate to WorkloadGraph (surface_expansion, regression). Low-signal persistence confirmations are ignored.

---

### `interp.py` — Payload Normalization

`canonical_interp_payload(interp)`: Flattens envelope to canonical payload dict.

Classification aliases normalized:
```
fully_realized → realized
blocked → not_realized
partial → indeterminate
indeterminate_h1 → indeterminate
```

`read_interp_payload(path)`: Reads JSON (single object) or NDJSON (last non-empty line = latest record).

---

### `feedback.py` — Feedback Ingestion

Watches INTERP_DIR for new projections; feeds them back into temporal, graph, and observation memory systems.

**Propagation Rule**: `signal_weight ≥ 0.8` only (surface_expansion, regression). Ignores persistence confirmations.

**Boundary**: "feedback routes consequences; feedback does not define truth."

State file: `SKG_STATE_DIR/feedback.state.json` tracking processed interp files.

---

## 5. `skg/substrate/` — Information Field Substrate

### `node.py` — NodeState

The atomic unit of the information field.

**Scalar interface (backward-compatible):**
- node_id, state (TriState), confidence, observed_at, source_kind, pointer, notes, attributes

**Extended substrate fields (Paper 4 evolution):**
- confidence_vector: [float] × 8 dimensions
- confidence_matrix: [[float]] × 8×8
- mass_matrix, damping_matrix: dynamics
- contradiction_vector: conflicting evidence detection
- local_energy, phase: field physics
- is_latent, projection_sources: metadata

**TriState enum**: REALIZED, BLOCKED, UNKNOWN

**ViewNode** (dataclass): Present-tense view of workload-local node context (for operator surface). Contains identity_key, manifestation_key, domain, attack_path_id, classification, score, realized/blocked/unknown lists, memory_overlay.

---

### `path.py` — Attack Path Definition

**Path** (dataclass): Ordered sequence of required node preconditions
- path_id, required_nodes, domain, description

**PathScore** (dataclass): Projection output
- score = |realized| / |required|
- classification: realized / not_realized / indeterminate
- entropy = |unknown| / |required| ∈ [0, 1] (residual uncertainty)

---

### `projection.py` — Projection Engine π

Domain-agnostic core. Same engine for security, supply chain, genomics.

**Algorithm** (`project_path(path, states, workload_id, run_id)`):
1. For each required node: look up NodeState (default unknown if missing)
2. Categorize as realized/blocked/unknown
3. score = |realized| / |required|
4. Classify: realized (all realized), not_realized (any blocked), indeterminate (else)
5. Attach rich fields if available (energy, latent nodes, sources)

**Design**: Conservative (score = realized/required intentional simplification). Honest (UNKNOWN is first-class). Extensible (rich NodeState observed but not used for scoring yet).

---

### `bond.py` — Bond State and Prior Propagation

**Bond types and strengths** (network/host + data pipeline):

Network topology:
```
same_host: 1.00, docker_host: 0.90, same_compose: 0.80
shared_cred: 0.70, same_domain: 0.60, same_subnet: 0.40
```

Data pipeline topology:
```
upstream_of: 1.00, derived_from: 0.90, same_batch: 0.80
shared_schema: 0.70, same_database: 0.60, same_pipeline: 0.40
```

**Prior Influence Formula** (Work 3 Section 7.4):
```
P_B(n, t) = s_ij × SW(t)
```

Derivation: Discrete-time Kuramoto coupling at phase transition (φ_i → 0). K/N factor absorbed into MAX_PRIOR = 0.85 ceiling in WorkloadGraph.

`prior_influence` property: `strength × PRIOR_ALPHA (1.0)` — attenuated by signal_weight at propagation time.

---

### `state.py` — SKGState

Wraps NodeState + PathScore into unified field snapshot for gravity planner, feedback, and API.

**Field energy** (`E` property):
```
E = |unknown| / |total_nodes|   ∈ [0, 1]
```
- E = 0.0: fully determined (no unknowns)
- E = 1.0: fully unknown (maximum gravitational pull)

---

## 6. Cross-Module Data Flow

```
skg/core/paths.py
  ↓ (path constants)

skg/core/coupling.py ← skg/core/domain_registry.py → skg/core/daemon_registry.py
  ↓ (K weights)         (domain inventory)              (daemon functions)

skg/identity/__init__.py ← skg/core/assistant_contract.py
  ↓ (canonical subjects)    (admissibility rules)

skg/intel/redteam_to_data.py   skg/intel/gap_detector.py
  ↓ (DP-* inference)             (forge candidates)

skg/intel/surface.py ← skg/intel/confidence_calibrator.py
  ↓ (operator picture)

skg/temporal/__init__.py (DeltaStore)
  ↓ (transitions + snapshots)

skg/temporal/feedback.py
  ↓ (propagation to WorkloadGraph)

skg/substrate/{node, path, projection, bond, state}.py
  ↓ (field types)

skg/core/daemon.py (orchestrates all)
```

---

## 7. Code Quality Observations

- No TODOs or FIXMEs found across examined files
- Clear module-level docstrings
- Consistent snake_case + CONSTANTS naming
- Type hints throughout (Python 3.9+ style)
- Comprehensive error handling with logging
- Atomic file writes (rename pattern for state files)
- Backward compatibility maintained: node/wicket aliases throughout
- Data classes for immutable record types
- Separation of concerns: each module has exactly one responsibility

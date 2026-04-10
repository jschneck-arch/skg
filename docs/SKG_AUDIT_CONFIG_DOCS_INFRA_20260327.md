# SKG Config, Resonance, UI, Feeds, Scripts & Docs Audit
**Date:** 2026-03-27
**Scope:** `config/` (7 YAML files + contracts), `skg/resonance/` (8 modules), `ui/` (HTML/JS/CSS), `feeds/`, `scripts/` (systemd), documentation index
**Method:** Deep read across all files in scope

---

## 1. Configuration System

### 1.1 `config/skg_config.yaml` — Master Platform Configuration

Central configuration hub for the SKG platform. Consumed by `skg/core/daemon.py`, all sensor adapters, and the resonance/LLM subsystem.

**Key Settings:**

| Section | Key | Type | Default | Notes |
|---------|-----|------|---------|-------|
| `gravity` | `autostart` | bool | false | Controls daemon auto-launch |
| `gravity` | `cycle_interval_s` | int | 120 | Gravity loop cycle time |
| `gravity` | `convergence_epsilon` | float | 0.01 | Field convergence detection |
| `sensors.enabled` | — | list | [usb, ssh, agent, msf, cve, bloodhound, web, data] | Active sensor list |
| `sensors.ssh` | `timeout_s` | int | 30 | SSH collection timeout |
| `sensors.ssh` | `collect_interval_s` | int | 300 | SSH collection frequency (5 min) |
| `sensors.msf` | `host:port` | str:int | 127.0.0.1:55553 | Metasploit RPC endpoint |
| `sensors.msf` | `password` | string | `${MSF_PASSWORD}` | From /etc/skg/skg.env |
| `sensors.cve` | `nvd_api_key` | string | `${NIST_NVD_API_KEY}` | NIST NVD API key |
| `sensors.cve.packages` | — | list | [log4j, docker, containerd, runc, openssl, spring-core, apache-struts] | Tracked package families |
| `sensors.bloodhound` | `url` | url | http://localhost:8080 | BloodHound CE REST API |
| `sensors.bloodhound` | `collect_interval_s` | int | 900 | BH collection frequency (15 min) |
| `resonance.ollama` | `url` | url | http://localhost:11434 | Ollama API endpoint |
| `resonance.ollama` | `model` | string | tinyllama:latest | Local LLM model tag |
| `resonance.ollama` | `temperature` | float | 0.1 | Generation temperature (low = deterministic) |
| `resonance.ollama` | `generation_timeout_s` | int | 900 | Max wait for generation (15 min) |
| `resonance.llm_pool.enabled` | — | bool | false | Enable multi-backend LLM pool |
| `resonance.llm_pool.strategy` | — | enum | race | race \| round_robin \| ensemble |
| `resonance.llm_pool.max_workers` | — | int | 4 | Thread pool size |
| `resonance.assistant.enabled` | — | bool | true | Enable AI assistant mode |
| `resonance.assistant.timeout_s` | — | float | 4.0 | Assistant task timeout |
| `resonance.assistant.num_predict` | — | int | 160 | Max tokens per assistant response |
| `resonance.web` | `timeout_s` | int | 30 | HTTP probe timeout |
| `resonance.web` | `collect_interval_s` | int | 600 | Web collection frequency (10 min) |
| `resonance.web` | `max_probe_paths` | int | 60 | Paths to probe per web target |
| `resonance.web` | `tor_proxy` | url | socks5://127.0.0.1:9050 | Tor SOCKS proxy for .onion |
| `cognitive_probe.enabled` | — | bool | false | LLM metacognition probing (MC-01..MC-08) |
| `cognitive_probe.backend` | — | enum | local | openai \| anthropic \| local |
| `cognitive_probe.collect_interval_s` | — | int | 3600 | Cognitive probe frequency (1 hour) |

**Issues:**
1. `generation_timeout_s: 900` (15 min) is too short for CPU-only inference; tinyllama at ~0.3 tok/s needs ~27 min for a 512-token response
2. No env var override for `resonance.ollama.url` (`SKG_OLLAMA_URL`); OllamaBackend handles this per-instance but config doesn't document it
3. No rate limiting config for NVD API; relies on API key but doesn't enforce per-second quota

---

### 1.2 `config/coupling.yaml` — Attack Path Coupling & Decay Model

Defines inter-domain coupling weights (K values) and evidence decay TTLs.

**Schema:**

```yaml
inter_local:          # Within local network
  host:
    host: 0.80
    smb: 0.80
    vuln: 0.85
    data: 0.70
    container: 0.60
    lateral: 0.80
    binary: 0.60
  [similar for smb, credential, web, cmdi, container, lateral, data, binary]

cluster:              # Cross-host within cluster
  [similar structure]

intra_target:         # Within single target
  web:
    data_pipeline: 0.65
    host: 0.60
    container_escape: 0.50
  [similar for host, container_escape, ad_lateral, aprs, binary_analysis, sysaudit, data_pipeline]

decay_ttl_hours:
  ephemeral: 4        # Runtime observations (4 hours)
  operational: 24     # Active service banners (1 day)
  structural: 168     # Config & static analysis (1 week)

reverse_discount: 0.8 # Backward propagation discount factor
```

**Consumed by:** `skg/core/coupling.py` → `inter_local_table()`, `cluster_table()`, `intra_target_table()`

**Issues:**
1. No sensitivity analysis documented for K values; empirically calibrated but not explained
2. `reverse_discount: 0.8` purpose not documented in the file
3. No variant support (dev vs. prod environments likely have different coupling profiles)

---

### 1.3 `config/targets.yaml` — Target & Workload Inventory

Defines monitored targets (SSH hosts, HTTP/HTTPS/onion endpoints, WinRM).

**Schema per target:**
```yaml
targets:
  - host: 192.168.1.10
    method: ssh | http | https | onion | winrm
    workload_id: linux-web-01        # Namespace (e.g., "linux-web-01")
    attack_path_id: log4j_jndi_rce_v1
    enabled: true
    tags: [linux, web, container]
    # transport-specific: user, key, password, verify_tls, timeout_s, url, auth.*
```

**Issues:**
1. Plaintext passwords in YAML; `${VAR}` substitution expected but not enforced
2. No schema validation on `workload_id` (should match `[a-z0-9_:-]+`)
3. No credential rotation schedule or expiry fields

---

### 1.4 `config/assistant_contracts.yaml` — AI Assistant Task Definitions

Defines 8 LLM prompting contracts. Each contract specifies artifact type, output format, max tokens, and purpose.

**Task Contracts:**

| Task | Artifact Type | Output | Tokens | Purpose |
|------|--------------|--------|--------|---------|
| `target_summary` | observation_rc | text | 280 | Target shape, current paths, next observations |
| `fold_explanation` | msf_rc | text | 320 | Fold existence, missing pieces, growth pressure |
| `proposal_explanation` | credential_test_plan | json | 220 | Proposal rationale, expected changes, supporting evidence |
| `memory_summary` | wicket_patch | json | 360 | Pearl neighborhood reinforcement & observation bias |
| `next_observation` | — | text | — | Next bounded observation recommendation |
| `engagement_note` | — | text | — | Operator engagement note with uncertainty and next steps |
| `fold_cluster_summary` | catalog_patch | json | 420 | Clustered folds as one structural deficit |
| `what_if` | — | text | — | Counterfactual: effects on uncertainty, folds, proposals, graph pressure |

**Artifact output formats:**

- **observation_rc** (Metasploit resource script skeleton): Required markers `["setg RHOSTS", "exit"]`
- **msf_rc** (full MSF RC script): Required markers `["use ", "exit"]`
- **credential_test_plan** (JSON): Required keys: plan_type, service_type, target_ip, port, user, secret, cred_type, origin_ip, wicket_hint, command_hint; `plan_type == "cred_reuse_v1"`
- **wicket_patch** (JSON draft): Required keys: patch_type, domain, reason, wickets (non-empty), attack_paths (non-empty); `patch_type == "wicket_patch_v1"`
- **catalog_patch** (JSON draft): Required keys: patch_type, domain, description, reason, wickets, attack_paths; `patch_type == "catalog_patch_v1"`

**Issues:**
1. No per-task timeout; all share `resonance.assistant.timeout_s: 4.0` (very short for JSON generation)
2. No fallback prompt if model response is invalid JSON or text
3. No cost model for cloud backends (Anthropic, HF)

---

### 1.5 `config/daemon_domains.yaml` — Toolchain Registry

Metadata registry for all attack domains. Maps toolchain directories to CLI entrypoints, project structure paths, and interpretation types.

**Daemon-Native Domains (7):**

| Domain | Dir | Default Path | Interp Type |
|--------|-----|-------------|------------|
| aprs | skg-aprs-toolchain | log4j_jndi_rce_v1 | attack_path.realizability |
| container_escape | skg-container-escape-toolchain | container_escape_privileged_v1 | container_escape.realizability |
| ad_lateral | skg-ad-lateral-toolchain | ad_kerberoast_v1 | ad_lateral.realizability |
| host | skg-host-toolchain | host_ssh_initial_access_v1 | host.realizability |
| data | skg-data-toolchain | data_completeness_failure_v1 | data.pipeline |
| web | skg-web-toolchain | web_full_chain_v1 | attack.path |
| nginx | skg-nginx-toolchain | — | attack.path |

**Auxiliary Domains (5):** binary, ai_target, supply_chain, iot_firmware, metacognition

**Consumed by:** `skg/resonance/ingester.py`, gravity scheduler for domain-specific sensor routing

**Issues:**
1. No version field for domain catalogs or adapters
2. No status field (stable / beta / experimental)
3. `interp_type` is a string path, not a Python class reference; resolution logic not shown

---

### 1.6 `config/data_sources.yaml` — Database Pipeline Targets

Defines external DB and data pipeline targets for SKG monitoring.

**Schema:**
```yaml
data_sources:
  - url: postgresql://user:pass@host/db | sqlite:///path/to/data.db
    table: table_name
    workload_id: banking::transactions
    contract: /path/to/contract.json
    attack_path_id: data_completeness_failure_v1
    ttl_hours: 1

pipeline_topology:
  - from: banking::raw_transactions
    to:   banking::transactions
    type: upstream_of | derived_from
```

**Example targets (commented):** banking PostgreSQL (ttl 1h), agriculture PostgreSQL (ttl 4h), medical PostgreSQL (ttl 24h), local SQLite

**Issues:**
1. Credentials embedded in URL; must use `${VAR}` substitution
2. No connection pool settings (max connections, timeout)
3. No result set size limit; unbounded queries could exhaust memory
4. `pipeline_topology` bonds are manually declared; no schema inference

---

### 1.7 `config/contracts/transactions.json` — Data Contract Example

Schema contract for banking transactions table.

```json
{
  "table": "transactions",
  "primary_key": "transaction_id",
  "ttl_hours": 1,
  "required_fields": ["transaction_id", "account_id", "amount", "currency", "created_at"],
  "bounds": {
    "amount": {"min": -1000000, "max": 1000000},
    "currency": {"enum": ["USD", "EUR", "GBP", "JPY", "CAD", "AUD"]}
  },
  "foreign_keys": [{"field": "account_id", "ref_table": "accounts", "ref_field": "id"}],
  "distribution_baselines": {
    "amount": {"mean": 150.0, "std": 80.0, "p50": 120.0, "p95": 400.0}
  }
}
```

**Issues:**
1. No schema-for-the-schema; contracts themselves are not validated
2. Distribution baseline is static; no adaptive/seasonal learning
3. NULL semantics for bounds checking are undefined

---

## 2. Resonance Subsystem

The resonance subsystem provides vector-backed semantic memory, LLM-driven catalog drafting, observation logging with feedback, and multi-backend LLM dispatch.

### 2.1 `resonance/engine.py` — Core Vector Memory

**Classes:**

**`_FallbackIndex(dim: int)`**
- Numpy-backed cosine search; no external deps
- `_vecs: np.ndarray[N, dim]` (float32, normalized)
- `add(vecs)`, `search(query, k)` → (scores[1,k], indices[1,k])

**`_make_index(dim) → (index, using_faiss: bool)`**
- Factory: tries `faiss.IndexFlatIP(dim)` (inner-product on normalized vectors ≈ cosine)
- Falls back to `_FallbackIndex`; logs warning if FAISS absent

**`MemoryStore[T](Generic)`**
- Generic store for WicketMemory, AdapterMemory, DomainMemory, ObservationRecord
- `load()` — reads JSONL, rebuilds index from embedder
- `save_record(record)` — appends to JSONL, adds vector to index
- `query(text, k)` → `list[(record, score)]` — semantic search
- `get_by_id(record_id)`, `has(record_id)`, `count`, `all_records`

**`ResonanceEngine`**
- Owns: `_wickets`, `_adapters`, `_domains` (MemoryStore each), `observations` (ObservationMemory)
- `boot()` — initialize embedder, load all stores (called by daemon on startup)
- `store_wicket(record)`, `store_adapter(record)`, `store_domain(record)` — idempotent (skips if exists)
- `surface(query, k_each) → dict` — unified semantic query across all 3 store types
- `status() → dict` — counts; `status_offline() → dict` — all zeros if not booted
- `save_draft(domain_name, catalog) → Path` — write draft JSON to `_drafts_dir`

**Data flow:**
```
Ingester → reads catalogs → creates records → engine.store_*()
                                              → JSONL append + FAISS add

UI/Assistant → engine.surface(query) → top-k records with scores

Drafter → engine.surface() for context → LLM prompt → engine.save_draft()
```

**Issues:**
1. JSONL files are append-only; no compaction. Malformed lines skipped but never removed
2. Index dimension mismatch not detected until load time; changing embedder invalidates all FAISS indexes
3. No concurrency control on JSONL writes; simultaneous appends could corrupt data
4. `_ready: bool` — no state machine (booting / ready / failed states)

---

### 2.2 `resonance/embedder.py` — Text → Vector Embedding

**`SentenceTransformerEmbedder`**
- Model: `all-MiniLM-L6-v2` (384 dimensions, float32, cosine-normalized)
- `embed(texts: list[str]) → np.ndarray[N, 384]`
- `embed_one(text: str) → np.ndarray[384]`

**`TFIDFEmbedder`** (fallback, no external deps)
- Dimension: 256; tokenizes via `[a-z0-9_]+` regex; fits IDF on first call
- `_vectorize(text)` → TF-IDF vector, L2-normalized, padded/truncated to 256
- Corpus grows as new texts arrive; refits on each add (O(corpus) per call)

**`make_embedder()` factory** — tries sentence-transformers, falls back to TF-IDF

**Issues:**
1. sentence-transformers model not fine-tuned on SKG domain (wickets, attack paths); generic similarity may not be optimal
2. TF-IDF fallback refits corpus on every embed call — O(N) where N is corpus size
3. No embedding caching; every query re-computes
4. No dimensionality mismatch detection between stored indexes (384D vs. 256D)

---

### 2.3 `resonance/memory.py` — Record Types

**`WicketMemory`**
```python
record_id: str        # "domain::wicket_id" e.g. "aprs::AP-L4"
domain: str
wicket_id: str
label: str
description: str
evidence_hint: str
attack_paths: list[str]
embed_text: str       # f"{label}. {description} Evidence: {evidence_hint}"
```

**`AdapterMemory`**
```python
record_id: str        # "domain::adapter_name"
domain: str
adapter_name: str
evidence_sources: list[str]
wickets_covered: list[str]
evidence_ranks: list[int]
embed_text: str       # f"{domain} adapter {adapter_name}. Evidence sources: ..."
```

**`DomainMemory`**
```python
record_id: str        # domain name
domain: str
description: str
wicket_count: int
attack_paths: list[str]
adapters: list[str]
catalog_version: str
embed_text: str       # f"{domain}: {description} Attack paths: ..."
```

All types support `to_dict()`, `from_dict()`, `to_json()`. Stored as JSONL (one object per line).

**Issues:**
1. No timestamps on records; cannot track when wickets were added
2. `embed_text` is pre-computed at creation; schema changes require full re-embedding
3. No record type versioning; schema evolution not handled

---

### 2.4 `resonance/observation_memory.py` — Closed-Loop Sensor Observations

**`ObservationRecord`**
```python
record_id: str
evidence_text: str                   # "log4j:1.2.17 found in /app/lib"
wicket_id: str
domain: str
source_kind: str                     # "filesystem_scan", "service_banner", etc.
evidence_rank: int                   # 1–5
sensor_realized: bool | None
projection_confirmed: str | None     # "realized" | other
confidence_at_emit: float
workload_id: str
identity_key: str
ts: str                              # ISO timestamp
embed_text: str                      # f"{domain} {wicket_id}: {evidence_text}"
local_energy_at_emit: float
phase_at_emit: float
is_latent_at_emit: bool
```

**`ObservationMemory`**
- Two JSONL files: `records_path` (confirmed), `pending_path` (awaiting projection outcome)
- `record_observation(evidence_text, wicket_id, ...) → record_id` — writes to pending
- `record_outcome(record_id, projection_confirmed)` — moves pending → confirmed, adds to index
- `recall(evidence_text, wicket_id, ..., k=10)` — semantic + structural filter (exact wicket_id or domain+target fallback)
- `historical_confirmation_rate(evidence_text, wicket_id, ...) → float | None` — realized/confirmed ratio; requires ≥3 similar observations
- `calibrate_confidence(base, evidence_text, ..., history_weight=0.4) → float` — Bayesian blend: `base×(1−w) + rate×w`

**Issues:**
1. Pending observations have no TTL; stale pending records accumulate indefinitely
2. `projection_confirmed` is a free string (no enum); no validation of valid values
3. No deduplication — identical observations from same source stored separately
4. `calibrate_confidence()` may silently override user-supplied base confidence

---

### 2.5 `resonance/ingester.py` — Toolchain Crawling & Memory Population

**Key functions:**

| Function | Purpose |
|----------|---------|
| `_find_toolchains(skg_home)` | Glob `skg-*-toolchain/contracts/catalogs/` |
| `_domain_from_toolchain(tc_dir)` | `skg-ad-lateral-toolchain` → `ad_lateral` |
| `_find_catalogs(tc_dir)` | Glob `contracts/catalogs/*.json` |
| `_find_adapters(tc_dir)` | List `adapters/*/parse.py` |
| `ingest_catalog(engine, domain, path)` | Creates WicketMemory + DomainMemory records |
| `ingest_adapters(engine, domain, adapter_dirs, catalog_path)` | Creates AdapterMemory records; parses wicket IDs from parse.py via regex `[A-Z]{2,3}-[A-Z]?[0-9]{1,2}` |
| `ingest_all(engine, skg_home)` | Walk all toolchains; return summary |

**Hardcoded adapter evidence source map (`ADAPTER_EVIDENCE_SOURCES`):**

| Adapter | Evidence Sources |
|---------|-----------------|
| config_effective | log4j jars, log4j2.xml, classpath/manifests |
| net_sandbox | docker inspect, iptables, DNS check, process list |
| container_inspect | docker inspect JSON, CapAdd, seccomp/apparmor, Mounts |
| bloodhound | users.json, computers.json, groups.json, acls.json, domains.json |
| ssh_collect | id, sudo -l, find, env vars, package manager, kernel, SSH keys, docker, ps aux |
| winrm_collect | PowerShell cmdlets: Get-Package, Get-Process, Get-NetTCPConnection, UAC, domain, tasks |
| nmap_scan | nmap XML output, -sV, NSE scripts, -O |
| msf_session | MSF RPC: sessions, db.creds, db.loots, db.hosts |

**Issues:**
1. `ADAPTER_EVIDENCE_SOURCES` is hardcoded; new adapters require code change here
2. Wicket ID regex `[A-Z]{2,3}-[A-Z]?[0-9]{1,2}` won't match non-standard naming schemes
3. No incremental update — re-ingests entire catalog tree on each boot if memory empty

---

### 2.6 `resonance/drafter.py` — LLM-Driven Catalog Proposal

**`draft_prompt(engine, domain_name, description) → dict`**
- Surfaces 4 wickets, 4 adapters, 4 domains from engine as context
- Builds system + user prompt; writes to `drafts_dir/prompt_<domain>_<timestamp>.txt`
- Writes pending marker JSON
- Returns `{prompt_path, pending_path, context_used, prompt}`

**`draft_accept(engine, domain_name, response_json) → dict`**
- Parses JSON (strips markdown fences); validates via `_validate_draft()`
- Saves to `engine.save_draft()`; updates pending marker

**`draft_catalog(engine, domain_name, description, api_key=None) → dict`**
- Fallback chain (in order):
  1. Anthropic API direct (`claude-sonnet-4-6`, 4096 tokens) if `ANTHROPIC_API_KEY` set
  2. `OllamaBackend().draft_catalog()` (local inference)
  3. `llm_pool.generate()` with race strategy
  4. Manual prompt mode (write files; user pastes into claude.ai)

**Validation (`_validate_draft`):**
- Required keys: version, description, wickets, attack_paths
- `len(wickets) >= 3`, `len(attack_paths) >= 1`
- All path `required_wickets` must reference defined wicket IDs
- Each wicket must have: id, label, description, evidence_hint

**Prompt structure:**
- System: tight contract ("Output must be valid JSON only")
- User: domain name, description, 4 similar wickets/adapters/domains as context, full schema example with rules

**Issues:**
1. Hardcoded model `claude-sonnet-4-6` for Anthropic path; not configurable
2. Fallback chain swallows all exceptions; user gets vague error if all backends fail
3. Manual prompt mode writes files but doesn't print clear instructions
4. No rate limiting on Anthropic API calls

---

### 2.7 `resonance/llm_pool.py` — Multi-Backend LLM Dispatch

**Abstract base:** `LLMBackend` — `name`, `available()`, `generate(prompt, num_predict, **kwargs)`

**`OllamaLLMBackend`** — wraps `OllamaBackend`; delegates `generate()` and `draft_catalog()`

**`AnthropicLLMBackend`**
- Config: model (default `claude-haiku-4-5-20251001`), `ANTHROPIC_API_KEY`, max_tokens (1024)
- POST `https://api.anthropic.com/v1/messages`; headers: x-api-key, anthropic-version: 2023-06-01

**`HuggingFaceAPIBackend`**
- Config: model (default `mistralai/Mistral-7B-Instruct-v0.3`), `HF_API_KEY` or `HUGGINGFACE_API_KEY`
- POST `https://api-inference.huggingface.co/models/<model>`; timeout 120s

**Pool strategies:**
- `race` — all backends in parallel via `ThreadPoolExecutor(max_workers)`; first valid response wins
- `round_robin` — rotate across backends
- `ensemble` — all run; longest/best response selected

**Config (skg_config.yaml, resonance.llm_pool):**
```yaml
enabled: false
strategy: race
max_workers: 4
backends:
  - {type: ollama, model: tinyllama:latest, temperature: 0.1}
  - {type: anthropic, model: claude-haiku-4-5-20251001, max_tokens: 1024}
  - {type: huggingface, model: mistralai/Mistral-7B-Instruct-v0.3}
```

**Issues:**
1. No per-worker timeout; pool can hang if any backend hangs
2. No circuit-breaker; failed backends stay in pool and are retried each call
3. `race` strategy wastes compute — all backends run to completion even after first result

---

### 2.8 `resonance/ollama_backend.py` — Local Ollama Integration

**Config priority (highest to lowest):** constructor args → env vars (`SKG_OLLAMA_URL`, `SKG_OLLAMA_MODEL`, `SKG_OLLAMA_TEMPERATURE`) → skg_config.yaml → hardcoded defaults

**Methods:**

| Method | Endpoint | Timeout | Purpose |
|--------|----------|---------|---------|
| `available()` | GET `/api/tags` | 3s | Health check |
| `list_models()` | GET `/api/tags` | 5s | Enumerate available models |
| `generate(prompt, num_predict=512)` | POST `/api/generate` | generation_timeout_s | Text generation |
| `draft_catalog(domain, description, context)` | (via generate) | — | Build catalog prompt, call generate, parse/validate JSON |

**Model preference order:** tinyllama:latest → tinyllama → tinydolphin → phi3:mini → phi3 → llama3.2:3b → llama3.2 → mistral:7b → mistral

**Prompt building (`_build_prompt`):**
- Derives wicket prefix from domain name (e.g., `log_analysis` → `LA`)
- Includes top 6 wickets, top 3 adapters, top 3 domains as context
- Strict JSON-only system instruction; detailed formatting rules

**Response parsing:**
- Strips markdown fences, finds first `{` to last `}`, parses JSON — naive and fragile on nested structures

**Issues:**
1. Response JSON parsing relies on first/last brace; breaks if LLM outputs explanation after JSON
2. Model selection is automatic with hardcoded preferences; no user override without env var
3. `generation_timeout_s` default 900s may be too short for CPU-only setups

---

## 3. UI System

### 3.1 `ui/index.html` — Main Interface Structure

Single-page application (SPA) with mode-driven workspace layout.

**Layout:**
```
┌──────────────────────────────────────────────────────────┐
│ TOPBAR: Logo | Metrics | Filter | Jump Buttons           │
├──────────────────────────────────────────────────────────┤
│ FIELD SUMMARY (2-col)        │ ASSISTANT OVERVIEW        │
├──────────────────────────────────────────────────────────┤
│ MODE TABS: [Operate] [Inspect] [History] [Report]        │
├──────────┬──────────────────────────┬────────────────────┤
│ LEFT     │ MAIN WORKSPACE           │ RIGHT RAIL         │
│ SIDEBAR  │                          │                    │
│ Targets  │ Tabs: Surface|Artifacts  │ Gravity Monitor    │
│ Folds    │       Timeline|Memory    │ Approvals Queue    │
│          │       Actions            │ Commands Desk      │
│          │                          │ Assistant Detail   │
│          │                          │ Report Panel       │
└──────────┴──────────────────────────┴────────────────────┘
```

**Mode tabs:** Operate (default), Inspect, History, Report

**Right rail panels:**
1. **Gravity Monitor** — status badge, Start/Stop/Run-Target buttons, live output
2. **Approvals Queue** — pending proposals (wicket patches, catalog patches, RC scripts)
3. **Commands Desk** — context-aware action suggestions for current selection
4. **Assistant Detail** — mode badge, task badge, task trigger buttons, assistant output
5. **Report Panel** — engagement summary, findings, next steps, artifact count (hidden until Report mode)

**Main workspace view tabs:**
1. **Surface** — field summary for selected target/fold/proposal
2. **Artifacts** — 2-col: measured support + artifact preview
3. **Timeline** — state transitions + assistant interpretation
4. **Memory** — pearl manifold neighborhood + memory notes
5. **Actions** — recent deployments + assistant engagement guidance

**Issues:**
1. No ARIA labels or keyboard navigation; no accessibility
2. Hard-coded 3-column layout; no responsive mobile breakpoints
3. No loading spinners or skeleton screens for async content
4. Search filter scope unclear (targets? folds? proposals? all?)

---

### 3.2 `ui/app.js` — Frontend Logic & API Binding

**State:**
```javascript
const state = {
  data: null,                    // Full SKG state from API
  selected: {kind, id, payload}, // Current selection (kind: target|fold|proposal|memory)
  filter: "",                    // Search filter string
  activeMode: "operate",         // operate|inspect|history|report
  activeView: "surface",         // surface|artifacts|timeline|memory|actions
  gravityStatus: null,
  artifactsByIdentity: {},       // Cache: identity_key → {artifacts: [...]}
  timelineByIdentity: {},        // Cache: identity_key → {transitions: [...]}
  assistantBySelection: {},      // Cache: "<selection_cache_key>:<task>" → response
  assistantTaskBySelection: {},  // Cache: "<selection_cache_key>" → current task
  // ...
};
```

**Core functions:**

| Function | Purpose |
|----------|---------|
| `fetchJson(path)` | Fetch + parse JSON; throws if not ok |
| `el(tag, cls, html)` | DOM element factory |
| `esc(value)` | HTML escape (& < > substitution) |
| `renderPills(values, cls)` | Array → `<span class="badge">` pills |
| `renderProfile(profile)` | Host profile: users, groups, kernel, packages, docker, sudo, AVs |
| `groupSurfaceByIdentity(surface)` | Group workloads by identity_key; sort paths by score |
| `selectionTask(selection)` | Default task per kind: target→target_summary, fold→fold_explanation, proposal→proposal_explanation, memory→memory_summary |
| `buildEngagementNote(payload)` | Multi-line note: Selection, Task, Mode, Summary, Findings, Next Actions, Cautions, References |
| `reportHtml()` | Multi-section report: identity, engagement summary, findings, next steps |
| `renderFieldSummary(data)` | Populate topbar metrics + field summary panel |
| `calibrate_confidence(base, ...)` | (client-side) confidence adjustment (mirrors server logic) |

**API endpoints consumed (inferred):**
- `/api/status` or `/api/data` — initial full state load
- `/api/artifacts?identity=<id>` — artifacts for identity
- `/api/timeline?identity=<id>` — timeline for identity
- `/api/assistant?selection=<key>&task=<task>` — assistant output
- `/api/gravity/status`, `/api/gravity/start`, `/api/gravity/stop` — gravity control
- `/api/gravity/run-target?target_id=<id>` — single-target gravity run

**Issues:**
1. No TypeScript; no type safety; runtime errors from object key typos
2. `fetchJson()` throws on failure — no try/catch boundary; single failed request breaks page
3. All caches grow indefinitely; stale data survives mode changes
4. Global mutable state object; no state machine for valid transitions
5. Implied render() function is likely very large with no component architecture

---

### 3.3 `ui/styles.css` — Dark Theme Styling

**CSS variables:**

| Variable | Value | Semantic Role |
|----------|-------|--------------|
| `--bg` | `#0d1117` | Main background (GitHub dark) |
| `--surface` | `#161b27` | Panel background |
| `--surface-raised` | `#1e2535` | Elevated panels, buttons |
| `--ink` | `#cdd4e0` | Primary text |
| `--ink-dim` | `#6b7a90` | Secondary text |
| `--ink-bright` | `#eaf0fa` | Headings |
| `--line` | `#252d3d` | Borders, separators |
| `--accent` | `#22c55e` | Success/active (green) |
| `--warn` | `#f59e0b` | Warning (amber) |
| `--danger` | `#f87171` | Error (red) |
| `--mono` | JetBrains Mono, Cascadia Code, monospace | Monospace stack |
| `--sans` | system-ui, sans-serif | UI text |
| `--radius` | 8px | Panel corners |

**Component classes:** `.panel`, `.badge`, `.list`, `.item`, `.selectable`, `.view-panel`, `.topbar`, `.workspace-shell`, `.mode-bar`, `.grid`

**Issues:**
1. No `@media` queries — no mobile/tablet breakpoints
2. No light theme variant
3. Font family fallbacks are developer-preference specific (JetBrains Mono)

---

## 4. Feeds & Data Ingestion

### `feeds/nvd_ingester.py` — NVD CVE Feed Integration

**Key functions:**

| Function | Purpose |
|----------|---------|
| `load_nvd_api_key()` | Checks `NIST_NVD_API_KEY` env; fallback: reads `/etc/skg/skg.env` |
| `nvd_query(params, api_key)` | GET `https://services.nvd.nist.gov/rest/json/cves/2.0?...`; timeout 30s |
| `query_by_keyword(keyword, ...)` | Keyword search → `data["vulnerabilities"]` list |
| `query_by_cpe(cpe_string, ...)` | CPE-based search |
| `query_by_cve_id(cve_id, ...)` | Single CVE lookup |
| `extract_service_info(banner)` | Match banner against `SERVICE_CPE_MAP`; return `(product, version, cpe_url)` list |

**SERVICE_CPE_MAP patterns:**

| Service Pattern | CPE Template | Product |
|-----------------|-------------|---------|
| `apache[/ ]?([\d.]+)` | `cpe:2.3:a:apache:http_server:{version}` | Apache HTTP Server |
| `nginx[/ ]?([\d.]+)` | `cpe:2.3:a:f5:nginx:{version}` | nginx |
| `php[/ ]?([\d.]+)` | `cpe:2.3:a:php:php:{version}` | PHP |
| `openssh[_ ]?([\d.]+)` | `cpe:2.3:a:openbsd:openssh:{version}` | OpenSSH |
| `mysql[/ ]?([\d.]+)` | `cpe:2.3:a:oracle:mysql:{version}` | MySQL |
| `tomcat[/ ]?([\d.]+)` | `cpe:2.3:a:apache:tomcat:{version}` | Apache Tomcat |
| + 7 more services | — | — |

**Hardcoded high-value CVEs always checked:**
- CVE-2021-44228, CVE-2021-45046 (Log4Shell)
- CVE-2021-41773, CVE-2021-42013 (Apache path traversal)
- CVE-2020-1472 (ZeroLogon)
- CVE-2019-5736 (runC escape)
- CVE-2024-21626 (Leaky Vessels)
- CVE-2023-44487 (HTTP/2 Rapid Reset)
- CVE-2024-3094 (XZ backdoor)
- CVE-2023-23397 (Outlook NTLM relay)

**CLI usage:**
```bash
python nvd_ingester.py --service "Apache/2.4.25" --out /tmp/cve_events.ndjson
python nvd_ingester.py --surface /var/lib/skg/discovery/surface_*.json --out-dir /var/lib/skg/cve/
python nvd_ingester.py --cpe "cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*"
```

**Issues:**
1. No pagination — only `resultsPerPage` param; large result sets silently truncated
2. High-value CVE list is hardcoded in source; requires code change to add new CVEs
3. **CVE → wicket mapping is missing** — ingester queries NVD but no documented path from CVE to wicket_id
4. Regex version extraction fails for distro-patched version strings (e.g., `Apache 2.4.25-ubuntu1`)
5. No explicit rate limit handling; relies on API key for quota

---

## 5. Deployment & Systemd Services

### Service Topology

**`scripts/skg.service`** — Main daemon
```ini
[Service]
Type=simple
After=network.target docker.service
ExecStart=/usr/bin/python3 /opt/skg/skg/core/daemon.py
Restart=on-failure
RestartSec=5
WorkingDirectory=/opt/skg
User=root
EnvironmentFile=-/etc/skg/skg.env
```

**`scripts/skg-train.service`** — Daily model fine-tuning (oneshot)
```ini
[Service]
Type=oneshot
After=network.target skg.service
ExecStart=python -m skg.training.scheduler_main
User=%i                  # templated; must be instantiated as skg-train.service@<user>
TimeoutSec=18000         # 5-hour timeout
EnvironmentFile=-/etc/skg/skg.env
```

**`scripts/skg-train.timer`** — Recurring trigger
```ini
[Timer]
OnCalendar=*-*-* 02:00:00   # Daily at 02:00 UTC
RandomizedDelaySec=600       # 0–10 min jitter
Persistent=true              # Catch up if missed
Unit=skg-train.service
```

**Startup order:**
1. `network.target` + `docker.service`
2. `skg.service` — initializes SKG state, boots resonance engine, starts gravity loop
3. `skg-train.timer` fires daily at 02:00 UTC → `skg-train.service` runs in background

**Environment variables set by systemd:**

| Variable | Value |
|----------|-------|
| `SKG_HOME` | `/opt/skg` |
| `SKG_STATE_DIR` | `/var/lib/skg` |
| `SKG_CONFIG_DIR` | `/etc/skg` |
| `PYTHONPATH` | `/opt/skg` |

**Secrets (from `/etc/skg/skg.env`):**
- `NIST_NVD_API_KEY`, `MSF_PASSWORD`, `BH_PASSWORD`
- Optional path overrides: `SKG_HOME`, `SKG_STATE_DIR`, `SKG_CONFIG_DIR`

**Issues:**
1. **`User=root`** for `skg.service` — unnecessary privilege; should run as unprivileged `skg:skg` user
2. No liveness probe; a hanging daemon (deadlock, infinite loop) won't trigger `Restart=on-failure` (which only catches abnormal exits)
3. `skg-train.service` uses `User=%i` template without a default; requires manual instantiation (`systemctl start skg-train.service@skgtrain`)
4. 18000s timeout for training with no progress visibility; no checkpoint logging
5. No rollback if training produces a corrupt model

---

### `scripts/skg.env.template` — Secrets Template

```bash
# NVD API key
NIST_NVD_API_KEY=

# Metasploit RPC password
MSF_PASSWORD=

# BloodHound CE password
BH_PASSWORD=

# Optional: override default paths
# SKG_HOME=/opt/skg
# SKG_STATE_DIR=/var/lib/skg
# SKG_CONFIG_DIR=/etc/skg
```

**Setup:** `sudo cp scripts/skg.env.template /etc/skg/skg.env && sudo chmod 600 /etc/skg/skg.env`

**Issues:**
1. Passwords in plaintext; relies solely on file permissions (600) and sudo access control
2. No format validation or example values
3. No integration with secret stores (Vault, AWS Secrets Manager, etc.)

---

## 6. Documentation Index

**Total documents:** ~47 `.md` files

### Core Architecture & Reference

| Document | Type |
|----------|------|
| SKG_REFERENCE_DIRECTORY_LAYOUT.md | Reference |
| SKG_CANONICAL_DATA_MODEL.md | Reference |
| SKG_CANONICAL_RUNTIME_MAP.md | Reference |
| SKG_RUNTIME_ARCHITECTURE.md | Whitepaper |
| SKG_IDENTITY_NODE_MANIFESTATION_MODEL.md | Whitepaper |
| SKG_STATE_TRANSITION_MODEL.md | Whitepaper |

### Conceptual Models

| Document | Topic |
|----------|-------|
| SKG_INFORMATION_FOLDS_MODEL.md | Folds & uncertainty |
| SKG_INFORMATION_ENERGY_AND_GRAVITY_MODEL.md | Gravity convergence |
| SKG_INSTRUMENT_SUPPORT_MODEL.md | Wickets & preconditions |
| SKG_CLOSED_OBSERVATION_LOOP.md | Observation memory & calibration |
| SKG_REFLEXIVE_OBSERVATION_MODEL.md | Sensor feedback |
| SKG_QUANTUM_MEASUREMENT_DIRECTION.md | Quantum-inspired uncertainty |

### User-Facing Guides

| Document | Purpose |
|----------|---------|
| SKG_RED_TEAM_ENGAGEMENT_MODEL.md | Engagement workflow |
| SKG_RED_TEAM_PLAYBOOK.md | Playbook for red teams |
| SKG_SAMPLE_ENGAGEMENT_WORKFLOW.md | Example workflow |
| SKG_OPERATOR_CHECKLIST.md | Pre-deployment checklist |
| SKG_UI_MINIMUM_VIABLE_SURFACE.md | UI design reference |
| SKG_FACET_READINESS_MATRIX.md | Toolchain readiness matrix |

### Formal Papers

| Document | Status |
|----------|--------|
| SKG_Work3_Final.md | Published |
| SKG_Work4_Draft.md | Draft |
| SKG_Work4_Final.md | Published |

### 2026-03-27 Audit Batch

| Document | Scope |
|----------|-------|
| SKG_AUDIT_INDEX_20260327.md | Master index |
| SKG_AUDIT_ARCHITECTURE_20260327.md | Architecture |
| SKG_AUDIT_KERNEL_TOPOLOGY_20260327.md | Kernel & topology |
| SKG_AUDIT_SENSORS_GRAVITY_FORGE_20260327.md | Sensor layer |
| SKG_AUDIT_GRAVITY_TOOLCHAIN_20260327.md | Gravity subsystem |
| SKG_AUDIT_CLI_ASSISTANT_20260327.md | CLI & assistant |
| SKG_AUDIT_CORE_INTEL_SUBSTRATE_20260327.md | Core intel layer |
| SKG_AUDIT_TOOLCHAINS_TESTS_20260327.md | Toolchains & tests |
| SKG_AUDIT_CONFIG_DOCS_INFRA_20260327.md | Config/infra (this doc) |
| SKG_CORE_UNIFICATION_AUDIT_20260327.md | Core unification |
| SKG_OBSERVATION_BOUNDARY_AUDIT_20260327.md | Observation boundaries |
| SKG_NODE_MODEL_AUDIT_20260327.md | Node model |
| SKG_MEASURED_AUTHORITY_AUDIT_20260327.md | Authority & confidence |
| SKG_GRAVITY_BOUNDARY_AUDIT_20260327.md | Gravity boundaries |
| SKG_IDENTITY_MEMORY_TOPOLOGY_AUDIT_20260327.md | Identity & memory |
| SKG_EVENT_AND_PEARL_CONTRACT_AUDIT_20260327.md | Events & memory contracts |
| SKG_UNIFICATION_AUDIT_20260327.md | Full unification |
| SKG_BOTTOM_UP_REMEDIATION_PLAN_20260327.md | Remediation plan |

### Field Reports & Engagement Docs

| Document | Date | Type |
|----------|------|------|
| SKG_SESSION_CONTINUATION_2026-03-16.md | 2026-03-16 | Session |
| engagement_report_dc01_win2022_20260323.md | 2026-03-23 | Engagement Report |
| skg_assessment_20260324.md | 2026-03-24 | Assessment |
| skg_code_audit_20260326.md | 2026-03-26 | Code Audit |
| SKG_FIELD_FUNCTIONAL.md | — | Field Reference |
| SKG_RUNTIME_UNIFICATION_PLAN.md | — | Plan |

### AI Assistant & Behavior Contracts

| Document | Purpose |
|----------|---------|
| SKG_AI_ASSISTANT_CONTRACT.md | LLM API contract |
| SKG_AI_ASSISTANT_BEHAVIORS.md | Expected behaviors |

---

## 7. Cross-Cutting Issues

### Security

| # | Issue | Priority |
|---|-------|---------|
| 1 | `skg.service` runs as `User=root`; unnecessary privilege | Critical |
| 2 | Plaintext credentials in targets.yaml and data_sources.yaml YAML files; relies on `${VAR}` substitution being used but not enforced | High |
| 3 | `/etc/skg/skg.env` holds plaintext secrets; relies on `chmod 600` and root-only access | High |
| 4 | No logging scrubber to prevent `ANTHROPIC_API_KEY`, `MSF_PASSWORD` from appearing in logs | Medium |

### Resilience & Correctness

| # | Issue | Priority |
|---|-------|---------|
| 5 | No liveness probe — hanging daemon not auto-restarted by systemd | High |
| 6 | JSONL files append-only without compaction; corrupt lines skipped silently; files grow unbounded | Medium |
| 7 | No concurrency control on JSONL writes (no file locking) | Medium |
| 8 | Pending observations in observation_memory have no TTL; accumulate indefinitely | Medium |
| 9 | FAISS index dimension mismatch on embedder change not detected until load time | Medium |
| 10 | `race` strategy in LLM pool runs all backends to completion even after first result | Low |

### Data Model & Integration

| # | Issue | Priority |
|---|-------|---------|
| 11 | **CVE → wicket mapping missing** in NVD ingester; no documented path from CVE to wicket_id | High |
| 12 | No NVD pagination; large result sets silently truncated at first page | Medium |
| 13 | Hard-coded high-value CVE list; requires code change to add new entries | Low |
| 14 | `ingest_all()` re-ingests entire catalog tree on boot if memory is empty; no incremental update | Low |

### UI & Frontend

| # | Issue | Priority |
|---|-------|---------|
| 15 | No TypeScript / type safety; runtime errors from key typos in state object | Medium |
| 16 | `fetchJson()` throws on any failure; single failed request breaks entire page | Medium |
| 17 | All caches grow indefinitely; stale data not evicted | Low |
| 18 | No responsive design; hard-coded 3-column layout | Low |

### Configuration & Deployment

| # | Issue | Priority |
|---|-------|---------|
| 19 | No YAML config schema validation at boot; typos in keys silently default | Medium |
| 20 | `generation_timeout_s: 900` may be too short for CPU-only inference | Low |
| 21 | `skg-train.service` templated user (`%i`) requires manual instantiation; no default | Low |
| 22 | 5-hour training timeout with no progress logging | Low |

---

## 8. Audit Completion

**Scope completed:**

| Area | Status |
|------|--------|
| Config system (7 YAML + 1 contract example) | Complete |
| Resonance subsystem (8 modules) | Complete |
| UI (index.html + app.js + styles.css) | Complete |
| Feeds (nvd_ingester.py) | Complete |
| Scripts (3 systemd units + env template) | Complete |
| Documentation index (47 docs) | Complete |

This document, together with `SKG_AUDIT_TOOLCHAINS_TESTS_20260327.md`, completes the 8-document audit set defined in `SKG_AUDIT_INDEX_20260327.md`.

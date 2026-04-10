# SKG Sensors, Gravity, and Forge Audit
**Date:** 2026-03-27
**Scope:** `skg/sensors/` (21 files) + `skg/gravity/` (5 files) + `skg/forge/` (6 files)

---

## 1. Sensors Module Overview

The sensors layer handles data collection. Every sensor inherits from `BaseSensor`, emits structured NDJSON events via `envelope()`, and is managed by `SensorLoop` which runs sweeps in a background thread.

### Sensor Inventory

| Sensor | File | Wicket Prefixes | Collection Method |
|--------|------|-----------------|-------------------|
| AgentSensor | agent_sensor.py | All | HTTP callback queue drain |
| BloodHoundSensor | bloodhound_sensor.py | AD- | BloodHound CE REST API |
| BootProbeSensor | boot_probe.py | BT- | SSH remote commands |
| CognitiveSensor | cognitive_sensor.py | MC- | LLM probe |
| CveSensor | cve_sensor.py | HO-11, AP-, CE-, AD- | NVD API |
| DataSensor | data_sensor.py | DP- | DB profiler adapter |
| DarkHypothesisSensor | dark_hypothesis_sensor.py | cognitive | LLM planner |
| GpuProbeSensor | gpu_probe.py | GP- | SSH remote commands |
| MsfSensor | msf_sensor.py | HO-, WB-, AD- | MSF console |
| NetSensor | net_sensor.py | HO-, AD-, CE-, AP-, WB- | tshark passive capture |
| ProcessProbeSensor | process_probe.py | PR- | SSH remote commands |
| SshSensor | ssh_sensor.py | HO-, AP-, AD-, CE- | SSH/WinRM credentialed |
| StructFetchSensor | struct_fetch.py | WB-30..WB-40 | HTTP structured endpoints |
| UsbSensor | usb_sensor.py | All | USB drop artifact routing |
| WebSensor | web_sensor.py | WB- | HTTP enumeration |

### Common Pattern: Event Envelope

```python
envelope(
    event_type="obs.attack.precondition",
    source_id="...",
    toolchain="skg-host-toolchain",
    payload=precondition_payload(
        wicket_id="HO-01",
        label="target_reachable",
        domain="host",
        status="realized",
    ),
    evidence_rank=4,
    source_kind="network_scan",
    pointer="...",
    confidence=0.85,
)
```

All events go to `EVENTS_DIR` as NDJSON.

---

## 2. Confidence Calibration Pipeline

Three-layer blending at emit time:

```
final_confidence = base × 0.45
                 + history_confirmation_rate × 0.35   (if available)
                 + graph_prior × 0.20                 (if available)
```

1. `confidence_calibrator.py`: Learns per-source precision from DeltaStore reversals
   - Precision = 1 − (evidence_decay within 3 steps of surface_expansion) / count
   - Calibrated = raw × (precision / assumed_reliability), clamped [0.1, 0.99]
   - MIN_OBSERVATIONS = 5 before applying calibration

2. `context.py` SensorContext: Blends base + history + graph prior
   - History: k-nearest-neighbor observation memory confirmation rate
   - Graph: WorkloadGraph prior for (workload_id, wicket_id)
   - Calibration applied before EVENTS_DIR write; recorded for future reversal analysis

---

## 3. Sensor-by-Sensor Notes

### agent_sensor.py
- Drains `SKG_STATE_DIR/agent_queue/*.json` written by embedded agents
- Agent callback schema includes: platform, packages, processes, network, java_homes, log4j_jars, docker_inspect, bh_data, env_vars
- Routes through adapter_runner for multi-domain routing
- **Issue**: State file (processed IDs) grows indefinitely

### bloodhound_sensor.py
- BloodHoundCEClient: JWT auth → paginated /api/v2 queries
- Cypher queries: kerberoastable users, unconstrained delegation, constrained delegation, ACL edges, adminSDHolder, ASREP roastable, stale DAs
- Normalizes BH CE format → BloodHound adapter schema → run_bloodhound()
- **Issue**: Token expiry hardcoded at 3500s; no multi-forest support

### boot_probe.py
- SSH remote command execution to probe /sys/firmware/efi, /proc/cmdline, /boot/grub
- 10 BT-* wickets: UEFI mode, Secure Boot, EFI writable, TPM, GRUB, kernel debug flags, kernel lockdown, legacy BIOS, recovery entries
- Fixed confidence 0.75–0.95; no SensorContext calibration
- **Issue**: Linux-only; no Windows firmware probing

### cognitive_sensor.py
- 8 probe types: pre_answer_confidence, evidence_injection, spontaneous_review, directed_review, failure_retry, solvability_discrimination, uncertainty_propagation, novel_domain
- Backends: OpenAI-compatible (/v1/chat/completions), Anthropic (/v1/messages)
- Response extraction via regex: CONFIDENCE: <float>, ABSTAIN, ANSWER: <text>
- **Issue**: No timeout on LLM calls; may block SensorLoop

### cve_sensor.py
- NVD API v2 query → CVE list → wicket mapping
- Rate limit: 5 req/30s unauthenticated, 50 req/30s with NIST_NVD_API_KEY
- Cache: 24-hour TTL at CVE_CACHE_FILE
- CVSS exploitabilityScore ≥ 3.9 → realized; else indeterminate
- **Issue**: Sleep-based rate limiting is inefficient; "DYNAMIC" wickets uncalibrated

### dark_hypothesis_sensor.py
- Reads dark hypotheses (high-torque, no-instrument wickets) from WicketGraph
- Queries LLM: "Which instrument can probe this unknown wicket?"
- Fallback chain: Ollama → Anthropic API → None
- Writes cognitive_action proposals to proposals/
- Filter: min torque 1.5, max 6 proposals/cycle
- **Issue**: LLM may hallucinate non-existent instruments; no command safety validation

### gpu_probe.py
- 10 GP-* wickets: device presence, IOMMU disabled, device file permissions, MPS running, OpenCL JIT, memory persistence, network-exposed compute API, driver CVE, Vulkan, ASLR equivalent
- Port scanning via socket.connect_ex() for compute APIs (50051/gRPC, 8080/REST)
- **Issue**: Port scanning may trigger IDS; driver CVE table is hardcoded and may be outdated

### msf_sensor.py
- MsfConsole wrapper via pymetasploit3
- Passive: drains active sessions only
- Active (engagement_mode=active): runs collection modules (portscan/tcp, ssh_version, ssh_login, smb_signing)
- Output parsers: 8 regex patterns → HO-01..HO-11, AD-01/16, WB-01/05
- Confidence: credential valid = 1.0, session opened = 1.0, port open = 0.85–0.90
- Audit trail: msf_audit/*.json (unbounded, no rotation)

### net_sensor.py
- Passive tshark capture (default 30s duration)
- Requires sudo or setcap cap_net_raw
- Maps Kerberos msg_type: AS-REQ(10)→AD-01, AS-REP(11)→AD-08
- Maps JNDI lookup in HTTP URI → AP-L8 (log4j)
- **Issue**: No flow state persistence across sweeps; tshark must be installed

### process_probe.py
- 10 PR-* wickets: ptrace_scope, unprivileged userns, eBPF, SUID binaries, executable stack, writable PATH, writable cron, shared memory, ASLR, kernel module loading
- Dangerous SUID set: nmap, vim, python, perl, ruby, bash, docker, pkexec, etc.
- **Issue**: Logic for userns parsing fragile (tries int() conversion)

### ssh_sensor.py
- Credentialed SSH (paramiko) or WinRM (pywinrm)
- On auth success: emits HO-03 (credential_valid, confidence 1.0) immediately
- Routes through run_ssh_host() adapter for full host toolchain evaluation
- Checks for BloodHound data in ssh_collection/<host>/bh_data/
- **Issue**: Credentials in YAML (relies on file permissions); no connection pooling

### struct_fetch.py
- 50+ wellknown HTTP endpoints probed
- Wickets WB-30..WB-40: schema exposed, config exposed, debug endpoints, health/version leakage, metrics, XML-RPC, security.txt, version disclosure, sensitive keys, private IP leakage, event stream
- Sensitive pattern: `password|passwd|secret|token|api_?key|access_?key|credential|auth_?token`
- **Issue**: Naive regex pattern (high false positive rate); no auth header support

### usb_sensor.py
- Scans `SKG_STATE_DIR/usb_drops/` for drop directories
- Routes artifacts through adapter_runner by type: docker_inspect→CE, bh_data→AD, packages+log4j→APRS
- State tracks processed_drops (unbounded growth)

---

## 4. Gravity Module (`skg/gravity/`)

### `gravity/__init__.py` — Exports

Public API:
- GravityFailureReporter
- Landscape: SERVICE_PORT_DOMAINS, applicable_wickets_for_domains, derive_effective_domains, summarize_view_nodes
- Runtime: emit_auxiliary_proposals, emit_follow_on_proposals, execute_triggered_proposals
- Selection: choose_instruments_for_target, rank_instruments_for_target

### `gravity/failures.py` — Cycle Error Tracking

GravityFailureReporter: append-only NDJSON at `SKG_STATE_DIR/gravity/cycle_failures.ndjson`.
Fields per record: ts, run_id, cycle, stage, severity, message, target_ip, exception, context.

### `gravity/landscape.py` — Domain Discovery

SERVICE_PORT_DOMAINS mapping (port → domain):
- 80/443/8080/8443 → web
- 22 → host
- 389/636/3268 → ad_lateral
- 2375/2376 → container_escape
- 11434/6333/8888/7860 → ai_target
- etc.

Key functions:
- `derive_effective_domains()`: view_state domains + target declared domains + service port mapping
- `apply_first_contact_floor()`: if no prior nmap, boost entropy to 25.0 minimum, apply broad wicket set
- `applicable_wickets_for_domains()`: union of wickets for domain set

**Issue**: First-contact floor is aggressive (25.0); may cause over-scanning of new targets.

### `gravity/selection.py` — Instrument Ranking

Five-stage scoring pipeline for each instrument candidate:

1. **Base Potential**: `entropy_reduction_potential(instrument, ip, states, applicable_wickets)` × `coherence_fn(instrument, target_row)`

2. **Memory Boost (Pearl)**: `reinforcement_fn(ip, instrument)` → multiply potential by (1.0 + score/10.0) if score ≥ 1.0, else add score

3. **R-Value Adjustment**: Per sphere, multiply by (1.0 + 0.25 × (1.0 − r_mean)) where r_mean is prior entropy reduction in that sphere

4. **H1 Penalty**: Overlap with indeterminate_h1 wickets → multiply by max(0.2, 1.0 − 0.8 × (overlap / wave_size))

5. **WorkloadGraph Boost**: Add 0.20 × log1p(wgraph_boost)

**Cold Start Overrides** (no prior nmap + no measured view):
```python
nmap:           max(potential, 30.0)
metasploit:     max(potential, 20.0)
nvd_feed:       max(potential, 18.0) if versioned service
http_collector: max(potential, 12.0) if web service
pcap:           max(potential, 10.0)
auth_scanner:   max(potential, 6.0) if web
```

**Bootstrap mode** (cold_start OR fresh_unknowns ≥ 20): run all BOOTSTRAP_NAMES instruments up to max(4, len(bootstrap_instruments)).

**Metasploit serialization**: If interactive mode, metasploit pulled from parallel set and run sequentially after (avoids blocking the parallel pool for 30-120s).

### `gravity/runtime.py` — Proposal Execution

Three functions:

**emit_follow_on_proposals()**: For each follow-on path identified by gravity cycle, generate MSF proposals.

**emit_auxiliary_proposals()**: For each auxiliary_map entry, if all required wickets realized → generate MSF RC → queue proposal.

**execute_triggered_proposals()**: Scan proposals/ for status=triggered, execute `msfconsole -q -r <rc_file>`:
- Auxiliary/runtime_observation → synchronous (subprocess.run, 120s timeout)
- Exploit modules → asynchronous (subprocess.Popen, background job)
- Output parsed → events ingested to EVENTS_DIR → closes gravity loop

---

## 5. Forge Module (`skg/forge/`)

### Purpose

The forge autonomously generates new domain toolchains when the gap detector identifies uncovered services. Pipeline: gap detection → catalog compilation → toolchain generation → validation → operator proposal.

### `forge/compiler.py` — CVE → Catalog

**TF-IDF Similarity Matching** (deduplication against existing corpus):
```python
IDF(t) = log((N+1)/(df[t]+1)) + 1
TF-IDF[t] = (count[t] / total_tokens) * IDF[t]
cosine_threshold = 0.35 (find_similar), 0.60 (cve_to_wicket dedup)
```

**CVE Parsing from NVD JSON**: description, CVSS v3.1/v3.0/v2.0, AttackVector, PrivilegesRequired, UserInteraction, CWE list, CPE list, references.

**Wicket Derivation Priority**:
1. CWE → cwe_labels table (command_injection_exploitable, sql_injection_exploitable, etc.)
2. Keyword extraction from description ("remote code execution" → rce_possible)
3. Fallback: package_severity_vuln_present

**Attack Path Generation**:
- Network wickets → network_exploit_v1 path
- Local wickets → local_exploit_v1 path
- All wickets → full_chain_v1 path
- Required wickets capped at 6–8 per path

**CLI usage**:
```bash
python3 -m skg.forge.compiler \
  --domain supply_chain \
  --description "Supply chain attack surface" \
  --packages "log4j,spring,fastjson" \
  --min-cvss 4.0 \
  --max-wickets 20 \
  --out catalog.json
```

### `forge/validator.py` — Staged Toolchain Validation

Five checks (order matters):

1. **Structural** (mandatory): VERSION file, adapters/*/parse.py, contracts/catalogs/*.json with wickets+attack_paths, projections/*/run.py, wicket IDs in attack_paths exist in wickets dict

2. **Import** (mandatory): Import adapter parse.py; verify TOOLCHAIN, SOURCE_ID constants; verify check_* or evaluate_* functions exist; graceful degradation for missing runtime deps

3. **Synthetic** (mandatory): Create synthetic realized events for required wickets of first attack path; run through projector; expected: classification="realized"

4. **Coverage** (warning only): For each catalog wicket, verify check_<wicket>() exists in adapter

5. **Stub Quality** (blocker): Scan for TODO, FIXME (error), or `return 'unknown'` (warning); reject if scaffold markers present

**Pass criteria**: structural AND import_check AND synthetic AND stub_quality all pass.

### `forge/pipeline.py` — Full Pipeline

```
detect_new_gaps(events_dir)
  → emit MC-03 (coverage gap detected) metacognition signal
  → generate_toolchain(domain, description, gap, resonance_engine)
  → validate(staging_path)
  → proposals.create(domain, description, gap, generation_result, validation_result)
  → emit CP-01 (toolchain candidate generated) cognitive signal
```

Cooldown mechanism: `proposals.is_in_cooldown(domain)` — skips recently rejected domains to prevent thrashing.

---

## 6. Cross-Cutting Concerns

### Strengths

| Strength | Location |
|----------|----------|
| Clean BaseSensor interface | sensors/__init__.py |
| Three-layer confidence blending | sensors/context.py |
| Standardized event envelope | sensors/__init__.py |
| Gravity/pearl reinforcement | gravity/selection.py |
| CVE → catalog autonomous pipeline | forge/compiler.py + pipeline.py |
| Closed execution loop | gravity/runtime.py (MSF → events → EVENTS_DIR) |

### Issues and Risks

| Issue | Location | Severity |
|-------|----------|----------|
| No per-sensor rate limiting | sensors/__init__.py | Medium |
| Unbounded state files | agent_sensor, usb_sensor, msf_sensor | Low |
| Adapter modules loaded without checksum validation | adapter_runner.py | Medium |
| LLM no timeout | cognitive_sensor.py | Medium |
| Credentials in YAML (file-permission reliant) | ssh_sensor.py | Medium |
| Port scanning may trigger IDS | gpu_probe.py | Low |
| tshark must be installed (no graceful degradation) | net_sensor.py | Low |
| Naive regex sensitive pattern matching | struct_fetch.py | Low |
| Forge stub quality detection regex-based | forge/validator.py | Low |
| First-contact entropy floor (25.0) aggressive | gravity/landscape.py | Low |

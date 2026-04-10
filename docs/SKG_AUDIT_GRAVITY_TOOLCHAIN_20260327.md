# SKG Gravity Toolchain Audit
**Date:** 2026-03-27
**Scope:** `skg-gravity/` — the main gravity field engine and supporting modules

---

## 1. Directory Overview

| File | Lines | Purpose |
|------|-------|---------|
| `gravity_field.py` | ~8,000+ | Core gravity orchestration engine |
| `exploit_dispatch.py` | ~1,347 | Attack path → Metasploit RC mapping |
| `cred_reuse.py` | ~906 | Credential reuse lateral movement |
| `gravity_web.py` | ~140 | Bond discovery and prior propagation |
| `exploit_proposals.py` | ~164 | CVE candidate → proposal persistence |
| `gravity.py` | ~48 | Compatibility shim → gravity_field.py |

**Total**: ~10,600+ lines

---

## 2. `gravity_field.py` — Core Engine

### Architecture Overview

The orchestration backbone. Implements the full entropy-driven instrument selection loop.

**Physics model:**
- State: Unknown wickets in superposition (high entropy)
- Observation: Instrument collapses wicket to REALIZED/BLOCKED (measurement)
- Energy: E = H(π | T) = Shannon entropy of projection given telemetry
- Gravity: Selects instrument to reduce entropy gradient
- Loop: observe → energy change → entropy shift → gravity redirects → next observation

**Key Singletons (module-level):**
- `_kernel`: KernelStateEngine instance
- `_wgraph`: WicketGraph instance (optional)
- `_pearls`: PearlLedger instance
- `_pearl_manifold`: PearlManifold instance

### Instrument Registry (50+ instruments)

`detect_instruments()` returns the full registered set:

**Network/Discovery**: nmap, pcap, nvd_feed
**Web**: http_collector, auth_scanner, gobuster, nikto, sqlmap, struct_fetch
**Host**: ssh_sensor, sysaudit, searchsploit, process_probe, boot_probe, gpu_probe
**Credentials**: cred_reuse
**Network analysis**: enum4linux
**AD/BloodHound**: bloodhound
**Container**: container_inspect
**Database**: db_discovery, data_profiler
**Binary**: binary_analysis
**Supply chain**: supply_chain
**AI**: ai_probe, cognitive_probe
**IoT**: iot_firmware
**Metasploit**: metasploit
**Specialized**: aprs (Log4Shell)

Each instrument has: name, description, wavelength, cost, availability, entropy_history.

### Instrument Execution Functions (~40 functions)

| Function | Instrument | Output |
|----------|-----------|--------|
| `_exec_nmap()` | nmap | Service discovery NDJSON |
| `_exec_metasploit()` | metasploit | MSF console events |
| `_exec_ssh_sensor()` | ssh_sensor | Host collection events |
| `_exec_http_collector()` | http_collector | Web surface events |
| `_exec_auth_scanner()` | auth_scanner | Auth test events |
| `_exec_bloodhound()` | bloodhound | AD lateral events |
| `_exec_cred_reuse()` | cred_reuse | Lateral movement events |
| `_exec_container_inspect()` | container_inspect | CE escape events |
| `_exec_nvd_feed()` | nvd_feed | CVE match events |
| `_exec_binary_analysis()` | binary_analysis | BA-* events |
| `_exec_db_discovery()` | db_discovery | Database events |
| `_exec_iot_firmware()` | iot_firmware | IF-* events |
| `_exec_supply_chain()` | supply_chain | SC-* events |
| `_exec_sysaudit()` | sysaudit | FI/PI/LI events |
| `_exec_data_profiler()` | data_profiler | DP-* events |
| `_exec_ai_probe()` | ai_probe | AI-* events |
| `_exec_pcap()` | pcap | Passive network events |
| `_exec_gobuster()` | gobuster | Directory enum events |
| `_exec_sqlmap()` | sqlmap | SQLi events |
| `_exec_enum4linux()` | enum4linux | SMB/AD events |
| `_exec_nikto()` | nikto | Web scanner events |
| `_exec_searchsploit()` | searchsploit | Exploit database events |
| `_exec_process_probe()` | process_probe | PR-* events |
| `_exec_boot_probe()` | boot_probe | BT-* events |
| `_exec_gpu_probe()` | gpu_probe | GP-* events |
| `_exec_cognitive_probe()` | cognitive_probe | MC-* events |

### LLM-Assisted Proposal Generation

Three functions use the Resonance engine (LLM):

1. `_create_toolchain_proposals_from_folds()`: For structural folds (uncovered services), ask LLM to suggest new attack surface toolchains

2. `_create_catalog_growth_proposals_from_folds()`: For contextual folds (CVEs without wickets), ask LLM to suggest catalog extensions

3. `_create_instrument_proposals_from_dark_hypotheses()`: For dark hypotheses (high-torque, no instrument), ask LLM to propose exploratory actions

### Main Loop

**`gravity_field_cycle()`**: Single cycle
1. Load fresh view state
2. Compute field entropy per target
3. Rank instruments per target
4. Execute top-k instruments (MAX_CONCURRENT = 8) in ThreadPoolExecutor
5. Ingest events → kernel state update
6. Detect folds + dark hypotheses
7. Generate proposals

**`gravity_field_loop()`**: Continuous loop
- Configurable max cycles
- Convergence epsilon = 0.01 (from skg_config.yaml)
- Entropy history tracking per instrument (failure detection)

**`main()`**: CLI entry point

### Hard Error Sentinel

`entropy_value = 500+` indicates a tool is missing. Gravity shifts to alternate instruments rather than retrying.

### Key Configuration

```python
MAX_CONCURRENT = 8       # parallel instruments per cycle
NMAP_TIMEOUT = 480       # seconds (increased from 120 after timeout bug)
PROPOSAL_TTL = 14400     # seconds (4 hours)
```

---

## 3. `exploit_dispatch.py` — Attack Path → MSF

### EXPLOIT_MAP (15+ attack paths)

```python
EXPLOIT_MAP = {
    "web_sqli_to_shell_v1": [
        {
            "module": "exploit/multi/http/php_cgi_arg_injection",
            "class": "exploit",
            "options": {"RHOSTS": "{target_ip}", "RPORT": "{port}", "LHOST": "{lhost}"},
            "requires": ["WB-01", "WB-10"],   # wickets that must be REALIZED
            "confidence": 0.85,
            "manual_step": "# Set TARGET to correct PHP version",
        }
    ],
    "host_ssh_initial_access_v1": [...],
    "host_network_exploit_v1": [...],
    "container_escape_socket_v1": [...],
    "ad_kerberoast_v1": [...],
    ...
}
```

### AUXILIARY_MAP

Post-exploitation auxiliary modules (scanning, enumeration):
- Tomcat, Elasticsearch, MySQL, FTP, SMB, Struts, GlassFish, SNMP

### PRIVESC_CHAIN (7 steps)

Ordered post-session privilege escalation:
1. local_exploit_suggester → HO-06
2. sudo_nopasswd → HO-07
3. suid_scan → HO-07
4. env creds → HO-09
5. docker escape → HO-15
6. ssh_keys → HO-12
7. kernel_vuln → HO-13

### `generate_exploit_proposals()`

1. Validate all required wickets REALIZED
2. Fill template variables: {target_ip}, {port}, {lhost}, {session_id}, {ssh_user}, {ssh_pass}
3. Generate MSF RC script:
   ```
   setg RHOSTS <target_ip>
   use <module>
   set LHOST <lhost>
   set ExitOnSession false
   run
   sleep 20
   exit
   ```
4. Call `create_msf_action_proposal()` for operator integration
5. Interactive review prompt

Payload auto-selection: Windows vs Linux based on module name heuristics.

### `generate_privesc_chain()`

For each step, skip if precondition wickets already known. Generates RC for each technique.

### `analyze_binary()`

Runs via SSH: `checksec`, `rabin2` (dangerous imports), `ltrace` (runtime), `ROPgadget` (head -50).
Emits BA-01 through BA-06 events.
Skips ltrace for binaries > 10MB.

---

## 4. `cred_reuse.py` — Credential Reuse

### CredentialStore

Persistent append-only JSONL ledger at `/var/lib/skg/credentials.jsonl`.

Fields: id, source, cred_type, user, secret, origin_ip, tested_on, found_at.

Deduplication by (user, secret) tuple. `mark_tested()` prevents redundant cross-target tests via identity aliasing.

### Credential Extraction

**From events** (`extract_from_events()`):
- WB-08: Default creds from HTTP login forms (regex: `_CRED_DETAIL_RE`)
- HO-09: Credentials from environment variables (regex: `_ENV_CRED_RE`)

**From targets.yaml** (`extract_from_targets_yaml()`):
- Operator-configured credentials loaded directly

### Credential Testing

**SSH** (`test_ssh_credential()`):
- Paramiko connection; 8.0s timeout
- Returns: success/failure/timeout with error details

**HTTP** (`test_http_credential()`):
- Tries 10 common login paths
- CSRF token extraction and reuse
- Form field discovery via regex
- Success heuristics: redirects, "logout"/"dashboard" in response

### `run_reuse_sweep()`

1. Detect SSH/HTTP services from target surface (ports 22, 80, 8080, 443, 8443, 8888)
2. Check CredentialStore for untested credentials
3. If `--authorized`: test directly, emit HO-03/WB-08 events
4. Else: create operator proposal

### Energy Estimation

```python
E_cred = |untested_credentials| × |service_count|
```

Used by gravity to prioritize cred_reuse instrument.

### Identity Aliasing

Canonical form matching for same-host detection. Prevents retesting same service under different workload IDs (e.g., `ssh::10.0.0.1` vs `host::server1`).

---

## 5. `gravity_web.py` — Bond Discovery

### BOND_STRENGTHS

```python
{
    "same_host": 1.00,
    "docker_host": 0.90,
    "same_compose": 0.80,
    "shared_cred": 0.70,
    "same_domain": 0.60,
    "same_subnet": 0.40,
}
```

### `build_gravity_web()`

Auto-discovers bonds from topology:
- Subnet grouping: first 3 octets of IP
- Gateway detection: *.0.1 addresses
- Docker host bonds: gateway ↔ container subnets (172.17.*, 172.18.*)
- Docker compose networks: 172.18.*
- Same-host detection: SSH + gateway proximity

**Issue**: Gateway heuristic (*.0.1) is fragile and non-universal.

### `compute_neighbor_priors()`

For each realized wicket on bonded target:
```python
prior = bond_strength × 0.5
```

Returns Dict[wicket_id → prior_strength] for influence injection into field entropy.

---

## 6. `exploit_proposals.py` — CVE Candidate Proposals

### `_module_candidates_for_service()`

Heuristic-only module ranking:
- Service family matching: Apache → http_version, dir_scanner, robots_txt
- CVE text analysis: "path traversal" → files_dir, "default credentials" → login scanners

Confidence range: 0.0–1.0. Deduplicates by module name (keeps highest confidence).

### `create_exploit_proposal()`

Persists proposal JSON at `PROPOSALS_DIR/{id}.json`:
- id, category, status, authorization_required=True, created_at, source
- CVE + module candidates
- Adjudication block (approved, review_notes)

---

## 7. `gravity.py` — Compatibility Shim

48-line module. Lazy-loads gravity_field.py via importlib. All attribute access forwarded. Allows legacy entry points to work without code duplication.

---

## 8. Cross-File Dependency Map

```
gravity_field.py (orchestrator)
  ├── cred_reuse.py (_exec_cred_reuse)
  ├── exploit_dispatch.py (generate_exploit_proposals, generate_privesc_chain)
  ├── gravity_web.py (build_gravity_web, compute_neighbor_priors)
  ├── exploit_proposals.py (create_from_nvd_candidates)
  ├── skg.kernel.engine.KernelStateEngine
  ├── skg.kernel.pearls.PearlLedger
  ├── skg.kernel.wicket_graph.WicketGraph (optional)
  ├── skg.kernel.folds.FoldManager
  ├── skg.gravity.{selection, landscape, runtime, failures}
  └── skg.resonance (LLM for proposal drafting)

exploit_dispatch.py
  └── skg.assistant.action_proposals.create_msf_action_proposal

cred_reuse.py
  └── skg.assistant.action_proposals.create_action_proposal

gravity.py
  └── gravity_field.py (shim delegation)
```

---

## 9. Security and Operator Safety Notes

1. **Operator-gated execution**: All exploits are proposals requiring `skg proposals trigger <id>`. `--authorized` flag only gates direct test execution in cred_reuse, not exploit deployment.

2. **Entropy-driven, not brute-force**: Gravity follows Shannon entropy gradients. It does not schedule by priority or hit all targets simultaneously.

3. **Fault-tolerant**: Instrument failure tracked in entropy_history; gravity shifts to alternate instruments rather than retrying.

4. **Credential isolation**: Credentials logged only to first 12 chars in CLI output. Secrets never fully logged.

5. **Error resilience**: Hard error sentinel (entropy = 500+) for missing tools; soft errors logged and gravity continues.

---

## 10. Potential Issues

| Location | Issue | Severity |
|----------|-------|----------|
| `gravity_field.py` | MAX_CONCURRENT=8 hardcoded; no backpressure if pool saturates | Low |
| `gravity_field.py` | Dynamic import of discovery.py at runtime can fail silently | Low |
| `gravity_web.py` | Gateway detection *.0.1 fragile (not universal) | Low |
| `cred_reuse.py` | mark_tested happens after test decision in loop (alias edge case) | Low |
| `cred_reuse.py` | HTTP testing heuristics; POST failures don't distinguish 404 from auth failure | Low |
| `exploit_dispatch.py` | String replacement templating doesn't handle escaped braces | Low |
| `exploit_dispatch.py` | ltrace with stdin redirect may hang on interactive binaries | Low |
| `exploit_proposals.py` | Module suggestions are text-pattern heuristics; CVE→module mapping crude | Low |
| `gravity_field.py` | Pearl reinforcement boost could be unbounded (no saturation cap noted) | Low |

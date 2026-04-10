# SKG Domain Toolchains & Tests Audit
**Date:** 2026-03-27
**Scope:** All 12 domain toolchains + `skg-discovery/` + `tests/`
**Method:** Deep read across all toolchain adapters, projections, contracts, and test files

---

## Overview

Each domain toolchain implements the unified SKG architecture:
- **Adapters** (`adapters/<name>/parse.py`) — collect raw data, emit `obs.attack.precondition` NDJSON
- **Projections** (`projections/<domain>/run.py`) — consume observations, score attack paths
- **Contracts** (`contracts/catalogs/*.json`) — define wickets and attack paths
- **forge_meta.json** — toolchain declaration consumed by the forge pipeline
- **bootstrap.sh** — dependency installation
- **tests/test_golden.py** — determinism validation

---

## 1. `skg-ad-lateral-toolchain`

**Path:** `/opt/skg/skg-ad-lateral-toolchain/`
**Version:** 0.1.0
**Domain:** `ad_lateral`

### forge_meta.json
Missing — predates forge integration.

### Catalog
`contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json`
- **Wickets:** AD-01 through AD-25
  - AD-01/02/03: Kerberoastable accounts (SPN presence, no AES enforcement, no detection)
  - AD-04/05: AS-REP roasting preconditions
  - AD-06/07: Unconstrained delegation
  - AD-08/09: Constrained delegation + protocol transition
  - AD-10–16: ACL edges (GenericAll, WriteDACL, DCSync)
  - AD-17/18: Plaintext credentials in LDAP descriptions
  - AD-19–22: AdminSDHolder, tiering, privilege reuse
  - AD-23/24/25: SPN on DA, weak password policy, LAPS absence
- **Attack Paths:** 4 — `ad_kerberoast_v1`, `ad_kerberoast_da_v1`, `ad_asrep_roast_v1`, delegation/ACL paths

### Adapters

**bloodhound/parse.py** (primary)
- Parses BloodHound v4 (SharpHound <2.0) and v5/CE (≥2.0) JSON
- Input files: users.json, computers.json, groups.json, acls.json, domains.json
- Normalizes both v4/v5 schemas to common representation
- Checks: SPN detection, encryption enforcement, delegation flags, ACL edges, group memberships
- Evidence rank: 2–3

**ldapdomaindump/parse.py**
- Parses ldapdomaindump YAML/JSON output
- Emits same AD-* wicket events; evidence rank: 2

**manual/parse.py**
- Hand-crafted JSON precondition records; evidence rank: 3

### Projection Engine (`projections/lateral/run.py`)
- Source: `projection.lateral`
- Tri-state per wicket: latest-wins accumulation (blocked > realized > unknown)
- Score = |realized| / |required|
- Classification: realized / not_realized (any blocked) / indeterminate
- Optional H¹ obstruction detection (`indeterminate_h1`)

### Bootstrap
Sets up Python venv, installs requirements.txt, runs test_golden.py.

### Tests
- `tests/test_golden.py` — 1 golden test: bloodhound fixture → adapter → projection → expected_payload.json

### Issues / Gaps
1. No forge_meta.json (predates forge)
2. Only 1 golden test; no adapter unit tests
3. No timeout/resource limits on BloodHound JSON parsing
4. Hardcoded `HIGH_VALUE_GROUPS` and `SENSITIVE_DELEGATION_SVCS` patterns may miss customer environments
5. No incremental replay — must re-ingest entire BloodHound dump

---

## 2. `skg-ai-toolchain`

**Path:** `/opt/skg/skg-ai-toolchain/`
**Version:** 1.0.0
**Domain:** `ai_target`

### forge_meta.json
Declares domain, instruments, 3 attack paths: `ai_llm_extract_v1`, `ai_rce_via_notebook_v1`, `ai_model_poison_v1`.

### Catalog
`contracts/catalogs/ai_attack_preconditions_catalog.v1.json`
- Attack paths covering prompt injection, notebook shell access, training data poisoning

### Adapters
None implemented — `adapters/` directory is empty.

### Projection Engine
None implemented.

### Issues / Gaps
1. **Catalog-only** — no adapters, no projection engine
2. No tests
3. forge_meta.json declares `ai_probe` instrument that does not exist

---

## 3. `skg-aprs-toolchain`

**Path:** `/opt/skg/skg-aprs-toolchain/`
**Version:** 1.0.0
**Domain:** `aprs` (Log4Shell / Log4j JNDI RCE)

### Catalog
`contracts/catalogs/attack_preconditions_catalog.v1.json`
- **Wickets:** AP-L4 through AP-L19
  - AP-L4: log4j_loaded_at_runtime (rank 1)
  - AP-L8: attacker_controlled_input_reaches_log4j_sink (rank 1)
  - AP-L9: exposure_class_supports_attacker_access (rank 4)
  - AP-L10: jndi_lookup_capability_present (rank 1)
  - AP-L11: lookups_enabled_in_effective_configuration (rank 3)
  - AP-L12–14: DNS, LDAP/RMI, HTTP egress (rank 4)
  - AP-L18/19: TLS validation and certificate pinning gaps (rank 4)
- **Attack Paths:** 5 — `log4j_dos_v1`, `log4j_info_disclosure_v1`, `log4j_jndi_callback_v1`, `log4j_jndi_rce_v1`, `log4j_rce_via_ldap_v1`

### Adapters

**config_effective/parse.py**
- Scans filesystem for log4j-core JARs (`rglob("*.jar")`)
- Detects `JndiLookup.class` inside JAR → AP-L10
- Parses log4j2.xml, log4j2.properties for `${...}` patterns → AP-L11
- Evidence rank: 2–3

**net_sandbox/parse.py**
- Input: docker inspect JSON, /etc/resolv.conf, iptables rules, ps output
- Tests DNS resolution, checks iptables egress rules, infers exposure via port bindings
- Emits AP-L7, AP-L9, AP-L12–14; evidence rank: 3–4

### Projection Engine (`projections/aprs/run.py`)
- Source: `projection.aprs`; supports legacy catalog format (dict *and* list of paths)
- Score = |realized| / |required|; tri-state classification

### CLI Wrapper (`skg.py`)
- Provides: `validate`, `latest`, `project aprs`, `ingest config_effective`, `ingest net_sandbox`
- Validates NDJSON via jsonschema against `contracts/envelope/skg.event.envelope.v1.json`

### Tests
- `tests/test_golden.py` — 1 golden test

### Issues / Gaps
1. `jar_has()` uses naive zipfile scan — can timeout on large JARs
2. `${...}` pattern matching fires on comments and string literals
3. No actual DNS/LDAP resolution test (passive only)
4. No timeout protection on large directory trees or corrupted ZIPs
5. Evidence rank inflation: rank 2–3 for config patterns when runtime proof is the standard

---

## 4. `skg-binary-toolchain`

**Path:** `/opt/skg/skg-binary-toolchain/`
**Version:** 0.1.0
**Domain:** `binary`

### Catalog
`contracts/catalogs/attack_preconditions_catalog.binary.v1.json`
- **Wickets:** BA-01–06
  - BA-01: NX disabled
  - BA-02: ASLR disabled or weak (PIE: no, randomize_va_space < 2)
  - BA-03: No stack canary
  - BA-04: Dangerous function imported (strcpy, gets, sprintf, system, exec*)
  - BA-05: Controlled input reaches call (ltrace proof)
  - BA-06: Exploit chain constructible (ROP gadgets ≥ 20)
- **Attack Paths:** 3–4 (e.g., `binary_stack_overflow_v1`)

### Adapters

**binary_analysis/parse.py** (SSH)
- Commands: `file`, `checksec`, `readelf -s/-d/-n` (fallback), `/proc/sys/kernel/randomize_va_space`, `rabin2 -i` / `nm`, `ROPgadget`
- Evidence rank: 1–3

### Projection Engine (`projections/binary/run.py`)
- Tri-state; optional H¹ sheaf analysis
- Output: single JSON object (not NDJSON lines — **inconsistent** with other toolchains)

### Bootstrap (`bootstrap.sh`)
- Verifies: checksec, rabin2 (radare2), ROPgadget, ltrace
- Warns if missing; issues `pacman -S checksec radare2 python-ropgadget ltrace`

### Tests
- `tests/test_golden.py` — 1 golden test

### Issues / Gaps
1. No local collection — always requires SSH
2. ROPgadget can hang on large binaries; no timeout
3. "20 gadgets" threshold arbitrary; not empirically calibrated
4. Output format (single JSON) differs from all other toolchain projections

---

## 5. `skg-container-escape-toolchain`

**Path:** `/opt/skg/skg-container-escape-toolchain/`
**Version:** 0.1.0
**Domain:** `container_escape`

### Catalog
`contracts/catalogs/attack_preconditions_catalog.container_escape.v1.json`
- **Wickets:** CE-01–14
  - CE-01: container running as root
  - CE-02: --privileged flag set
  - CE-03: docker.sock mounted
  - CE-04/05: CAP_SYS_ADMIN, CAP_SYS_PTRACE
  - CE-06/07: --pid=host, --network=host
  - CE-08–10: sensitive paths mounted, seccomp/AppArmor disabled
  - CE-11–14: NET_ADMIN, writable host paths, IPC namespace, user ns remapping
- **Attack Paths:** 5 — privileged, socket, sys_admin, ptrace, mount

### Adapters

**container_inspect/parse.py**
- Input: `docker inspect` JSON
- Parses: .Config.User, .HostConfig.Privileged, .Mounts[].Source, .HostConfig.CapAdd, PidMode, NetworkMode, SecurityOpt, IpcMode
- Evidence rank: 3

### Projection Engine (`projections/escape/run.py`)
- Source: `projection.escape`; tries `skg.substrate.projection`, falls back to local implementation
- Tri-state; optional H¹ sheaf analysis

### Tests
- `tests/test_golden.py` — 1 golden test with sample_inspect.json fixture

### Issues / Gaps
1. All CE-08 (sensitive paths) treated equally regardless of sensitivity level
2. Assumes docker inspect field names are stable across Docker API versions
3. No seccomp profile content analysis — only checks if disabled
4. No modeling of newer CAP_* additions

---

## 6. `skg-data-toolchain`

**Path:** `/opt/skg/skg-data-toolchain/`
**Version:** 0.1.0
**Domain:** `data`

### Catalogs
1. `attack_preconditions_catalog.data.v1.json` — DP-01–13 (data pipeline quality: NULLs, FK violations, duplicates, domain constraints, schema versioning)
2. `attack_preconditions_catalog.db_exposure.v1.json` — DE-01–10 (database exposure: port exposed, default/weak creds, no TLS, backup/replica exposure)

### Adapters

**db_discovery/parse.py** (SSH)
- Probes DB ports: 3306, 5432, 27017, 6379, 1433, 1521, 5984, 9200
- Tests default credentials + harvested creds (reads HO-18 from state store — credential reuse)
- Runs SHOW DATABASES, SELECT COUNT(*), table name regex scan for sensitive names
- Evidence rank: 1–4

**db_profiler/profile.py**
- Input: SQLAlchemy URL, table name, contract JSON
- Analyzes NULL constraints, FK violations, duplicates, uniqueness, domain constraints
- Evidence rank: 1 (live query results)

### Projection Engine (`projections/data/run.py`)
- Output type: `interp.data.pipeline` (non-standard envelope type)
- Tri-state; emits human-readable interpretation field

### Tests
- `tests/test_bwapp_data.py` (top-level, 4+ unit tests with SQLite fixture; conditional MySQL tests via `@pytest.mark.bwapp`)
- No toolchain-local test_golden.py

### Issues / Gaps
1. No async DB connections — synchronous pymysql may hang on dead hosts
2. Projection emits single JSON object, not NDJSON lines — inconsistent
3. Output envelope type `interp.data.pipeline` differs from `interp.*.realizability` convention
4. No PII/compliance wickets (only quality and exposure)

---

## 7. `skg-host-toolchain`

**Path:** `/opt/skg/skg-host-toolchain/`
**Version:** 1.0.0
**Domain:** `host`

### Catalogs
1. `attack_preconditions_catalog.host.v1.json` — HO-01–25+
   - HO-01–04: SSH service and configuration
   - HO-05–10: Sudo/SUID/capability escalation
   - HO-11–18: Credentials in env/history, cron, SSH keys, selinux/apparmor disabled
   - HO-19–25: Kernel vulnerabilities, missing patches, privileged processes
2. `attack_preconditions_catalog.sysaudit.v1.json` — compliance/risk wickets

### Adapters

**ssh_collect/parse.py**
- Commands: id, uname -a, ps -ef (rank 1); dpkg -l, rpm -qa, ls ~/.ssh (rank 2); sudo -l, /etc/sudoers, crontab -l (rank 3); find / -perm -4000 (SUID)
- Wicket checks: HO-01 (sshd in ps), HO-02 (sshd_config PasswordAuthentication), HO-05 (NOPASSWD in sudo -l), HO-07 (SUID binaries), HO-11 (PASSWORD/TOKEN in env/history), HO-12 (vulnerable kernel via VULN_KERNEL_PATTERNS), HO-17 (root processes)
- Also emits HOST_TOOL_CATALOG (nmap, sqlmap, searchsploit, etc. found on target)

**nmap_scan/parse.py** — nmap XML parsing; service/version → wicket emission; evidence rank: 4

**winrm_collect/parse.py** — Windows evidence (WinRM, UAC, registry keys); evidence rank: 1–2

**msf_session/parse.py** — Converts Metasploit session facts to host wickets; evidence rank: 2

### Projection Engine (`projections/host/run.py`)
- Uses `StateEngine` + `SupportEngine` with `CollapseThresholds(realized=0.5, blocked=0.5)`
- H¹ sheaf analysis for indeterminate classification
- `canonical_observation_subject()` extraction from payloads

### Tests
- `tests/test_golden.py` — 1 golden test

### Issues / Gaps
1. `find / -perm -4000` will hang on large filesystems; no timeout enforced
2. VULN_KERNEL_PATTERNS is a static list — does not account for backported patches
3. Credential regex (PASSWORD/TOKEN patterns) has false positive risk on config comments
4. HO-05 checks sudo -l output but does not verify NOPASSWD actually executes without password

---

## 8. `skg-iot_firmware-toolchain`

**Path:** `/opt/skg/skg-iot_firmware-toolchain/`
**Version:** 1.0.0
**Domain:** `iot_firmware`

### Catalog
`contracts/catalogs/attack_preconditions_catalog.iot_firmware.v1.json`
- IF-01: firmware_extraction_possible
- IF-02–05: Weak/no authentication
- IF-06–10: Unsigned firmware, no secure boot
- IF-11–15: Update mechanism vulnerabilities

### Adapters
None implemented.

### Projection Engine (`projections/iot_firmware/run.py`)
- Tri-state; optional H¹ sheaf analysis

### Tests
None.

### Issues / Gaps
1. **No adapters at all** — no collection mechanism
2. No UART/JTAG enumeration
3. No RTOS-specific wickets (FreeRTOS, TinyOS, etc.)
4. No tests
5. Catalog lacks version-specific CVE mappings

---

## 9. `skg-metacognition-toolchain`

**Path:** `/opt/skg/skg-metacognition-toolchain/`
**Version:** 0.1.0
**Domain:** `metacognition`

### forge_meta.json
Declares 3 adapters (confidence_elicitation, review_revision, known_unknown), 4 capability paths, `cognitive` sensor.

### Catalog
`contracts/catalogs/attack_preconditions_catalog.metacognition.v1.json`
- **Wickets:** MC-01–08
  - MC-01: confidence_calibration (ECE ≤ 0.15 across N≥20 trials)
  - MC-02: error_detection (spontaneous corrections)
  - MC-03: known_unknown_discrimination (solvability accuracy)
  - MC-04: directed_review_effectiveness (confidence changes with counter-evidence)
  - MC-05: failure_recovery (retry after explicit failure)
  - MC-06: confidence_update_on_evidence (rapid response to injected evidence)
  - MC-07: uncertainty_propagation (admits unknowns when compounding)
  - MC-08: unknown_propagation_across_domains (novel domain recognition)
- **Capability Paths:** `meta_calibration_only_v1`, `meta_error_loop_v1`, `meta_epistemic_honesty_v1`, `meta_full_v1`

### Adapters

**confidence_elicitation/parse.py**
- Input: NDJSON trials file (trial_id, subject_id, probe_type, prompt, stated_confidence, ground_truth, evidence_direction, confidence_before/after)
- Computes ECE binned over ECE_BINS (default 10); MC-01 realized if ECE ≤ 0.15 with ≥20 trials
- MC-06: counter-evidence → confidence drop ≥ 0.10; confirm-evidence → confidence rise ≥ 0.05
- Output: `obs.substrate.node` events (not `obs.attack.precondition` — **different envelope type**)

**review_revision/parse.py** — MC-02, MC-04, MC-05; evidence rank 1; `obs.substrate.node` output

**known_unknown/parse.py** — MC-03, MC-07, MC-08; evidence rank 1; `obs.substrate.node` output

### Projection Engine (`projections/metacognition/run.py`)
- Handles both `obs.substrate.node` and `obs.attack.precondition` input types
- Output: `obs.projection.result` (third envelope type — non-standard)
- Computes field energy E = len(unknown); emits terminal-friendly table with checkmarks/crosses
- Tracks `latest_confidence` per wicket with 4-decimal precision

### Tests
None.

### Issues / Gaps
1. ECE_THRESHOLD (0.15) and MIN_TRIALS (20) hardcoded; not configurable per subject
2. All trials weighted equally; no evidence_rank weighting
3. Three different output envelope types across 3 adapters + projection
4. No longitudinal tracking (improvement/decay over time)
5. No multi-subject comparison support

---

## 10. `skg-nginx-toolchain`

**Path:** `/opt/skg/skg-nginx-toolchain/` (+ `.backup/`)
**Version:** 0.1.0-forge
**Domain:** `nginx`

### forge_meta.json
```json
{
  "generation_backend": "template",
  "errors": ["Used template catalog — no generation backend available", "Used template adapter — check collection commands"]
}
```
Attack surface: path traversal, SSRF via proxy_pass, header injection.

### Catalog
NX-01–10 range (path traversal, SSRF, header injection, auth gaps, version CVEs).

### Adapters
`adapters/ssh_collect/parse.py` — generic SSH collection shared with host toolchain; no nginx-specific nginx.conf parsing.

### Projection Engine (`projections/nginx/run.py`)
- Auto-generated by forge; tri-state

### Tests
None in main toolchain (backup has 1 golden test).

### Issues / Gaps
1. **Template-generated code** — forge reported errors at generation time
2. No nginx.conf directive parsing (proxy_pass, alias, root, try_files)
3. No active path traversal or SSRF testing
4. Upgrade path from template to real adapters is unclear

---

## 11. `skg-supply-chain-toolchain`

**Path:** `/opt/skg/skg-supply-chain-toolchain/`
**Version:** 1.0.0
**Domain:** `supply_chain`

### Catalog
SC-01–15: third-party dependency vulnerabilities, build/CI/CD pipeline gaps, release artifact integrity.

### Adapters
None implemented.

### Projection Engine (`projections/supply_chain/run.py`)
- Tri-state; optional H¹ sheaf analysis

### Tests
None.

### Issues / Gaps
1. **No adapters** — no SCA tool integration, no git analysis
2. No SBOM support (CycloneDX / SPDX)
3. No CI/CD pipeline analysis (GitHub Actions, GitLab CI)
4. No artifact checksum/signature validation
5. No tests

---

## 12. `skg-web-toolchain`

**Path:** `/opt/skg/skg-web-toolchain/` (+ `.backup/`)
**Version:** 0.1.0-forge
**Domain:** `web`

### forge_meta.json
Template-generated (same errors as nginx). Attack surface: SQLi, auth bypass, SSRF, XXE, path traversal, insecure deserialization, TLS gaps.

### Catalog
WB-01–25+: full OWASP-aligned wicket set. Includes legacy alias `web_sqli_to_shell_v1` → `web_full_chain_v1`.

### Adapters
`adapters/ssh_collect/parse.py` — generic SSH collection; no active HTTP probing.

### Projection Engine (`projections/web/run.py`)
- Auto-generated by forge; tri-state
- `_normalize_required_wicket()` converts W-* prefix to WB-* prefix
- Legacy path_id aliasing (web_sqli_to_shell_v1 → web_full_chain_v1)
- Output type: `interp.attack.path` (generic)

### Tests
- `tests/test_golden.py` — 1 golden test (in `.backup/` only)

### Issues / Gaps
1. Template-generated; no custom web adapters
2. No active SQLi/XSS/CSRF probe execution
3. W-* → WB-* normalization may silently drop unknown prefixes
4. Legacy aliasing is hardcoded; breaks if path IDs change
5. Only checks HTTP headers/status codes; no response body analysis

---

## 13. `skg-discovery/`

**Path:** `/opt/skg/skg-discovery/discovery.py`
Not a toolchain — standalone network and service discovery module.

### Key Functions

| Function | Purpose |
|----------|---------|
| `detect_local_subnets()` | Parses `ip -4 addr show`; returns list of CIDRs (excludes 127.0.0.0/8) |
| `detect_docker_networks()` | Runs `docker network ls` + `docker network inspect`; extracts subnet CIDRs |
| `enumerate_docker_containers()` | Runs `docker ps` + `docker inspect`; returns container metadata |
| `ping_sweep(subnet, timeout=0.5)` | TCP connect to [80,443,22,445,135,3389,8080]; fallback ICMP; `ThreadPoolExecutor(50)` |
| `SERVICE_PORTS` | Port→service name catalog (21→ftp, 22→ssh, 80→http, etc.) |

### Issues / Gaps
1. **No NDJSON emission** — discovery outputs raw dicts, not `obs.attack.precondition` events; manual conversion needed downstream
2. No scope limits — `ping_sweep` on a /8 network attempts 16M hosts
3. `max_workers=50` may be insufficient for large subnets
4. Docker-centric; traditional host discovery is secondary
5. SERVICE_PORTS list is not versioned; may be outdated

---

## 14. `tests/` — Top-Level Test Suite

**Path:** `/opt/skg/tests/`

### Structure
```
tests/
  conftest.py                          # adds /opt/skg to sys.path
  fixtures/
    create_webapp_db.py                # SQLite fixture generator
    webapp.db                          # pre-built SQLite DB
    users_contract.json                # DP-* wicket contract
    orders_contract.json
  test_bwapp_data.py
  test_cli_commands.py
  test_dark_hypothesis_sensor.py
  test_gravity_routing.py
  test_gravity_runtime.py
  test_ollama_backend.py
  test_resonance_drafter.py
  test_runtime_regressions.py
  test_sensor_projection_loop.py
```

### Test Files

**test_bwapp_data.py** (~200 lines)
- `TestSQLiteFixture` (always runs): test_fixture_db_exists, test_users_dp03_null_email_blocked, test_orders_dp08_duplicate_blocked, test_ndjson_event_format
- `TestbWAPPMySQL` (`@pytest.mark.bwapp`, conditional): MySQL credential testing, DE-* wicket emission
- ~8 tests; covers DP-03 (NULL), DP-08 (duplicates)

**test_cli_commands.py** (~200 lines)
- `TestCmdCheck`, `TestCmdReplay`
- Tests: import sanity, output format, daemon-not-running graceful degradation, missing/empty dir exits nonzero, end-to-end replay with valid events
- ~8 tests; covers CLI arg parsing and error handling

**test_dark_hypothesis_sensor.py** (~150 lines)
- Tests: LLM unavailable handling, min_torque filtering, valid LLM response → proposal, null instrument response skipped
- ~4 tests; all mocked (no live LLM calls)

**test_gravity_routing.py** (~150 lines)
- Tests: energy=0 when all realized, energy=|unknown|, blocked nodes don't contribute, fold weight is additive
- ~4 tests; covers `EnergyEngine` and landscape sorting

**test_gravity_runtime.py** (~200 lines)
- Tests: failure reporter writes NDJSON, follow-on proposals use supplied generator, auxiliary proposals use contract-backed helper
- ~3 tests

**test_ollama_backend.py**
- Ollama LLM integration; requires Ollama service running to pass live tests

**test_resonance_drafter.py**
- Resonance observation synthesis; pattern matching and propagation

**test_runtime_regressions.py** (~250 lines)
- Tests: project events keep distinct attack paths per run, gap detector tracks new hosts per service, sensor context loads persisted calibration, confidence calibration persists stats, NDJSON round-trip preserves precision, interpretation subsetting filters by run_id
- ~6 regression tests; covers gap_detector, confidence calibration, NDJSON precision

**test_sensor_projection_loop.py** (~400 lines)
- `SensorProjectionLoopTests(unittest.TestCase)`
- Tests: canonical field functional order-stable and curved, fiber coupling matrix symmetric for same sphere, energy engine produces canonical ordering, projection with mixed domains produces multi-sphere, knot detection identifies circular dependencies
- ~5 integration tests; all synthetic data

### Coverage Assessment

| Area | Coverage | Notes |
|------|----------|-------|
| CLI parsing | Good | arg errors, output format, daemon degradation |
| Energy engine | Good | tri-state accounting, fold weights |
| Confidence calibration | Good | persistence, round-trip precision |
| Gap detection | Good | per-service, per-host tracking |
| Sensor → projection loop | Moderate | synthetic data only |
| Adapter parsing (all 12 toolchains) | Poor | only golden tests in toolchain dirs |
| Projection scoring logic | Poor | only golden tests; no unit tests |
| Error recovery / malformed input | None | no negative tests |
| Cross-toolchain attack chains | None | no integration scenarios |
| Timeouts / resource exhaustion | None | no stress tests |
| Credential extraction regex | None | no unit tests for patterns |

**Estimated total test count:** ~45–55 tests across all files

### Issues / Gaps
1. Toolchain-local `tests/test_golden.py` files are **not included** in top-level pytest discovery
2. No adapter unit tests — bloodhound, APRS, container_inspect, ssh_collect have no parse.py tests
3. No negative tests for malformed NDJSON, corrupt JARs, SSH timeout
4. No cross-toolchain integration scenarios
5. `webapp.db` fixture requires manual creation via `fixtures/create_webapp_db.py` if absent
6. `@pytest.mark.bwapp` tests fail silently when MySQL unavailable; no skip message
7. No `pytest-cov` / coverage.py integration visible

---

## Cross-Cutting Observations

### Output Format Inconsistency
| Format | Used by |
|--------|---------|
| NDJSON lines of `obs.attack.precondition` | AD, APRS, container, host, nginx, web |
| Single JSON object | binary, data (projection outputs) |
| `obs.substrate.node` lines | metacognition adapters |
| `obs.projection.result` | metacognition projection |
| `interp.data.pipeline` | data projection |
| `interp.attack.path` | web projection |

No unified output envelope schema is enforced at toolchain boundaries.

### Sheaf Analysis Pattern
All projection engines optionally import `from skg.topology.sheaf import classify_with_sheaf` and silently skip if unavailable. This means `indeterminate_h1` classification is silently dropped in environments where the sheaf module is absent.

### Catalog Format Evolution
- **Legacy (list):** APRS supports `attack_paths` as list of dicts with `"id"` or `"attack_path_id"`
- **Modern (dict):** All others use `attack_paths: {path_id: {...}}`
- Only APRS explicitly handles both; other projectors may reject legacy format

### Bootstrap Coverage
7 of 12 toolchains have no `bootstrap.sh`. Only AD, APRS, binary, and host have documented dependency installation.

### Forge Coverage
Only metacognition, nginx, and web have `forge_meta.json`. AI toolchain has one but is otherwise empty. 8 of 12 toolchains predate forge integration.

### Maturity Summary

| Toolchain | Adapters | Projection | Tests | forge_meta |
|-----------|----------|-----------|-------|-----------|
| AD Lateral | 3 | ✓ | 1 golden | ✗ |
| AI | 0 | ✗ | 0 | ✓ (hollow) |
| APRS | 2 | ✓ | 1 golden | ✗ |
| Binary | 1 | ✓ | 1 golden | ✗ |
| Container Escape | 1 | ✓ | 1 golden | ✗ |
| Data | 2 | ✓ | 4+ unit | ✗ |
| Host | 4 | ✓ | 1 golden | ✗ |
| IoT Firmware | 0 | ✓ | 0 | ✗ |
| Metacognition | 3 | ✓ | 0 | ✓ |
| Nginx | 1 shared | ✓ (template) | 0 | ✓ (errors) |
| Supply Chain | 0 | ✓ | 0 | ✗ |
| Web | 1 shared | ✓ (template) | 1 golden | ✓ (errors) |

### Recommendations

**Immediate:**
1. Include toolchain `tests/test_golden.py` files in top-level pytest (add to `conftest.py` or `pytest.ini`)
2. Add timeout parameters to all SSH adapter calls and SUID/JAR enumeration
3. Make sheaf import failure loud (warning log), not silent
4. Validate W-* → WB-* normalization does not silently discard unrecognized prefixes

**Short-term:**
1. Write adapter unit tests for parse.py files (bloodhound, APRS, container_inspect, ssh_collect)
2. Add negative tests: malformed NDJSON, corrupt ZIP, SSH timeout, empty input
3. Standardize output envelope type across all projection engines
4. Make ECE_THRESHOLD and MIN_TRIALS in metacognition toolchain configurable

**Long-term:**
1. Implement AI toolchain adapters (LLM endpoint probing)
2. Implement IoT firmware adapters (binwalk, UART enumeration)
3. Implement Supply Chain adapters (SCA tool integration, SBOM ingestion)
4. Add skg-discovery NDJSON emission so discovery feeds directly into the substrate
5. Add forge_meta.json to all pre-forge toolchains

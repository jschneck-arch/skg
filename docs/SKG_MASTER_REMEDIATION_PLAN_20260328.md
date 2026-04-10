# SKG_MASTER_REMEDIATION_PLAN_20260328.md

## 1. EXECUTIVE SUMMARY

### Problem Categories Identified

Across 18 audit documents covering architecture, kernel, sensors, gravity, CLI, core layers, toolchains, tests, configuration, and 7 specialized unification/boundary audits, **134+ distinct issues** were identified across 6 categories:

| Category | Count | Severity |
|----------|-------|----------|
| **BROKEN** | 23 | Critical/High |
| **UNWIRED** | 18 | Medium/High |
| **ABSENT** | 31 | Medium |
| **UNCANONICAL** | 37 | Medium |
| **CONFUSED** | 22 | Medium/Low |
| **INSECURE** | 3 | Medium |

### Overall System Health Assessment

**SKG Status**: Functionally viable but architecturally split. The substrate (kernel, temporal, identity, topology layers) is real and active. However, multiple authority boundaries have drifted, and wrapper/orchestration layers still bypass the substrate through:

1. **Config injection** — declared targets treated as measured state
2. **Filename heuristics** — domain/workload/run identity inferred from artifact names
3. **Hardcoded tables** — instrument/domain/sphere mappings embedded in core paths
4. **Parallel surfaces** — gravity, surface, target registry all maintain separate truth models
5. **Silent corruption** — state loader failures swallowed without operator visibility

**Priority**: Restore substrate authority and reduce parallel truth layers. This is not about removing features—it is about establishing which paths are canonical, which are secondary, and which are compatibility shims.

---

## 2. PROBLEM TAXONOMY

### **BROKEN** — Code exists but is wrong, produces incorrect output, or crashes

Examples: Logic errors, data-structure mismatches, timeout/resource leaks, unsafe assumptions.

### **UNWIRED** — Code exists but is not connected to the system (dead code, unreachable)

Examples: Unused classes, branches never executed, registers defined but not called.

### **ABSENT** — Declared, promised, or referenced but not implemented

Examples: Stubs, empty directories, missing adapters, unimplemented sensors.

### **UNCANONICAL** — Works but inconsistently; different subsystems solve the same problem differently

Examples: Multiple event envelopes, multiple gravity invocation stories, three different "surface" definitions.

### **CONFUSED** — Design is self-contradictory, mixes concerns, or has unclear contracts

Examples: Fold location field overloaded, Fiber.anchor means different things, feedback/projection shapes mixed.

### **INSECURE** — Security risk in current implementation

Examples: Credential handling, injection risks, unsafe deserialization.

---

## 3. ITEMS BY CATEGORY

### BROKEN — 23 Items

#### BRK-001: Wrapped Interp Results Do Not Flow Into Delta Store
**Area**: Temporal / Projection
**File(s)**: `skg/sensors/projector.py:289-427`, `skg/temporal/__init__.py:235-295`
**Description**: Wrapped projection envelopes (with nested payload) are accepted by `projector.py` but `DeltaStore.ingest_projection()` only reads top-level fields. Wrapped interps (binary, data, web toolchains) produce empty snapshots with no wicket_states or attack_path_id.
**Impact**: Timeline state silently under-reports wrapped projections. Observation closure may fail for wrapped interps. Closed-loop observation chain breaks for ~33% of toolchains.
**Fix**: Normalize interp shape before `DeltaStore` ingestion. Add `canonical_interp_payload()` call in `feedback.py:176-197` before passing to `ingest_projection()`. Validate unwrapping logic in test.

#### BRK-002: Workload Target Resolution Collapses Node Identity to IP String
**Area**: Kernel / Adapters
**File(s)**: `skg/kernel/adapters.py:107-113`, `skg-host-toolchain/projections/host/run.py:51-69`, `skg/substrate/projection.py:235-255`
**Description**: Events with non-IP workload IDs (e.g., `binary::192.168.1.1::ssh-keysign`) are forced into `target_ip` by splitting on `::` and taking the last token. Result: event for binary artifact becomes observation with target `ssh-keysign` instead of identity anchor.
**Impact**: Binary and data observations aggregated against wrong subject. Support engine cannot properly correlate cross-domain evidence. Node/workload model reduced to target string at core boundary.
**Fix**: Replace target inference with identity-aware lookup. Preserve workload_id → identity_key → manifestation_key chain without string slicing. Add tests for non-IP workload subjects.

#### BRK-003: SshSensor.run() Reloads targets.yaml Instead of Honoring Supplied Config
**Area**: Sensors
**File(s)**: `skg/sensors/ssh_sensor.py:77-95`
**Description**: `SshSensor.run()` ignores the target config passed in initialization and reloads all targets from `targets.yaml`. A direct `/collect` request for a single target can be re-routed to all configured targets.
**Impact**: Observation boundary broken at sensor entry point. Operator cannot control which hosts are collected. Cross-contamination of evidence across unintended targets.
**Fix**: Remove target reload inside `run()`. Honor the target set supplied via initialization. If config reload needed, do it at the daemon level, not inside sensor.run().

#### BRK-004: Collect Response Artifact Path Does Not Match Actual Emit Output
**Area**: Daemon / Sensors
**File(s)**: `skg/core/daemon.py:1385-1397`, `skg/sensors/__init__.py:566-576`
**Description**: `/collect` endpoint returns synthetic filename `host_{workload_id}_{run_id}.ndjson`, but `emit_events()` uses timestamped names. API reports files that do not exist on disk.
**Impact**: Operator cannot verify collection outcomes. Automation expecting the reported filename breaks. Audit trail mismatch between promise and reality.
**Fix**: Either emit real filename and return it, or return canonical pattern so operator knows actual file location. Coordinate between daemon and sensor emission.

#### BRK-005: First-Contact Entropy Floor Is Aggressive and Oversaturates
**Area**: Gravity / Landscape
**File(s)**: `skg/gravity/landscape.py:147-168`, `skg-gravity/gravity_field.py:6152-6165`
**Description**: When no prior nmap exists, entropy is forced to 25.0 minimum and broad wicket set applied. This triggers massive bootstrap sweeps on legitimate first-contact targets, causing noisy false-positive evidence and overwhelming operator queues.
**Impact**: New targets immediately flooded with observations. High false-positive rate early in engagement. Operator must triage massive proposal queue before real attack surface emerges.
**Fix**: Lower floor to 10.0 or make it configurable. Tie to actual observable uncertainty, not arbitrary floor. Validate that bootstrap energy reduction actually correlates with field convergence in test.

#### BRK-006: Gravity Selects Surface by Richness Over Recency
**Area**: Gravity / Core
**File(s)**: `skg/core/daemon.py:50-65`, `skg-gravity/gravity_field.py:177-193`
**Description**: Gravity picks the surface with highest `(target_count + service_count)` even if it is older. Stale ports/services can remain authoritative because cardinality doesn't decrease reliably. Services discovered at T0 may still govern gravity at T+24h even if T+1h measurement contradicted them.
**Impact**: Stale state authority. Gravity can chase services that no longer exist. Operator measurements ignored if discovery snapshot was richer.
**Fix**: Prefer most recent surface by mtime. Richness is a tiebreaker only. Document surface file TTL and eviction policy.

#### BRK-007: Topology Energy Injects Realized World States From Hybrid Surface
**Area**: Topology / Energy
**File(s)**: `skg/topology/energy.py:793-864`
**Description**: Target domains/services from hybrid `surface_*.json` are directly promoted to realized `WicketState` entries like `world::{host}::domain::web` without passing through projection/measurement discipline. A configured target can become "measured" just by existing in surface file.
**Impact**: Hybrid discovery facts mixed with measured facts. Field energy incorrect because non-measured state treated as realized. Gravity steering corrupted.
**Fix**: Separate world-state contribution (presentation) from realized state contribution (measurement). World states should be labeled as "context" not "realized." Only projection-derived wickets become realized.

#### BRK-008: Feedback State Load Silently Resets on Parse Error
**Area**: Temporal / Feedback
**File(s)**: `skg/temporal/feedback.py:122-128`
**Description**: If `feedback.state.json` is corrupted, state is silently reset to empty dict. Operator has no visibility that history was lost.
**Impact**: Silent loss of temporal state. Observation memory boundary invisible to operator. May cause observation closure to misbehave.
**Fix**: Log warning or write corruption event to operator-visible stream. Do not silently reset. If unable to parse, quarantine file and start fresh with explicit notice.

#### BRK-009: Observation Closure Matches Pending Records by Substring (Heuristic)
**Area**: Temporal / Feedback
**File(s)**: `skg/temporal/feedback.py:271-292`
**Description**: Closes pending observations by exact workload match OR target-string substring match. A pending record for `host::192.168.1.5` may be closed by evidence for `mysql::192.168.1.5::table1` if substring matches IP.
**Impact**: Cross-domain observations may close unintended pending records. Confidence calibration misbehaves when wrong observation closes the record.
**Fix**: Use explicit identity/workload join. If heuristic necessary for compatibility, label it as such and validate with tests.

#### BRK-010: Kernel Engine Still Computes by target_ip Instead of Workload
**Area**: Kernel / Engine
**File(s)**: `skg/kernel/engine.py:149-399`
**Description**: `KernelStateEngine` loads observations, collapses state, computes energy, and scores instruments all via `target_ip` parameter. Non-IP workload locals cannot be evaluated; they are forced into IP representation.
**Impact**: Binary and data nodes cannot be first-class kernel subjects. Field energy computed for IP not for domain/workload pair. Selection biased toward host domain.
**Fix**: Refactor engine to accept `(workload_id, domain)` pair as primary key. Keep target_ip as optional compatibility parameter only.

#### BRK-011: Gravity Selection Still Ranked by Target Row, Not Workload Locals
**Area**: Gravity / Selection
**File(s)**: `skg/gravity/selection.py:64-210`
**Description**: `rank_instruments_for_target()` takes a target row dict and computes selection from service heuristics and prior artifact checks. The actual Work 4 field-local union is not consulted; instead the function operates on hydrated surface state.
**Impact**: Instrument selection biased toward host/web domains. Cross-domain coupling effects not propagated to selection. System acts like target orchestrator with field modifiers, not field-first scheduler.
**Fix**: Refactor to `rank_instruments_for_locals(workload_locals)` accepting a set of field locals indexed by (workload, domain). Derive applicable instruments from union of local unresolved mass.

#### BRK-012: SSH Credentials Logged in Plain Text to CLI Output
**Area**: Security / CLI
**File(s)**: `skg/sensors/ssh_sensor.py:154-178`, `skg-gravity/cred_reuse.py:206-250`
**Description**: SSH credentials (username, password) are visible in CLI/log output even when "obfuscated." Only first 12 chars masked in some places but full secrets appear elsewhere.
**Impact**: Credentials visible in shell history, logs, CI/CD output. Operator machines may cache secrets.
**Fix**: Never emit full credentials to stdout/logs. Redact at INFO level; allow only at DEBUG with explicit --unsafe-debug flag.

#### BRK-013: HTTP Credential Testing Heuristics Do Not Distinguish 404 From Auth Failure
**Area**: Gravity / Credential Reuse
**File(s)**: `skg-gravity/cred_reuse.py:315-370`
**Description**: HTTP form testing relies on heuristics: success = redirect OR "logout" in response. No distinction between "login page not found" (404) and "login failed" (401/403). False positives possible.
**Impact**: Incorrect WB-08 (default creds) events generated. Confidence calibration corrupted by false positives.
**Fix**: Check HTTP status codes explicitly. 401/403 = auth required. 200 with form = login page. 302/303 to non-login = success.

#### BRK-014: Toolchain test_golden.py Files Not Discovered by Top-Level pytest
**Area**: Tests
**File(s)**: `tests/conftest.py`, `skg-*-toolchain/tests/test_golden.py` (11 files)
**Description**: Each of 12 toolchains has `tests/test_golden.py` with adapter/projection tests, but they are not included in `pytest.ini` or `conftest.py`. Running `pytest` from repo root skips them entirely.
**Impact**: Adapter logic not regression-tested at CI level. Projection output changes undetected. ~12 golden-path tests missing from coverage.
**Fix**: Add glob pattern to `pytest.ini` or configure `conftest.py` to discover and run toolchain-local tests.

#### BRK-015: Sheaf Import Failure Silent (No Obstruction Detection)
**Area**: Topology / Manifold
**File(s)**: `skg-*-toolchain/projections/*/run.py` (all toolchains)
**Description**: All projector entrypoints try `from skg.topology.sheaf import classify_with_sheaf` but silently skip if import fails. H¹ obstruction detection vanishes in partial deployments.
**Impact**: Classification silently downgrades from `indeterminate_h1` to `indeterminate`. Constraint-structure analysis lost without operator knowledge.
**Fix**: Log warning if sheaf import fails. Make behavior explicit: "H1 analysis disabled" in output.

#### BRK-016: Malformed NDJSON Events Dropped Without Operator Signal
**Area**: Sensors / Adapters
**File(s)**: `skg/sensors/adapter_runner.py:61-72`, `skg/sensors/projector.py:446-453`, `skg/intel/surface.py:85-121`
**Description**: Bad JSON lines, corrupt projection files, unreadable interp artifacts all silently skipped. Operator never sees evidence loss.
**Impact**: Observations disappear from the system. Audit trail incomplete. Operator cannot debug collection/projection failures.
**Fix**: Write all parse failures to a quarantine stream (NDJSON or JSON lines). Emit warning to operator. Keep data for forensics.

#### BRK-017: Port Scanning May Trigger IDS (gpu_probe.py, other active probes)
**Area**: Sensors / GPU Probe
**File(s)**: `skg/sensors/gpu_probe.py:115-145`
**Description**: `socket.connect_ex()` attempts to ports 50051, 8080, etc. without rate limiting or evasion. IDS/WAF may block the operator's IP or the target.
**Impact**: Operational disruption. Engagement scope drift (unintended detection).
**Fix**: Add delay between probes. Make timeout configurable. Document IDS risk in sensor config.

#### BRK-018: Dangerous SUID Set Is Hardcoded
**Area**: Sensors / Process Probe
**File(s)**: `skg/sensors/process_probe.py:58-75`
**Description**: SUID binaries list includes `vim`, `python`, `perl`, `ruby`, `bash`, `docker`, `pkexec`, etc. But many environments legitimately have these as SUID for operational reasons.
**Impact**: False-positive PR-04 events. Confidence calibration corrupted.
**Fix**: Make SUID list configurable per deployment. Build from advisory database rather than hardcoding.

#### BRK-019: Userns Parsing Fragile (Requires int() Conversion)
**Area**: Sensors / Process Probe
**File(s)**: `skg/sensors/process_probe.py:140-160`
**Description**: Code tries `int(val)` on `/proc/sys/user.max_user_namespaces` without bounds checking. If value is >= 1, userns assumed enabled. But string parsing fragile if `/proc` format varies.
**Impact**: PR-01 (ptrace scope) events may fail to parse on non-standard systems. Coverage gap.
**Fix**: Use `int(val, base=10)` explicitly. Add fallback behavior if parse fails.

#### BRK-020: CVE Sensor Rate Limiting Is Sleep-Based (Inefficient)
**Area**: Sensors / CVE Sensor
**File(s)**: `skg/sensors/cve_sensor.py:95-135`
**Description**: NVD rate limit (5 req/30s unauthenticated) enforced via `sleep()` between requests. Blocks SensorLoop if multiple sensors need rate limiting.
**Impact**: Observation loop stalls. Concurrency lost.
**Fix**: Use token-bucket or sliding-window rate limiter. Queue CVE requests independently.

#### BRK-021: BloodHound Token Expiry Hardcoded at 3500s
**Area**: Sensors / BloodHound
**File(s)**: `skg/sensors/bloodhound_sensor.py:65-75`
**Description**: JWT token refresh hardcoded to 3500 seconds. If collection takes longer or token is slow to refresh, auth fails silently.
**Impact**: Large BloodHound collections fail mid-run. AD-* coverage gaps.
**Fix**: Make TTL configurable. Refresh proactively if time > 80% of TTL. Detect 401 errors and refresh on-demand.

#### BRK-022: LLM Calls in cognitive_sensor Have No Timeout
**Area**: Sensors / Cognitive Sensor
**File(s)**: `skg/sensors/cognitive_sensor.py:180-220`
**Description**: `anthropic.Anthropic().messages.create()` has no explicit timeout. If LLM is slow or unresponsive, SensorLoop blocks indefinitely.
**Impact**: Gravity cycle hangs. Operator must kill daemon.
**Fix**: Set `timeout=30` on LLM client. Catch timeout exception and emit failed event.

#### BRK-023: Web Observation Registration Ignores events_file Parameter
**Area**: CLI / Observation
**File(s)**: `skg/cli/utils.py:241-264`
**Description**: `_register_web_observation_target()` accepts `events_file` but never reads it. Surface update derived from URL/port classification, not from projection artifact.
**Impact**: Web observation events not inserted into substrate. Evidence wasted.
**Fix**: Read events_file, project to wickets, integrate into surface update via workload locals.

---

### UNWIRED — 18 Items

#### UNW-001: IdentityRegistry Class Is Defined But Never Used
**Area**: Kernel / Identity
**File(s)**: `skg/kernel/identities.py:12-33`
**Description**: `Identity` and `IdentityRegistry` classes exist but are not imported or used anywhere in the codebase. Identity authority comes from `parse_workload_ref()` instead.
**Impact**: Dead code. Class tests missing. Future maintainers confused about which is canonical.
**Fix**: Either activate `IdentityRegistry` as the canonical kernel identity authority or remove and document why `skg.identity` is preferred.

#### UNW-002: GravityScheduler.rank() Not Actually Used for Scheduling
**Area**: Kernel / Gravity
**File(s)**: `skg/kernel/gravity.py:5-14`, `skg-gravity/gravity_field.py:6069-6365`
**Description**: `GravityScheduler.rank()` is a simple proposal-scoring function, but the real scheduling logic lives in `gravity_field.py` landscape construction and target ordering. The class name implies responsibility it does not carry.
**Impact**: Confusing API. Maintenance burden. True scheduler logic hard to locate.
**Fix**: Rename `GravityScheduler` to `ProposalScorer`. Create a `GravityScheduler` class that owns landscape, target ordering, and execution batching.

#### UNW-003: Formal BondState Objects Not Imported Anywhere
**Area**: Substrate / Bond
**File(s)**: `skg/substrate/bond.py:1-140`
**Description**: `BondState`, `Bond`, and coupling semantics are formally defined but not imported in any live code path. Live graph layer at `skg/graph/__init__.py` uses ad-hoc dictionaries instead.
**Impact**: Formal model vs. live implementation drift. Dead reference code.
**Fix**: Audit live graph implementation. If formal bonds needed, integrate. Otherwise, document as "formal reference model for future unification."

#### UNW-004: exploit_proposals.py Module Never Called
**Area**: Gravity / Proposals
**File(s)**: `skg-gravity/exploit_proposals.py:1-154`
**Description**: `create_exploit_proposal()` and supporting functions exist but are never called by gravity_field.py or CLI. Live proposal path uses `exploit_dispatch.py` instead.
**Impact**: Duplicate proposal mechanisms. Code rot if not maintained.
**Fix**: Remove or document as legacy/preserved. Consolidate onto `exploit_dispatch.py` path only.

#### UNW-005: gravity_web.py Never Imported Outside Itself
**Area**: Gravity / Web
**File(s)**: `skg-gravity/gravity_web.py:1-40`, `skg-gravity/gravity_field.py`
**Description**: Bond discovery and prior propagation defined in `gravity_web.py` but never called from gravity_field.py or elsewhere. Live graph layer has its own implementation.
**Impact**: Alternative prior-propagation logic that doesn't execute. Code duplication.
**Fix**: Document as legacy. Consolidate prior propagation into single authority (likely `skg/graph/__init__.py`).

#### UNW-006: CLI Daemon Communication Fallback Never Tested
**Area**: CLI / API
**File(s)**: `skg/cli/utils.py:42-60`
**Description**: `_api_required()` function checks daemon availability and exits if unreachable. But no tests verify this graceful degradation path.
**Impact**: Daemon unavailability path untested. Operator experience unclear.
**Fix**: Add test that runs CLI commands with daemon down, verify exit behavior.

#### UNW-007: Ollama Backend Status Endpoint Exists But UI Not Bound
**Area**: Daemon / Resonance
**File(s)**: `skg/core/daemon.py:1826-1835`, `ui/app.js` (not found in UI code)
**Description**: `/api/resonance/ollama` endpoint reports Ollama backend health but UI has no corresponding control or status display.
**Impact**: Operator cannot verify LLM availability from UI. Fallback behavior hidden.
**Fix**: Bind endpoint to UI display. Show warning if Ollama unavailable.

#### UNW-008: WorkloadGraph Propagation Rules Never Tested End-to-End
**Area**: Kernel / Graph
**File(s)**: `skg/graph/__init__.py:409-503`
**Description**: Prior propagation across bonds is implemented but no test verifies that a prior boost on one target actually drives gravity selection toward a coupled target.
**Impact**: Cross-target coupling effects untested. May not work as designed.
**Fix**: Add integration test: realize wicket on target A, verify prior on target B, run gravity on B, verify coupled instrument boosted.

#### UNW-009: skg/cli.py Compatibility Shim Never Documented
**Area**: CLI / Shim
**File(s)**: `skg/cli.py:1-6`
**Description**: Shim file forwards imports to `skg.cli.app` but is not documented. Users may import from it unknowingly.
**Impact**: Support burden. Users rely on undocumented interface.
**Fix**: Document in README as "legacy; use `skg.cli.app` directly." Or deprecate and remove if no known external users.

#### UNW-010: Field Functional Breakdown Never Called From Live Gravity
**Area**: Kernel / Field Functional
**File(s)**: `skg/kernel/field_functional.py:158-201`, `skg/kernel/engine.py:419-443`
**Description**: `L_field_functional()` is computed but `gravity_field.py` does not import or use it for ranking. Gravity uses `phi_fiber()` from field_functional module but not `L()` breakdown.
**Impact**: Work 4 formal model not fully integrated into live scheduler. Dissipation term never consulted.
**Fix**: Integrate `L_field_functional()` into gravity ranking pipeline. Weight against `phi_fiber()` to validate coupling effects.

#### UNW-011: DarkHypothesisSensor Proposals Not Integrated Into Main Loop
**Area**: Sensors / Dark Hypothesis
**File(s)**: `skg/sensors/dark_hypothesis_sensor.py:1-150`, `skg/sensors/__init__.py` (not called)
**Description**: Sensor that queries LLM for instruments to probe high-torque wickets exists but is never registered in SensorLoop.
**Impact**: Dark hypothesis cognitive actions never generated. Structural fold detection unused.
**Fix**: Register sensor in daemon config. Add to SensorLoop execution. Test end-to-end.

#### UNW-012: Fold Resolution Events Create Pearls But Not Recorded Consistently
**Area**: Kernel / Folds & Pearls
**File(s)**: `skg/core/daemon.py:4048-4065`
**Description**: Fold resolution records pearls in operator action path but direct fold detection (during gravity cycle) does not record them.
**Impact**: Pearl history incomplete. Memory curvature biased toward operator-triggered actions.
**Fix**: Record pearls whenever fold state changes, not just during operator actions.

#### UNW-013: Credential Reuse mark_tested() Called After Decision, Not Before
**Area**: Gravity / Credential Reuse
**File(s)**: `skg-gravity/cred_reuse.py:425-470`
**Description**: Logic marks credential tested after decision to test is made, but before actual test. If test fails and loop iterates again, credential may be marked tested despite failure.
**Impact**: Credential testing boundary ambiguous. May skip valid credentials.
**Fix**: Mark tested only after successful test or explicit skip reason.

#### UNW-014: Projector Output Format Inconsistency Not Enforced
**Area**: Sensors / Projector
**File(s)**: `skg/sensors/projector.py:321-477`
**Description**: Projector accepts both wrapped envelopes and top-level payload dicts without enforcing a schema. No validation of output format.
**Impact**: Downstream consumers must handle multiple formats. Wrapped toolchains produce invalid delta state.
**Fix**: Enforce one canonical output format. Validate before returning from projector.

#### UNW-015: NDJSON Envelope Validation Schema Not Enforced
**Area**: Sensors / Event Envelope
**File(s)**: `skg/sensors/__init__.py:71-177`
**Description**: Envelope helpers exist but no toolchain validates output against schema before writing to EVENTS_DIR. Ad hoc events still produced.
**Impact**: Event contract drifts. Adapters can emit incompatible events.
**Fix**: Validate each event envelope before emission. Reject non-compliant events with clear error.

#### UNW-016: Temporal Fold Dedup Only Works Within One IP
**Area**: Kernel / Folds
**File(s)**: `skg/kernel/folds.py:490-531`
**Description**: Temporal folds track latest realized evidence but only within a single target IP context. Cross-manifestation dedup relies on identity normalization upstream.
**Impact**: If workload_id normalization fails, duplicate temporal folds for same identity.
**Fix**: Make temporal fold dedup directly identity-aware; do not rely on upstream normalization.

#### UNW-017: Surface Hydration Helpers Not Exposed Via API
**Area**: CLI / Gravity
**File(s)**: `skg-gravity/gravity_field.py:243-269`, `skg-gravity/gravity_field.py:437-470`
**Description**: Gravity internally hydrates surface targets from nmap/wicket state, but CLI `skg surface` command reimplements hydration. No shared path.
**Impact**: Two different surface hydration implementations. Drift risk.
**Fix**: Extract hydration logic to shared function. Both CLI and gravity import from it.

#### UNW-018: Domain Registry Discover Silently Falls Back on Config Mismatch
**Area**: Core / Domain Registry
**File(s)**: `skg/core/domain_registry.py:118-128`
**Description**: If domain discovery fails to find a toolchain, silently uses configured entry without warning.
**Impact**: Toolchain discovery failures invisible. Operator may not know toolchain is missing.
**Fix**: Log warning if discovery fails. Make fallback explicit.

---

### ABSENT — 31 Items

#### ABS-001: AI Toolchain Has No Adapters (Catalog Only)
**Area**: Toolchains / AI
**File(s)**: `/opt/skg/skg-ai-toolchain/adapters/` (empty directory)
**Description**: AI domain toolchain defines `ai_target` domain and attack paths but has no adapter implementations. No AI endpoint probing.
**Impact**: AI domain is declared but unmeasured. forge_meta.json references non-existent `ai_probe` instrument.
**Fix**: Implement adapter for AI endpoint enumeration (LLM model discovery, prompt injection probing, etc.).

#### ABS-002: IoT Firmware Toolchain Has No Adapters
**Area**: Toolchains / IoT
**File(s)**: `/opt/skg/skg-iot_firmware-toolchain/adapters/` (empty), `/opt/skg/skg-iot_firmware-toolchain/tests/` (empty)
**Description**: IoT domain defined but zero collection mechanisms. No UART, JTAG, firmware extraction, or RTOS-specific probes.
**Impact**: IoT devices not measurable. Domain abandoned.
**Fix**: Implement UART enumeration, firmware extraction, and RTOS-specific wickets (FreeRTOS, TinyOS, etc.).

#### ABS-003: Supply Chain Toolchain Has No Adapters
**Area**: Toolchains / Supply Chain
**File(s)**: `/opt/skg/skg-supply-chain-toolchain/adapters/` (empty)
**Description**: Supply chain domain catalog exists but no SCA tool integration, no git analysis, no SBOM ingestion, no CI/CD analysis.
**Impact**: Supply chain domain unmeasured. Catalog + projection only.
**Fix**: Integrate with Snyk, Dependabot, or syft SBOM generation. Add git history analysis.

#### ABS-004: Web Toolchain Has No Active HTTP Probing
**Area**: Toolchains / Web
**File(s)**: `skg-web-toolchain/adapters/ssh_collect/` (generic SSH only)
**Description**: Web domain uses generic SSH collection (config analysis) but not active HTTP scanning (SQLi, auth bypass, XSS probing).
**Impact**: Web surface discovered but not tested. WB-* wickets only from static analysis.
**Fix**: Add HTTP adapter with sqlmap, nikto, or custom active scanning.

#### ABS-005: Binary Toolchain Cannot Run Locally (SSH Only)
**Area**: Toolchains / Binary
**File(s)**: `skg-binary-toolchain/adapters/binary_analysis/parse.py` (SSH required)
**Description**: Binary analysis requires SSH to target. No local binary analysis path for artifacts already on the operator machine.
**Impact**: Cannot analyze binaries without target access. Coverage gap.
**Fix**: Add local binary adapter. Allow file paths as workload subjects.

#### ABS-006: Data Toolchain Uses Synchronous DB Connections (No Async)
**Area**: Toolchains / Data
**File(s)**: `skg-data-toolchain/adapters/db_profiler/` (pymysql, psycopg2)
**Description**: All database profiling is synchronous. No async support. Slow/dead hosts block the entire sensor.
**Impact**: SensorLoop can hang on DB timeouts. Concurrency lost.
**Fix**: Add asyncio-based DB clients (asyncpg, aiomysql, motor). Implement connection pooling with timeout.

#### ABS-007: Nginx Toolchain Lacks Directive Parsing
**Area**: Toolchains / Nginx
**File(s)**: `skg-nginx-toolchain/adapters/ssh_collect/` (generic only)
**Description**: Nginx domain catalog defines NX-* wickets but adapter does not parse nginx.conf directives (proxy_pass, alias, root, try_files, etc.).
**Impact**: Nginx security properties not analyzed. Template-generated code, not real.
**Fix**: Parse nginx.conf with proper syntax awareness. Map directives to NX-* wickets.

#### ABS-008: Nginx / Web Toolchains Are Template-Generated, Not Real Adapters
**Area**: Toolchains / Template
**File(s)**: `skg-nginx-toolchain/forge_meta.json`, `skg-web-toolchain/forge_meta.json`
**Description**: Both toolchains have `generation_backend: "template"` and explicit errors logged at generation time.
**Impact**: Template code never finalized. Toolchains partially broken by design.
**Fix**: Implement real adapters or mark as deprecated/example-only in documentation.

#### ABS-009: No Rate Limiting Between Sensors
**Area**: Sensors / Loop
**File(s)**: `skg/sensors/__init__.py:520-576` (SensorLoop)
**Description**: If one sensor is slow or producing many events, no backpressure. No queuing between sensor runs.
**Impact**: One slow sensor blocks all others. Memory growth unbounded.
**Fix**: Add rate limiting and event queue between sensors.

#### ABS-010: No Per-Sensor Timeout Enforcement
**Area**: Sensors / Timeouts
**File(s)**: `skg/sensors/__init__.py` (all sensor.run() calls)
**Description**: Sensor execution has no global timeout. Individual sensors may run indefinitely.
**Impact**: Gravity cycle stalls. Daemon hangs.
**Fix**: Add timeout parameter per sensor. Default 300s; configurable.

#### ABS-011: No Unbound State File Rotation
**Area**: Daemon / Runtime State
**File(s)**: `skg/sensors/agent_sensor.py:80-100`, `skg/sensors/usb_sensor.py:140-180`, `skg-gravity/msf_sensor.py:130` (msf_audit/)
**Description**: Processed state files, MSF audit logs, and agent queue state grow indefinitely. No rotation or cleanup.
**Impact**: Disk space leak. Over time, `/var/lib/skg` becomes bloated.
**Fix**: Add state file rotation (daily or size-based). Compress old files. Define TTL for cleanup.

#### ABS-012: No Operator-Visible Substrate Corruption Events
**Area**: Core / Reliability
**File(s)**: `skg/temporal/feedback.py:122-128`, `skg/graph/__init__.py:202-224`, `skg/kernel/pearls.py:103-113`
**Description**: Malformed state files are silently reset or dropped. No operator event or quarantine record.
**Impact**: Silent data loss. Operator has no audit trail of corruption.
**Fix**: Write all parse failures to operator-visible event stream. Quarantine corrupted files.

#### ABS-013: No Explicit Test for Surface Authority vs. Discovery Surface
**Area**: Tests / Observation Boundary
**File(s)**: `tests/` (no such test)
**Description**: No test asserts that measured `/surface` is authoritative, not hybrid `surface_*.json`.
**Impact**: Authority drift undetected. Future changes may revert to discovery surface without notice.
**Fix**: Add regression test: measured surface should win even if older than discovery surface.

#### ABS-014: No Test for SshSensor Target Reload Bug
**Area**: Tests / Sensors
**File(s)**: `tests/` (no such test)
**Description**: No test verifies that SshSensor.run() honors the supplied target, not config targets.
**Impact**: Bug will regress. Observation boundary vulnerability undetected.
**Fix**: Add test: supply single target to collect, verify only that target is processed.

#### ABS-015: No Test for Wrapped Interp Delta Ingestion
**Area**: Tests / Temporal
**File(s)**: `tests/test_sensor_projection_loop.py` (not covered)
**Description**: No test exercises wrapped binary/data/web interps through DeltaStore. Silent breakage possible.
**Impact**: Wrapped domains silently fail to enter temporal memory.
**Fix**: Add test: project wrapped interp, verify delta snapshot contains valid wicket_states.

#### ABS-016: No Test for Gravity Selection Over Workload Locals (Not Target Rows)
**Area**: Tests / Gravity
**File(s)**: `tests/test_gravity_runtime.py` (not covered)
**Description**: No test validates that gravity could select instruments based on field locals, not target rows.
**Impact**: Refactoring gravity to use locals untested. Risk of regression.
**Fix**: Add test: supply field locals, verify instrument selection matches field energy, not target service heuristics.

#### ABS-017: No Test for Pearl Identity Enrichment End-to-End
**Area**: Tests / Pearls
**File(s)**: `tests/test_sensor_projection_loop.py:944-955` (only unit test)
**Description**: Unit test exists but no end-to-end test verifies pearls recorded during gravity cycle are identity-enriched.
**Impact**: Pearl enrichment may be partially broken without notice.
**Fix**: Add integration test: run gravity cycle, verify pearls have identity_key set.

#### ABS-018: No Test for Fold Dedup Across Manifestations
**Area**: Tests / Folds
**File(s)**: `tests/` (not covered for structural/contextual/projection folds)
**Description**: Temporal fold dedup tested but structural/contextual/projection folds not tested for identity-aware dedup.
**Impact**: Duplicate folds for same identity possible.
**Fix**: Add test: create structural folds for two manifestations of same identity, verify single fold returned.

#### ABS-019: No Test for Field Functional Coupling Matrix Symmetry
**Area**: Tests / Topology
**File(s)**: `tests/` (not covered)
**Description**: Field-local coupling matrix claimed symmetric but never tested.
**Impact**: Coupling asymmetry undetected.
**Fix**: Add test: verify K(a→b) ≈ K(b→a) for all domain pairs.

#### ABS-020: No Explicit Configuration for Decoherence Thresholds
**Area**: Config / Kernel
**File(s)**: `skg/kernel/field_local.py:271-284` (hardcoded C≥0.70, φ_c<0.15, φ_d<0.20)
**Description**: Decoherence criterion thresholds are hardcoded constants. No way to adjust per deployment.
**Impact**: Cannot tune field behavior. Thresholds not documented as configurable.
**Fix**: Move thresholds to skg_config.yaml. Document derivation.

#### ABS-021: No Explicit Configuration for Compatibility Score Formulation
**Area**: Config / Kernel
**File(s)**: `skg/kernel/support.py:123-128` (hardcoded formula)
**Description**: Compatibility score `C = 1.0 - concentration + 0.1×(n-1)` hardcoded. No way to adjust weights.
**Impact**: Cannot tune observation aggregation per deployment.
**Fix**: Move formula coefficients to config.

#### ABS-022: No Test for Projection-Based Surface vs. Hybrid Target Surface
**Area**: Tests / Surface
**File(s)**: `tests/` (not covered)
**Description**: No test validates API `/surface` (measured) vs. CLI `skg surface` (hydrated discovery).
**Impact**: Divergence between paths undetected.
**Fix**: Add test: ensure both paths return same classified domains for same workload set.

#### ABS-023: Missing Adapter Unit Tests for Bloodhound, APRS, Container, SSH Collect
**Area**: Tests / Adapters
**File(s)**: `skg-ad-lateral-toolchain/tests/`, `skg-aprs-toolchain/tests/`, etc. (only golden tests)
**Description**: Each adapter has parse.py with complex logic but no parse.py-specific unit tests. Only golden tests.
**Impact**: Adapter bugs in edge cases not caught. Coverage gaps.
**Fix**: Add unit tests for each parse function. Cover error cases, malformed input, etc.

#### ABS-024: No Test for CLI Graceful Degradation Without Daemon
**Area**: Tests / CLI
**File(s)**: `tests/test_cli_commands.py` (not covered for daemon-down case)
**Description**: `_api_required()` function for daemon unavailability never tested.
**Impact**: Daemon unavailability path untested.
**Fix**: Add test: kill daemon, run CLI command, verify graceful exit with message.

#### ABS-025: No Test for Confidence Calibration Persistence and Recall
**Area**: Tests / Calibration
**File(s)**: `tests/test_runtime_regressions.py` (partial coverage)
**Description**: Calibration state is persisted but round-trip recall never tested.
**Impact**: Persisted calibration may be silently lost.
**Fix**: Add test: train calibration, save, reload, verify weights match.

#### ABS-026: No Security Audit of Credentials in Event Payload
**Area**: Security / Events
**File(s)**: `skg/sensors/__init__.py` (event envelope)
**Description**: Event payload can carry credentials if adapter emits them. No scrubbing at envelope level.
**Impact**: Credentials might leak into EVENTS_DIR files.
**Fix**: Scrub known credential fields from payload before emission. Document what fields are never safe.

#### ABS-027: No Health Check Endpoint for Core Subsystems
**Area**: Daemon / Health
**File(s)**: `skg/core/daemon.py` (no explicit health endpoint)
**Description**: Daemon has `/api/status` but no comprehensive health check (event flow, kernel state, temporal memory, graph).
**Impact**: Operator cannot detect partial failures (e.g., temporal memory corruption).
**Fix**: Add `/api/health` with subsystem-level checks.

#### ABS-028: No Documented Upgrade Path for Template Toolchains
**Area**: Toolchains / Upgrade
**File(s)**: `skg-nginx-toolchain`, `skg-web-toolchain`
**Description**: Template-generated toolchains documented as having generation errors. No clear path to real implementations.
**Impact**: Operator confused about whether toolchains are usable.
**Fix**: Document upgrade process or mark as example-only.

#### ABS-029: Missing Correlator for Cross-Toolchain Attack Chains
**Area**: Kernel / Projection
**File(s)**: No such module
**Description**: No mechanism to correlate attack paths across multiple toolchains (e.g., web SQLi + data dump).
**Impact**: Cross-domain chains require operator judgment.
**Fix**: Add projection correlator that identifies sequential preconditions across domains.

#### ABS-030: No Formal Specification for Gravity Convergence
**Area**: Docs / Gravity
**File(s)**: `skg-gravity/gravity_field.py:6446-6489` (convergence epsilon = 0.01)
**Description**: Convergence criterion is simple epsilon check on entropy change. No formal proof that algorithm terminates or converges.
**Impact**: Operator cannot reason about cycle length. No bounds on runtime.
**Fix**: Document convergence properties or add timeout with graceful degradation.

#### ABS-031: No Formal Specification for Fiber-Driven Gravity Algorithm
**Area**: Docs / Gravity
**File(s)**: `skg/kernel/field_functional.py`, `skg-gravity/gravity_field.py` (implementation only)
**Description**: Paper 4 defines Φ_fiber but runtime implementation is ad hoc. No formal algorithm spec.
**Impact**: Behavior unclear. Changes risky.
**Fix**: Document fiber-driven selection algorithm formally (pseudocode, invariants, proofs).

---

### UNCANONICAL — 37 Items

#### UNC-001: Three Different "Surface" Products With Same Name
**Area**: Core / Surface
**File(s)**: `skg/core/daemon.py:1467-1482` (measured), `skg/core/daemon.py:1419-1452` (hybrid targets), `skg/cli/commands/surface.py:61-78` (hydrated discovery)
**Description**: API `/surface` = measured projection surface. API `/targets` = hybrid target registry. CLI `skg surface` = hydrated discovery surface. Same word, different semantics.
**Impact**: Operator confusion. Automation fragile.
**Fix**: Rename or clearly label: `/surface` (measured), `/workloads` (measured locals), `/targets` (hybrid registry), `/discovery` (bootstrap).

#### UNC-002: Event Envelope Construction Fragmented
**Area**: Sensors / Events
**File(s)**: `skg/sensors/__init__.py:71-177` (canonical), `skg/sensors/web_sensor.py:578-608`, `skg/sensors/ssh_sensor.py:154-178`, `skg-gravity/gravity_field.py:3908-3923`
**Description**: Some sensors use canonical envelope helpers; others hand-roll events. No enforcement.
**Impact**: Event shape inconsistent. Some events carry provenance; others omit it.
**Fix**: Enforce envelope helper at toolchain boundary. Validate all emitted events.

#### UNC-003: Projector Output Shape Inconsistent
**Area**: Sensors / Projection
**File(s)**: `skg-binary-toolchain/projections/binary/run.py:34-42` (wrapped), `skg-host-toolchain/projections/host/run.py:130-154` (top-level)
**Description**: Some projectors return wrapped envelope; others return payload dict. No schema enforcement.
**Impact**: Feedback/delta consumers must handle both. Silent failures for wrapped shapes.
**Fix**: Enforce one canonical output shape. Validate in projector.py.

#### UNC-004: Fold Location Field Overloaded
**Area**: Kernel / Folds
**File(s)**: `skg/kernel/folds.py:372-700`
**Description**: `Fold.location` carries host (structural), IP (contextual), workload_id (projection), or identity_key (temporal). No type safety.
**Impact**: Fold semantics ambiguous. Dedup logic fragile.
**Fix**: Create Fold subclasses: `StructuralFold(location_host)`, `TemporalFold(identity_key)`, etc.

#### UNC-005: Fiber Anchor Semantics Overloaded
**Area**: Topology / Energy
**File(s)**: `skg/topology/energy.py:375-389` (documented as identity anchor), `skg/topology/energy.py:1059-1109` (used as service or relation name)
**Description**: `Fiber.anchor` docstring says identity, but code uses it as service, relation, or domain.
**Impact**: Type confusion. Tests encode overloaded meaning.
**Fix**: Rename overloaded uses: `Fiber.identity_anchor`, `Fiber.service_pivot`, `Fiber.relation_name`.

#### UNC-006: Binary Sphere Placement Disagrees Between Layers
**Area**: Kernel & Topology / Sphere Mapping
**File(s)**: `skg/kernel/field_functional.py:45` (binary_analysis → binary), `skg/topology/energy.py:76` (binary_analysis → host)
**Description**: Field functional treats binary as separate sphere; topology collapses it into host.
**Impact**: Coupling and energy computations disagree. Field locals may be assigned to different spheres.
**Fix**: Unify sphere mapping. Document canonical sphere assignment for all domains.

#### UNC-007: Gravity Selection Has Multiple Bootstrap Policies
**Area**: Gravity / Selection
**File(s)**: `skg/gravity/landscape.py:147-168` (first-contact floor), `skg/gravity/selection.py:141-156` (cold-start boosts), `skg/gravity/selection.py:183-201` (broad bootstrap sweep)
**Description**: Three different bootstrap mechanisms: entropy floor, instrument boosts, broad sweeps. Overlapping logic.
**Impact**: Complex heuristics compound. Hard to predict behavior.
**Fix**: Consolidate into one bootstrap policy with clear entry criteria.

#### UNC-008: Gravity Invocation Has Multiple Stories
**Area**: Gravity / Invocation
**File(s)**: `skg/core/daemon.py:470-603` (subprocess), `skg/core/daemon.py:632-663` (inline comment vs. actual call), `skg/cli/commands/gravity.py:11-73` (direct module load)
**Description**: Daemon shells out to gravity_field.py. CLI loads it as module. Comments say inline but code shells out.
**Impact**: Confusing control flow. Operator doesn't know which path is used.
**Fix**: Unify to one invocation story. Document clearly.

#### UNC-009: Target Authority Duplicated in Three Places
**Area**: Sensors / Config
**File(s)**: `skg/sensors/__init__.py:220-243`, `skg/sensors/ssh_sensor.py:38-48`, `skg/cli/utils.py:286-298`
**Description**: Target loading logic in three places with slight differences.
**Impact**: Config changes don't propagate uniformly. Tests fragile.
**Fix**: Single shared target loader. Import from canonical location.

#### UNC-010: Domain-to-Instrument Mapping Hardcoded in Multiple Places
**Area**: Gravity / Selection
**File(s)**: `skg/gravity/selection.py:10-45` (BOOTSTRAP_NAMES, SPHERE_PREFIXES), `skg/gravity/landscape.py:92-137` (SERVICE_PORT_DOMAINS)
**Description**: Instrument/domain/service tables defined in multiple modules. No single registry.
**Impact**: Adding new domain requires edits in multiple places. Drift risk.
**Fix**: Centralize in domain_registry.py or config file.

#### UNC-011: Workload Subject Resolution Still Target-Centric
**Area**: Substrate / Identity
**File(s)**: `skg/kernel/adapters.py:107-113`, `skg/substrate/projection.py:235-255`, `skg-host-toolchain/projections/host/run.py:51-69`
**Description**: Different modules resolve workload ID to target differently. Some use `.split("::")[-1]`, others use identity parser.
**Impact**: Node/workload model not uniform. Cross-domain observations may not correlate.
**Fix**: Single canonical subject resolution using identity parser everywhere.

#### UNC-012: Observation Closing Uses Both Exact Match and Substring Match
**Area**: Temporal / Feedback
**File(s)**: `skg/temporal/feedback.py:271-292`
**Description**: Pending records closed by exact workload match OR substring target match. Two different join semantics.
**Impact**: Wrong observation may close record. Calibration misbehaves.
**Fix**: Single explicit join logic. Document fallback if necessary.

#### UNC-013: Coupling Matrix Has Inconsistent Values
**Area**: Kernel / Field Local
**File(s)**: `skg/core/coupling.py:50-80` (inter_local_table), `skg/substrate/bond.py:10-80` (formal bonds), `skg/graph/__init__.py:75-93` (live graph)
**Description**: Same domain pairs have different coupling values in different modules. E.g., same_domain = 0.35 (graph) vs. 0.60 (bond) vs. 0.60 (coupling.yaml).
**Impact**: Field energy and gravity ranking inconsistent. Coupling semantics unclear.
**Fix**: Single authoritative coupling matrix. All modules import from it.

#### UNC-014: Folds Persisted By IP But Internally Identity-Aware
**Area**: Kernel / Folds
**File(s)**: `skg-gravity/gravity_field.py:6652-6668` (persist by IP), `skg/kernel/folds.py:589-615` (temporal use identity_key)
**Description**: Temporal folds use identity_key, but runtime persistence partitions folds by IP and reads them by `folds_<ip>.json`.
**Impact**: Fold semantics broken at persistence boundary. Cross-manifestation folds may be duplicated.
**Fix**: Persist by identity_key. Rename files to `folds_<identity>.ndjson`.

#### UNC-015: Pearl Recording Only In Gravity Cycle, Not All Field Changes
**Area**: Kernel / Pearls
**File(s)**: `skg-gravity/gravity_field.py:5477-5606` (gravity), `skg/temporal/feedback.py:176-252` (feedback, no pearls), `skg/core/daemon.py:4048-4065` (fold resolution)
**Description**: Pearls recorded for gravity cycles and operator actions, but not for direct observe/project transitions.
**Impact**: Pearl memory incomplete. Memory curvature biased.
**Fix**: Record pearls whenever field state transitions, not just on gravity cycles.

#### UNC-016: Confidence Calibration Has Two Different Definitions
**Area**: Sensors / Calibration
**File(s)**: `skg/sensors/confidence_calibrator.py:40-80` (evidence reversal-based), `skg/temporal/__init__.py:355-375` (DeltaStore, transition-based)
**Description**: Two paths compute calibration differently. One uses evidence decay; the other uses transitions.
**Impact**: Calibration values may diverge. Hard to predict confidence weighting.
**Fix**: Single canonical calibration logic.

#### UNC-017: Surface Ranking Uses Both Cardinality and Recency (Hybrid)
**Area**: Gravity / Core
**File(s)**: `skg/core/daemon.py:50-65` (richness by count), `skg-gravity/gravity_field.py:177-193` (same richness logic)
**Description**: Surfaces ranked by `(target_count + service_count, target_count, mtime)`. Older richer surfaces preferred.
**Impact**: Stale state authority. Operator measurements ignored.
**Fix**: Primary key = mtime (most recent). Richness is tiebreaker only.

#### UNC-018: Event Provenance Fields Incomplete and Inconsistent
**Area**: Sensors / Events
**File(s)**: `skg/sensors/__init__.py:71-177` (some events), `skg/sensors/web_sensor.py:578-608` (missing provenance)
**Description**: Some events carry `source_kind`, `pointer`, `evidence_rank`. Others omit them.
**Impact**: Audit trail incomplete for some observations.
**Fix**: Enforce all provenance fields. Reject events missing them.

#### UNC-019: Applicable Wickets Derived From Heuristics, Not Measured Locals
**Area**: Gravity / Selection
**File(s)**: `skg/gravity/landscape.py:92-137`
**Description**: Effective domains from service ports and AI speculation, not from measured projection state.
**Impact**: Gravity blind to measured states. Relies on heuristics instead of field.
**Fix**: Derive applicable wickets from union of active workload locals. Use services only as confirmation.

#### UNC-020: Manifest vs. Manifestation Terminology Inconsistent
**Area**: Identity / Docs
**File(s)**: Code comments, `skg/kernel/pearls.py` (manifestation_key), `skg/identity/__init__.py` (manifestation vs manifest)
**Description**: Sometimes "manifest," sometimes "manifestation." Different meanings in different layers.
**Impact**: Documentation ambiguous. Code harder to follow.
**Fix**: Choose one term. Update all comments and variable names.

#### UNC-021: "Fiber" Means Different Things in Topology vs. Memory
**Area**: Topology / Semantics
**File(s)**: `skg/kernel/field_functional.py:158-201` (fiber term in formula), `skg/topology/energy.py:375-1361` (Fiber class)
**Description**: Work 4 uses "fiber" as abstract coupling term. Code has `Fiber` class with anchor, coherence, tension. Semantic mismatch.
**Impact**: Reader confused by overloading. Paper language doesn't match code.
**Fix**: Clarify: formal "fiber" is a mathematics concept; code `Fiber` is an implementation artifact. Rename class if needed.

#### UNC-022: Projection Payload Normalization Scattered
**Area**: Temporal / Projection
**File(s)**: `skg/temporal/interp.py:5-15` (canonical_interp_payload), `skg/sensors/projector.py:289-318` (additional normalization)
**Description**: Two different normalization paths for projection payloads. Both try to handle wrapped vs. unwrapped.
**Impact**: Normalization logic duplicated. One path may be incomplete.
**Fix**: Single canonical normalization. Both paths use it.

#### UNC-023: Instrument Family Names Inconsistent
**Area**: Kernel / Support
**File(s)**: `skg/kernel/support.py:140-160` (nmap → network_scan, ssh_sensor → host_access)
**Description**: No registry for instrument family names. Ad hoc string matching.
**Impact**: New instruments require edits. Family name collisions possible.
**Fix**: Instrument registry with explicit family declarations.

#### UNC-024: Energy Computation Has Multiple Entry Points
**Area**: Kernel / Energy
**File(s)**: `skg/kernel/energy.py:1-150`, `skg/topology/energy.py:1-1361`
**Description**: Two different energy modules with overlapping semantics. One is old; one is new. Both imported in places.
**Impact**: Dual energy computation paths. Risk of inconsistency.
**Fix**: Consolidate. Mark one as canonical.

#### UNC-025: Gravity "Potential" Computed Three Different Ways
**Area**: Gravity / Selection
**File(s)**: `skg/kernel/engine.py:273-399` (phi_fiber), `skg/gravity/selection.py:66-78` (entropy reduction), `skg-gravity/gravity_field.py:6122-6195` (combined score)
**Description**: Base potential, fiber potential, and combined potential all computed separately.
**Impact**: Understanding gravity ranking requires reading three modules.
**Fix**: Single potential computation function. Document all terms.

#### UNC-026: Workload Identity Normalization Not Centralized
**Area**: Kernel / Identity
**File(s)**: `skg/identity/__init__.py:23-68` (parse_workload_ref), `skg/kernel/pearls.py:24-29` (fallback), `skg/substrate/projection.py:195-255` (inline parsing)
**Description**: Workload/identity parsing logic repeated in multiple places.
**Impact**: Inconsistencies introduced when one path updated.
**Fix**: Single canonical workload parser. All modules use it.

#### UNC-027: Pearl Manifold Grouping Uses Mixed Keys
**Area**: Kernel / Pearls
**File(s)**: `skg/kernel/pearl_manifold.py:106-155`
**Description**: Pearls grouped by `(identity_key, domain)`, but older code still uses workload_id fallback to `gravity::{target_ip}`.
**Impact**: Mixed grouping semantics. Dedup fragile.
**Fix**: Normalize all pearls to identity_key before grouping.

#### UNC-028: Topology World States Mixed With Measured Wickets
**Area**: Topology / Energy
**File(s)**: `skg/topology/energy.py:793-970`
**Description**: World states from daemon target rows and pearl aggregates injected as realized field contributions without passing through measurement discipline.
**Impact**: Hybrid state mixed into field energy. Field semantics broken.
**Fix**: Separate world-state contribution (presentation) from realized contribution (measurement).

#### UNC-029: Sheaf Classification Silent Failure (No Warning)
**Area**: Topology / Sheaf
**File(s)**: All toolchain projectors that import `classify_with_sheaf`
**Description**: If sheaf module unavailable, classification silently drops `indeterminate_h1`. No operator warning.
**Impact**: Feature silently vanishes. Operator unaware.
**Fix**: Log warning if sheaf import fails.

#### UNC-030: W-* Prefix Normalization to WB-* In Web Toolchain
**Area**: Toolchains / Web
**File(s)**: `skg-web-toolchain/projections/web/run.py:21-25`
**Description**: Wicket IDs may come in as W-* (legacy) and are normalized to WB-* (current). But normalization uses string prefix match without validation.
**Impact**: Unknown prefixes silently dropped.
**Fix**: Explicit mapping table. Reject unknown prefixes with error.

#### UNC-031: Legacy Wicket Aliasing (web_sqli_to_shell_v1 → web_full_chain_v1)
**Area**: Toolchains / Web
**File(s)**: `skg-web-toolchain/projections/web/run.py:26-50`
**Description**: Old path IDs aliased to new ones without systematic registry.
**Impact**: Brittle. If path IDs change, aliasing breaks.
**Fix**: Formal alias registry. Document migration path.

#### UNC-032: API Response Types Inconsistent (Some Partial, Some Full)
**Area**: Daemon / API
**File(s)**: `skg/core/daemon.py` (various endpoints)
**Description**: Some endpoints return full objects; others return partial views. No consistent schema.
**Impact**: Clients must handle variable shapes.
**Fix**: Define OpenAPI schema. Enforce response shapes.

#### UNC-033: Wicket Graph and Formal Wicket Catalog Can Disagree
**Area**: Kernel / WicketGraph
**File(s)**: `skg/kernel/wicket_graph.py:1-50` (seeded from catalogs), `skg/kernel/wicket_graph.py:80-150` (hardcoded semantic edges)
**Description**: WicketGraph loaded from catalogs but also has hardcoded semantic edges (SSH chain, lateral movement, etc.). Catalogs and hardcoded edges may conflict.
**Impact**: Coverage gaps. Hardcoded edges bypass catalog authority.
**Fix**: All edges should come from catalogs or explicit registry. No hardcoded embeddings.

#### UNC-034: Observation Status Encoding Inconsistent (status vs. state)
**Area**: Sensors / Events
**File(s)**: `skg/sensors/__init__.py:71-177` (status), `skg/substrate/node.py:66-144` (state)
**Description**: Events use "status" (realized/blocked/unknown). Nodes use "state". Same concept, different names.
**Impact**: Terminology confusion. Code harder to follow.
**Fix**: Use one term everywhere. Update codebase.

#### UNC-035: Evidence Rank Not Consistently Applied
**Area**: Sensors / Observation
**File(s)**: `skg/sensors/adapters.py:1-50` (rank varies by adapter), `skg/kernel/adapters.py:1-50` (loaded from events)
**Description**: Different adapters assign different ranks for similar evidence. No normalization.
**Impact**: Confidence calibration skewed by adapter choice.
**Fix**: Explicit evidence rank table. Adapters map to it.

#### UNC-036: Confidence Blending Formula Hardcoded
**Area**: Sensors / Context
**File(s)**: `skg/sensors/context.py:60-80`
**Description**: Three-way blend: `base × 0.45 + history × 0.35 + prior × 0.20`. Weights hardcoded.
**Impact**: Cannot tune per deployment.
**Fix**: Move to config.

#### UNC-037: Message Envelope Type Varies (obs.attack.precondition, obs.substrate.node, obs.projection.result)
**Area**: Sensors / Events
**File(s)**: `skg/sensors/__init__.py:71-177` (obs.attack.precondition), `skg-metacognition-toolchain/adapters/*/parse.py` (obs.substrate.node), metacognition projection (obs.projection.result)
**Description**: Different toolchains emit different envelope types. No unified contract.
**Impact**: Consumers must handle multiple types. Interp mixing.
**Fix**: Single canonical observation envelope for all domains.

---

### CONFUSED — 22 Items

#### CON-001: Is Pearl Memory Part of SKG or an Add-On?
**Area**: Kernel / Pearls
**File(s)**: `skg/kernel/pearls.py`, `skg/kernel/field_functional.py:182-187`, `skg-gravity/gravity_field.py:5477-5606`
**Description**: Pearls are formal part of Work 4 (`docs/SKG_Work4_Final.md:373-379`), integrated into field functional, and reinforcement used in gravity. But pearl recording is gravity-centric, incomplete, and sometimes optional.
**Impact**: Operator confusion about whether pearls are real or optional. Coverage incomplete.
**Fix**: Document pearls as core SKG (not optional). Ensure complete recording across all field transitions.

#### CON-002: Is the Substrate Node-First or Target-First?
**Area**: Kernel / Design
**File(s)**: `skg/kernel/observations.py:13-45` (targets list), `skg/kernel/engine.py:149-399` (target_ip), `skg/substrate/node.py:4-12` (node is primary)
**Description**: Papers define node/precondition as primary. Code still organizes around target lists and target_ip keys.
**Impact**: Reader confused about canonical model. Design intent unclear.
**Fix**: Refactor engine to be node/workload-first. Document target_ip as compatibility only.

#### CON-003: Is FieldLocal Supposed to Be Scalar or Vector?
**Area**: Kernel / Field Local
**File(s)**: `skg/kernel/field_local.py:237-284` (single target), `skg/substrate/node.py:385-395` (confidence_vector, mass_matrix extended fields)
**Description**: FieldLocal docstring describes single target. NodeState has vector/matrix fields. Unclear which is canonical.
**Impact**: Designer unsure of right abstraction level. Code may compute at wrong granularity.
**Fix**: Clarify: FieldLocal is single (workload, domain). Extended fields in NodeState are optional. Document both shapes.

#### CON-004: Is Gravity Driven By Field Locals or Target Rows?
**Area**: Gravity / Design
**File(s)**: `docs/SKG_Work4_Final.md:251` (field locals), `skg-gravity/gravity_field.py:6069-6250` (target rows)
**Description**: Work 4 says selection driven by field locals and coupling. Code drives by target rows and service heuristics.
**Impact**: Implementation does not match papers. Unclear which is intended.
**Fix**: Document decision: either refactor to field-local selection or document why hybrid is necessary.

#### CON-005: Is Measurement Authority the Measured Surface or the Hybrid Surface?
**Area**: Core / Authority
**File(s)**: `skg/intel/surface.py:164-261` (measured, projection-derived), `skg/cli/utils.py:72-116` (hybrid, config+discovery)
**Description**: Docs say observations primary. Runtime still prefers hydrated discovery surface for operator reporting.
**Impact**: Operator cannot tell which is truth.
**Fix**: Explicitly label: `/surface` = measured (canonical), `/discovery` = bootstrap (secondary).

#### CON-006: Should Config Targets Be Treated as Measured State?
**Area**: Core / Authority
**File(s)**: `skg/core/daemon.py:152-184` (injected), `skg/core/daemon.py:1732-1775` (merged into index), `skg/topology/energy.py:807-864` (promoted to realized)
**Description**: Configured targets injected into surface and field. Are they measured or not?
**Impact**: Operator cannot distinguish declared from measured.
**Fix**: Clear separation: targets.yaml = scope/hints (secondary), measured projections = truth (primary).

#### CON-007: What Is the Canonical Identity Anchor?
**Area**: Kernel / Identity
**File(s)**: `skg/identity/__init__.py:23-68` (workload-derived), `skg/kernel/pearls.py:24-29` (fallback to gravity::{target_ip}), `skg/kernel/identities.py:12-33` (unused IdentityRegistry)
**Description**: Three different identity representations in different modules. No single authority.
**Impact**: Cross-module identity matching fragile. Dedup unreliable.
**Fix**: Activate `IdentityRegistry` or document why `parse_workload_ref()` is canonical.

#### CON-008: What Is Meant By "Fold"?
**Area**: Kernel / Folds
**File(s)**: `skg/kernel/folds.py:1-50` (gap in field structure), `docs/SKG_Work4_Final.md:207` (unresolvable structure)
**Description**: Folds are documented as "unresolved field gaps." But code uses them for missing instruments (structural), missing wicket→CVE maps (contextual), and stale evidence (temporal).
**Impact**: Fold semantics overloaded. Use cases mixed.
**Fix**: Separate fold types explicitly. Document each type's resolution path.

#### CON-009: Is Decoherence a Measure of Quality or a Cost?
**Area**: Kernel / Field Local
**File(s)**: `skg/kernel/support.py:133-138` (decay-based penalty), `skg/kernel/field_local.py:271-284` (criterion: φ_d < 0.20)
**Description**: Decoherence is computed as decay loss. But protected-local criterion checks if it is below threshold (good). Unclear if decoherence is quality metric or cost metric.
**Impact**: Semantics ambiguous. Gravity effects unclear.
**Fix**: Define decoherence formally. Document its role in protected-local criterion.

#### CON-010: Is Pearl Reinforcement a Memory Fact or a Gravity Hint?
**Area**: Kernel / Pearls
**File(s)**: `skg/kernel/pearl_manifold.py:195-225` (reinforcement boost), `skg/gravity/selection.py:116-120` (memory boost as multiplier)
**Description**: Pearl reinforcement used to boost gravity potential. But is it part of field truth or just a heuristic?
**Impact**: If pearl reinforcement dominates, measurements become secondary. Truth boundary unclear.
**Fix**: Document pearl reinforcement as modifier only. Measured field locals should dominate.

#### CON-011: Is Compatibility Score (C) a Quality Measure or a Weighting Factor?
**Area**: Kernel / Support
**File(s)**: `skg/kernel/support.py:123-128` (formula), `skg/kernel/field_local.py:274` (criterion)
**Description**: C measures how many distinct instrument families have observed a wicket. Used in protected-local criterion. But unclear if it is confidence metric or diversity metric.
**Impact**: When to trust a single-source observation unclear.
**Fix**: Clarify semantics. Document minimum C thresholds per domain.

#### CON-012: Is the Projector Contract Observation → Payload or Observation → Envelope?
**Area**: Sensors / Projection
**File(s)**: `skg/sensors/projector.py:289-318` (both shapes accepted), feedback consumers (expect different shapes)
**Description**: Projectors may return wrapped envelope or top-level payload. Feedback/delta must handle both.
**Impact**: Contract ambiguous. Silent failures possible.
**Fix**: Define one canonical contract. Enforce at projector output.

#### CON-013: Is the Surface for Operator Visibility or for Gravity Input?
**Area**: Gravity / Surface
**File(s)**: `skg/intel/surface.py:164-261` (operator visibility), `skg-gravity/gravity_field.py:5850-5890` (gravity input)
**Description**: Gravity loads a surface file for instrument selection. But which surface? Discovery (bootstrap) or measured (true)?
**Impact**: Gravity's starting state unclear. May use stale data.
**Fix**: Explicit documentation: gravity uses measured surface (primary) with discovery fallback (bootstrap only).

#### CON-014: Is the Aperture Point for Measurement the Event Envelope or the Observation Object?
**Area**: Kernel / Observation
**File(s)**: `skg/sensors/__init__.py:71-177` (envelope), `skg/kernel/adapters.py:87-157` (observation object)
**Description**: Events emitted as NDJSON envelopes. Kernel converts to Observation. Which is canonical?
**Impact**: If event specification changes, does it require Observation change? Unclear responsibility.
**Fix**: Document: envelope is outer contract, Observation is internal substrate object.

#### CON-015: Should LLM Output Be Allowed Into the Observation Plane?
**Area**: Core / LLM
**File(s)**: `skg/core/assistant_contract.py:1-50` (custody chain rules), `skg/sensors/dark_hypothesis_sensor.py:80-120` (LLM proposals only)
**Description**: Some LLM output allowed into proposals but not into observations (per assistant contract). But dark_hypothesis_sensor.py asks LLM for instruments. Where does output go?
**Impact**: LLM output channel unclear. Operator cannot verify provenance.
**Fix**: Explicit admission rules. Document what LLM outputs are observations vs. proposals vs. hints.

#### CON-016: Is the "World" Snapshot a Derived View or an Independent Truth Source?
**Area**: Daemon / World
**File(s)**: `skg/core/daemon.py:2013-2117` (identity world), `skg/topology/energy.py:1059-1109` (world fibers)
**Description**: Daemon computes world snapshots from target index. Topology injects world snapshots as realized field contributions.
**Impact**: Is world derived from measured state or independent? Field energy contaminated?
**Fix**: Document: world is derived view only. Realized contributions come from measured projections.

#### CON-017: Is Bounce Strength a Prior or a Coupling?
**Area**: Substrate / Bond
**File(s)**: `skg/substrate/bond.py:1-80` (bond strength for prior), `skg/core/coupling.py:50-80` (inter_local coupling)
**Description**: Bonds define prior influence. Coupling matrix defines domain coupling. Are they the same thing?
**Impact**: Unclear which influences gravity. Two different values in code.
**Fix**: Clarify: bonds (network) vs. coupling (domain). Document relationship.

#### CON-018: Is Sphere Membership Derived From Domain or From Wicket Prefix?
**Area**: Topology / Sphere
**File(s)**: `skg/kernel/field_functional.py:45-60` (domain → sphere), `skg/gravity/selection.py:27-45` (prefix → sphere)
**Description**: Two different sphere mappings. One from domain_registry; one from wicket prefix.
**Impact**: Sphere assignment ambiguous. Risk of mismatch.
**Fix**: Single canonical mapping. Prefer domain (formal) over prefix (heuristic).

#### CON-019: Is Wicket History Meaningful (Should Pearl Reinforcement Apply)?
**Area**: Kernel / Pearls
**File(s)**: `skg/kernel/pearl_manifold.py:172-185` (reinforcement boost), `skg/gravity/selection.py:116-120` (applied to ranking)
**Description**: Pearl memory gives wavelength boost to previous-successful instruments. But is past success a reliable predictor on the same identity?
**Impact**: May bias gravity toward previous instruments even if field suggests new ones.
**Fix**: Document assumptions. Make reinforcement weight tunable.

#### CON-020: What Is "Latent" State?
**Area**: Substrate / Node
**File(s)**: `skg/substrate/node.py:127-144` (is_latent field), `skg/kernel/support.py:1-60` (unmanifested potential)
**Description**: Latent state mentioned in docs and code but semantics unclear. When is a wicket latent?
**Impact**: Latent-state handling unpredictable.
**Fix**: Define latent formally. Document when and how latency is set/cleared.

#### CON-021: Is the Convergence Criterion Achievable?
**Area**: Gravity / Convergence
**File(s)**: `skg-gravity/gravity_field.py:6446-6489` (epsilon < 0.01)
**Description**: Convergence epsilon = 0.01. But real systems may oscillate or asymptote. Is convergence guaranteed?
**Impact**: Cycles may run indefinitely. No bounds on engagement time.
**Fix**: Document convergence properties. Add timeout with graceful degradation.

#### CON-022: Is the Forge Pipeline Autonomous or Proposal-Driven?
**Area**: Forge / Pipeline
**File(s)**: `skg/forge/pipeline.py:1-50` (autonomous generation), `skg/core/daemon.py` (proposal queuing)
**Description**: Forge can autonomously generate toolchains. But they must be operator-approved as proposals. When can they auto-deploy?
**Impact**: Operator confused about automation scope.
**Fix**: Document forge behavior explicitly: discovery → candidate → proposal queue (no auto-deploy).

---

### INSECURE — 3 Items

#### SEC-001: SSH Credentials Stored in targets.yaml (File Permission Reliant)
**Area**: Security / Configuration
**File(s)**: `/etc/skg/targets.yaml`, `skg/sensors/ssh_sensor.py:1-50`
**Description**: SSH credentials (username, password, keys) defined in config YAML. Security relies on file permissions (600). No encryption, no secret management.
**Impact**: Credentials visible to any process reading `/etc/skg/targets.yaml`. History in shell/git. If machine compromised, all credentials exposed.
**Fix**: Integrate with secret manager (Vault, AWS Secrets Manager, etc.). Or use keyfile-only auth, prompt for password at runtime.

#### SEC-002: Credential Extraction Regex Overly Broad (False Positives)
**Area**: Security / Sensors
**File(s)**: `skg-gravity/cred_reuse.py:195-220`
**Description**: Credentials extracted from env/history using regex: `PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|CREDENTIAL|AUTH_?TOKEN`. Matches comments and config examples.
**Impact**: Non-credential strings extracted and tested. False credentials pollute CredentialStore. May trigger rate limiting on legitimate targets.
**Fix**: Improve regex with context awareness. Add config to exclude patterns. Validate extracted credentials before storing.

#### SEC-003: Dark Hypothesis Sensor LLM May Suggest Non-Existent Instruments
**Area**: Security / LLM
**File(s)**: `skg/sensors/dark_hypothesis_sensor.py:80-120`, `skg/sensors/dark_hypothesis_sensor.py:160-170`
**Description**: LLM queried to suggest instruments for high-torque wickets. Output not validated. LLM may hallucinate instruments that don't exist. Proposals created without verification.
**Impact**: Operator sees proposals for non-existent instruments. If executed, may attempt code injection via fake instruments.
**Fix**: Validate suggested instrument against registered instrument registry before creating proposal. Log hallucinations.

---

## 4. PRIORITIZED FIX PLAN

### P0 — Correctness Blockers (12 items)

These break system operation or produce wrong results. Must be fixed first.

1. **BRK-002**: Workload target resolution (affects all multi-domain analysis)
2. **BRK-003**: SshSensor target reload (breaks observation boundary)
3. **BRK-001**: Wrapped interp delta ingestion (affects 33% of toolchains)
4. **BRK-004**: Collect artifact path mismatch (automation/verification broken)
5. **BRK-010**: Kernel engine target_ip dependency (blocks workload-first refactoring)
6. **BRK-009**: Observation closure heuristic (causes wrong closures)
7. **BRK-020**: CVE sensor rate limiting (blocks sensor loop)
8. **BRK-021**: BloodHound token expiry (breaks large AD collections)
9. **BRK-022**: LLM timeout (daemon hang)
10. **BRK-008**: Feedback state silent reset (data loss, invisible to operator)
11. **BRK-016**: Malformed NDJSON silent drop (evidence loss, no audit)
12. **SEC-001**: SSH credentials in plaintext config (credentials exposed)

**Execution order**: 2 → 3 → 1 → 10 → 9 → 4 → (others in parallel)

### P1 — Integration Gaps (15 items)

Subsystems exist but are disconnected from main paths. Fix after P0.

1. **UNW-011**: DarkHypothesisSensor not registered (sensor never runs)
2. **UNW-001**: IdentityRegistry unused (activate or remove)
3. **UNW-002**: GravityScheduler mismatch (rename/refactor)
4. **ABS-023**: Adapter unit tests missing (add tests for all parse functions)
5. **ABS-024**: CLI daemon-down test missing (add test)
6. **ABS-013**: Surface authority test missing (add regression test)
7. **ABS-014**: SshSensor target reload test missing (add test)
8. **ABS-015**: Wrapped interp test missing (add test)
9. **UNW-014**: Projector output validation missing (enforce schema)
10. **UNW-015**: Event envelope validation missing (validate before emission)
11. **ABS-025**: Calibration persistence test missing (add round-trip test)
12. **UNW-017**: Surface hydration consolidation (shared function)
13. **UNC-002**: Event envelope construction fragmented (enforce canonical helpers)
14. **UNC-003**: Projector output shape inconsistent (enforce single shape)
15. **ABS-001**, **ABS-002**, **ABS-003**: Missing adapters (AI, IoT, supply chain implementations)

### P2 — Consistency & Canonical Form (28 items)

Things that work but are inconsistent across subsystems. Fix after P1.

1. **UNC-001**: Three "surface" products (rename/label clearly)
2. **UNC-004**: Fold location overloaded (use subclasses)
3. **UNC-005**: Fiber anchor overloaded (use distinct fields)
4. **UNC-006**: Binary sphere disagreement (unify mapping)
5. **UNC-013**: Coupling matrix values inconsistent (single matrix)
6. **UNC-009**: Target authority duplicated (single loader)
7. **UNC-010**: Domain-instrument mapping hardcoded (centralize)
8. **UNC-011**: Workload subject resolution scattered (use identity parser everywhere)
9. **UNC-016**: Confidence calibration two definitions (single logic)
10. **UNC-017**: Surface ranking hybrid (prefer mtime)
11. **UNC-018**: Event provenance incomplete (enforce all fields)
12. **UNC-019**: Applicable wickets from heuristics (derive from locals)
13. **UNC-027**: Pearl grouping mixed keys (normalize to identity_key)
14. **UNC-031**: Legacy path aliasing (formal registry)
15. **UNC-034**: Status vs. state terminology (pick one, update everywhere)
16. **UNC-035**: Evidence rank inconsistent (rank table)
17. **UNC-036**: Confidence blend hardcoded (move to config)
18. **BRK-005**: First-contact floor aggressive (lower or configure)
19. **BRK-006**: Gravity surface by richness (prefer recency)
20. **BRK-007**: Topology energy world injection (separate presentation)
21. **BRK-023**: Web observation ignores events_file (read and integrate)
22. **CON-002**: Substrate target-first not node-first (refactor engine)
23. **CON-005**: Authority surface ambiguous (label clearly)
24. **CON-006**: Config targets as measured (separate scope from truth)
25. **BRK-014**: Toolchain tests not discovered (add to pytest)
26. **BRK-015**: Sheaf failure silent (log warning)
27. **BRK-017**: Port scanning IDS risk (add delays, configurable)
28. **BRK-018**: SUID list hardcoded (make configurable)

### P3 — Polish & Hardening (8 items)

Operational hardening, security, test coverage. Fix after P2.

1. **ABS-027**: No health check endpoint (add /api/health)
2. **ABS-011**: Unbounded state files (add rotation/cleanup)
3. **ABS-012**: No operator corruption events (write quarantine stream)
4. **SEC-002**: Credential extraction overly broad (improve regex)
5. **SEC-003**: LLM hallucination validation (check against registry)
6. **BRK-012**: SSH credentials logged plaintext (redact, add --unsafe-debug)
7. **BRK-013**: HTTP auth failure heuristic (check status codes)
8. **BRK-019**: Userns parsing fragile (bounds check)

---

## 5. CROSS-CUTTING THEMES

### Theme 1: Authority Inversion
Multiple core paths treat hybrid discovery/config state as primary before measured state has the final word. This affects:
- Gravity starting landscape (uses hydrated surface, not measured locals)
- Topology energy (world states promoted to realized)
- Surface ranking (prefers cardinality over recency)
- Operator-facing API (targets registry mixes declared + measured)

**Fix**: Audit every authority boundary. Document which is canonical. Remove parallel truth layers.

### Theme 2: Observation Boundary Fragility
The entrance to the substrate is leaky:
- SshSensor reloads targets instead of honoring supplied config
- Web observation registration ignores event files
- Event construction not centralized (some hand-rolled)
- Wrapped interps not flowing through delta store
- Malformed events silently dropped

**Fix**: Harden observation admission. Single envelope contract. Validate all inputs. Make failures visible.

### Theme 3: Node/Workload/Identity Model Not Unified
Papers define node-first substrate. Code still organizes around target IP:
- Kernel engine uses target_ip primary key
- Gravity selection takes target rows
- Fold persistence by IP
- Workload resolution by string slicing

**Fix**: Refactor core layers to use (workload_id, domain) pair as primary key. Keep target_ip as optional compat layer.

### Theme 4: Parallel Invocation Stories
Gravity is invoked via three different paths (daemon subprocess, CLI module load, comments that don't match reality). Same for surface hydration, target loading, calibration.

**Fix**: One invocation story per component. Document explicitly. Remove parallel paths.

### Theme 5: Silent Failures
Corruption, malformed input, missing dependencies all fail silently:
- NDJSON parse errors dropped without quarantine
- Sheaf import failure with no warning
- Feedback state reset on corruption, no notice
- Domain discovery fallback without logging

**Fix**: Every parse failure goes to operator-visible stream. Quarantine corrupted data. Log fallbacks.

### Theme 6: Incomplete Coverage of Formal Model
Work 4 papers define field-local coupling, fiber-driven selection, pearl memory, decoherence criterion. But:
- Pearl recording incomplete (gravity-centric, not all transitions)
- Gravity selection not purely field-local
- Decoherence criterion not uniformly applied
- Field functional computed but not fully integrated

**Fix**: Audit implementation against papers. Close gaps. Test formal properties.

---

## 6. QUICK WINS (< 1 hour each)

1. **BRK-015**: Add log warning if sheaf import fails → 5 min
2. **UNW-018**: Log warning if domain discovery falls back → 10 min
3. **UNC-034**: Pick one term (observation_status) and create global replace → 15 min
4. **ABS-020**, **ABS-021**: Move decoherence/compatibility thresholds to config → 30 min
5. **BRK-014**: Add pytest glob pattern to discover toolchain test_golden.py files → 10 min
6. **UNC-036**: Move confidence blend weights to config → 15 min
7. **SEC-002**: Add config to exclude credential patterns → 20 min
8. **BRK-017**: Add 0.5s delay between port probes in gpu_probe → 5 min
9. **CON-001**: Document pearls as core SKG in README → 10 min
10. **UNW-009**: Document skg/cli.py as legacy shim in README → 10 min

---

## 7. DEFERRED / WON'T FIX

### Intentionally Deferred

1. **Full async database support**: Low priority for current scope. Add when scaling requires it.
2. **Secret manager integration**: Important but requires ops infrastructure setup. Defer to ops phase.
3. **Formal proof of gravity convergence**: Research question, not blocking. Document assumptions instead.
4. **Full SBOM/SCA integration**: Complex feature. Implement after core unification complete.
5. **Cross-toolchain attack-chain correlator**: Nice-to-have. Implement after surface becomes authoritative.

### Explicitly Won't Fix (Preserved by Design)

1. **skg_deploy mirror**: Preserved for deploy reference. Do not delete or consolidate.
2. **forge_staging directory**: Preserved for generation artifacts. Keep as staging area.
3. **Preserved backup trees (*.backup, *.pre_fix)**: Kept for historical reference. Document as non-canonical.
4. **target-oriented CLI verbs (skg target add/remove/list)**: Keep as operator convenience layer, but document as non-authoritative.
5. **Config-driven bootstrap**: targets.yaml and discovery surfaces remain useful for scope/hints. Document as secondary.

---

## APPENDIX A: Summary Metrics

| Metric | Count |
|--------|-------|
| Total items identified | 134 |
| BROKEN | 23 |
| UNWIRED | 18 |
| ABSENT | 31 |
| UNCANONICAL | 37 |
| CONFUSED | 22 |
| INSECURE | 3 |
| P0 fixes | 12 |
| P1 fixes | 15 |
| P2 fixes | 28 |
| P3 fixes | 8 |
| Quick wins | 10 |
| Lines of code affected | ~15,000+ |
| Modules with drift | 42+ |
| Test gaps | 18+ |

---

## APPENDIX B: Recommended Reading Order

1. Start: **SKG_BOTTOM_UP_REMEDIATION_PLAN_20260327.md** (layer-by-layer strategy)
2. Then: **SKG_OBSERVATION_BOUNDARY_AUDIT_20260327.md** (where truth enters)
3. Then: **SKG_MEASURED_AUTHORITY_AUDIT_20260327.md** (which paths are canonical)
4. Then: **SKG_NODE_MODEL_AUDIT_20260327.md** (substrate semantics)
5. Then: **SKG_GRAVITY_BOUNDARY_AUDIT_20260327.md** (selection semantics)
6. Then: **SKG_CORE_UNIFICATION_AUDIT_20260327.md** (base SKG health)
7. Finally: **SKG_IDENTITY_MEMORY_TOPOLOGY_AUDIT_20260327.md** + **SKG_EVENT_AND_PEARL_CONTRACT_AUDIT_20260327.md** (memory layers)

---

## APPENDIX C: Definition of Done

This remediation effort is complete when:

1. **Authority unified**: One canonical path per concept (surface, observation, identity, gravity).
2. **Substrate primary**: Field locals, measured state govern decisions. Config/discovery are secondary.
3. **Node-first**: Kernel engine, gravity selection, folding all use (workload_id, domain) not target_ip.
4. **Contracts enforced**: Event envelope, projector output, fold semantics all validated.
5. **Failures visible**: No silent parse failures, corruption, or fallbacks without operator notice.
6. **Tests comprehensive**: All P0/P1 items have regression tests. P2 items have consistency tests.
7. **Docs match code**: Papers align with implementation. Comments reflect reality.
8. **Papers satisfied**: Work 3, Work 4 formal models fully implemented and tested.

---

**Generated**: 2026-03-28  
**Source documents**: 18 comprehensive audits  
**Next step**: Begin P0 fixes in dependency order. Recommend starting with BRK-002 (workload resolution).
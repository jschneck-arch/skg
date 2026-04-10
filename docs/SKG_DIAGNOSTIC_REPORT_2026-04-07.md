# SKG Diagnostic Report — 2026-04-07

**Scope**: Full in-depth audit of `/opt/skg` — why the system is broken, why domains don't function, why research doesn't work, and what needs to be fixed.

**Method**: Import-chain tracing, direct code reads, runtime execution, cross-referencing against the existing `/opt/skg/review/OPEN_ISSUES.md` audit document (2302 lines), and live test execution.

**Test baseline**: `298 passed` (main suite) + `142 passed` (packages) — tests pass, but they test isolated units. They do not catch the systemic integration failures documented here.

---

## TL;DR

SKG has **two parallel, diverged codebases** (legacy toolchains vs new domain packs) that are not connected to each other. The gravity/research pipeline has **80+ confirmed open issues** ranging from blocking semantic collisions to orphaned modules. The AI-backed research system (resonance) has at least **10 active bugs** preventing meaningful catalog generation or adaptive learning. Most individual components work in isolation — the tests prove that — but they fail in integration because identity, namespacing, and data-flow contracts are inconsistent across layers.

---

## 1. Structural Problem: Two Codebases That Don't Know About Each Other

### What exists

```
/opt/skg/
├── skg-*-toolchain/          ← Legacy toolchains (what gravity uses)
│   ├── adapters/
│   ├── projections/
│   └── contracts/catalogs/
├── packages/skg-domains/     ← New domain-pack architecture (NOT wired to gravity)
│   ├── host/
│   ├── ad/
│   ├── web/
│   ├── redteam/              ← status: scaffold (empty adapters dir)
│   └── ...
└── skg_deploy/               ← Stale diverged copy of old deployment tree
```

### The problem

The new `packages/skg-domains/` architecture (domain-pack runtime) is fully built out with proper Python packages (`skg_domain_host`, `skg_domain_ad`, etc.), clean adapter/projector structure, and 142 passing tests. But **nothing in the gravity engine, daemon, or CLI imports or invokes any of it**.

```python
# /opt/skg/skg-gravity/gravity_field.py — uses legacy paths ONLY
from skg.core.paths import SKG_CONFIG_DIR, SKG_HOME, SKG_STATE_DIR, DISCOVERY_DIR
# drives toolchain dispatch via daemon_domains.yaml → skg-*-toolchain/
```

```yaml
# /opt/skg/config/daemon_domains.yaml — only knows about legacy toolchain dirs
domains:
  - name: host
    dir: skg-host-toolchain    # ← legacy dir
    cli: skg_host.py
```

The `packages/skg-domains/host` package has a new, cleaner adapter (`host_ssh_assessment`, `host_nmap_profile`) and projector. The gravity engine is still calling the legacy `skg-host-toolchain/skg_host.py` CLI script, completely ignoring the new package. **All investment in domain packs is currently dead weight**.

### The stale skg_deploy copy

`/opt/skg/skg_deploy/` is a fork of the old deployment that has diverged from the main tree:

```
Only in /opt/skg/skg-gravity: adapters      ← new adapters dir doesn't exist in skg_deploy
Only in /opt/skg/skg-gravity: cred_reuse.py ← new file missing from skg_deploy
Files gravity_field.py differ               ← core engine has diverged
Files exploit_dispatch.py differ
```

This creates confusion about which version is canonical. The `apply_gravity_fix.py` in the deploy root suggests patches were applied to one but not synced to the other.

### Fix

Either wire `packages/skg-domains/` into the daemon domain registry and retire the legacy toolchains, or document clearly that domain packs are pre-production scaffolding. As-is, engineers are doing duplicate work in two incompatible systems.

---

## 2. The Web Domain Is Completely Broken (HIGH-03)

This is the most active domain for pentesting, and it is fundamentally broken at the data contract level.

### Wicket semantic collision — four adapters disagree on what the same IDs mean

The web domain uses wicket IDs `WB-01` through `WB-43`. The catalog is the authority. **Three different adapters have assigned completely different meanings to the same IDs**:

| Wicket ID | Catalog (authority) | `auth_scanner.py` emits | `gobuster_adapter.py` emits |
|-----------|--------------------|--------------------------|-----------------------------|
| `WB-08` | `git_exposure` | "accepted credentials" | `.git/` directory (correct) |
| `WB-09` | `env_file_exposed` | SQL injection found | — |
| `WB-11` | `tls_weak_or_missing` | XSS found | — |
| `WB-14` | `auth_surface_present` | command injection found | — |
| `WB-05` | `admin_interface_exposed` | "sensitive paths accessible" | admin/login paths (correct) |

**Example from `auth_scanner.py`** (lines 396-420, 476-503):
```python
# auth_scanner.py says WB-09 means SQL injection:
"WB-09": "sql_injection",
"WB-14": "command_injection",
"WB-11": "xss_found",
"WB-08": "credentials_accepted",

# But the catalog (attack_preconditions_catalog.web.v1.json) says:
# WB-08 = git_exposure
# WB-09 = env_file_exposed
# WB-11 = tls_weak_or_missing
# WB-14 = auth_surface_present
```

This means: when `auth_scanner` finds an SQL injection and emits `WB-09`, the projector reads that as `.env file exposed`. A web SQLi → RCE chain will **never project correctly** because the wicket tokens are semantically wrong.

### Attack path ID mismatch

```python
# skg/sensors/web_sensor.py:851 — live sensor defaults to:
attack_path_id = "web_surface_v1"

# skg/cli/commands/target.py:288-295 — observe command uses:
"web_surface_v1" or "web_sqli_to_shell_v1"

# skg-web-toolchain/projections/web/run.py:21 — aliases:
"web_sqli_to_shell_v1" → "web_full_chain_v1"

# But the actual catalog also now defines web_full_chain_v1 directly
# AND struct_fetch.py defaults to "web_sqli_to_shell_v1" directly
# AND gravity_field.py:2917-2927 generates follow-ons for "web_cmdi_to_shell_v1"
```

There are at least **4 different path ID strings** used for what should be one canonical web exploitation chain, with mapping aliases layered on top. The root web projector (`skg-web-toolchain/projections/run.py:21`) still references a non-existent catalog file:

```python
# skg-web-toolchain/projections/run.py:21
catalog_path = "web_attack_preconditions_catalog.v1.json"  # ← FILE DOES NOT EXIST
```

### Workload identity fragmentation for web targets

```python
# CLI web observe writes to DISCOVERY_DIR (not EVENTS_DIR):
# skg/cli/commands/target.py:271-296

# And does NOT pass --workload-id, so collector defaults to bare hostname/IP:
# skg-web-toolchain/adapters/web_active/collector.py:1227-1228
workload_id = parsed_hostname_or_ip  # "example.com" or "192.168.1.5"

# But sensor-driven web flows use:
workload_id = f"web::{identity}"     # "web::192.168.1.5"
```

The same web target appears as two different entities in the engagement dataset. DP-05 (orphan detection) will delete projections for one form when the other form's observations are present.

### Fix

1. Audit all web adapters against the catalog and assign correct wicket IDs in `auth_scanner.py`
2. Pick one canonical attack path ID for each chain (`web_sqli_to_shell_v1`) and remove aliases
3. Enforce `web::` prefix in CLI web observe path
4. Delete or quarantine the stale root `projections/run.py`

---

## 3. Identity Fragmentation Across the Whole System (HIGH-02, MED-13, MED-19, MED-73–MED-78)

The same physical target can appear under multiple distinct identity strings, causing observation and projection records to be treated as different entities. This is the root cause of many "engagement is broken" symptoms.

### The identity shapes in the wild

```
192.168.1.5                  ← raw discovery IP
host::192.168.1.5            ← SSH sensor prefix
ssh::192.168.1.5             ← SSH direct prefix (alias of above)
web::192.168.1.5             ← web sensor prefix
web::example.com             ← hostname form
msf_workspace                ← MSF adapter default
10.0.0.7                     ← MSF session adapter raw IP
```

**From `skg-host-toolchain/adapters/msf_session/parse.py` (lines 184-189)**:
```python
# Emits HO-17 with raw IP:
event["workload_id"] = "10.0.0.7"      # ← raw, no prefix

# But skg/cli/commands/proposals.py:323-326 rewrites session opens to:
event["workload_id"] = f"host::{identity_key}"   # ← prefixed
```

The same MSF session produces host events with `10.0.0.7` and the post-exploitation rewrite produces `host::10.0.0.7`. These are different keys in the engagement database. DP-05 sees the projection (with `host::10.0.0.7`) as orphaned because no observation with that workload_id exists.

### Engagement integrity false-positives

From `skg/intel/engagement_dataset.py:678-684`:
```python
# DP-05 uses exact string match — no normalization:
orphaned = {p["workload_id"] for p in projections
            if p["workload_id"] not in {o["workload_id"] for o in observations}}
```

`skg engage clean` **deletes valid projections** based on this false-orphan detection.

### MED-73/MED-74: Target list splits one node into two rows

```python
# skg/cli/commands/surface.py + daemon list_targets():
# If a target was discovered as 192.168.1.5 but also has hostname dc01.corp.local,
# the target list shows TWO separate rows instead of one merged identity
```

### Fix

Adopt a single canonical normalization function (`parse_workload_ref` already exists in `skg/identity`) and enforce it at all adapter ingestion boundaries. DP-05 should compare normalized keys, not raw strings.

---

## 4. The AI Research System (Resonance) Cannot Actually Do Research

SKG's resonance engine is meant to power adaptive catalog generation, wicket drafting, and research-driven observation recommendations. It has at least 10 active bugs.

### MED-24 + MED-26: The catalog drafting CLI doesn't exist and the engine contract is broken

```python
# skg/resonance/drafter.py:428-433 tells operators to run:
raise ValueError("Run: skg resonance draft-prompt <domain> <description>")
raise ValueError("Then: skg resonance draft-accept <draft-id>")

# But skg/cli/app.py:355-372 exposes NO such commands:
resonance_sub.add_parser("status")
resonance_sub.add_parser("ingest")
resonance_sub.add_parser("query")
resonance_sub.add_parser("draft")      # ← exists, but no draft-prompt/draft-accept
resonance_sub.add_parser("drafts")
```

The operator-facing fallback for AI catalog generation fails hard and points to commands that return `error code 2`. The only actual generation path requires either a working Ollama model or an `ANTHROPIC_API_KEY`.

### MED-26: drafter expects tuple shape, engine returns dict shape (PARTIALLY FIXED)

```python
# skg/resonance/engine.py:268-285 returns:
{"wickets": [{"record": {...}, "score": 0.95}, ...], ...}

# skg/resonance/drafter.py:48-68 USED TO iterate as tuples:
for record, score in context["wickets"]:   # ← was broken, caused TypeError

# Now has _extract_record() adapter at drafter.py:270-287 — FIXED
```

The fix is in place but has no test coverage (MED-25).

### MED-27: Standalone resonance CLI crashes on `skg resonance drafts`

```python
# skg/resonance/cli.py:106-120:
drafts = engine.list_drafts()    # ← AttributeError: ResonanceEngine has no list_drafts()

# ResonanceEngine in engine.py has NO list_drafts() method.
# The main skg CLI works around this by scanning the drafts directory directly,
# but the standalone resonance CLI is completely broken for this command.
```

### MED-28: Resonance ingestion says it learned things it didn't

```python
# skg/resonance/ingester.py:173-181:
store_domain(DomainMemory(
    domain_name=domain,
    adapters=[],         # ← always empty, never populated
    ...
))
# But ingest_all() still increments domains_added even when store_domain() returns False
```

After running `skg resonance ingest`, the summary reports X domains added and Y adapters indexed. The adapter-to-domain linkage in the domain memory objects is always empty — the resonance system can't recommend adapters by domain because it never stored that mapping.

### MED-29: Historical confirmation rate mixes data from different targets

```python
# skg/resonance/observation_memory.py:255-275
# recall() takes workload_id but first accepts ANY record matching wicket_id:
for rec in self._records:
    if rec.wicket_id == condition_id:    # ← no workload filter yet
        results.append(rec)
# workload check only happens in the fallback branch

# Confirmed: historical_confirmation_rate(workload_id='host::10.0.0.1')
# mixes 'realized' from 10.0.0.1 with 'blocked' from 10.0.0.2
# when both have the same wicket/domain
```

The sensor confidence calibration that determines observation priority is fed corrupted data. The system may de-prioritize real attack paths because a different target's negative evidence is bleeding in.

### MED-30: TF-IDF embedder mutates its own basis on every call

```python
# skg/resonance/embedder.py:77-111:
def embed(self, texts: list[str]) -> np.ndarray:
    self._corpus = self._corpus + texts    # ← MUTATES corpus state
    self._idf = refit(self._corpus + texts)  # ← refit changes all existing vectors too

# But MemoryStore and ObservationMemory only append NEW vectors:
# skg/resonance/engine.py:120-127
self._index = np.vstack([self._index, new_vectors])  # ← old vectors now incompatible
```

After adding enough records, the TF-IDF basis has shifted so far that early-indexed entries no longer match queries they should match. Resonance search quality degrades silently over time.

### MED-31: Confidence calibration always returns defaults

```python
# skg/temporal/__init__.py:620-628:
rank = t.evidence_rank if hasattr(t, "evidence_rank") else None
# WicketTransition DOES have evidence_rank field (line 94), so hasattr is True
# BUT the field is set to default 1 in all constructed transitions:
# line 353: WicketTransition(...) — no evidence_rank kwarg passed

# Result: calibrate_confidence_weights() groups all transitions under rank=1
# and returns "insufficient_data" defaults for every rank level
```

`skg calibrate` appears to run successfully but produces only hardcoded defaults regardless of your engagement history. The calibration output is not trustworthy.

### MED-45: AI gravity runner overwrites valid events with summary dicts

```python
# skg-gravity/gravity_field.py: _exec_ai_runner()
# After collecting AI probe events, overwrites them with a summary dict
# before passing to the projection step
# Result: valid MC-* events are discarded, projection gets summary data instead
```

The AI domain is one of the more interesting research domains (metacognition attack surface), and the gravity runner corrupts its own output before it can be projected.

---

## 5. Gravity Field Engine Has Numerous Wiring Bugs (MED-46 through MED-56)

### MED-46: `_exec_post_exploitation()` crashes on Windows targets

```python
# skg-gravity/gravity_field.py: _exec_post_exploitation()
# Accesses target["os_family"] or target["platform"] before session discovery
# Windows sessions don't always have this metadata populated at that point
# Raises KeyError/AttributeError before session discovery runs
```

Every Windows pentest engagement will crash the post-exploitation phase unless the target metadata was pre-populated.

### MED-49: `gravity_field_cycle()` loses subject identity

```python
# The main gravity cycle function loses the subject identity context mid-execution
# and undercount energy terms after calling certain adapters
# This means field energy calculations after adapter execution can be wrong,
# causing the system to route to already-visited low-value instruments
```

### MED-51: `_exec_ssh_sensor()` writes duplicate events into the same NDJSON

```python
# _exec_ssh_sensor() calls the sensor twice under certain paths
# Both calls append to the same output file
# Result: the same host events appear twice in events/
# Projection reads both, giving doubled confidence to the same evidence
# This inflates wicket support and can prematurely collapse superposition
```

### MED-52: sysaudit events are collected but never projected

```python
# _exec_sysaudit() emits FI/PI/LI events into the event stream
# But the gravity loop's projection dispatch never handles sysaudit-domain events
# All file-integrity and process-integrity evidence is silently dropped
# at the projection stage — the substrate never sees it
```

### MED-53: gravity crashes when targets.yaml uses list-root format

```python
# skg-gravity/gravity_field.py: load_targets()
targets = yaml.safe_load(f)
for ip, meta in targets.items():   # ← assumes dict root

# /opt/skg/config/targets.yaml actual format:
# targets:
#   - host: 192.168.1.10
#     method: ssh
# This is dict-root with a "targets" key containing a list
# If anyone writes a plain list-root YAML, this crashes immediately
```

### MED-84: Several gravity adapters call `envelope()` without required `pointer`

```python
# Multiple adapters in skg-gravity/adapters/:
event = envelope(
    source_id=source_id,
    toolchain=toolchain,
    wicket_id=wicket_id,
    # ← missing pointer= kwarg
)
# envelope() requires pointer for provenance chain
# Events emitted without it fail downstream provenance validation silently
```

---

## 6. CLI Surface Has Dead-Ends and Missing Commands

### MED-10: `skg train run` advertised but doesn't exist

```python
# skg/training/scheduler.py:15:
# "Also callable manually: skg train run"
# skg/training/scheduler.py:181:
# "called by systemd timer or skg train run"

# skg/cli/app.py:63-420: NO "train" parser exists
# skg/cli/commands/: NO cmd_train.py file
```

The training system is described as manually invocable but is actually systemd-only. The systemd timer itself is misconfigured (MED-01): `skg-train.timer` targets `skg-train.service` as a plain unit but the service uses `User=%i` (template syntax), so it will fail to start without an explicit instance name.

### MED-11: `skg data redteam` advertised but doesn't exist

```python
# skg/intel/redteam_to_data.py:34-35:
# "Usage: skg data redteam --out-dir <dir>"

# skg/cli/app.py:154-183: data subcommands are only:
# profile, project, paths, catalog, discover
# No "redteam" subcommand
```

`redteam_to_data.py` is a real cross-domain analysis module (maps redteam findings to data pipeline exposure) but is CLI-orphaned. You can't reach it through the CLI.

### MED-23: `skg field` rejects active domains

```python
# skg/cli/app.py:377-384:
choices=["host", "container_escape", "ad_lateral", "aprs", "web", "supply_chain", "data"]

# But active workload domains include:
# binary, data_pipeline, binary_analysis, metacognition, ai_target, nginx
# All rejected with parser error code 2
```

You cannot query field state for a binary analysis workload or an AI domain target through the CLI.

### MED-24: `skg resonance draft-prompt` and `draft-accept` don't exist

The fallback path when no AI key is available (prompt mode) tells operators to use these commands. They return `error: argument resonance_cmd: invalid choice: 'draft-prompt'`. The no-backend drafting workflow is completely broken at the CLI level.

---

## 7. Data Pipeline Integrity Issues

### MED-09: Training corpus gets doubled on every proposal decision

```python
# skg/forge/proposals.py:592-596 — accept path:
on_proposal_accept(proposal, ...)    # ← call 1
# ... more code ...
on_proposal_accept(proposal, ...)    # ← call 2 (same accept flow)

# skg/forge/proposals.py:676-679 — reject path:
on_proposal_reject(proposal, reason) # ← call 1
on_proposal_reject(proposal, reason) # ← call 2

# skg/training/corpus.py:87-134: appends one shard per call, no deduplication
```

Every proposal accept/reject writes two training examples instead of one. Over time the corpus has 2x the training data but half the signal-to-noise. The model being trained on this will have degraded learning.

### MED-12: `skg engage build` silently drops all transition history (FIXED)

This was a bug where `delta_dir` defaulted to `SKG_STATE_DIR` instead of `SKG_STATE_DIR/delta`. **This is fixed in the current tree** (line 475 of `engagement_dataset.py` now defaults to `DELTA_DIR`). Leaving this note as the fix is recent and the issue explains many "empty engagement reports" from past sessions.

### MED-16: "Zero folds" from daemon triggers stale disk fallback

```python
# skg/cli/utils.py:407-413:
def _choose_fold_summary(online):
    if online.get("summary", {}).get("total", 0) > 0:
        return online["summary"]
    return _offline_fold_summary()   # ← fallback when total == 0

# This means: if the daemon says "no folds right now", the CLI shows
# the STALE DISK FOLDS from the last time folds existed
# Operator thinks there are outstanding folds when the field is clean
```

### MED-19: MSF adapter workload_id inconsistency

```python
# skg-host-toolchain/adapters/msf_session/parse.py:302:
# defaults to workload_id = "msf_workspace"

# parse.py:184-189 emits HO-17 with raw IP: "10.0.0.7"
# parse.py:202-204 emits HO-10 with same raw IP: "10.0.0.7"

# But proposals.py:323-326 rewrites session-opened events to: "host::10.0.0.7"

# Three different identity strings for the same target:
# msf_workspace, 10.0.0.7, host::10.0.0.7
```

---

## 8. Bootstrap and Install Are Broken

### MED-01: install_layer4.sh smoke-tests non-existent classes

```python
# install_layer4.sh:145-177 (the fresh-install validation):
from skg.forge.proposals import Ingester           # ← ImportError, class doesn't exist
from skg.forge.proposals import SurfaceBuilder     # ← ImportError
from skg.forge.compiler import CatalogCompiler     # ← ImportError, module doesn't exist
from skg.intel.gap_detector import GapDetector     # ← ImportError, class doesn't exist
```

A fresh install smoke test will fail immediately. Any CI that runs `install_layer4.sh` will get false failures that make the codebase look broken even when it isn't.

```python
# install.sh:89-91 and setup_arch.sh:207-209:
assert BondState.from_type(..., "docker_host").prior_influence == 0.45
# But skg/substrate/bond.py now returns 0.9 for docker_host
# → AssertionError on fresh install
```

### pyproject.toml vs requirements.txt conflict

```
# pyproject.toml treats these as OPTIONAL extras:
faiss-cpu, sentence-transformers, pywinrm, pymetasploit3

# requirements.txt installs them as BASELINE requirements

# Result: pip install -e . gives you a partial install
#         pip install -r requirements.txt gives you the full install
# If you follow pyproject.toml packaging conventions you're missing key deps
```

---

## 9. Dark Hypothesis Engine Doesn't See Its Own Toolchains (MED-21)

```python
# skg/sensors/dark_hypothesis_sensor.py:108-129:
def _available_instruments():
    # Only scans:
    return glob(SKG_STATE_DIR / "toolchains" / "*/forge_meta.json")
    # ← NEVER looks at SKG_HOME, domain_registry, or the checked-in skg-*-toolchain/ trees
```

When the dark hypothesis sensor identifies a "dark" attack surface region (a service with no toolchain), it checks whether any instrument can cover it. But it only looks in the runtime-installed toolchains directory. **All the checked-in toolchains in the repo are invisible to this planner.**

This means: the system reports "no instrument available for nginx" even though `skg-nginx-toolchain/` is sitting right there. Dark hypotheses are systematically over-reported because the planner can't see what's already built.

---

## 10. Catalog Compiler Filename Mismatch (MED-32)

Any catalog authored through `skg catalog` is unloadable by the runtime toolchain discovery:

```python
# skg/catalog/compiler.py:220-231 — writes:
"attack_preconditions_catalog.v1.{domain}.json"   # e.g. attack_preconditions_catalog.v1.web.json

# skg/forge/generator.py:642 — writes:
"attack_preconditions_catalog.{domain}.v1.json"   # e.g. attack_preconditions_catalog.web.v1.json

# All checked-in toolchains use the second format.
# The domain registry discovery code expects the second format.
# Catalogs from the compiler are silently ignored at runtime.
```

---

## Summary Table: Severity vs Fix Effort

| Issue | Severity | Fix Effort | Impact |
|-------|----------|------------|--------|
| Web wicket semantic collision (HIGH-03) | BLOCKING | Medium | Web engagements produce false data |
| Identity fragmentation (HIGH-02, MED-13, MED-19) | BLOCKING | Medium | Engagement DB corrupted, projections deleted |
| Resonance draft-prompt CLI missing (MED-24) | BLOCKING | Low | No-API-key drafting workflow broken |
| Resonance list_drafts AttributeError (MED-27) | HIGH | Low | `skg resonance drafts` crashes |
| MED-09: duplicate corpus writes | HIGH | Low | Training data poisoned |
| MED-21: dark hypothesis misses toolchains | HIGH | Low | All dark folds overreported |
| MED-31: calibration always returns defaults | HIGH | Low | `skg calibrate` is a no-op |
| MED-46: post-exploit crash on Windows | HIGH | Low | Windows engagements always crash |
| MED-51: SSH sensor double-events | HIGH | Low | Confidence values inflated 2x |
| MED-52: sysaudit never projected | HIGH | Low | FI/PI/LI evidence lost entirely |
| MED-10: `skg train run` doesn't exist | MED | Low | Training workflow undiscoverable |
| MED-11: `skg data redteam` doesn't exist | MED | Low | Cross-domain analysis unavailable |
| MED-23: `skg field binary` rejected | MED | Trivial | Can't query binary domain state |
| MED-30: TF-IDF moving basis | MED | Medium | Resonance search degrades over time |
| MED-32: catalog filename mismatch | MED | Trivial | `skg catalog` output silently ignored |
| MED-53: targets.yaml format crash | MED | Trivial | List-format YAML crashes gravity |
| Domain packs unwired | STRUCTURAL | Large | All packages/skg-domains investment dead |
| install_layer4.sh broken | STRUCTURAL | Low | Fresh install validation fails |

---

## Recommended Fix Order

### Immediate (breaks real work today)

1. **Fix web wicket semantics in `auth_scanner.py`** — remap WB-08/09/11/14 to match the catalog. This is the most impactful single fix for pentest engagements.
2. **Fix identity normalization** — enforce `web::` prefix in CLI web observe; use normalized keys in DP-05 joins.
3. **Fix MED-09 duplicate corpus** — remove the second `on_proposal_accept` / `on_proposal_reject` call in `proposals.py`.
4. **Fix MED-51 SSH double-events** — add a dedup guard in `_exec_ssh_sensor()`.
5. **Fix MED-52 sysaudit projection** — wire sysaudit domain through the gravity projection dispatch.
6. **Fix MED-31 calibration** — pass `evidence_rank` when constructing `WicketTransition` in the delta store.
7. **Fix MED-21 dark hypothesis** — add toolchain discovery from `SKG_HOME` and `domain_registry`.

### Short-term (blocks research workflows)

8. **Add `skg resonance draft-prompt` and `draft-accept` CLI subcommands** (MED-24).
9. **Add `list_drafts()` to `ResonanceEngine`** or fix the standalone resonance CLI (MED-27).
10. **Fix TF-IDF basis stability** — freeze/refit-on-change instead of append-only (MED-30).
11. **Add `skg train run` CLI** or remove the advertised manual invocation text (MED-10).
12. **Add `skg data redteam` CLI subcommand** (MED-11).
13. **Fix `skg field` domain choices** — derive from registry, not hardcoded list (MED-23).
14. **Fix catalog compiler filename** — use `{domain}.v1` not `v1.{domain}` (MED-32).

### Architecture

15. **Decide on domain packs** — either wire `packages/skg-domains/` into the daemon registry or mark it pre-production. Right now it's neither wired nor documented as not-wired.
16. **Clean up `skg_deploy/`** — it's a stale diverged copy causing confusion. Either delete it or make it canonical.
17. **Fix install scripts** — update smoke-test imports to reflect current class names.

---

## Appendix: Files With the Most Issues

| File | Issues |
|------|--------|
| `skg-gravity/gravity_field.py` (8056 lines) | MED-46, 49, 51, 52, 53, 84, 45 |
| `skg/cli/app.py` | MED-10, 11, 23, 24 |
| `skg/resonance/drafter.py` | MED-24, 26 |
| `skg/resonance/ingester.py` | MED-28 |
| `skg/resonance/embedder.py` | MED-30 |
| `skg/temporal/__init__.py` | MED-31 |
| `skg/forge/proposals.py` | MED-09, 22 |
| `skg-web-toolchain/adapters/web_active/auth_scanner.py` | HIGH-03 |
| `skg/intel/engagement_dataset.py` | MED-13 |
| `skg/sensors/dark_hypothesis_sensor.py` | MED-21, 22 |
| `skg/catalog/compiler.py` | MED-32 |
| `install_layer4.sh`, `install.sh`, `setup_arch.sh` | MED-01 |

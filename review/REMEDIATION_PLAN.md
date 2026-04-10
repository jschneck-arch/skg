# SKG Remediation Plan of Action

Generated: 2026-03-30

## Priority Ordering Summary

| Priority | Group | Rationale |
|---|---|---|
| **P0** | Group 1 (Web Unification) | Renders entire web domain non-functional; semantic collisions cause silent false positives |
| **P0** | Group 2 (Collection/Identity) | `/collect` silently succeeds with zero events; identity fragmentation breaks projection joins |
| **P1** | Group 3 (Authority Boundary) | Stale discovery state can override measured state in operator views |
| **P1** | Group 6 (Proposal/Training) | Duplicate corpus writes corrupt learning dataset; cognitive_action proposals untriggerable |
| **P1** | Group 7 (Engagement Integrity) | Default delta ingest silently ingests zero transitions; engage clean deletes valid projections |
| **P2** | Group 4 (CLI Gaps) | Operator-visible hard failures and misleading help text |
| **P2** | Group 5 (Resonance Correctness) | Drafting fails at runtime with TypeError; TF-IDF index drift accumulates silently |
| **P2** | Group 9 (Toolchain Specifics) | Domain-scoped; some affect projection correctness (supply chain, metacognition) |
| **P3** | Group 8 (Temporal Calibration) | Calibration silently falls back to defaults; doesn't affect correctness, only optimality |
| **P3** | Group 10 (Sidecar Cleanup) | Orphaned code not actively harmful but creates state fragmentation risk if reactivated |
| **P3** | Group 11 (Bootstrap) | Install scripts fail but runtime already installed; risk on fresh deploys |
| **P3** | Group 12 (Test Coverage) | Build alongside each group fix |

---

## Group 1: Web Domain Unification (HIGH-03) — P0

**Issues:** HIGH-03

1. Adopt `WB-*` as canonical namespace; retire `WEB-*` emissions from `skg/sensors/web_sensor.py`.
2. Rewrite `web_sensor.py` wicket assignments to match checked-in catalog semantics (`WB-05=admin_interface_exposed`, etc.).
3. Reconcile helper adapters (`auth_scanner`, `gobuster_adapter`, `nikto_adapter`, `sqlmap_adapter`) so emitted wicket IDs match catalog definitions.
4. Extend checked-in web catalog to formally define `WB-21..WB-24` (collector) and `WB-30..WB-40` (struct-fetch), or prune those gravity references.
5. Unify attack-path IDs: add `web_sqli_to_shell_v1`, `web_cmdi_to_shell_v1` etc. to the catalog, or fix callers to use defined paths.
6. Normalize web workload-id shape: fix `skg/cli/commands/target.py` to pass `--workload-id web::{identity}` to the active collector.
7. Delete stale root `skg-web-toolchain/projections/run.py` (references non-existent catalog, ignores workload_id).
8. Move direct CLI web observe output from `DISCOVERY_DIR` to `EVENTS_DIR`.
9. Add end-to-end web sensor → projector regression test.

---

## Group 2: Collection and Workload Identity Normalization (HIGH-01, MED-19) — P0

**Issues:** HIGH-01, MED-19

1. Fix `collect_host()` (`skg/sensors/__init__.py`): pass supplied target list to `SshSensor` directly; return `False` when zero events are emitted.
2. Remove `_force_collect` — set but never read; wire it or delete it.
3. Fix interval gating: explicit single-target collection must bypass `_should_collect()`.
4. Fix event filename scheme so `project_events_dir(..., since_run_id=...)` matches what sensors emit.
5. Normalize `/collect` daemon workload_id to `ssh::{ip}` (`skg/core/daemon.py:1387-1395`).
6. Normalize MSF adapter workload ids (`skg-host-toolchain/adapters/msf_session/parse.py`): emit `host::{ip}` not raw IP or `msf_workspace`.
7. Add regressions: zero-event collect, since_run_id filtering, daemon-online vs offline workload-id shape, MSF adapter subject identity.

---

## Group 3: Measured-State Authority Boundary (HIGH-02, MED-16, MED-17, MED-20) — P1

**Issues:** HIGH-02, MED-16, MED-17, MED-20

1. Define authority boundary explicitly in code: measured events/projections take precedence; discovery surfaces are labeled secondary.
2. Fix `_choose_fold_summary()` / `_choose_fold_rows()` (`skg/cli/utils.py`): select by freshness/timestamp, not by `len()` or total count.
3. Fix `cmd_surface` (`skg/cli/commands/surface.py`): key summaries by `(subject, attack_path_id)`; stop scanning `DISCOVERY_DIR` and `/tmp`.
4. Fix `derived rebuild` (`skg/cli/commands/derived.py`): make substrate-only (remove `DISCOVERY_DIR` projection and surface-IP fold matching), or relabel as hybrid and document.
5. Fix topology `energy.py` and daemon startup: gravity loop must not gate on raw discovery surface availability when measured state exists.
6. Add regressions: fold-source precedence, surface projection per-target.

---

## Group 4: CLI Surface / Contract Gaps — P2

**Issues:** MED-10, MED-11, MED-15, MED-23, MED-24, MED-27

1. **`field` domain enum** (`skg/cli/app.py:377-384`): derive choices from runtime registry or add `binary`, `data_pipeline`.
2. **`skg train`**: add CLI command calling `scheduler.run()`, or remove advertised entrypoint from `skg/training/scheduler.py`.
3. **`skg data redteam`**: expose `redteam_to_data` as subcommand, or strip advertised CLI usage from `skg/intel/redteam_to_data.py`.
4. **`skg resonance draft-prompt` / `draft-accept`**: add to CLI, or update `drafter.py:428-433` to not advertise non-existent commands on fallback.
5. **`resonance.cli.list_drafts()`** (`skg/resonance/cli.py:106-120`): add `list_drafts()` to `ResonanceEngine`, or scan drafts dir directly (as main CLI does).
6. **`skg report` daemon-offline**: detect daemon absence; print explicit warning when folds/self-audit are empty due to unavailability, not data absence.
7. **`cmd_check` WinRM import**: fix `pywinrm` → `winrm`.

---

## Group 5: Resonance / Drafting Internal Correctness — P2

**Issues:** MED-26, MED-27, MED-28, MED-29, MED-30

1. Fix `_build_user_prompt()` (`skg/resonance/drafter.py:48-68`): align with `{"record": ..., "score": ...}` dict shape from `ResonanceEngine.surface()`.
2. Fix `draft_catalog()` no-backend path: either write prompt artifacts usably or fail cleanly without advertising non-existent subcommands.
3. Fix `DomainMemory.adapters`: populate from adapter discovery or remove from the memory model.
4. Fix ingester domain counters: distinguish "processed" from "newly added" in `ingest_all()` summary.
5. Fix `historical_confirmation_rate()` identity scoping (`skg/resonance/observation_memory.py:255-275`): apply workload filter before wicket-id match, not after.
6. Fix TF-IDF fallback (`skg/resonance/embedder.py`): freeze IDF basis at first fit; add rebuild trigger on corpus change. Or document as rebuild-on-change only.

---

## Group 6: Proposal and Training Lifecycle Correctness — P1

**Issues:** MED-09, MED-14, MED-22

1. Fix duplicate corpus hook calls (`skg/forge/proposals.py`): one `on_proposal_accept()` / `on_proposal_reject()` call per operator decision.
2. Lifecycle-integrate `cognitive_action` proposals: normalize to `field_action` kind, or add explicit dispatch support in `proposals.py` and `proposals trigger`.
3. Fix `proposals trigger` post-session projection: derive host projection path from proposal/module/session semantics, not hardcoded `host_linux_privesc_sudo_v1`.
4. Add regressions: corpus hook call counts, cognitive_action trigger path, post-session projection path selection.

---

## Group 7: Engagement / Delta Data Integrity — P1

**Issues:** MED-12, MED-13

1. Fix `build_engagement_db()` default `delta_dir` (`skg/intel/engagement_dataset.py:452`): change to `DELTA_DIR`.
2. Carry normalized `node_key` into projection records; use it for DP-05 / `engage clean` integrity checks instead of exact `workload_id` string equality.
3. Add regressions: default-path delta ingest ingests transitions; `engage clean` does not delete valid projections that differ only in workload-id manifestation prefix.

---

## Group 8: Temporal / Calibration Correctness — P3

**Issues:** MED-31

1. Add `evidence_rank` (and optionally `metadata`) to `WicketTransition` (`skg/temporal/__init__.py:53-92`), or remove that field from `calibrate_confidence_weights()` logic and use a different signal.
2. Add regression: calibration weights differ from defaults after ingesting real transitions.

---

## Group 9: Toolchain-Specific Fixes — P2

| Toolchain | Action |
|---|---|
| **Web** | Covered under Group 1; delete stale root `projections/run.py`. |
| **Host** | Remove dead code after `return 0` in `adapters/ssh_collect/parse.py`. Update `evidence_hint` minima for HO-01/HO-02/HO-04 to match SSH/WinRM rank-1 output. |
| **Supply chain** | Align `sbom_check` adapter SC-10 semantics with catalog, or update catalog. Prune SC-11/SC-12 if no adapter or attack path requires them. |
| **Metacognition** | Fix adapter envelope: top-level `id`, flat `source_id`, flat `evidence_rank`. Fix projector to use recency-based resolution, not fixed `blocked > realized > unknown`. |
| **IoT firmware** | Wire `probe_network_only()` fallback into `probe_device()` for HTTP-only devices. Reconcile dual adapter implementations (`__init__.py` vs `probe.py`). |
| **APRS** | Update root CLI and projector default catalog path to `attack_preconditions_catalog.aprs.v1.json`. |
| **All nested projectors** | Fix `Path(__file__).resolve().parents[4]` sheaf shim: should be `parents[3]` to resolve `/opt/skg`, not `/opt`. |

---

## Group 10: Sidecar / Orphaned Code Cleanup — P3

**Issues:** MED-33

1. `skg-gravity/gravity_web.py` and `exploit_proposals.py`: wire to canonical proposal queue or delete. Do not leave writing to a separate `state/exploit_proposals` queue.
2. `skg/catalog/compiler.py`: align output filename to `attack_preconditions_catalog.{domain}.v1.json`, or mark explicitly as legacy/dev-only.
3. `skg/core/state_db.py`: no live callsites — wire into daemon/runtime or delete.
4. `skg-web-toolchain/projections/run.py` (stale root): delete after Group 1 reference cleanup.

---

## Group 11: Bootstrap / Install — P3

**Issues:** MED-01

1. `install_layer4.sh`: remove smoke imports for `Ingester`, `SurfaceBuilder`, `ForgeCompiler`, `GapDetector`, `CatalogCompiler`; replace with current module paths.
2. `install.sh` / `setup_arch.sh`: fix `BondState` `prior_influence` assertion `0.45` → `0.9`.
3. Align bootstrapped toolchain coverage to the 12 registered runtime domains, or document a reduced supported set.
4. Fix systemd training timer: target instantiated `skg-train.service@<user>` or remove `%i` template variable.
5. Confirm or remove `docs/package.json`.

---

## Group 12: Test Coverage Gaps — P3 (build alongside each group)

| Area | Needed tests |
|---|---|
| `/collect` end-to-end | Zero-event success semantics, interval gating bypass, filename matching, daemon workload-id shape |
| Web sensor → projector | `WEB-*` vs `WB-*` namespace, workload-id shape, struct-fetch path-id resolution |
| `skg.training.*` | Corpus hook call counts, scheduler invocation, trainer flow |
| Resonance CLI | `resonance draft`, `resonance drafts`, no-backend fallback, `list_drafts()` |
| Ollama backend | `available()`, `list_models()`, `generate()`, `status()` |
| Engagement dataset | Default-path delta ingest, workload-id drift in integrity checks |
| `cmd_replay` semantics | Pin whether it uses real support/state engines or local majority vote |
| Dark hypothesis toolchain discovery | Built-in vs state-installed toolchain coverage |
| Calibration | Transition ingestion → non-default calibration weights |
| Metacognition toolchain | Adapter envelope shape, projector recency semantics |

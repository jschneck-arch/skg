# SKG Open Issues

Last updated: 2026-03-31 full remaining-file audit pass.

## High-Risk Open Issues

### HIGH-01 (Downgraded): Earlier `/collect` single-target defects are largely fixed in the current tree

Evidence:

- `skg/sensors/__init__.py:307-314` now returns `bool(ids)` from `collect_host(...)`, so zero-event runs propagate as `False`
- `skg/sensors/ssh_sensor.py:81-95` uses injected targets when provided and bypasses interval gating for that injected single-target path
- `skg/core/daemon.py:1394` now defaults daemon-backed single-target `workload_id` to `f"ssh::{req.target}"`
- `skg/core/daemon.py:1403` now locates artifacts via `*_{run_id}.ndjson`, matching current emitter naming
- direct regressions now exist in `tests/test_runtime_regressions.py:928-1037` and `1109-1123` for zero-event semantics, injected-target behavior, interval bypass, and `ssh::` workload-id default

Impact:

- the earlier high-risk `/collect` mismatches (false success on zero events, injected-target bypass failure, raw-vs-prefixed host workload-id drift) are not reproduced in the current code path
- remaining sweep run-scoping drift is still active, but it is tracked separately as `MED-07`

Needed follow-up:

- keep direct daemon `/collect` endpoint integration coverage (beyond source-string assertions) to prevent regressions

### HIGH-02: Measured-state authority is still mixed with discovery/config state

Evidence:

- `skg/core/daemon.py:66-75` and `skg/topology/energy.py:105-120` select the "best" discovery surface by richness
- `skg/core/daemon.py:1873-1916` merges config targets, discovery surfaces, and local injected targets into one target index
- `skg/core/daemon.py:640-667` still drives gravity loop startup from selected surface availability
- `skg/cli/commands/system.py:68-86` builds status views from raw latest-surface data and `_print_what_matters_now(...)`
- `skg/cli/utils.py:753-809` ranks those targets via `_surface_subject_rows(measured_surface=surface, target_surface=surface)`, so raw discovery surface inputs stay raw rather than being replaced by measured workloads
- `skg/cli/commands/surface.py:174-178` builds the gravity-web view from raw discovery targets plus folds, without a measured-surface merge
- `docs/SKG_ARCHITECTURE_SYNTHESIS_20260328.md` explicitly calls out this same structural dissonance

Impact:

- convenience/bootstrap state can still influence operator views and field computations after measured state exists
- architecture remains partially Work-3 target/surface-centric despite Work-4 field-local claims
- operator shell views do not share one authority boundary: some commands are partially measured-view aware while others remain discovery-centric

Needed follow-up:

- trace each daemon and topology endpoint for whether it should consume measured state, discovery state, or both
- define and enforce an explicit authority boundary

### HIGH-03: Live web collection and projection are mutually incompatible

Evidence:

- `skg/sensors/web_sensor.py:851` defaults the live web sensor to `attack_path_id="web_surface_v1"`
- `skg/cli/commands/target.py:288-295` drives web observation with `web_surface_v1` or `web_sqli_to_shell_v1`
- `skg/cli/commands/target.py:271-296` writes direct web observe output to `DISCOVERY_DIR/observe_web_*.ndjson`, not `EVENTS_DIR`
- `skg/cli/commands/target.py:294-296` does not pass `--workload-id` to the active collector
- `skg-web-toolchain/adapters/web_active/collector.py:1227-1228` therefore defaults direct CLI web observe output to the bare parsed hostname/IP, not `web::{identity}`
- `skg-web-toolchain/contracts/catalogs/attack_preconditions_catalog.web.v1.json:148-183` only defines `web_initial_access_v1`, `web_credential_exposure_v1`, `web_info_disclosure_v1`, and `web_cve_exploitation_v1`
- `skg-web-toolchain/projections/web/run.py:19-22` aliases `web_sqli_to_shell_v1` to `web_full_chain_v1`, but the checked-in catalog does not define `web_full_chain_v1`
- `skg/sensors/web_sensor.py:626-759` emits `WEB-*` wickets, while the checked-in web catalog, projector, tests, and most runtime code use `WB-*`
- targeted runtime validation in this pass confirmed `WEB-01`/`WEB-05` events remain `indeterminate` while equivalent `WB-01`/`WB-05` events realize `web_initial_access_v1`
- `skg-web-toolchain/adapters/web_active/collector.py` emits `WB-21`, `WB-22`, `WB-23`, and `WB-24`, which are absent from the checked-in web catalog
- `skg/sensors/struct_fetch.py` emits `WB-30..WB-40` and defaults to `attack_path_id="web_sqli_to_shell_v1"`, which is absent from the checked-in catalog
- `skg-gravity/gravity_field.py:1801-1817` treats `web_struct_fetch` and its `WB-30..WB-40` wavelength as a first-class runtime instrument
- `skg-gravity/gravity_field.py:2917-2927` generates web exploit follow-on proposals for `web_cmdi_to_shell_v1` and `web_sqli_to_shell_v1`
- `skg-gravity/exploit_dispatch.py:65-136` defines active exploit maps for `web_sqli_to_shell_v1`, `web_cmdi_to_shell_v1`, `web_ssti_to_rce_v1`, and `web_default_creds_to_admin_v1`, none of which are present in the checked-in web catalog
- targeted validation in this pass showed `skg-gravity/gravity_field.py` references `34` distinct `WB-*` wickets while the checked-in web catalog defines only `20`; missing checked-in catalog wickets include `WB-21`, `WB-22`, `WB-24`, and `WB-30..WB-40`
- `skg-web-toolchain/projections/run.py:21` references a non-existent `web_attack_preconditions_catalog.v1.json`, indicating an additional stale projector artifact
- `skg/core/domain_registry.py:179-186` prefers nested `projections/*/run.py` over root `projections/run.py`, so the registry-selected web projector is the nested `projections/web/run.py`; the stale root projector is likely dormant but still misleading
- `tests/test_runtime_regressions.py:424-451` only verifies the `struct_fetch._event()` subject contract; it does not prove the default `struct_fetch` path ID resolves against the checked-in projector/catalog
- `skg/sensors/web_sensor.py:666-752` assigns meanings like `WEB-05=default_credentials`, `WEB-08=cors_wildcard`, and `WEB-09=missing_security_headers`
- `skg-web-toolchain/adapters/web_active/collector.py:474-490`, `1105-1195`, and `245-260` assign meanings like `WB-05=sensitive_paths`, `WB-08=default_credentials`, and `WB-19=missing_security_headers`
- `skg-web-toolchain/contracts/catalogs/attack_preconditions_catalog.web.v1.json:34-39`, `55-60`, and `132-144` define `WB-05=admin_interface_exposed`, `WB-08=git_exposure`, `WB-19=elasticsearch_unauth`, and `WB-20=jenkins_script_console`
- targeted synthetic projection validation in this pass confirmed that a collector-style `WB-05` event with detail `Sensitive paths accessible` still realizes the checked-in `web_initial_access_v1` path, because the projector keys only on wicket ids
- `skg-web-toolchain/adapters/web_active/auth_scanner.py:396-420`, `476-503`, `532-535`, and `603-620` emit `WB-09` for SQLi, `WB-14` for command injection, `WB-11` for XSS, and `WB-08` for accepted credentials, while the checked-in catalog defines `WB-09=env_file_exposed`, `WB-14=auth_surface_present`, `WB-11=tls_weak_or_missing`, and `WB-08=git_exposure`
- `skg-web-toolchain/adapters/web_active/gobuster_adapter.py:29-35` maps `WB-03` to admin/login paths, `WB-04` to backup files, `WB-15` to traversal indicators, `WB-17` to debug/status endpoints, and `WB-20` to webshell paths, while the checked-in catalog defines `WB-03=stack_leaked`, `WB-04=security_headers_absent`, `WB-15=cms_detected`, `WB-17=sensitive_path_exposed`, and `WB-20=jenkins_script_console`
- `skg-web-toolchain/adapters/web_active/nikto_adapter.py:17-31` maps `WB-05` to SQL injection, `WB-08` to XSS, `WB-07` to command execution, `WB-09` to default password, and `WB-10` to authentication bypass, which conflicts with the checked-in catalog labels for those same ids
- targeted identity parsing validation in this pass confirmed raw host workload ids and `web::...` workload ids produce different manifestation keys, and current web flows use both shapes

Impact:

- the live web sensor path is unlikely to project into the checked-in web toolchain correctly
- current web defaults in sensor and CLI do not align with the registry-inferred default path (`web_initial_access_v1`)
- web observation is split across incompatible discovery/sensor/toolchain/gravity vocabularies, so different execution paths produce materially different semantics
- the split is active in current runtime code, not just legacy artifacts
- at least part of the split causes direct false positives because identical `WB-*` ids map to different meanings across collector and checked-in catalog
- workload identity for the same web target can fragment across raw and `web::...` manifestation keys depending on which operator path emitted the event

Needed follow-up:

- unify live web wicket namespace and attack-path IDs against the checked-in catalog
- reconcile web wicket semantics, not just prefixes and aliases
- decide whether CLI web observe is a discovery path or a measured event path, then make that boundary explicit
- normalize web workload-id shape across CLI, gravity, struct-fetch, and sensor flows
- quarantine or delete stale web projection artifacts only after reference cleanup
- add an end-to-end web sensor -> projector regression test

## Medium-Risk Open Issues

### MED-01: Install/bootstrap scripts are partially stale and lag the runtime inventory

Evidence:

- `install_layer4.sh:145-177` smoke-imports `Ingester`, `SurfaceBuilder`, and `ForgeCompiler`, which do not exist at those current module paths/classes
- `install_layer4.sh:145-177` also smoke-imports `GapDetector` and `CatalogCompiler`, which do not exist at those current module paths/classes
- `install_layer4.sh:64-80` copies only 8 toolchains and bootstraps only 6, despite the current runtime inventory containing 12 registered domains
- `setup_arch.sh:133-143` bootstraps more toolchains than `install_layer4.sh`, but still omits `nginx` and `metacognition`
- `install.sh:89-91` asserts `BondState.from_type(..., "docker_host").prior_influence == 0.45`, but the live implementation in `skg/substrate/bond.py` returns `0.9`
- `setup_arch.sh:207-209` repeats the same obsolete `prior_influence == 0.45` assertion
- `pyproject.toml` treats `faiss-cpu`, `sentence-transformers`, `pywinrm`, and `pymetasploit3` as optional extras, while `requirements.txt` still installs them as baseline requirements
- `docs/package.json:1-5` contains only a `nuclei` dependency and does not align with current Python packaging/runtime structure
- `scripts/skg-train.service:8-15` is templated with `User=%i`, but `scripts/skg-train.timer:3-9` targets plain `skg-train.service` rather than an instantiated `skg-train.service@<user>`
- `skg-host-toolchain/bootstrap.sh:1-11` creates the venv and installs requirements, but unlike the APRS, AD lateral, and container-escape bootstraps it does not run its own golden test

Impact:

- install/bootstrap documents and scripts are not trustworthy as operational validation
- fresh-host bootstrap may fail or give false confidence
- the packaged daily training path is unlikely to activate correctly without extra systemd wiring
- toolchain bootstrap confidence is inconsistent even among the smaller checked-in toolchains

Needed follow-up:

- align bootstrap coverage with the actual domain registry or explicitly document a reduced supported set
- execute script smoke checks in isolation or convert them into maintained tests
- decide whether `docs/package.json` is still intentional

### MED-09: Proposal accept/reject paths duplicate training examples

Evidence:

- `skg/forge/proposals.py:592-596` calls `skg.training.corpus.on_proposal_accept(...)`
- `skg/forge/proposals.py:620-629` calls `skg.training.corpus.on_proposal_accept(...)` again in the same accept flow
- `skg/forge/proposals.py:676-679` calls `skg.training.corpus.on_proposal_reject(...)`
- `skg/forge/proposals.py:689-692` calls `skg.training.corpus.on_proposal_reject(...)` again in the same reject flow
- `skg/training/corpus.py:87-134` appends one new shard per call and increments counters with no dedupe layer
- repo-wide search in this pass found no focused tests around proposal corpus hook invocation counts

Impact:

- accepted and rejected proposal examples are likely written twice into the learning corpus
- corpus counters, holdout splits, and scheduler readiness thresholds can drift from actual operator decisions

Needed follow-up:

- collapse accept/reject corpus hook invocation to one call per operator decision
- add direct tests for corpus side effects on proposal accept/reject flows

### MED-10: Training subsystem advertises a CLI entrypoint that does not exist

Evidence:

- `skg/training/scheduler.py:15` says the scheduler is "Also callable manually: skg train run"
- `skg/training/scheduler.py:181` repeats that `run()` is called by systemd timer or `skg train run`
- `skg/cli/app.py:63-420` defines no `train` parser or training subcommands
- repo-wide search in this pass found no `cmd_train` implementation under `skg/cli/commands/`

Impact:

- operator-facing training docs/docstrings overstate available CLI behavior
- the live training path is effectively systemd-only unless the module is invoked directly

Needed follow-up:

- either add an explicit `skg train` CLI surface or remove the claimed manual CLI entrypoint from docs/docstrings
- add at least one direct test around the supported training invocation path

### MED-11: `redteam_to_data` advertises a CLI path that the CLI does not expose

Evidence:

- `skg/intel/redteam_to_data.py:34-35` says the feature is available via `skg data redteam --out-dir ...`
- `skg/cli/app.py:155-183` defines only `profile`, `project`, `paths`, `catalog`, and `discover` subcommands under `data`
- `skg/cli/commands/data.py:191-192` prints usage limited to `profile|project|paths|catalog|discover`

Impact:

- a real cross-domain analysis module is effectively CLI-orphaned
- docs and module-level usage text overstate the supported operator surface

Needed follow-up:

- decide whether `redteam_to_data` is intended as a supported CLI workflow or an internal module
- if supported, expose it in `skg.cli.app` and `cmd_data`; otherwise remove the advertised CLI usage text

### MED-12: `engagement_dataset` misses transition history on its default path

Evidence:

- `skg/intel/engagement_dataset.py:452` defaults `delta_dir` to `SKG_STATE_DIR`, not `DELTA_DIR`
- `skg/core/paths.py:42-45` defines the canonical transition location under `DELTA_DIR = SKG_STATE_DIR / "delta"`
- `skg/intel/engagement_dataset.py:381-392` only checks `delta_dir / "delta_store.ndjson"` and parent fallbacks; when `delta_dir` is `SKG_STATE_DIR`, those checks miss `SKG_STATE_DIR / "delta" / "delta_store.ndjson"`
- targeted isolated runtime validation in this pass confirmed `build_engagement_db(..., delta_dir=None)` ingests `0` transitions while the same temp data with `delta_dir=DELTA_DIR` ingests `1`

Impact:

- `skg engage build` can silently omit delta transition history under default runtime layout
- engagement dataset summaries and downstream integrity/reporting lose temporal evidence by default

Needed follow-up:

- default `build_engagement_db()` to `DELTA_DIR`
- add a direct regression proving default transition ingest works under canonical runtime paths

### MED-13: Engagement integrity joins are fragile against already-confirmed workload-id drift

Evidence:

- `skg/intel/engagement_dataset.py:51-68` stores both `workload_id` and stable `node_key` on observations
- `skg/intel/engagement_dataset.py:71-85` stores only `workload_id` on projections, not a normalized node identity
- `skg/intel/engagement_dataset.py:678-684` implements DP-05 by exact `workload_id` string membership
- `skg/cli/commands/report.py:612-617` deletes "orphaned" projections using the same exact `workload_id` string join during `skg engage clean`
- earlier audit passes already confirmed equivalent targets can appear as raw host strings and prefixed forms like `ssh::...` or `web::...`, which share identity but differ in manifestation/workload strings

Impact:

- DP-05 can report false orphaned projections when observations and projections use different manifestation strings for the same identity
- `skg engage clean` can delete valid projections if workload-id drift exists in the dataset

Needed follow-up:

- carry a normalized identity key into projections and use that for referential integrity checks
- add a regression covering raw-vs-prefixed workload-id cases in engagement analysis and cleanup

### MED-14: `proposals trigger` hardcodes one host attack path for all post-session projection

Evidence:

- `skg/cli/commands/proposals.py:14-30` defines `_run_post_projection(...)`
- `skg/cli/commands/proposals.py:23-28` always invokes the host projector with `--attack-path-id host_linux_privesc_sudo_v1`
- `skg/cli/commands/proposals.py:338-340` calls that helper whenever a Metasploit session was opened
- `skg-host-toolchain/projections/host/run.py:188` defaults the host projector itself to `host_ssh_initial_access_v1`
- `skg-host-toolchain/contracts/catalogs/attack_preconditions_catalog.host.v1.json:183-305` defines multiple distinct host paths, including `host_ssh_initial_access_v1`, `host_winrm_initial_access_v1`, `host_linux_privesc_sudo_v1`, `host_linux_privesc_suid_v1`, `host_linux_privesc_kernel_v1`, `host_msf_post_exploitation_v1`, and `host_network_exploit_v1`

Impact:

- all session-backed proposal execution collapses host interpretation through one Linux sudo-privesc path regardless of module, platform, or observed evidence
- Windows sessions and non-sudo Linux sessions can produce misleading host interpretations

Needed follow-up:

- derive the host projection path from proposal/module/session semantics or project multiple host paths explicitly
- add a direct regression for post-session projection path selection

### MED-15 (Downgraded): `report` now warns on daemon-offline fold/self-audit degradation

Evidence:

- `skg/cli/utils.py:15-29` makes `_api(...)` return `None` on daemon `URLError`
- `skg/cli/commands/report.py:60-63` now emits an explicit offline warning when `/folds` is unavailable
- `skg/cli/utils.py:1229-1252` still builds substrate self-audit from daemon endpoints for resonance, feedback, graph, folds, and ollama status
- `skg/cli/commands/report.py:153` includes that self-audit in the report

Impact:

- the earlier "silent" failure mode is reduced because report now prints a daemon-offline warning
- report content can still be partial when daemon-backed subsystems are unavailable

Needed follow-up:

- keep explicit daemon-offline signaling in `report`
- decide whether report should prefer strict daemon-required behavior or richer local fallbacks for self-audit surfaces

### MED-16: Fold-source fallback treats daemon-zero as offline and can resurrect stale disk folds

Evidence:

- `skg/cli/utils.py:407-413` makes `_choose_fold_summary(...)` use daemon summary only when `online.total > 0`; `online.total == 0` falls back to offline disk summary
- `skg/cli/utils.py:429-435` makes `_choose_fold_rows(...)` use daemon rows only when `online` is non-empty; empty daemon rows fall back to offline disk rows
- `skg/cli/commands/report.py:60-61`, `skg/cli/commands/system.py:71-86`, and `skg/cli/commands/surface.py:176-178` consume those helpers for operator views
- targeted helper validation in this pass confirmed `_choose_fold_rows({"folds": []})` returns offline rows and `_choose_fold_summary({"summary": {"total": 0}})` returns offline summary

Impact:

- a live daemon response of "zero folds" can be replaced by stale offline fold files in report/status/surface views
- operator views can overstate unresolved structure even when current daemon state is empty/cleared

Needed follow-up:

- choose fold sources by daemon reachability/authority and freshness, not "non-empty vs empty" fallback
- add regressions covering online-vs-offline precedence

### MED-17: `cmd_surface` projection summary conflates targets and stale artifacts

Evidence:

- `skg/cli/commands/surface.py:127-133` loads interpretation artifacts from `SKG_STATE_DIR/interp`, `DISCOVERY_DIR`, and `/tmp`
- `skg/cli/commands/surface.py:137-154` keys the summary map only by `attack_path_id`
- `skg/cli/commands/surface.py:157-163` therefore prints only one "best" row per attack path across all targets
- targeted `cmd_surface` validation in this pass with two targets and two interp files sharing `web_initial_access_v1` produced exactly one displayed projection row

Impact:

- the generic surface view can hide conflicting per-target interpretations
- stale or unrelated interp artifacts from `DISCOVERY_DIR` or `/tmp` can leak into the operator surface summary

Needed follow-up:

- key surface projection summaries by subject plus attack path, not attack path alone
- stop scanning non-canonical loose interp directories or clearly label those artifacts as secondary

### MED-18: `cmd_replay` overstates fidelity to the live substrate

Evidence:

- `skg/cli/commands/replay.py:8-18` says replay is identical to the live gravity cycle because the substrate is event-sourced
- `skg/cli/commands/replay.py:62-68` imports `SupportEngine` and `StateEngine`
- `skg/cli/commands/replay.py:77-98` does not use those engines and instead collapses each wicket with a local positive-vs-negative majority vote
- `skg/cli/commands/replay.py:91` reports only the max observed confidence for display rather than aggregating weighted support like the live substrate

Impact:

- `skg replay` is a convenience inspection tool, not a faithful live-kernel replay
- operators can overtrust replay output as equivalent to real support aggregation and collapse behavior

Needed follow-up:

- either route replay through the actual support/state engines or narrow the command’s claims and output labeling
- add tests that pin the intended replay semantics

### MED-19: MSF-session ingestion emits inconsistent host workload ids

Evidence:

- `skg-host-toolchain/adapters/msf_session/parse.py:184-189` emits session-backed `HO-17` events with raw host workload ids like `10.0.0.7`
- `skg-host-toolchain/adapters/msf_session/parse.py:202-204` emits `HO-10` on the same raw workload id
- `skg-host-toolchain/adapters/msf_session/parse.py:302` defaults `--workload-id` to `msf_workspace`
- targeted offline execution of the adapter in this pass confirmed emitted `workload_id` values `10.0.0.7`
- `skg/cli/commands/proposals.py:323-326` rewrites post-execution Metasploit console output to `host::{identity_key}` when a session is opened
- earlier passes already confirmed raw and prefixed workload ids share identity but fragment manifestation keys

Impact:

- host post-exploitation evidence can fragment across raw host strings, `host::...`, and `msf_workspace`
- engagement, projection, and identity-joined operator views can see the same MSF-derived host evidence as different manifestations

Needed follow-up:

- normalize MSF-derived host workload ids to one canonical subject shape
- add regression coverage for MSF adapter and CLI-triggered host-event subject identity

### MED-20: `derived rebuild` is not currently substrate-only despite claiming append-only reconstruction

Evidence:

- `skg/cli/app.py:205-208` and `skg/cli/commands/derived.py:138-140` describe `skg derived rebuild` as rebuilding derived state from append-only substrate
- `skg/cli/commands/derived.py:74-89` reprojects interpretations from both `SKG_STATE_DIR / "events"` and `DISCOVERY_DIR`
- `skg/cli/commands/derived.py:92-126` rebuilds folds from `FoldDetector().detect_all(events_dir=DISCOVERY_DIR, ...)`
- `skg/cli/commands/derived.py:93-117` also depends on `_latest_surface()` and maps folds to targets by substring/`endswith(...)` matching against current surface IPs
- targeted helper validation in this pass confirmed `_rebuild_interp_from_events()` calls the projector for both the state events directory and the discovery directory

Impact:

- archived and rebuilt derived state can reincorporate discovery artifacts and current target-surface heuristics
- the command is not presently a clean reconstruction from append-only measured substrate

Needed follow-up:

- decide whether `derived rebuild` is supposed to be substrate-only or hybrid
- if substrate-only, stop using `DISCOVERY_DIR` and current-surface matching in rebuild logic
- if hybrid, relabel the command/help text and add regressions pinning the intended input set

### MED-21: Dark-hypothesis instrument discovery ignores checked-in toolchains

Evidence:

- `skg/sensors/dark_hypothesis_sensor.py:108-129` scans only `SKG_STATE_DIR / "toolchains" / */forge_meta.json`
- the helper never consults `SKG_HOME`, `domain_registry`, or the checked-in `skg-*-toolchain/` trees
- targeted helper validation in this pass confirmed `_available_instruments()` returns `[]` when a built-in style toolchain exists outside `SKG_STATE_DIR/toolchains`
- `tests/test_dark_hypothesis_sensor.py:89-93` and `154-158` patch `_available_instruments(...)`, so current tests do not cover real toolchain discovery behavior

Impact:

- dark-hypothesis planning can report that no instrument applies even when the repo/runtime already has suitable checked-in toolchains
- structural "dark" hypotheses can be overstated because the planner sees only one narrow installation location

Needed follow-up:

- source instruments from the canonical runtime domain inventory or explicitly maintain a shared installed-toolchain index
- add direct coverage for built-in and state-installed toolchain discovery

### MED-22: `cognitive_action` proposals are not integrated into the shared proposal lifecycle

Evidence:

- `skg/sensors/dark_hypothesis_sensor.py:24-25` says these proposals are operator-reviewable and potentially auto-dispatchable
- `skg/sensors/dark_hypothesis_sensor.py:247-266` writes `proposal_kind = "cognitive_action"` files directly into `state/proposals`
- `skg/cli/commands/proposals.py:533-535` refuses to `trigger` any proposal whose kind is not `field_action`
- `skg/forge/proposals.py:504-575` only special-cases `catalog_growth`, `field_action`, legacy `action.rc_file`, or staged toolchain proposals; otherwise it requires `staged_path` and raises
- `skg/cli/commands/proposals.py:445-457` and `468-521` still list and show arbitrary proposal kinds, so `cognitive_action` proposals can appear queue-valid to operators
- `tests/test_dark_hypothesis_sensor.py:78-109` only verifies proposal file creation, not acceptance or trigger behavior

Impact:

- `cognitive_action` proposals can accumulate in the queue without a standard shared execution path
- the sensor claims a more complete operator/dispatch lifecycle than the live proposal machinery currently implements

Needed follow-up:

- either normalize dark-hypothesis outputs onto `field_action` or add explicit lifecycle support for `cognitive_action`
- add end-to-end proposal acceptance/trigger coverage for this path

### MED-23: `field` CLI rejects active non-host domain values

Evidence:

- `skg/cli/app.py:377-384` restricts `skg field` domain choices to `host`, `container_escape`, `ad_lateral`, `aprs`, `web`, `supply_chain`, and `data`
- `tests/test_runtime_regressions.py:579-689` confirms active `binary` workload identity, projection, and lookup flows
- targeted parser validation in this pass confirmed `skg field binary::192.168.254.5::ssh-keysign binary` exits with parser error code `2`
- targeted parser validation in this pass also confirmed `skg field data::users data_pipeline` exits with parser error code `2`

Impact:

- operators cannot query per-workload field state for at least some active domains through the CLI
- the parser enum is lagging actual runtime domain inventory and naming

Needed follow-up:

- derive `field` domain choices from the runtime registry or a maintained alias set instead of a stale literal list
- add parser and behavior coverage for active non-host domains

### MED-24: Resonance prompt-mode workflow is documented in code but not exposed by the live CLI

Evidence:

- `skg/resonance/drafter.py:13-14` says prompt mode is the default when no API key is available
- `skg/resonance/drafter.py:275-276` says `draft_catalog()` falls back to prompt mode when no API key is present
- `skg/resonance/drafter.py:428-433` raises instructions telling the operator to run `skg resonance draft-prompt` and `skg resonance draft-accept`
- `skg/cli/app.py:355-372` exposes only `status`, `ingest`, `ollama`, `query`, `draft`, and `drafts` under `resonance`
- `skg/resonance/cli.py:123-152` also exposes only `status`, `ingest`, `query`, `draft`, and `drafts`
- targeted parser validation in this pass confirmed `skg resonance draft-prompt ...` and `skg resonance draft-accept ...` exit with parser error code `2`
- targeted helper validation in this pass confirmed `draft_catalog(..., api_key=None)` with Ollama and pool unavailable raises a `ValueError` and writes no prompt artifacts
- targeted helper validation in this pass also confirmed `draft_prompt()` and `draft_accept()` do work when called directly from Python

Impact:

- the operator-facing resonance drafting fallback advertised by the code is not actually reachable through the live CLI
- no-backend drafting fails hard while telling the operator to use subcommands that do not exist

Needed follow-up:

- either expose `draft-prompt` / `draft-accept` in the CLI or stop advertising them in runtime errors and module text
- decide whether no-backend drafting should really create prompt artifacts automatically or simply fail clearly
- add direct CLI and helper coverage for the intended fallback behavior

### MED-25: Resonance/Ollama coverage is much thinner than the feature surface suggests

Evidence:

- `tests/test_ollama_backend.py:13-34` only verifies config loading from `skg_config.yaml`
- `tests/test_resonance_drafter.py:27-44` only verifies the direct Ollama happy path with `OllamaBackend.available()`, `.model()`, and `.draft_catalog()` patched
- repo-wide search in this pass found no direct tests for `OllamaBackend.available()`, `list_models()`, `model()`, `generate()`, or `status()`
- repo-wide search in this pass found no direct CLI coverage for `resonance draft`, `resonance drafts`, or the missing prompt-mode helper path
- `tests/test_gravity_routing.py:1-14` describes itself as an integration routing test with scheduler coverage, but imports only `EnergyEngine`, `Fold`, and `TriState` at `:20-22`

Impact:

- routing and resonance test names/descriptions overstate the amount of real operator/backend coverage
- important backend-selection, availability, and fallback semantics remain effectively unpinned

Needed follow-up:

- add direct tests for resonance CLI behaviors and no-backend fallback semantics
- add backend-level tests for Ollama availability/model selection/generation/status
- either broaden `test_gravity_routing.py` to actual runtime routing or narrow its description to what it really tests

### MED-26: Resonance drafting expects a different surface context shape than the engine returns

Evidence:

- `skg/resonance/engine.py:252-271` returns surface buckets shaped like `{"record": r.to_dict(), "score": ...}`
- `skg/resonance/drafter.py:48-68` iterates `context["wickets"]`, `context["adapters"]`, and `context["domains"]` as if they were `(record, score)` tuples
- `skg/resonance/drafter.py:285-288` passes the raw `engine.surface(...)` result into `_build_user_prompt(...)`
- targeted helper validation in this pass confirmed `draft_prompt()` fails against the current engine-style surface payload with `TypeError: string indices must be integers, not 'str'`

Impact:

- the prompt-mode helper path is not only CLI-drifted; it is currently incompatible with the live engine contract
- API-key-backed drafting likely shares the same prompt-building fragility because it uses the same prompt builder

Needed follow-up:

- make `ResonanceEngine.surface()` and `_build_user_prompt()` agree on one stable data shape
- add direct regressions for `draft_prompt()` and `draft_catalog()` against the real engine surface output

### MED-27: Standalone resonance CLI calls a missing `ResonanceEngine.list_drafts()` method

Evidence:

- `skg/resonance/cli.py:106-120` implements `drafts` by calling `engine.list_drafts()`
- `skg/resonance/engine.py:1-317` defines no `list_drafts()` method
- targeted runtime inspection in this pass confirmed `hasattr(ResonanceEngine(...), "list_drafts") == False`
- the top-level CLI does not hit this exact bug because `skg/cli/commands/intelligence.py:269-346` scans the drafts directory directly instead of calling the engine

Impact:

- the standalone resonance CLI has diverged from both the main CLI and the engine contract
- operators using the standalone path can hit a hard failure even when the main `skg` CLI appears to support the feature

Needed follow-up:

- either add `list_drafts()` to `ResonanceEngine` or stop the standalone CLI from calling it
- decide whether the standalone CLI remains supported or should be reduced to the main CLI surface

### MED-28: Resonance ingester overstates adapter/domain completeness

Evidence:

- `skg/resonance/ingester.py:27-100` relies on hard-coded `ADAPTER_EVIDENCE_SOURCES` rather than reading adapter metadata dynamically
- `skg/resonance/ingester.py:205-215` regex-scans `parse.py` files for wicket ids
- `skg/resonance/memory.py:80-92` models `DomainMemory.adapters` as part of the stored domain shape
- `skg/resonance/ingester.py:173-181` stores `DomainMemory(..., adapters=[])`
- targeted ingester validation in this pass confirmed `ingest_all()` leaves `DomainMemory.adapters == []` and increments `domains_added` even when `store_domain()` returns `False`

Impact:

- the resonance memory model currently advertises domain-to-adapter linkage that is not actually populated
- ingester summaries can overstate what was newly learned versus merely processed

Needed follow-up:

- decide whether `DomainMemory.adapters` is meant to be authoritative or remove/de-emphasize it
- make ingest summaries distinguish processed, updated, and newly added records
- add direct tests for adapter/domain completeness semantics

### MED-29: Workload-scoped observation history still mixes exact-wicket records across workloads

Evidence:

- `skg/sensors/context.py:108-114` passes `workload_id` into `historical_confirmation_rate(...)`
- `skg/resonance/observation_memory.py:255-275` computes `query_identity`, but `recall()` first accepts any record whose `rec.wicket_id == condition_id` at `:260-262`
- identity/target checks only happen later in the fallback branch at `:264-274`
- targeted validation in this pass confirmed `historical_confirmation_rate(..., workload_id='host::10.0.0.1')` still mixed `realized` records from `host::10.0.0.1` and `blocked` records from `host::10.0.0.2` when both shared the same wicket/domain
- `tests/test_sensor_projection_loop.py:911-947` only verifies shared-identity aliasing (`ssh::172.17.0.3` vs `host::172.17.0.3`), not separation across different identities

Impact:

- sensor-side confidence calibration is weaker than advertised for exact-wicket history
- one workload's confirmation history can dilute another workload's confidence even when `workload_id` is supplied

Needed follow-up:

- decide whether exact-wicket recall should still be identity-scoped when a workload id is supplied
- add regressions that distinguish same-identity aliasing from cross-identity contamination

### MED-30: TF-IDF resonance fallback uses a moving embedding basis under append-only indexes

Evidence:

- `skg/resonance/embedder.py:77-111` refits TF-IDF state on `self._corpus + texts` for every `embed(...)` call
- `skg/resonance/embedder.py:113-114` implements `embed_one(...)` by calling `embed([text])`, which also mutates corpus/idf state
- `skg/resonance/engine.py:120-127` and `skg/resonance/observation_memory.py:229-232` append only new vectors to their indexes
- neither `MemoryStore` nor `ObservationMemory` re-embed previously indexed records when the TF-IDF model changes
- targeted validation in this pass confirmed the same text embeds differently after corpus growth, and a targeted `MemoryStore` validation confirmed append-only query ordering can drift under a changing embedder basis
- repo-wide search in this pass found no direct tests for `skg.resonance.embedder`

Impact:

- the live fallback path in environments without `sentence-transformers` can accumulate vectors from incompatible TF-IDF states
- resonance and observation-memory search quality can drift over time without any rebuild signal

Needed follow-up:

- either freeze/refit-and-rebuild TF-IDF state deterministically or treat the fallback as rebuild-on-change rather than append-only
- add direct tests for fallback embedder stability and index-update semantics

### MED-31: `DeltaStore.calibrate_confidence_weights()` cannot see the evidence-rank data it claims to use

Evidence:

- `skg/temporal/__init__.py:565-599` documents confidence-weight calibration from transition history keyed by `evidence_rank`
- `skg/temporal/__init__.py:623-628` tries to read `t.evidence_rank` or `t.metadata["evidence_rank"]`
- `skg/temporal/__init__.py:53-92` defines `WicketTransition` with no `evidence_rank` or `metadata` field
- `skg/temporal/__init__.py:350-376` constructs `WicketTransition` instances without any evidence-rank payload
- targeted validation in this pass confirmed `calibrate_confidence_weights()` returned only default `insufficient_data` weights even after ingesting a real `unknown`→`realized` transition

Impact:

- the temporal calibration helper currently overstates what it can learn from live transition data
- operators can read a plausible calibration result that is actually just the hard-coded defaults

Needed follow-up:

- decide whether transition records should carry evidence-rank metadata or whether calibration belongs on a different artifact stream
- add direct tests for calibration on real ingested transitions

### MED-32: The standalone YAML catalog compiler emits repo-inconsistent filenames

Evidence:

- `skg/catalog/compiler.py:220-231` writes compiled output as `attack_preconditions_catalog.v1.{domain}.json`
- `skg/forge/generator.py:642` writes toolchain catalogs as `attack_preconditions_catalog.{domain}.v1.json`
- `skg/cli/commands/toolchains.py:101` and multiple checked-in toolchains expect `attack_preconditions_catalog.{domain}.v1.json`
- repo-wide naming search in this pass found the checked-in catalog convention is consistently `{domain}.v1`, not `v1.{domain}`

Impact:

- catalogs produced by the standalone YAML compiler are likely to miss the runtime/toolchain discovery convention
- the repo now has two catalog-authoring paths with different output contracts

Needed follow-up:

- decide whether `skg.catalog.compiler` is still a supported authoring path
- if yes, align its filename/output contract with the live toolchain/runtime convention and add tests

### MED-33: `gravity_web.py` and `exploit_proposals.py` appear unwired sidecar layers

Evidence:

- `skg-gravity/gravity.py:4-8` describes itself as a compatibility shim delegating to `gravity_field.py`
- repo-wide callsite search in this pass found no live references to `skg-gravity/gravity_web.py` helpers outside their own module
- repo-wide callsite search in this pass found no live references to `skg-gravity/exploit_proposals.py` helpers outside their own module
- `skg-gravity/exploit_proposals.py:13-22` writes to `SKG_STATE_DIR / "exploit_proposals"` rather than the shared `state/proposals` queue used by `skg.forge.proposals`

Impact:

- these modules currently look ceremonial or abandoned rather than part of the canonical runtime
- if reactivated later, `exploit_proposals.py` would fragment proposal state across a second queue

Needed follow-up:

- classify these modules as supported compatibility layers or archive/remove them from the canonical path
- add explicit tests or runtime integration if they are intended to remain live

### MED-34: `db_discovery` emits DE-* events outside the normal measured event contract

Evidence:

- `skg-data-toolchain/adapters/db_discovery/parse.py:108-135` builds events via `_ev(...)`
- that helper emits only top-level `source` plus `payload.rank` / `payload.confidence`
- targeted event-shape validation in this pass confirmed `check_de_01()` outputs events with no `provenance` block and no `attack_path_id` in payload
- `skg/cli/commands/data.py:130-151` exposes this path directly under `skg data discover`

Impact:

- operator-facing DE-* discovery output does not follow the canonical event envelope used by the rest of the substrate
- downstream projection/provenance handling has to infer or guess missing metadata if these events are ever routed through generic tooling

Needed follow-up:

- decide whether DE-* discovery is meant to be canonical measured input or only an operator-side report artifact
- if it is canonical, align it with the normal `provenance` and `attack_path_id` contract and add direct tests

### MED-35: IoT firmware probe can miss ordinary HTTP-only devices and leaves its network fallback unwired

Evidence:

- `skg-iot_firmware-toolchain/adapters/firmware_probe/probe.py:254-272` treats device reachability as “received a spontaneous TCP banner on one of several ports”
- if no banner is seen, it emits `IF-01` `unknown` and returns before the later HTTP probing block at `:275-294`
- `probe_network_only()` exists at `:426-555`, but repo-wide search in this pass found no callsites outside its own definition
- targeted adapter validation in this pass confirmed a monkeypatched HTTP-only device path still returned only `IF-01` `unknown`

Impact:

- HTTP-admin devices that do not emit a banner before a request can be missed by the main probe path
- the adapter carries an unwired fallback that could have reduced that blind spot but currently does not participate in the main flow

Needed follow-up:

- decide whether reachability should include active HTTP probing before early exit
- either wire `probe_network_only()` into the main path or retire it as dead code
- add direct regressions for HTTP-only devices

### MED-36: The stale root web projector is broken in multiple ways

Evidence:

- `skg-web-toolchain/projections/run.py:21` points at `web_attack_preconditions_catalog.v1.json`
- targeted path validation in this pass confirmed that file does not exist, while the checked-in catalog is `attack_preconditions_catalog.web.v1.json`
- `skg-web-toolchain/projections/run.py:152-177` accepts `workload_id`, but targeted validation in this pass confirmed `latest(..., workload_id='web::a')` still returned the last `web_initial_access_v1` record for `web::b`
- repo-wide search in this pass found no direct tests for the root web projector

Impact:

- the root projector is not just stale; it is actively unreliable if invoked
- later reviewers can mistake it for a supported alternate entrypoint because it still ships in-tree

Needed follow-up:

- either remove/archive the root projector from the canonical runtime path or bring it into line with the nested web projector and catalog naming
- add direct regression coverage if it remains supported

### MED-37: The IoT firmware toolchain contains two divergent adapter implementations

Evidence:

- `skg-iot_firmware-toolchain/adapters/firmware_probe/__init__.py:120-230` implements an SSH/image collector flow via `collect_live(...)`, `collect_from_image(...)`, and `run_firmware_probe(...)`
- `skg-iot_firmware-toolchain/adapters/firmware_probe/__init__.py:225-246` defaults to `attack_path_id="firmware_rce_via_busybox_v1"`
- `skg-iot_firmware-toolchain/adapters/firmware_probe/probe.py:235-377` implements a network/banner/HTTP flow via `probe_device(...)`, `evaluate_versions(...)`, and `probe_from_image(...)`
- `skg-iot_firmware-toolchain/adapters/firmware_probe/probe.py:242` and `362` default to `attack_path_id="iot_firmware_rce_v1"`
- the two files assign different semantics to the same package surface while sharing `TOOLCHAIN = "skg-iot_firmware-toolchain"` and `SOURCE_ID = "adapter.firmware_probe"`

Impact:

- the package does not have one obvious canonical firmware adapter contract
- runtime behavior can differ materially depending on which entrypoint is imported or invoked
- later repair work could accidentally “fix” one IoT path while leaving the other live and divergent

Needed follow-up:

- decide which IoT adapter is canonical for live runtime use
- either reconcile the two implementations or clearly quarantine the secondary path
- add direct tests that pin the supported IoT entrypoint and default attack-path behavior

### MED-38: Several nested toolchain projectors use a fragile repo-root shim for optional sheaf imports

Evidence:

- `skg-iot_firmware-toolchain/projections/iot_firmware/run.py:68-76` inserts `Path(__file__).resolve().parents[4]` before importing `skg.topology.sheaf`
- `skg-data-toolchain/projections/data/run.py:90-103` does the same
- `skg-container-escape-toolchain/projections/escape/run.py:126-134` does the same for its sheaf path
- `skg-ad-lateral-toolchain/projections/lateral/run.py:114-127` does the same
- `skg-host-toolchain/projections/host/run.py:117-126` does the same
- `skg-supply-chain-toolchain/projections/supply_chain/run.py:73-82` does the same
- targeted path-resolution validation in this pass confirmed `Path(__file__).resolve().parents[4]` resolves to `/opt` for those in-tree toolchains, not `/opt/skg`

Impact:

- optional sheaf refinement silently degrades out of generated projector flows unless some unrelated import context already makes `skg` importable
- projector behavior can change depending on cwd or surrounding launcher behavior rather than just repo contents

Needed follow-up:

- replace the brittle repo-root shim with a correct import strategy
- add direct projector tests that exercise sheaf classification when run from normal toolchain entrypoints

### MED-41: The supply-chain adapter no longer matches the checked-in supply-chain catalog

Evidence:

- `skg-supply-chain-toolchain/contracts/catalogs/attack_preconditions_catalog.supply_chain.v1.json:90-96` defines `SC-10` as `cryptography_high_vuln_present` with a Spectrum Cash Receipting / weak-password CVE narrative
- `skg-supply-chain-toolchain/adapters/sbom_check/check.py:108-113` evaluates `SC-10` using `requests < 2.20.0` and `urllib3 < 1.24.2`
- `skg-supply-chain-toolchain/adapters/sbom_check/check.py:291-317` only emits SC-* wickets present in `VULNERABLE_PACKAGES`, so the adapter never emits the checked-in catalog’s `SC-11` or `SC-12`
- `skg-supply-chain-toolchain/contracts/catalogs/attack_preconditions_catalog.supply_chain.v1.json:97-110` still defines `SC-11` and `SC-12`, but `attack_paths` at `:112-167` never require them
- repo-wide inventory in this pass found no local tests under `skg-supply-chain-toolchain/`

Impact:

- the active supply-chain toolchain does not have one stable semantic contract for at least `SC-10`
- later review or repair work can treat catalog text, emitted events, and attack-path semantics as aligned when they are not
- `SC-11` and `SC-12` currently look live in the catalog but behave like dead wickets

Needed follow-up:

- choose whether the adapter or the catalog is canonical for supply-chain semantics
- reconcile or retire `SC-10`, `SC-11`, and `SC-12` so emitted events and checked-in attack paths describe the same domain
- add direct tests for `sbom_check` against the checked-in catalog

### MED-42: The metacognition toolchain does not follow normal SKG event and recency semantics

Evidence:

- `skg-metacognition-toolchain/adapters/confidence_elicitation/parse.py:85-114`, `skg-metacognition-toolchain/adapters/known_unknown/parse.py:94-122`, and `skg-metacognition-toolchain/adapters/review_revision/parse.py:88-116` emit `obs.substrate.node` records with no top-level `id`
- those same adapters use `source.id` rather than `source_id`, and place `evidence_rank` under `provenance.evidence` instead of the more typical top-level `provenance.evidence_rank`
- `skg-metacognition-toolchain/projections/metacognition/run.py:70-91` resolves conflicting wicket states by fixed priority `blocked > realized > unknown`, not by newest timestamp
- targeted helper validation in this pass confirmed that an older blocked `MC-01` event still overrides a newer realized `MC-01` event
- repo-wide search in this pass found no direct tests for the metacognition adapters or projector; existing metacognition references in `tests/test_sensor_projection_loop.py` only cover proposal metadata, not toolchain behavior

Impact:

- the metacognition toolchain is not aligned with the normal SKG measured-event envelope contract
- later positive evidence cannot supersede earlier blocked evidence inside the current metacognition projector
- generic runtime handling, archival reasoning, and longitudinal re-evaluation can diverge from other toolchains

Needed follow-up:

- decide whether metacognition is intended to use the same shared event-envelope contract as the rest of SKG
- if so, normalize adapter event shape and make projector resolution recency-aware
- add direct tests for adapter envelope shape and for blocked-versus-newer-realized resolution

### MED-43: Several web helper adapters emit partial manual events and unstable URL-shaped workload ids

Evidence:

- `skg-web-toolchain/adapters/web_active/gobuster_adapter.py:101-117` emits manual event dicts without top-level `source` or `provenance`
- `skg-web-toolchain/adapters/web_active/nikto_adapter.py:87-103` does the same
- `skg-web-toolchain/adapters/web_active/sqlmap_adapter.py:75-145` does the same, and also emits `DP-10` / `DP-02` data-domain events from the web helper path
- those helpers set workload ids like `web::{target_url}` or `data::{target_url}` at `gobuster_adapter.py:108`, `nikto_adapter.py:95`, and `sqlmap_adapter.py:82`, `101`, `119`, so the workload subject can include full URL strings rather than the host-shaped identities used elsewhere
- `gobuster_adapter.py:220-254` has a separate fallback path that does use the shared `envelope(...)` / `precondition_payload(...)` helpers, so the emitted contract changes depending on which enumeration backend happens to run
- repo-wide search in this pass found no direct tests for `auth_scanner.py`, `gobuster_adapter.py`, `nikto_adapter.py`, `sqlmap_adapter.py`, or `transport.py`

Impact:

- web helper outputs are not one stable measured event contract
- workload identity can fragment further because helper adapters use full URLs as workload subjects
- data-domain observations can be injected from a web helper path without the normal shared event-envelope metadata

Needed follow-up:

- route all helper adapters through the shared event envelope helpers
- normalize helper workload ids to the same canonical host/web identity scheme used elsewhere
- add direct tests for helper event shape and subject normalization

### MED-44: A legacy `W-*` web SSH collector still lives inside the canonical web toolchain tree

Evidence:

- `skg-web-toolchain/adapters/ssh_collect/parse.py:85`, `102`, `123`, `144`, and `172` emit `W-01` through `W-05`, not the checked-in `WB-*` vocabulary used elsewhere in the live web toolchain
- that same file is Apache/APR-specific: `W-03` checks Apache `< 2.2.6`, `W-04` checks APR `< 1.3.3`, and `W-05` is Solaris-specific APR logic
- repo-wide reference search in this pass found that path only in itself, `forge_staging/skg-web-toolchain/...`, and older evidence/doc artifacts, not in active tests or other obvious runtime callsites
- repo-wide search in this pass found no direct tests for `skg-web-toolchain/adapters/ssh_collect/parse.py`

Impact:

- the canonical web toolchain tree still contains a stale collector path that does not match the current web catalog/projector vocabulary
- later repair passes can easily inspect or patch this legacy path by mistake and treat it as live canonical web behavior

Needed follow-up:

- confirm whether this collector is intentionally dormant or should still participate in the live web domain
- if it is non-canonical, quarantine it or mark it clearly so later work does not confuse it with the active `WB-*` paths
- if it is still intended to be live, add callsite-based validation and reconcile it with the current checked-in web catalog

### MED-45: The gravity AI runner overwrites valid AI probe events with summary dicts before projection

Evidence:

- `skg-gravity/gravity_field.py:2442-2449` calls `ai_probe.probe_device(..., out_path=str(events_file))` and then appends the returned `service_events` into `all_events`
- `skg-ai-toolchain/adapters/ai_probe/probe.py:650-696` writes full events to `out_path` via the adapter helpers but returns only summary dicts of the form `{"wicket_id": ..., "status": ..., "port": ..., "service": ...}`
- `skg-gravity/gravity_field.py:2540-2554` then rewrites `events_file` from `all_events` and immediately feeds that file into `_project_gravity_events(...)`
- `skg/sensors/projector.py:448-456` only admits lines whose top-level `type` is `obs.attack.precondition` and that carry the normal event envelope
- targeted monkeypatch validation in this pass confirmed `_exec_ai_probe()` rewrote a valid AI event file into summary-only NDJSON rows like `{"wicket_id": "AI-01", "status": "realized", "port": 11434, "service": "ollama"}`
- repo-wide search in this pass found no direct tests for `skg-gravity/gravity_field.py::_exec_ai_probe`

Impact:

- the active gravity AI service-probe path can discard valid measured events that the underlying AI adapter already wrote correctly
- the copied gravity AI event file in `events/` and the projector input can become malformed summary rows, so AI path realizations can be lost before interpretation

Needed follow-up:

- preserve the adapter-authored event file or make `probe_device()` return full event envelopes rather than summary rows
- add direct regression coverage for gravity AI execution through projection
- keep LLM analyst output separate from the service-probe event stream unless both paths emit the same canonical envelope

### MED-46: `_exec_post_exploitation()` can crash before session discovery when target OS metadata is absent

Evidence:

- `skg-gravity/gravity_field.py:2602-2610` iterates `active_sessions` inside the non-Windows branch before that variable is initialized
- `skg-gravity/gravity_field.py:2670-2678` only defines `active_sessions` later in the function
- `skg-gravity/gravity_field.py:4538-4545` calls `_exec_post_exploitation(...)` from the active Metasploit execution path
- targeted validation in this pass confirmed `_exec_post_exploitation(...)` raises `UnboundLocalError: cannot access local variable 'active_sessions' where it is not associated with a value` when the target lacks explicit OS metadata
- repo-wide search in this pass found no direct tests for `_exec_post_exploitation()`

Impact:

- active gravity post-exploitation collection can fail before any session-aware enrichment runs
- the failure mode depends on missing target metadata rather than a clean unsupported-platform check, so it is easy to trigger on partially-known hosts

Needed follow-up:

- initialize session state before any branch uses it
- add a direct regression for host targets that have a session but no explicit OS metadata

### MED-47: Gravity-generated host and web events still overload canonical wicket ids with conflicting meanings

Evidence:

- `skg-gravity/adapters/smbclient.py:94`, `113`, and `162` use `HO-06` for SMB share enumeration, `HO-20` for anonymous SMB session, and `HO-07` for interesting files accessible
- `skg-host-toolchain/contracts/catalogs/attack_preconditions_catalog.host.v1.json:41-50` and `139-145` define `HO-06=sudo_misconfigured`, `HO-07=suid_binary_present`, and `HO-20=rdp_service_exposed`
- `skg-gravity/adapters/ldap_enum.py:121` also uses `HO-20` for anonymous LDAP bind
- `skg-gravity/adapters/openssl_tls.py:89`, `162`, and `181` use `WB-05`, `WB-06`, and `WB-07` for TLS findings
- `skg-web-toolchain/contracts/catalogs/attack_preconditions_catalog.web.v1.json:34-55` defines `WB-05=admin_interface_exposed`, `WB-06=api_docs_exposed`, and `WB-07=debug_endpoint_exposed`
- `skg-gravity/gravity_field.py:4873-4891` maps RDP and WinRM port detection to `HO-03` and `HO-02`, even though the checked-in host catalog uses those ids for `ssh_credential_valid` and `ssh_service_exposed`
- `skg-gravity/gravity_field.py:3490-3504` maps successful Hydra SSH/FTP brute-force to `HO-02` rather than the host catalog's credential-valid wicket
- repo-wide search in this pass found no direct tests that pin gravity-emitted host/web wickets against the checked-in catalogs

Impact:

- successful gravity collection can realize the wrong canonical wickets even when the underlying observation is true
- downstream path projection, support collapse, and follow-on proposal ranking can be wrong because the semantic collision is inside active runtime code

Needed follow-up:

- stop reusing canonical host/web wicket ids for gravity-local meanings
- add regressions that validate gravity-emitted wickets against the checked-in host and web catalogs

### MED-48: Several gravity plugin adapters emit non-projectable `skg-gravity` toolchain events

Evidence:

- `skg-gravity/adapters/ldap_enum.py:119-329`, `skg-gravity/adapters/openssl_tls.py:89-201`, and `skg-gravity/adapters/smbclient.py:76-160` emit `obs.attack.precondition` events with `source.toolchain = "skg-gravity"`
- `skg/sensors/projector.py:448-458` only projects events whose `source.toolchain` resolves to a discoverable checked-in toolchain projector
- targeted validation in this pass confirmed that a normal `obs.attack.precondition` event with `toolchain="skg-gravity"` produces `[]` from `project_event_file(...)`
- these plugin adapters ingest their own events into the kernel, but unlike some gravity shell paths they do not call `_project_gravity_events(...)`
- repo-wide search in this pass found no direct tests for `ldap_enum.py`, `openssl_tls.py`, `smbclient.py`, or `theharvester.py`

Impact:

- active gravity plugin observations can be present in raw event history but absent from interpreted path state
- operator views and follow-on reasoning can miss realizations that gravity just measured

Needed follow-up:

- either emit on canonical toolchain lanes with checked-in projectors or explicitly route these events through a maintained gravity projection path
- add direct regression coverage for gravity plugin events reaching interpretation output

### MED-49: `gravity_field_cycle` loses subject identity and undercounts energy terms after execution

Evidence:

- `skg-gravity/gravity_field.py:669-727` builds gravity subject rows keyed by `identity_key`
- `skg-gravity/gravity_field.py:7416-7418` passes only `t["target"]` into `execute_instrument(...)`, not the full subject row
- `skg-gravity/gravity_field.py:2188-2203` then derives `node_key` from `target.get("identity_key") or target["ip"]`
- `skg-gravity/gravity_field.py:7512-7520` refreshes post-run state by raw IP via `_load_fresh_view_state(ip)` and `load_wicket_states(ip)`
- `skg-gravity/gravity_field.py:7150-7178` computes pre-run `E` from `E_base + fold_boost + field_pull_boost + L_F_boost + wgraph_boost`
- `skg-gravity/gravity_field.py:7520-7542` computes `E_after` from only `E_after_base + new_fold_boost`
- repo-wide search in this pass found no direct regressions for gravity subject identity preservation or like-for-like post-run energy accounting

Impact:

- execution can be scheduled on one identity-shaped subject and then remeasured or accounted on a raw-IP surrogate
- reported entropy reduction is not a like-for-like comparison when non-base energy terms were present before execution

Needed follow-up:

- preserve the selected subject identity through execution and post-run refresh
- compare pre-run and post-run energy using the same term set
- add regressions for alias-preserving execution and delta-E accounting

### MED-50: A dead BloodHound collector copy is embedded inside `_exec_data_profiler()`

Evidence:

- `skg-gravity/gravity_field.py:5713-6019` defines `_exec_data_profiler(...)` and returns at line `6019`
- `skg-gravity/gravity_field.py:6025-6118` then contains a second indented BloodHound collection block after that `return`
- `skg-gravity/gravity_field.py:2332-2415` already contains the live `_exec_bloodhound(...)` implementation
- targeted structural validation in this pass confirmed the `_exec_data_profiler` slice contains the BloodHound collector prose/body but no nested `def _exec_bloodhound`

Impact:

- the gravity shell now contains two divergent BloodHound implementations, but one is dead code hidden inside an unrelated data-profiler function
- later repair work can easily patch the unreachable copy by mistake and assume the BloodHound path was fixed

Needed follow-up:

- remove the embedded dead BloodHound block from `_exec_data_profiler()`
- keep one maintained BloodHound implementation and add direct coverage around it

### MED-51: `_exec_ssh_sensor()` duplicates host events into the same NDJSON file

Evidence:

- `skg-gravity/gravity_field.py:6257-6268` passes `events_file` into `run_ssh_host(..., out_file=events_file, ...)`
- `skg/sensors/adapter_runner.py:443-498` makes `run_ssh_host()` use the provided `out_file` as its adapter output path and then read events back from that same file
- `skg-gravity/gravity_field.py:6272-6275` then opens `events_file` in append mode and writes every returned event into it again
- repo-wide search in this pass found no direct tests for the gravity SSH execution path

Impact:

- gravity SSH collection can duplicate otherwise-valid host observations inside its persisted event artifact
- projection, replay, and later event-history analysis can see doubled host evidence from one collection run

Needed follow-up:

- stop appending returned events back into the same file after `run_ssh_host()` already wrote them
- add a direct regression that pins one emitted event to one persisted NDJSON line

### MED-52: `_exec_sysaudit()` emits events but does not project them in the gravity loop

Evidence:

- `skg-gravity/gravity_field.py:5697-5709` writes the sysaudit event file and records it in `result["events_file"]`
- unlike adjacent gravity branches such as supply-chain (`skg-gravity/gravity_field.py:5635`) and data-profiler (`skg-gravity/gravity_field.py:5950`, `6008`), `_exec_sysaudit()` never calls `_project_gravity_events(...)`
- `skg-host-toolchain/adapters/sysaudit/audit.py:1118-1185` returns event dicts only; it does not create interpretation artifacts itself
- repo-wide search in this pass found no direct tests for the gravity sysaudit path

Impact:

- sysaudit measurements can land in raw event history without updating interpreted path state during the same gravity cycle
- entropy reduction and operator views can lag behind the observations that gravity just collected

Needed follow-up:

- project sysaudit event files the same way other gravity instrument branches do
- add direct regression coverage for sysaudit execution through interpretation

### MED-53: Gravity target merge assumes dict-shaped `targets.yaml` and crashes on list-root configs

Evidence:

- `skg-gravity/gravity_field.py:520-556` implements `_merge_configured_targets(...)`
- `skg-gravity/gravity_field.py:536` iterates `data.get("targets")` without handling the list-root `targets.yaml` shape used elsewhere in the repo
- other runtime paths in the repo explicitly support both list and dict roots for target inventory
- `skg-gravity/gravity_field.py:6894` calls `_merge_configured_targets(surface)` inside the live gravity field loop
- targeted validation in this pass confirmed `_merge_configured_targets({'targets': []})` raises `AttributeError: 'list' object has no attribute 'get'` when `targets.yaml` is list-root

Impact:

- gravity startup and target enrichment can fail on a repository-supported `targets.yaml` shape
- the gravity loop is less robust than the rest of the runtime against one of the repo's normal config forms

Needed follow-up:

- normalize gravity target loading to the same list-or-dict inventory contract used elsewhere
- add a direct regression for list-root and dict-root `targets.yaml`

### MED-54: BloodHound availability and workload scoping do not match the advertised fallback model

Evidence:

- `skg-gravity/gravity_field.py:1618-1633` marks `bloodhound` available only if a quick `urllib.request.urlopen(bh_url, timeout=2)` succeeds
- `skg-gravity/gravity_field.py:2332-2415` and `skg/sensors/bloodhound_sensor.py:632-646` both implement a real Neo4j fallback path when the CE API is unavailable
- targeted validation in this pass confirmed `detect_instruments()` returns `bloodhound.available == False` when `NEO4J_PASSWORD` is set but the CE URL is unreachable
- `skg/sensors/bloodhound_sensor.py:434` accepts `domain_sid`, but `collect_via_api(...)` never uses it
- `skg/sensors/bloodhound_sensor.py:629` defaults sensor `workload_id` to `self.domain_sid or self.url.split('//')[-1].split(':')[0]`, so without `domain_sid` the AD workload becomes the BloodHound server hostname
- `skg/sensors/bloodhound_sensor.py:25` and `602-603` still present `domain_sid` as the intended domain-scoping config

Impact:

- gravity can suppress BloodHound as an available instrument even when the documented Neo4j fallback is actually configured
- AD observations can be recorded under a collector-hostname surrogate rather than a stable domain identity when `domain_sid` is unset
- the advertised domain filter/scoping story is stronger than the implementation actually provides

Needed follow-up:

- make availability reflect either CE API or Neo4j fallback reachability
- implement or remove `domain_sid` filtering in the collection path
- normalize BloodHound workload identity to the actual AD domain, not the collector endpoint hostname

### MED-55: `wicket_graph` catalog discovery and prefix mapping lag active AI, data, and IoT domains

Evidence:

- `skg/kernel/wicket_graph.py:151` and `751` seed from `attack_preconditions_catalog.*.json`
- the active AI catalog is `skg-ai-toolchain/contracts/catalogs/ai_attack_preconditions_catalog.v1.json`, so it does not match that glob
- `skg/kernel/wicket_graph.py:701-710` maps stale prefixes like `DA-` and `IO-`, but current active data and IoT wickets are `DP-*`, `DE-*`, and `IF-*`
- targeted validation in this pass confirmed `_domain_from_wicket_id('DP-01')`, `_domain_from_wicket_id('DE-01')`, and `_domain_from_wicket_id('IF-01')` all return `unknown`
- targeted validation in this pass confirmed `get_wicket_graph(force_rebuild=True)` leaves `DP-01`, `DE-01`, and `IF-01` with `domain == "unknown"` and omits `AI-01` entirely
- repo-wide search in this pass found no direct tests for `get_wicket_graph()` against the current AI/data/IoT catalog inventory

Impact:

- wicket-space domain expansion and dark-hypothesis classification are weaker or wrong for active AI, data, and IoT domains
- some real wickets are treated as unclassified pressure, and some AI wickets are absent from the graph entirely

Needed follow-up:

- align graph catalog discovery with the actual checked-in catalog naming set
- update wicket-prefix domain inference for current data and IoT wicket families
- add a direct regression covering AI, data, and IoT catalog seeding

### MED-56: `surface.py` under-ranks explicit `data_pipeline` and `binary_analysis` projections

Evidence:

- `skg/intel/surface.py:37-47` defines `SCORE_KEY` without entries for `data_pipeline` or `binary_analysis`
- `skg/intel/surface.py:50-60` defines `DOMAIN_LABEL` without entries for those same explicit domains
- `skg/intel/surface.py:107-128` preserves explicit `domain` values from interp payloads when present
- `skg/intel/surface.py:130-137` therefore falls back to realized/required inference when an explicit `data_pipeline` or `binary_analysis` projection carries `data_score` or `binary_score`
- targeted validation in this pass confirmed a `domain=\"data_pipeline\"` projection with `data_score=0.9` is surfaced as `domain_label=\"data_pipeline\"` and `score=0.0`
- targeted validation in this pass confirmed a `domain=\"binary_analysis\"` projection with `binary_score=0.8` is surfaced as `domain_label=\"binary_analysis\"` and `score=0.0`

Impact:

- measured surface ranking can understate active data and binary paths even when the projector emitted explicit scores
- CLI and daemon views that depend on `surface()` can mis-rank or de-emphasize those domains relative to host/web paths

Needed follow-up:

- align `SCORE_KEY` and `DOMAIN_LABEL` with the explicit domains emitted by current projectors
- add direct regressions for explicit `data_pipeline` and `binary_analysis` payloads

### MED-39: The APRS toolchain still uses an older catalog naming contract

Evidence:

- `skg-aprs-toolchain/skg.py:49-50` defaults `project aprs` to `contracts/catalogs/attack_preconditions_catalog.v1.json`
- `skg-aprs-toolchain/projections/aprs/run.py:106-107` defaults to the same filename
- the repo-wide toolchain/runtime convention elsewhere is `attack_preconditions_catalog.{domain}.v1.json`, including host, data, web, container escape, and the standalone generator flow

Impact:

- APRS remains internally coherent, but it is a naming outlier relative to the current repo contract
- future tooling that assumes the dominant `{domain}.v1` pattern can miss APRS or treat it as stale by mistake

Needed follow-up:

- decide whether APRS is an intentional legacy special-case or should be renamed to the current convention
- add a small compatibility test if the older contract is retained deliberately

### MED-40: `ssh_collect` contains a duplicated unreachable copy of its main collection flow

Evidence:

- `skg-host-toolchain/adapters/ssh_collect/parse.py:755-879` contains the active `main()` collection flow and returns `0` at line `879`
- `skg-host-toolchain/adapters/ssh_collect/parse.py:881-957` contains a second near-identical copy of the connection and HO-* collection logic after that `return`
- the duplicated tail is unreachable in normal execution but still present in the live file

Impact:

- future edits can land in the dead copy instead of the active path
- readers and later repair passes have to reason about two divergent versions of the same flow in one file

Needed follow-up:

- remove the unreachable duplicate block after confirming no intentional fallback is hidden there
- add direct behavioral coverage for the active `ssh_collect` path so later edits land on one maintained implementation

### LOW-08: Host catalog evidence hints lag the stronger live adapter ranks

Evidence:

- `skg-host-toolchain/contracts/catalogs/attack_preconditions_catalog.host.v1.json:6-18` describes `HO-01` and `HO-02` as requiring minimum rank-4 network evidence
- `skg-host-toolchain/contracts/catalogs/attack_preconditions_catalog.host.v1.json:27-38` describes `HO-04` as requiring minimum rank-4 network evidence
- `skg-host-toolchain/adapters/ssh_collect/parse.py:192-200` emits `HO-01` and `HO-02` at rank `1` after successful SSH authentication
- `skg-host-toolchain/adapters/winrm_collect/parse.py:94-103` emits `HO-04` and `HO-05` at rank `1` after successful WinRM authentication

Impact:

- the host catalog’s human-facing evidence guidance no longer matches the strongest evidence the live adapters actually emit
- later reviewers can mistake stronger runtime confirmations for off-contract data when the drift is really in the catalog text

Needed follow-up:

- update host catalog evidence hints to reflect both network-grade and stronger authenticated evidence paths
- keep catalog prose aligned with the adapters if evidence-rank semantics continue to evolve

### LOW-09: The nginx adapter's error-page version-disclosure path is unreachable as written

Evidence:

- `skg-nginx-toolchain/adapters/ssh_collect/parse.py:197-198` and `212-218` treat `http_error_page` as if it contains body text where `nginx/X.Y.Z` can be recovered
- `skg-nginx-toolchain/adapters/ssh_collect/parse.py:715-719` actually collects `http_error_page` with `curl -sI`, which only returns headers
- the same collector truncates that response to `head -15`, so the adapter never captures the error-page body branch it claims to analyze
- repo-wide inventory in this pass found no local tests under `skg-nginx-toolchain/`

Impact:

- one advertised version-disclosure evidence path in the nginx adapter cannot fire as written
- later readers can overestimate adapter coverage because the body-inspection branch looks live in code review

Needed follow-up:

- either collect the real error-page body or remove the unreachable body-based branch
- add direct adapter tests for version disclosure via headers versus error pages

### MED-02: Generic proposal execution still embeds lab-specific exploit delivery logic

Evidence:

- `skg/cli/commands/proposals.py:103-170` prints and auto-delivers payloads against `http://{target_ip}/vulnerabilities/exec/`
- the same path logs into DVWA, extracts a CSRF token, and injects a CMDI payload inside the generic proposal execution helper

Impact:

- the operator shell is less domain-agnostic than the docs imply
- lab/demo assumptions are mixed into a generic proposal execution path
- later repairs can accidentally treat scenario-specific exploit flow as canonical runtime behavior

Needed follow-up:

- isolate lab-specific delivery helpers from generic proposal execution
- make any retained demo behavior explicit and clearly gated

### MED-03: Legacy and non-canonical trees remain co-located with canonical code

Evidence:

- `skg_deploy/ARCHIVED.md:1-27` says `skg_deploy/` is a non-canonical deployment mirror
- repo root still contains `*.backup` trees and `forge_staging/`

Impact:

- later reviewers can easily inspect the wrong tree
- stale code can be mistaken for current runtime behavior

Needed follow-up:

- mark or quarantine non-canonical trees more aggressively
- ensure future review passes stay rooted in canonical paths

### MED-04: Supply-chain naming drift between legacy domain code and active toolchain

Evidence:

- `skg/domains/supply_chain/nodes.py` defines `PKG-*`
- `skg-supply-chain-toolchain/contracts/catalogs/attack_preconditions_catalog.supply_chain.v1.json` defines `SC-*`
- repo-wide reference search in this pass found current tests and projector/runtime code on the `SC-*` side, with `PKG-*` references confined to the legacy `skg.domains.supply_chain` package

Impact:

- there are at least two supply-chain vocabularies in-repo
- reviewers and future code may bind to the wrong namespace

Needed follow-up:

- determine whether `skg/domains/supply_chain/*` is legacy-only or still referenced
- remove or isolate dead naming layers only after reference analysis

### MED-05: Docs path mismatch exists at the repo boundary

Evidence:

- requested path `/opt/skg/doc` does not exist
- actual docs root is `/opt/skg/docs`

Impact:

- operator instructions and future audit prompts can point at a non-existent path

Needed follow-up:

- fix references that still name `/opt/skg/doc`

### MED-06: `skg.intel.surface` no longer matches older API and doc expectations cleanly

Evidence:

- `install_layer4.sh` expects `from skg.intel.surface import SurfaceBuilder`, but repo-wide search found no `SurfaceBuilder`
- `skg/intel/surface.py:3-15` says the surface layer reads `DELTA_DIR`, `WorkloadGraph`, and `ObservMemory`
- `skg/intel/surface.py:243-364` actually builds `surface()` from interp payloads, pearl overlays, and observed-tool overlays; `graph` is only an optional neighbor overlay and `delta_store` is not used by `surface()` itself

Impact:

- installer expectations and code-level API expectations point at an interface that no longer exists
- the operator surface layer is harder to reason about because the public story and implementation diverged

Needed follow-up:

- either restore a clear builder abstraction or update installers/docs to the current functional API
- remove or justify unused parameters and overstated module-level contract text

### MED-07: Run-scoped auto-projection is not actually run-scoped under current event naming

Evidence:

- `skg/sensors/__init__.py:482-500` calls `project_events_dir(..., run_id=run_id, since_run_id=run_id)` and falls back to a recent full scan when no outputs are found
- `skg/sensors/projector.py:483-489` treats `since_run_id` as a filename glob suffix pattern `*_{since_run_id}.ndjson`
- `skg/sensors/__init__.py:566-593` supports optional run-id suffixes, but sweep scoping still depends on producers passing the sweep run id through
- `skg/sensors/ssh_sensor.py:100-126` emits with a per-target run id (`self._run_id` or a new UUID), not the sensor-loop sweep id
- `skg/sensors/web_sensor.py:805-883` emits web events without passing `run_id` to `emit_events(...)`
- targeted runtime validation in this pass confirmed emitted files like `..._10_0_0_9_<uuid>.ndjson` and `..._web_web__demo.local_80.ndjson` while `*_{sweep_run_id}.ndjson` matched none
- repo-wide test search in this pass found no direct coverage of `since_run_id` filtering

Impact:

- the intended sweep-local projection boundary does not currently exist
- auto-projection can reproject recent files under a new sweep `run_id` instead of only the current sweep's output
- feedback and forge behavior become less attributable to one concrete sweep

Needed follow-up:

- either include sweep `run_id` in emitted filenames or change the projector filter to inspect file contents/metadata instead of filename suffixes
- add direct regression coverage for run-scoped auto-projection

### MED-08: `skg.core.state_db` is only a write-side sidecar today

Evidence:

- `skg/core/state_db.py:1-292` defines a SQLite mirror for wicket states, credentials, pivot targets, and instrument runs
- the module docstring says it is updated and read by the gravity loop
- `skg-gravity/gravity_field.py:175-178` constructs `_state_db` at module import time
- `skg-gravity/gravity_field.py:3309`, `3324`, and `7097` only use it for `add_credential(...)`, `add_pivot_target(...)`, and `bulk_upsert_wickets(...)`
- repo-wide search in this pass found no read-side callsites for `wicket_states()`, `credentials_for_node()`, `all_credentials()`, `pivot_targets()`, or `recent_runs()` outside `skg/core/state_db.py` itself

Impact:

- the repo contains a documented fast-query layer that is, at most, a write-only sidecar today rather than a live query boundary
- future reviewers can mistake it for an active persistence boundary

Needed follow-up:

- confirm whether the SQLite mirror is intended to be a real read path or only best-effort telemetry shadowing
- if it remains effectively unread, either remove it or clearly mark it as secondary/dormant

### MED-57: `KernelStateEngine` fallback domain inference still uses stale wicket prefixes

Evidence:

- `skg/kernel/engine.py:45-55` still maps wicket prefixes as `DA- -> data`, `CE- -> container`, `LA- -> lateral`, `BI- -> binary`, `IO- -> iot_firmware`, and `AP- -> aprs`
- `skg/kernel/engine.py:59-67` uses that mapping in `_infer_domain_wickets(...)`
- `skg/kernel/engine.py:338` falls back to `_infer_domain_wickets(applicable_wickets)` in `instrument_potential(...)` when `domain_wickets` is not supplied
- `skg/kernel/engine.py:419-421` does the same for `field_locals(...)`
- targeted validation in this pass confirmed `_infer_domain_wickets({'AD-01','BA-01','DP-01','DE-01','IF-01','WB-01'})` groups `AD-01`, `BA-01`, `DP-01`, `DE-01`, and `IF-01` under `unknown`
- targeted validation in this pass confirmed `KernelStateEngine.field_locals(...)` groups those same active wickets into one `unknown` local while keeping `WB-01` under `web`
- `tests/test_sensor_projection_loop.py:290-345` still pins older `DA-01` / `domain="data"` / `domain_wickets={"data": {"DA-01"}}` naming in the kernel fiber/instrument tests
- `tests/test_gravity_runtime.py:534-557` and `727-819` already expect current `data_pipeline` / `binary_analysis` domain names elsewhere in the gravity layer

Impact:

- fallback field-local grouping and fiber-driven instrument scoring can lose active AD, binary, data, and IoT domain separation unless callers supply explicit `domain_wickets`
- kernel-level coverage is split across old and new naming, so the current tests do not reliably catch this drift

Needed follow-up:

- align `KernelStateEngine` prefix-domain inference with the active domain vocabulary
- add direct regressions for current `AD-*`, `BA-*`, `DP-*`, `DE-*`, and `IF-*` wicket families through `field_locals(...)` or `instrument_potential(...)`

### MED-58: `load_observations_for_node()` can miss discovery artifacts for hostname identities

Evidence:

- `skg/kernel/adapters.py:189-228` selects discovery files by filename patterns derived from `node_key` (`gravity_http_{node_key}_*`, `gravity_auth_{node_key}_*`, `gravity_ssh_{node_key}_*`, etc.)
- `skg/kernel/adapters.py:286-293` does content-based identity filtering only after a file has already been selected
- targeted validation in this pass created `discovery/gravity_http_10_0_0_7_run.ndjson` with payload identity `workload_id=\"web::db.internal:443\"`, `identity_key=\"db.internal\"`, and `target_ip=\"10.0.0.7\"`
- that same validation confirmed `load_observations_for_node('db.internal', discovery_dir, events_dir)` returned `0` observations because the IP-shaped discovery filename was never selected
- `tests/test_runtime_regressions.py:599-622` only covers the events-dir path for an IP-anchored binary workload and does not exercise hostname identities against IP-shaped discovery filenames

Impact:

- kernel state, energy, and field-local computation can miss discovery-backed observations for alias identities even when the event payload itself carries the correct stable identity
- measured views can diverge depending on whether observations were mirrored into `events/` or remained only in discovery artifacts

Needed follow-up:

- stop relying on `node_key`-shaped filename patterns as the primary discovery-file selector for identity-aware loading
- add a regression for hostname identity plus IP-named discovery artifact loading

### MED-59: Gravity/kernel sphere helpers still lag current domain vocabulary

Evidence:

- `skg/gravity/selection.py:27-35` still maps wavelengths with `DA-`, `CE-`, `LA-`, and `BI-` prefixes, but not current `DP-*`, `DE-*`, `BA-*`, or `IF-*`
- targeted validation in this pass confirmed `_instrument_spheres(['BA-03','DP-01','IF-01','WB-01','HO-01'])` returns only `['host', 'web']`
- targeted validation in this pass confirmed `_observed_tooling_boost('binary_analysis', ...)` returns `0.0` when only `domain_hints=['binary']` are present for a `BA-03`-wavelength instrument
- `skg/kernel/field_functional.py:32-46` maps `binary_analysis -> binary`, `container_escape -> container`, and `ad_lateral -> ad`, but has no explicit `data_pipeline -> data` normalization
- targeted validation in this pass confirmed `domain_to_sphere('data_pipeline') == 'data_pipeline'`
- targeted validation in this pass confirmed `field_functional_breakdown(...)` for a `FieldLocal(domain='data_pipeline')` with topology spheres keyed as `data` ignores that topology row and returns only the baseline curvature term
- `tests/test_sensor_projection_loop.py:120-218` still exercises field-functional relevant spheres with old `domain='data'`, while `tests/test_gravity_runtime.py:534-557` already expects current `data_pipeline`, `binary_analysis`, and `container_escape` names

Impact:

- observed-tool domain hints and sphere-based weighting in gravity selection can miss current binary, data, and IoT instruments
- field-functional/topology coupling can split old and current sphere names and silently drop topology contribution for current `data_pipeline` locals

Needed follow-up:

- unify internal sphere/domain alias handling across `kernel.engine`, `kernel.field_functional`, `gravity.selection`, and other helper layers
- add direct regressions for current `BA-*`, `DP-*`, `DE-*`, and `IF-*` families plus topology-coupled `data_pipeline` locals

### MED-60: Default inter-local coupling still privileges old domain names over current ones

Evidence:

- `skg/core/coupling.py:15-35` defines `DEFAULT_INTER_LOCAL` with old labels like `data`, `container`, `binary`, `lateral`, and `cmdi`, but not current runtime names like `data_pipeline`, `binary_analysis`, `container_escape`, or `ad_lateral`
- targeted validation in this pass confirmed `coupling_value('web', 'data', table='inter_local') == 0.85`, but `coupling_value('web', 'data_pipeline', table='inter_local') == 0.1`
- targeted validation in this pass confirmed `coupling_value('host', 'binary', table='inter_local') == 0.6`, but `coupling_value('host', 'binary_analysis', table='inter_local') == 0.1`
- targeted validation in this pass confirmed `coupling_value('host', 'container', table='inter_local') == 0.6`, but `coupling_value('host', 'container_escape', table='inter_local') == 0.1`
- targeted validation in this pass confirmed `coupling_value('host', 'ad', table='inter_local') == 0.1` and `coupling_value('host', 'ad_lateral', table='inter_local') == 0.1`, despite active gravity/runtime code using `ad_lateral`
- targeted validation in this pass confirmed `field_functional_breakdown([web, data_old]).coupling_energy == 1.53` for old `domain='data'`, while the same structure with `domain='data_pipeline'` drops to `0.2`
- `tests/test_sensor_projection_loop.py:120-218` still exercises field-functional coupling with old `domain='data'`, not current `data_pipeline`

Impact:

- current domain names can receive dramatically weaker coupling than the legacy names the runtime used earlier
- field-functional scoring and any consumer that relies on `coupling_value(...)` can materially underweight current data, binary, and container relationships unless config explicitly overrides the defaults

Needed follow-up:

- normalize the default coupling tables onto the current runtime domain vocabulary or add a stable alias layer before lookup
- add direct regressions that compare legacy and current domain-name equivalents through `coupling_value(...)` and `field_functional_breakdown(...)`

### MED-61: Daemon projection lookup only normalizes binary aliases

Evidence:

- `skg/core/daemon.py:75-81` `_projection_domain_aliases(...)` only aliases `binary <-> binary_analysis`
- `skg/core/daemon.py:83-111` `_infer_projection_domain(...)` still falls back to legacy names like `data` and `binary` from score keys and filename hints
- `skg/core/daemon.py:1163-1165` and `1226-1233` route `/projections/{workload_id}/field` and `/projections/{workload_id}` through `_find_projection_files(...)`
- targeted validation in this pass confirmed `_find_projection_files(interp_dir, 'data', 'data::users')` returns a `domain='data'` projection file, while `_find_projection_files(interp_dir, 'data_pipeline', 'data::users')` returns `[]` for that same artifact
- `tests/test_runtime_regressions.py:685-686` only pins the `binary <-> binary_analysis` alias case and does not cover current-vs-legacy `data`, `container`, or `ad` name pairs

Impact:

- daemon projection endpoints can miss equivalent legacy projection artifacts when queried with current runtime domain names
- daemon-side measured views still fragment old `data` / `binary` naming from current `data_pipeline` / `binary_analysis` naming instead of normalizing them consistently

Needed follow-up:

- add a stable alias layer for current-vs-legacy domain names in daemon projection lookup
- add direct daemon regressions for `data` / `data_pipeline`, `container` / `container_escape`, and `ad` / `ad_lateral` lookup equivalence

### MED-62: Topology energy helpers still drop or mis-map current binary and data domain names

Evidence:

- `skg/topology/energy.py:75-84` maps `FIELD_DOMAIN_TO_SPHERE['binary_analysis'] = 'host'` while `SPHERE_MAP` treats `BA-*` as `binary`
- targeted validation in this pass confirmed `anchored_field_pull(..., domains={'binary_analysis'}, sphere_pulls={'binary': 10.0}, ...) == 0.0`, while equivalent current-name cases for `data_pipeline`, `container_escape`, and `ad_lateral` still produce nonzero pull
- `skg/topology/energy.py:797-852` `_world_states_from_surface(...)` handles `data`, `container_escape`, `ai_target`, `supply_chain`, `iot_firmware`, and `ad_lateral`, but has no branches for `data_pipeline` or `binary_analysis`
- targeted validation in this pass confirmed `_world_states_from_surface(...)` on a target with domains `['data_pipeline','binary_analysis','container_escape','ad_lateral']` returned only spheres `['ad', 'container']`
- `tests/test_sensor_projection_loop.py:2416-2424`, `2509-2512`, `2516`, and `2753` still pin topology/world-state coverage around old `data` / `container` sphere names, and `tests/test_runtime_regressions.py:685-686` still only covers binary aliasing in daemon projection lookup

Impact:

- topology field pull can ignore binary sphere context for current `binary_analysis` locals
- discovery-surface world-state supplementation still drops current `data_pipeline` and `binary_analysis` domain signals
- current tests do not reliably catch this alias drift because the relevant topology cases still use mostly legacy names

Needed follow-up:

- align `FIELD_DOMAIN_TO_SPHERE` and `_world_states_from_surface(...)` with the active runtime domain vocabulary
- add direct topology regressions for `binary_analysis` pull and `data_pipeline` / `binary_analysis` world-state lifting from discovery surfaces

### MED-63: Daemon field-state computation omits binary domain mapping entirely

Evidence:

- `skg/core/daemon.py:996-1011` derives `target_domains` for host, web, container escape, data, AD, AI, IoT, and supply chain attack-path prefixes, but has no `binary_` branch
- `skg/core/daemon.py:1013-1021` then feeds those derived domains into `anchored_field_pull(...)` when building daemon-side field state
- targeted validation in this pass monkeypatched `anchored_field_pull(...)` and confirmed `_compute_field_state_inner()` calls it with `[]` for `binary_stack_overflow_v1`, but with `['data_pipeline']` for `data_exposure_v1`
- the same validation confirmed daemon field state returns `field_pull == 0.0` and `E == 1.0` for the binary path, while the data path receives the mocked field pull (`field_pull == 7.0`, `E == 8.0`)
- repo-wide search in this pass found no direct behavioral tests for `_compute_field_state_inner()` or `get_projection_field(...)`; `tests/test_sensor_projection_loop.py:2945-2965` only carries a static `field_state` fixture row rather than exercising the live computation

Impact:

- daemon-side field-state views systematically underweight binary projections relative to other domains
- binary attack paths can miss topology/fiber pull entirely even when binary sphere context exists

Needed follow-up:

- add explicit `binary_` to daemon field-state domain derivation and align it with the active binary sphere/domain vocabulary
- add direct regressions for live binary field-state computation through `_compute_field_state_inner()` or `get_projection_field(...)`

### MED-64: Daemon world manifestations silently zero out binary and AD scores

Evidence:

- `skg/core/daemon.py:2124-2149` `_identity_manifestations(...)` extracts `score` only from `host_score`, `web_score`, `data_score`, `escape_score`, and `ai_score`
- that same helper omits current score keys like `binary_score`, `lateral_score`, `iot_score`, `supply_chain_score`, and APRS-like score paths
- targeted validation in this pass confirmed `_identity_manifestations('10.0.0.7')` returns a binary manifestation row with `score: 0.0` even when the interp payload carries `binary_score: 0.82`
- the same validation confirmed `_identity_manifestations('corp.local')` returns an AD manifestation row with `score: 0.0` even when the payload carries `lateral_score: 0.73`
- `skg/core/daemon.py:1532-1548` exposes these manifestation rows through `/world/{identity_key}`
- `tests/test_sensor_projection_loop.py:2236-2239` patches `_identity_manifestations` to `[]` in the main `_identity_world(...)` test, and repo-wide search in this pass found no direct behavioral tests for manifestation score extraction

Impact:

- daemon world views understate binary and AD manifestation strength even when projection payloads carry explicit scores
- operator and assistant consumers of `/world/{identity_key}` can see misleading zeroed manifestation scores for non-host/web/data/container/AI domains

Needed follow-up:

- align `_identity_manifestations(...)` score extraction with the active domain score keys
- add direct regressions for manifestation-score extraction across binary, AD, IoT, supply-chain, and other non-host score families

### MED-65: First daemon field-state caller after cache invalidation can see an empty field state

Evidence:

- `skg/core/daemon.py:868-875` `_compute_field_state()` only starts a background refresh thread when the cache is stale, then immediately returns the current cache contents
- `skg/core/daemon.py:800-803` `status_refresh()` explicitly clears the cache to `{}` and marks it stale
- `skg/core/daemon.py:794` injects `_compute_field_state()` directly into `/status`
- `skg/core/daemon.py:3274` also uses `_compute_field_state()` directly when building assistant context
- `skg/core/daemon.py:3520-3567` and `3574-3645` route `/assistant/explain` and `/assistant/what-if` through `_assistant_prepare_context(...)`, so both assistant endpoints inherit that same cold-cache field-state behavior
- targeted validation in this pass patched `_compute_field_state_inner()` to sleep, then confirmed the first `_compute_field_state()` call after cache invalidation returned `{}`, while a second call after the background refresh returned the computed result
- repo-wide search in this pass found no direct tests for `status_refresh()`, the stale-cache `/status` path, or `_assistant_context(...)` with a cold field-state cache

Impact:

- the first `/status` or assistant-context caller after cache invalidation or TTL expiry can observe an empty field-state snapshot
- operator-facing and assistant-facing summaries can temporarily degrade from “stale” to “missing” field-state data

Needed follow-up:

- decide whether these call sites should block for a synchronous recompute when the cache is empty
- add direct regressions for cold-cache `/status` and assistant-context behavior

### MED-66: Identity timeline only discovers workloads from current `interp/` files

Evidence:

- `skg/core/daemon.py:2344-2357` discovers workloads for `identity_timeline(...)` only by scanning `INTERP_DIR` and matching `workload_id` identity keys
- `skg/core/daemon.py:2360-2372` only calls `kernel.feedback.timeline(workload_id)` for workloads found in that interp scan
- targeted validation in this pass confirmed `identity_timeline('db.internal')` returns `workload_count == 0` and empty snapshots/transitions when `kernel.feedback.timeline(...)` is available but `INTERP_DIR` is empty
- the same validation confirmed adding one interp payload for `host::db.internal` makes `identity_timeline('db.internal')` return the expected snapshot/transition rows
- `skg/core/daemon.py:3274-3378` feeds `identity_timeline(...)` directly into assistant context
- `tests/test_sensor_projection_loop.py:3031-3032` mocks both `_compute_field_state` and `identity_timeline`, so the main assistant-context test does not exercise the live workload-discovery path
- repo-wide search in this pass found no direct tests for `identity_timeline(...)`

Impact:

- daemon identity-history views can drop to empty whenever an identity lacks current interp artifacts, even if feedback history still exists for known workloads
- assistant target/fold/proposal summaries can understate transition and neighbor history because they depend on that same timeline function

Needed follow-up:

- decide whether identity-history discovery should use current interp artifacts, known manifestations, feedback state, or a merged source
- add direct regressions for identities with feedback history but missing current interp rows

### MED-67: Assistant graph context ignores `timeline.workloads` and can pivot onto neighbor ids instead

Evidence:

- `skg/core/daemon.py:2789-2797` builds `workload_ids` for `_assistant_reasoning_bundle(...)` only from surface-group paths, field rows, and `timeline["graph_neighbors"]`
- that same workload seed list does not include `timeline["workloads"]`, even though `identity_timeline(...)` returns it at `skg/core/daemon.py:2384-2385`
- `skg/core/daemon.py:2684-2706` then calls `kernel.graph.neighbors(...)` for each seeded workload id to build assistant graph context
- targeted validation in this pass confirmed a bundle with `timeline={"workloads": ["host::db.internal"], "graph_neighbors": []}` and no surface/field rows produced `calls == []` and an empty assistant graph context
- targeted validation in this pass confirmed a bundle with `timeline={"workloads": ["host::db.internal"], "graph_neighbors": [{"workload_id": "web::10.0.0.7:443", "weight": 0.4}]}` called `kernel.graph.neighbors('web::10.0.0.7:443')` instead of `kernel.graph.neighbors('host::db.internal')`
- `skg/core/daemon.py:3520-3567` and `3574-3645` return assistant API `references` derived from that same bundle/context path
- `tests/test_sensor_projection_loop.py:3031-3032` mocks `identity_timeline(...)` in the main assistant-context test and does not exercise the live bundle workload-selection logic
- `tests/test_sensor_projection_loop.py:3076-3133` and `3135-3159` also test `assistant_what_if` / `assistant_explain` by mocking `_assistant_prepare_context(...)`, so the live endpoint path is not covered either
- repo-wide search in this pass found no direct tests for `_assistant_reasoning_bundle(...)`

Impact:

- assistant graph context can omit graph structure for the selected identity when only timeline workloads are known
- assistant summaries can also drift onto second-hop neighbor workloads instead of the selected identity’s own manifestations

Needed follow-up:

- include `timeline["workloads"]` in assistant bundle workload seeding before querying graph neighbors
- add direct regressions for assistant graph-context seeding with empty group/field rows and timeline-only workloads

### MED-68: Assistant target summaries can report zero active paths even when field state exists

Evidence:

- `skg/core/daemon.py:3286-3298` builds target subjects from `groups = _assistant_group_surface(surface.get("workloads") or [])`
- when no measured-surface group exists for the selected identity, that branch creates a fallback group with empty `manifestations` and empty `paths`
- `skg/core/daemon.py:3156-3164` `_assistant_fallback(...)` for `kind == "target"` summarizes from `subject["manifestations"]` and `subject["paths"]`, not from `context["field_state"]`
- targeted validation in this pass confirmed `_assistant_context(...)` can return `field_state["count"] == 1` while `subject["paths"] == []` when `field_surface()` is empty
- the same validation confirmed `_assistant_fallback({... task='target_summary'})` then reports `0 manifestations and 0 active attack-path rows` even though one field-state row exists
- `tests/test_sensor_projection_loop.py:3031-3032` and `3157-3158` mock `_compute_field_state` / `_assistant_prepare_context` and do not exercise this live mismatch between subject paths and field state

Impact:

- assistant target summaries can understate live substrate pressure when measured surface rows are absent or lagging but field-state rows already exist
- operator-facing explanations can therefore describe an identity as having no active paths even while the daemon’s field engine has one

Needed follow-up:

- decide whether target summaries should fall back to field-state rows when subject paths are empty
- add direct regressions for target-summary generation with empty measured surface and non-empty field state

### MED-69: Daemon world manifestations are order-dependent rather than newest-wins

Evidence:

- `skg/core/daemon.py:2126-2148` iterates interp files and dedupes on `(workload_id, attack_path_id)` using `seen`, but never compares timestamps or mtimes before accepting the first row
- targeted validation in this pass monkeypatched `INTERP_DIR.glob("*.json")` to return an older `host::10.0.0.7 / host_ssh_initial_access_v1` interp payload before a newer one, and `_identity_manifestations('10.0.0.7')` returned the older `classification='indeterminate'` / `host_score=0.2` row
- `skg/core/daemon.py:2156-2245` feeds `_identity_manifestations(...)` directly into `_identity_world(...)`
- `skg/core/daemon.py:1528-1551` exposes that world payload directly through `/world/{identity_key}`
- repo-wide search in this pass found no direct behavioral tests for `_identity_manifestations(...)`
- the only opened world-view test at `tests/test_sensor_projection_loop.py:2239` patches `_identity_manifestations` to `[]`

Impact:

- daemon world views can surface stale manifestation classification/score depending on interp iteration order
- operator and assistant consumers of `/world/{identity_key}` can therefore see non-deterministic or stale manifestation state

Needed follow-up:

- make `_identity_manifestations(...)` newest-wins by timestamp or file mtime before deduping
- add direct regressions for duplicate manifestation rows with conflicting recency

### MED-70: Daemon artifact lookup can attribute files by filename token even when payload identity disagrees

Evidence:

- `skg/core/daemon.py:2265-2270` returns `(True, None)` immediately when the raw identity string or normalized token appears in the filename
- only after that shortcut does `skg/core/daemon.py:2272-2291` inspect JSON/NDJSON payload identity
- targeted validation in this pass confirmed `_artifact_matches_identity(Path('observe_db_internal_noise.json'), 'db.internal')` returned `matched == True` with `workload_id == None` even though the payload carried `workload_id='host::other.internal'`
- `skg/core/daemon.py:2295-2325` builds `/artifacts/{identity_key}` directly from `_artifact_matches_identity(...)`
- `skg/core/daemon.py:3348-3369` then feeds `identity_artifacts(...)` directly into assistant context
- repo-wide search in this pass found no direct tests for `_artifact_matches_identity(...)` or `identity_artifacts(...)`

Impact:

- daemon artifact views can attach unrelated files to an identity based only on filename token overlap
- assistant artifact previews can therefore be grounded in the wrong file set

Needed follow-up:

- make payload identity authoritative over filename-token heuristics, or at least require filename matches to be confirmed by payload identity when readable
- add direct regressions for misleading filenames with mismatched payload identities

### MED-71: Daemon world summary counts projection rows as manifestations

Evidence:

- `skg/core/daemon.py:2126-2148` builds `manifestations` as one row per `(workload_id, attack_path_id)`
- targeted validation in this pass confirmed `skg.intel.surface.surface()` also emits one workload row per attack path while preserving a shared `manifestation_key`, so the row-shaped manifestation model is live outside the daemon as well
- `skg/cli/utils.py:592-741` then groups those measured path rows by `identity_key` and dedupes `manifestation_key` values into one CLI subject row
- targeted validation in this pass confirmed `_surface_subject_rows()` collapses two measured path rows sharing `manifestation_key='host::10.0.0.7'` into one subject row with `manifestations == ['host::10.0.0.7']` and merged realized/unknown counts
- `skg/core/daemon.py:2238` then reports `world_summary["manifestation_count"] = len(manifestations)`
- targeted validation in this pass mocked two attack-path rows sharing one `manifestation_key='host::10.0.0.7'` and `_identity_world(...)` returned `manifestation_count == 2` while the unique manifestation count was `1`
- `skg/core/daemon.py:1528-1551` exposes that world summary directly through `/world/{identity_key}`
- `skg/core/daemon.py:1505-1511` also injects `_identity_world(...).get("world_summary", {})` directly into `list_targets()`
- targeted validation in this pass confirmed one `list_targets()` row can expose `manifestations == ['host::10.0.0.7']` from the measured-view index while `world_summary["manifestation_count"] == 2` from `_identity_world(...)`
- repo-wide search in this pass found no direct assertions on `world_summary["manifestation_count"]`
- the opened world-view test at `tests/test_sensor_projection_loop.py:2239` checks only credential/network summary fields and patches `_identity_manifestations` entirely
- the opened target-list test at `tests/test_sensor_projection_loop.py:3598` patches `_identity_world` to a synthetic `{"world_summary": {"service_count": 1}}`

Impact:

- daemon world summaries can overstate how many distinct manifestations an identity currently has
- operator-facing and assistant-facing world summaries can therefore conflate “multiple projected paths on one manifestation” with “multiple manifestations”
- the same overcount can surface in `list_targets()` summaries as well as `/world/{identity_key}`
- target-list payloads can therefore be internally inconsistent: one field reports one manifestation key while the adjacent world summary reports more than one manifestation
- the inconsistency is now structural across operator surfaces: raw measured surface is path-row shaped, CLI subject rows are identity-grouped with deduped manifestations, and daemon world summaries still count path rows as manifestations

### MED-72: Target-list manifestations can disappear while adjacent world summary still reports manifestations

Evidence:

- `skg/core/daemon.py:1443-1499` builds the top-level `manifestations` field in `list_targets()` only from `_view_index()`, which is derived from `field_surface()`
- `skg/intel/surface.py:269-348` emits measured surface rows one per attack path, while `list_targets()` dedupes top-level manifestation keys from those rows
- `skg/cli/utils.py:592-741` shows the same deduped-manifestation aggregation is used by CLI `surface`, `target list`, and `report`
- `skg/core/daemon.py:1505-1511` then injects `_identity_world(...).get("world_summary", {})` independently
- targeted validation in this pass confirmed `list_targets()` returned `manifestations is None` while `world_summary["manifestation_count"] == 1` when `field_surface()` was empty but `_identity_world(...)` reported one manifestation for the same identity
- targeted validation in this pass also confirmed `_surface_subject_rows()` turns two measured surface path rows for one manifestation into one subject row with one manifestation key, so `list_targets()` is currently juxtaposing a deduped manifestation list against a world summary derived from path-shaped manifestation rows
- repo-wide search in this pass found no direct assertions on target-list manifestation presence when measured surface is empty
- the only opened target-list test at `tests/test_sensor_projection_loop.py:3598` patches `_identity_world` and does not exercise the live interaction between measured-view manifestations and world-summary state

Impact:

- target-list payloads can under-report manifested state in their top-level `manifestations` field even while the adjacent world summary reports manifestations
- operator/UI consumers can therefore see self-contradictory target rows whenever measured-view rows lag world-derived manifestation state
- even when measured-view rows exist, the target payload is still combining a deduped manifestation list with a world summary derived from path-shaped rows, which makes the two fields easy to compare incorrectly
- the same aggregation split now extends to CLI surfaces that reuse `_surface_subject_rows()`, so daemon and CLI can both present deduped manifestation keys beside counts that are not at the same aggregation level

Needed follow-up:

- decide whether `list_targets().manifestations` should fall back to world-derived manifestation keys when the measured-view index is empty
- add direct regressions for target rows with empty measured surface but non-empty world manifestations

Needed follow-up:

- decide whether `world["manifestations"]` should stay path-row shaped while `world_summary["manifestation_count"]` counts unique manifestation keys
- add direct regressions for one-manifestation/multi-path cases

## Lower-Risk Open Issues

### LOW-01: Malformed literal directories exist from failed brace expansion

Evidence:

- `/opt/skg/skg-data-toolchain/{adapters`
- `/opt/skg/skg-metacognition-toolchain/{adapters`

Impact:

- inventory tools and reviewers see invalid structural noise

Needed follow-up:

- verify they are unused, then remove deliberately in a cleanup pass

### LOW-10: Assistant API reference counts are preview-sized, not total counts

Evidence:

- `skg/core/daemon.py:3339-3369` truncates assistant artifacts to preview rows before putting them into context, while `timeline["graph_neighbors"]` is also truncated to `limit`
- `skg/core/daemon.py:3350` reads only `identity_artifacts(...).get("artifacts", [])` and drops the upstream `count`
- `skg/core/daemon.py:2818-2824` stores bundle `neighbor_count` and `artifact_count`, but those artifact counts are already based on the truncated preview slice
- `skg/core/daemon.py:3559-3567` and `3608-3616` return `references["graph_neighbor_count"] = len(bundle.graph.neighbors)` and `references["artifact_count"] = len(context["artifacts"])`
- targeted validation in this pass confirmed `assistant_explain(...)` reported `graph_neighbor_count == 2` for a bundle whose `graph.neighbor_count` was `9`, and `artifact_count == 2` for a bundle whose artifact count was `7`
- targeted validation in this pass confirmed `_assistant_context(...)` set `bundle["artifacts"]["count"] == 2` when `identity_artifacts(...)` reported `count == 7` but returned two preview rows
- repo-wide search in this pass found no direct tests for assistant reference-count semantics

Impact:

- assistant bundle and assistant API metadata can both understate how much graph or artifact context was actually available
- UI or operator code consuming only `references` can get a narrower picture than the bundle itself implies

Needed follow-up:

- preserve the true `identity_artifacts(...).count` through assistant context/bundle assembly
- decide whether assistant `references` should report preview counts or total counts
- add direct regressions for assistant bundle artifact counts plus `references.graph_neighbor_count` / `references.artifact_count`

### LOW-11: Public artifact preview is line-bounded but not payload-bounded for JSON files

Evidence:

- `skg/core/daemon.py:3742-3778` presents `_artifact_preview_payload(...)` as a bounded helper and limits NDJSON/text by line count
- `skg/core/daemon.py:3773-3779` handles `.json` by loading the full file and returning it as `rows[0]["data"]`
- `skg/core/daemon.py:3792-3798` exposes that helper directly through `/artifact/preview` with the docstring `Bounded preview of one runtime artifact file.`
- targeted validation in this pass confirmed `_artifact_preview_payload(str(big.json), lines=1)` returned a JSON preview whose `payload.big` string length was `5000`
- repo-wide search in this pass found no direct tests for `_artifact_preview_payload(...)`, `_assistant_compact_artifact_preview(...)`, or `/artifact/preview`

Impact:

- the public preview endpoint can return much larger JSON content than its interface suggests
- operator/UI code may treat it as bounded even though large JSON objects are returned intact

Needed follow-up:

- decide whether JSON previews should be key-bounded only or value-bounded as well
- add direct regressions for bounded JSON preview behavior

### LOW-12: `skg target list` labels `unknown_count` as `E`

Evidence:

- `skg/cli/commands/target.py:233-241` prints the target-list header as `Node  E  Services  Domains`
- `skg/cli/commands/target.py:241` renders that `E` column with `int(row.get('unknown_count', 0))`
- targeted validation in this pass confirmed a mocked row with `unknown_count == 3` printed as:
  - `Node                    E Services                       Domains`
  - `db.internal             3 3306/mysql                     data_pipeline`
- the opened test `tests/test_cli_commands.py:704-742` only asserts that `Node` and `db.internal` appear in output; it does not pin the meaning of the `E` column

Impact:

- the CLI target-list view presents a misleading field label in a core operator surface
- operators can plausibly read unknown-wicket count as energy or some other scalar field quantity

Needed follow-up:

- either rename the column to match the rendered value or print the intended energy-like metric instead
- add a direct CLI assertion for target-list column semantics

### LOW-13: `skg target list` bypasses hydrated surface loading used by `surface` and `report`

Evidence:

- `skg/cli/commands/surface.py:82-90` loads the latest surface through `gravity_runtime._hydrate_surface_from_latest_nmap(surface_path)` before falling back to raw JSON
- `skg/cli/commands/report.py:24-32` uses the same hydration path
- `skg/cli/commands/target.py:226` reads `Path(surface_path).read_text()` directly and does not attempt hydration
- targeted validation in this pass mocked `_hydrate_surface_from_latest_nmap(...)` to return one database target while the on-disk latest-surface JSON contained `{"targets": []}`
- in that setup, `cmd_surface(...)` printed `10.0.0.9  [database]  3306/mysql`, while `cmd_target(target_cmd='list')` rendered only the empty table header
- the opened target-list test `tests/test_cli_commands.py:704-742` patches only `_latest_surface` and does not exercise hydrated-surface parity with `surface` or `report`
- repo-wide search in this pass found no opened direct command tests for `cmd_surface` or `cmd_report`

Impact:

- CLI commands that appear to summarize the same latest surface can disagree about which targets exist before measured-state aggregation even begins
- operator workflows can therefore get different answers from `skg surface`, `skg report`, and `skg target list` on the same repo state

Needed follow-up:

- decide whether `target list` should use the same hydrated surface-loading path as `surface` and `report`
- add a parity regression for the latest-surface loading path across these commands

### MED-73: CLI subject-row merging misses IP/hostname identity aliases

Evidence:

- `skg/cli/utils.py:596-610` builds `target_index` keyed only by exact `identity_key` derived from target `workload_id`, `ip`, or `host`
- `skg/cli/utils.py:615-633` then looks up `target_meta = target_index.get(identity_key, {})` for measured rows using exact `identity_key`
- targeted validation in this pass used:
  - a target-surface row rooted at `ip='10.0.0.9', host='10.0.0.9', hostname='db.internal'`
  - a measured row rooted at `identity_key='db.internal', workload_id='mysql::db.internal:3306::users'`
- `_surface_subject_rows(...)` produced two rows instead of one merged row:
  - one `db.internal` row with manifestations and counts but no services
  - one `10.0.0.9` row with services but no measured workloads
- targeted validation in this pass confirmed `cmd_target(target_cmd='list')` exposes that split directly:
  - `db.internal             1                                data`
  - `10.0.0.9                0 3306/mysql                     data`
- the opened happy-path test `tests/test_cli_commands.py:624-678` avoids this bug by using a target row rooted at `host='db.internal'`
- the opened target-list test `tests/test_cli_commands.py:703-742` only asserts that `db.internal` appears in output and does not assert row count or alias-merge behavior

Impact:

- CLI `surface`, `target list`, and `report` can split one underlying node into separate identity rows when discovery uses an IP subject and measured state uses a hostname/FQDN subject
- one row can carry services with no measured evidence while the other carries measured evidence with no services
- operator workflows can therefore misread the node inventory and under-merge evidence even when alias information is already available

Needed follow-up:

- decide whether `_surface_subject_rows()` should merge target-shell metadata by subject aliases rather than exact identity key only
- add a regression for IP-root target rows plus hostname-root measured rows

### MED-74: Daemon `list_targets()` splits one node into separate IP-root and hostname-root rows

Evidence:

- `skg/core/daemon.py:1475-1486` seeds the target list from `_all_targets_index()` and derives `identity_key` from exact `workload_id`, `ip`, or `host`
- `skg/core/daemon.py:1489-1498` then merges measured-view rows from `_view_index()` by exact `identity_key`
- `skg/core/daemon.py:1441-1471` builds `_view_index()` from `field_surface()` rows keyed by measured `identity_key`
- targeted validation in this pass used:
  - `_all_targets_index()` returning one discovery target rooted at `ip='10.0.0.9', host='10.0.0.9', hostname='db.internal'`
  - `field_surface()` returning one measured row rooted at `identity_key='db.internal', workload_id='mysql::db.internal:3306::users'`
- in that setup, `list_targets()` returned two target payloads instead of one merged row:
  - one `identity_key='10.0.0.9'` row with services
  - one `identity_key='db.internal'` row with manifestations and `fresh_unknown_mass`
- targeted validation in this pass then allowed `_identity_world(...)` to run against a real hostname-root interp artifact and confirmed the split rows carry complementary world state:
  - the `10.0.0.9` row kept `services=[{'port': 3306, 'service': 'mysql'}]` but `world_summary.manifestation_count == 0`
  - the `db.internal` row kept `manifestations=['mysql::db.internal:3306::users']` and `world_summary.manifestation_count == 1` but had `services is None`
- the opened test `tests/test_sensor_projection_loop.py:3558-3611` explicitly codifies the same behavior by asserting that both `db.internal` and `10.0.0.7` rows are present in the result

Impact:

- daemon target inventory can split one underlying node into multiple target payloads when discovery uses an IP identity and measured state uses a hostname/FQDN identity
- one daemon row can carry services while another carries measured manifestations, so later world-summary and assistant logic start from an already fragmented target inventory
- the split also distorts world summaries directly, because the service-bearing row and the manifestation-bearing row each report only half of the node's state
- the split is not just untested drift; the opened regression currently expects it

Needed follow-up:

- decide whether `list_targets()` should merge discovery and measured rows by subject aliases rather than exact identity key only
- update the opened daemon regression once the intended identity-merge behavior is defined

### MED-75: `_identity_profile()` matches discovery evidence by literal identity strings and fragments profile state

Evidence:

- `skg/core/daemon.py:1577-1597` already defines `_identity_aliases(...)` and `_identity_matches(...)` helpers for parsed identity-aware matching
- `skg/core/daemon.py:1644-1670` globs discovery artifacts using literal `identity_key` and normalized-token filename patterns such as `gravity_data_{identity_key}_*.ndjson`
- `skg/core/daemon.py:1677-1684` then filters loaded events with `if identity_key not in wid and identity_key != target_ip: continue`
- targeted validation in this pass wrote one hostname-keyed artifact `gravity_data_db.internal_a.ndjson` carrying a `DP-10` event for `mysql::db.internal:3306::users`
- with `DISCOVERY_DIR` patched to that temp directory:
  - `_identity_profile('db.internal')` returned `datastore_access=['MySQL accessible as root — database access confirmed']`, one `datastore_observations` row, and `evidence_count == 1`
  - `_identity_profile('10.0.0.9')` returned empty datastore evidence and `evidence_count == 0`
- targeted validation in this pass also wrote one hostname-keyed `gravity_ssh_db.internal_keys.ndjson` artifact carrying `HO-13` key-file evidence for `host::db.internal`
- with `DISCOVERY_DIR` patched to that temp directory:
  - `_identity_profile('db.internal')` returned `ssh_keys=['/home/app/.ssh/id_rsa']`
  - `_identity_profile('10.0.0.9')` returned `ssh_keys=[]`
- this compounds `MED-74`, because daemon `list_targets()` can already split one underlying node into `10.0.0.9` and `db.internal` rows before calling `_identity_profile(...)`
- the opened world-view test `tests/test_sensor_projection_loop.py:2235-2250` patches `_identity_profile(...)`, so the live profile-matching seam is not directly covered
- repo-wide search in this pass found no opened direct tests for daemon shared-credential relation behavior built on `_identity_profile(...)`

Impact:

- daemon world views can lose profile evidence simply because one sibling row is IP-rooted while the discovery evidence is hostname-rooted
- service-bearing rows and profile-bearing rows can diverge even further than the already-confirmed service/manifestation split
- assistant and world-summary consumers built on `_identity_profile(...)` can therefore inherit a second layer of fragmented node state
- `_identity_relations(...)` can also diverge between the sibling rows because it re-enters `_identity_profile(...)` for shared-credential edges while hostname-root rows with no IP also lose meaningful subnet reasoning

Needed follow-up:

- decide whether `_identity_profile()` should match by parsed identity aliases rather than literal string inclusion
- add a direct regression for hostname-keyed discovery artifacts against IP-root daemon targets

### MED-76: `identity_artifacts()` and `identity_timeline()` miss alias-equivalent history

Evidence:

- `skg/core/daemon.py:1577-1597` already defines `_identity_aliases(...)` and `_identity_matches(...)` helpers for parsed identity-aware matching
- `skg/core/daemon.py:2261-2291` implements `_artifact_matches_identity(...)` by checking filename tokens first and then requiring `parse_workload_ref(workload_id).get("identity_key") == identity`
- `skg/core/daemon.py:2298-2326` builds `identity_artifacts(...)` directly from `_artifact_matches_identity(...)`
- `skg/core/daemon.py:2337-2355` builds `identity_timeline(...)` workloads only when `parse_workload_ref(workload_id).get("identity_key") == identity_key`
- targeted validation in this pass used hostname-root artifacts for `mysql::db.internal:3306::users` plus a mocked feedback backend
- with `EVENTS_DIR`, `INTERP_DIR`, `SKG_STATE_DIR`, and `kernel.feedback` patched:
  - `identity_artifacts('db.internal')` returned `count == 2` with `['mysql_interp.json', 'gravity_data_db.internal_a.ndjson']`
  - `identity_artifacts('10.0.0.9')` returned `count == 0`
  - `identity_timeline('db.internal')` returned `workloads == ['mysql::db.internal:3306::users']` and `snapshot_count == 1`
  - `identity_timeline('10.0.0.9')` returned `workloads == []` and `snapshot_count == 0`
- repo-wide search in this pass found no opened direct tests for `identity_artifacts(...)` or `identity_timeline(...)`

Impact:

- daemon artifact views and identity timelines can disappear when the selected identity is an IP-root sibling of hostname-root measured history
- assistant context built on artifacts/timeline can therefore lose grounding even when relevant runtime history exists on disk
- the daemon identity fragmentation cluster now spans target rows, profiles, relations, artifacts, and timelines

Needed follow-up:

- decide whether `identity_artifacts()` and `identity_timeline()` should match through parsed identity aliases rather than exact identity equality
- add direct regressions for hostname-root artifacts and timelines queried through IP-root daemon identities

### MED-77: `_assistant_context()` misses alias-equivalent target and field rows

Evidence:

- `skg/core/daemon.py:1532-1547` already resolves `/world/{identity_key}` target rows through `_identity_matches(...)`
- `skg/core/daemon.py:3274-3281` builds `targets_by_identity` keyed only by exact `identity_key` / `ip` / `host` strings
- `skg/core/daemon.py:3287-3296` then resolves target selections with `targets_by_identity.get(identity_key, {})` and `groups.get(identity_key)`
- `skg/core/daemon.py:3338-3346` filters field rows by exact `row.get("identity_key") == identity_key`
- targeted validation in this pass used split daemon rows:
  - one `identity_key='10.0.0.9'` row with services and no manifestations
  - one `identity_key='db.internal'` row with manifestations and no services
  - one measured field row under `identity_key='db.internal'`
- with `Req(kind='target', id='10.0.0.9', identity_key='10.0.0.9')`, `_assistant_context(...)` returned:
  - `subject.manifestations == []`
  - `subject.paths == []`
  - `field_path_count == 0`
  - `field_state.count == 0`
- the opened assistant-context regression `tests/test_sensor_projection_loop.py:2895-3052` uses one fully aligned identity (`10.0.0.7`) across target rows, field rows, timeline, and artifacts, so it does not exercise alias-split selection

Impact:

- assistant target summaries can lose manifestations and field paths simply because the selected identity is the IP-root sibling of a hostname-root measured row
- this compounds the daemon identity-fragmentation cluster by pushing exact-key splits directly into assistant reasoning inputs
- the daemon already has alias-aware matching in some endpoints, so assistant behavior is now inconsistent with the broader daemon shell

Needed follow-up:

- decide whether `_assistant_context()` should resolve target rows, groups, and field rows through alias-aware identity matching rather than exact string keys
- add a regression for assistant target selection when daemon target rows and measured rows use alias-equivalent identities

### MED-78: `/world/{identity_key}` selects alias-matched targets but still builds world state with the raw requested identity

Evidence:

- `skg/core/daemon.py:1532-1547` selects a target row for `/world/{identity_key}` via `_identity_matches(...)`
- `skg/core/daemon.py:1548` then calls `_identity_world(identity_key, target)` with the original requested identity, not the matched target row's identity
- targeted validation in this pass monkeypatched `_identity_world(...)` to echo inputs; with `identity_world('10.0.0.9')` and a matched target row rooted at `identity_key='db.internal'`, the endpoint passed `identity_key_seen='10.0.0.9'` and `target_seen.identity_key='db.internal'`
- targeted validation in this pass patched `list_targets()` to return one target row rooted at `identity_key='db.internal', ip='10.0.0.9', hostname='db.internal'`
- targeted validation in this pass also supplied a hostname-root interp payload for `mysql::db.internal:3306::users`
- with `identity_world('10.0.0.9')`, the endpoint returned:
  - `service_count == 1`
  - `services == [{'port': 3306, 'service': 'mysql'}]`
  - `manifestation_count == 0`
  - `manifestations == []`
- repo-wide search in this pass found no opened direct tests for the `/world/{identity_key}` endpoint path; the only opened world-view test `tests/test_sensor_projection_loop.py:2235-2250` exercises `_identity_world(...)` directly with one fully aligned identity

Impact:

- `/world/{identity_key}` can return a mixed payload that combines target services from an alias-matched row with profile/manifestation state from the wrong identity variant
- operator/UI consumers can therefore see a world view that looks partially populated but still under-reports manifestations for the same node
- this deepens the daemon identity-fragmentation cluster even in the endpoint that already appears to be alias-aware

Needed follow-up:

- decide whether `/world/{identity_key}` should canonicalize to the matched target identity before calling `_identity_world(...)`
- add a direct endpoint regression for IP-root requests that alias-match hostname-root target rows and artifacts

### MED-79: `_resolution_hint(...)` does not recognize active web wicket prefixes

Evidence:

- `skg/core/daemon.py:1059-1075` maps web hints under prefix `WE`, while active runtime web wickets are `WB-*` (catalog/projector) and `WEB-*` (live web sensor)
- targeted validation in this pass confirmed `_resolution_hint('WB-01')` returns generic fallback text, not a web-specific hint
- targeted validation in this pass confirmed `_resolution_hint('WEB-01')` also returns generic fallback text
- targeted validation in this pass confirmed `_compute_field_state_inner()` on a web path with unknown `WB-01` stores `resolution_required['WB-01'] = 'Sensor sweep required ...'` generic fallback text
- repo-wide search in this pass found no direct tests for `_resolution_hint(...)` or web-specific `resolution_required` hint mapping

Impact:

- daemon field-state guidance under-reports actionable web-specific resolution steps even when unknown web wickets are explicit
- assistant and operator consumers of `resolution_required` inherit weaker guidance for web unknowns than for other domains

Needed follow-up:

- align `_resolution_hint(...)` web prefix handling with active `WB-*` / `WEB-*` vocabularies
- add direct regression coverage for web unknown-node hint mapping in daemon field-state output

### MED-80: `DataSensor` runtime paths still dereference undefined private attributes

Evidence:

- `skg/sensors/data_sensor.py:174` writes to `self._events_dir`, but `BaseSensor` exposes `self.events_dir`; `_events_dir` is never initialized in `DataSensor`
- `skg/sensors/data_sensor.py:206` dereferences `self._graph` directly in `_register_bonds()` without guarding missing attribute
- `skg/sensors/data_sensor.py:209` reads topology from `self._cfg`, but the class initializes only `self.cfg`
- targeted validation in this pass confirmed `DataSensor.run()` with a stubbed `profile_table(...)` raises `AttributeError: 'DataSensor' object has no attribute '_events_dir'`
- targeted validation in this pass confirmed direct `sensor._register_bonds()` raises `AttributeError: 'DataSensor' object has no attribute '_graph'`
- `tests/test_runtime_regressions.py:914-916` currently patches `sensor._graph` and `sensor._cfg` manually before exercising `_register_bonds()`, which masks the default-object-path defect

Impact:

- data sensor collection can fail at runtime on a normal object without external monkeypatching
- bond registration depends on hidden/private attribute injection not provided by the base sensor contract

Needed follow-up:

- align `DataSensor` to canonical base attributes (`events_dir`, `cfg`) and guard optional graph access safely
- add direct regression coverage for `DataSensor.run()` and `_register_bonds()` on an unpatched sensor instance

### MED-81: `zero_day_detector` root/path and coverage checks are inconsistent with live inputs

Evidence:

- `skg/sensors/zero_day_detector.py:33` sets `SKG_HOME = Path(__file__).resolve().parents[3]`, which resolves to `/opt` from `/opt/skg/skg/sensors/zero_day_detector.py` instead of repo root `/opt/skg`
- `skg/sensors/zero_day_detector.py:274` therefore targets catalog writes under `/opt/<toolchain>/contracts/catalogs` rather than `/opt/skg/<toolchain>/contracts/catalogs`
- `skg/sensors/zero_day_detector.py:127-150` checks product/version coverage by searching strings like `"apache 2.4.49"` inside `domain_wickets`
- `skg-gravity/gravity_field.py:7274-7277` passes `domain_wickets` from `load_all_wicket_ids()`, i.e. wicket-id sets (e.g., `WB-01`) rather than description strings
- targeted validation in this pass confirmed `detect_version_gaps([Apache/2.4.49], {'web': {'WB-01'}} ...)` reports a gap, while a synthetic description string containing `apache 2.4.49` suppresses the gap
- targeted validation in this pass confirmed module constant `SKG_HOME` currently resolves to `/opt`

Impact:

- auto-generated zero-day catalogs can be written outside the canonical repo toolchain trees
- version-gap detection can over-trigger because it compares product/version text against wicket IDs

Needed follow-up:

- correct `SKG_HOME` derivation to repo root and validate catalog output paths
- compare coverage against catalog metadata/labels explicitly rather than raw wicket-id tokens

### MED-82: `process_probe` emits literal template expressions in key detail strings

Evidence:

- `skg/sensors/process_probe.py:153-156`, `164-167`, and `175-178` split f-strings with non-f literal segments that contain inline conditional templates
- targeted validation in this pass confirmed emitted `PR-03`, `PR-09`, and `PR-10` details include literal text like `{'ASLR off ...' if aslr_disabled else 'ASLR enabled'}` instead of resolved prose
- repo-wide search in this pass found no direct tests asserting detail-string formatting for `probe_process_surface(...)`

Impact:

- operator-facing process-probe evidence is degraded and can look like template source code rather than interpreted findings
- downstream report consumers parsing detail text can inherit noisy/unreadable evidence strings

Needed follow-up:

- normalize these detail builders to proper evaluated strings
- add focused probe-helper formatting coverage for emitted details

### MED-83: `MsfSensor` tracks `seen_sessions` but does not suppress repeat session emission

Evidence:

- `skg/sensors/msf_sensor.py:420` accepts a `seen` set in `_drain_sessions(...)`
- `skg/sensors/msf_sensor.py:427-440` always emits `HO-10` events for listed sessions and only then updates `seen`
- `skg/sensors/msf_sensor.py:586-593` passes persisted `seen_sessions` into `_drain_sessions(...)` each sweep, implying intended dedupe
- targeted validation in this pass confirmed `_drain_sessions(...)` emits the same session events even when `seen` already contains that session key (`len(first)==1`, `len(second)==1`)

Impact:

- recurring sweeps can repeatedly emit identical session-derived host events
- confidence/support accumulation can over-count persistent sessions as fresh evidence

Needed follow-up:

- gate session emission on unseen session keys or explicit session-change signals
- add direct regression coverage for repeated `_drain_sessions(...)` calls with stable session lists

### MED-84: Multiple gravity adapters call `envelope(...)` without required `pointer`

Evidence:

- `skg-gravity/adapters/impacket_post.py:49-64` calls `envelope(...)` without a `pointer`
- `skg-gravity/adapters/ldap_enum.py:116-131` and subsequent event builds do the same
- `skg-gravity/adapters/openssl_tls.py:84-99` and `_check_cert(...)` event builds omit `pointer`
- `skg-gravity/adapters/smbclient.py:73-88` and subsequent event builds omit `pointer`
- `skg/sensors/__init__.py:73-88` defines `envelope(...)` with required positional `pointer`
- targeted validation in this pass confirmed all four adapters raise `TypeError: envelope() missing 1 required positional argument: 'pointer'` on reachable event-emission paths
- current opened tests in `tests/test_runtime_regressions.py:1762-1782` for `smbclient.py` and `openssl_tls.py` are string-level wicket-ID checks and do not execute adapter event construction

Impact:

- these gravity adapters can fail at runtime when they attempt to emit events
- intended kernel evidence from impacket/LDAP/TLS/SMB adapter paths can be dropped entirely

Needed follow-up:

- add canonical `pointer` fields to all adapter envelope calls
- add direct execution-path tests for these adapters, not just source-string assertions

### MED-85: `db_profiler.profile_table(...)` accepts `attack_path_id` but never emits it

Evidence:

- `skg-data-toolchain/adapters/db_profiler/profile.py:841-845` accepts `attack_path_id` in `profile_table(...)`
- repo-wide search in this pass found no use of `attack_path_id` in emitted payloads or event builders; `_ev(...)` payload at `profile.py:86-93` lacks `attack_path_id`
- `skg/sensors/data_sensor.py:148` forwards source-config `attack_path_id` into `profile_table(...)`
- targeted runtime validation in this pass called `profile_table(..., attack_path_id='custom_path_v9')` and confirmed emitted events contain no `payload.attack_path_id`

Impact:

- data-source-specific attack-path routing intent is dropped before projection
- per-source path semantics in `data.sources[*].attack_path_id` are effectively ignored

Needed follow-up:

- carry `attack_path_id` through `_ev(...)` payloads and check outputs
- add direct regression ensuring configured data-source attack-path ids survive into emitted events

### MED-86: `feeds/nvd_ingester.py` dedupes CVE lookup by service string across all targets, dropping per-target emission

Evidence:

- `feeds/nvd_ingester.py:454-465` tracks a global `seen_services` set and `continue`s before calling `ingest_service(...)` for repeated service strings
- `feeds/nvd_ingester.py:464` passes the current target IP into `ingest_service(...)`, so skipping the call also skips target-scoped CVE event emission
- targeted validation in this pass monkeypatched `ingest_service(...)` and ran `ingest_from_surface(...)` with two targets sharing banner `Apache/2.4.49`; exactly one call was made, only for the first target (`10.0.0.1`)

Impact:

- repeated service versions on additional targets can be silently skipped
- CVE observation coverage can under-report target scope in multi-host surfaces

Needed follow-up:

- cache API query responses separately from target emission, or dedupe by `(target, service)` instead of only `service`
- add a direct regression for multi-target surfaces where two targets expose the same service version

### MED-87: `skg_paper_evidence.py` section C is stale against current `WorkloadGraph` coupling API

Evidence:

- `skg_paper_evidence.py:353-357` reads `wg.INTRA_TARGET_COUPLING` to compute expected propagation deltas
- targeted runtime validation in this pass (`python skg_paper_evidence.py --out /tmp/skg_evidence_run --quiet`) failed section `C_propagation` with `'WorkloadGraph' object has no attribute 'INTRA_TARGET_COUPLING'`
- the same run completed other sections and summarized one issue, confirming this is an active section-level runtime break rather than a full-script startup failure

Impact:

- paper-evidence generation currently produces partial output with a failed cross-domain propagation section
- empirical figures and summary claims tied to section C can be missing or stale

Needed follow-up:

- align section C with the live `WorkloadGraph` coupling interface
- add a focused script-level regression that asserts section C executes successfully against the current graph API

### LOW-02: Gravity loop comments no longer describe the runtime cleanly

Evidence:

- `skg/core/daemon.py:645-646` says gravity loop logic is used inline to avoid subprocess overhead and share state, but overall runtime architecture still includes externalized gravity components and hybrid invocation paths

Impact:

- comments overstate unification

### LOW-03: Some docs are skeletal or lagging the code

Likely current authority:

- `README.md`
- `ENGAGEMENT.md`
- `docs/SKG_ARCHITECTURE_SYNTHESIS_20260328.md`
- `docs/SKG_CANONICAL_RUNTIME_MAP.md`
- `docs/SKG_RUNTIME_UNIFICATION_PLAN.md`
- `docs/SKG_AI_ASSISTANT_CONTRACT.md`
- `docs/SKG_Work3_Final.md`
- `docs/SKG_Work4_Final.md`

Likely stale, duplicate, or too skeletal to treat as primary:

- `docs/SKG_CANONICAL_DATA_MODEL.md`
- `docs/SKG_RUNTIME_ARCHITECTURE.md`
- `docs/SKG_REFERENCE_DIRECTORY_LAYOUT.md`
- `docs/SKG_INFORMATION_ENERGY_AND_GRAVITY_MODEL.md`
- `docs/SKG_CLOSED_OBSERVATION_LOOP.md`
- `docs/SKG_STATE_TRANSITION_MODEL.md`
- `docs/SKG_IDENTITY_NODE_MANIFESTATION_MODEL.md`
- `docs/SKG_INSTRUMENT_SUPPORT_MODEL.md`
- `docs/SKG_INFORMATION_FOLDS_MODEL.md`

### LOW-04: Duplicate FastAPI route definition exists for `/delta/workloads`

Evidence:

- `skg/core/daemon.py:4146-4152` defines `@app.get("/delta/workloads")` twice with identical bodies

Impact:

- route registration is unnecessarily ambiguous
- future edits can silently diverge while still appearing to touch the same endpoint

Needed follow-up:

- deduplicate the route and add direct endpoint coverage

### LOW-05: `skg.intel.__init__` still names an old forge module

Evidence:

- `skg/intel/__init__.py:6-8` still documents `toolchain_forge.py`
- the live implementation is the `skg/forge/` package, not `skg/intel/toolchain_forge.py`

Impact:

- module-level package documentation sends readers to a non-existent or obsolete name

### LOW-06: `cmd_proposals` has a dead toolchain maturity-display branch

Evidence:

- `skg/cli/commands/proposals.py:447-455` truncates `proposal_kind` to `[:14]` before comparing it to `"toolchain_gener"`
- targeted shell validation in this pass confirmed `"toolchain_generation"[:14] == "toolchain_gene"`, so the comparison can never be true

Impact:

- toolchain proposal rows never show the intended maturity suffix in `skg proposals list`

Needed follow-up:

- compare the untruncated `proposal_kind` or use the actual truncated literal consistently

### LOW-07: `cmd_check` validates WinRM support with the wrong import name

Evidence:

- `skg/cli/commands/check.py:44-45` tries to validate WinRM support via `__import__("pywinrm")`
- live runtime code imports `winrm` in `skg/sensors/ssh_sensor.py:201` and `skg-host-toolchain/adapters/winrm_collect/parse.py:245`
- targeted import validation in this pass confirmed `winrm` imports successfully while `pywinrm` raises `ModuleNotFoundError`

Impact:

- `skg check` can falsely report WinRM support missing even when the runtime dependency is installed and usable

Needed follow-up:

- validate the runtime import name `winrm` instead of the package-install name `pywinrm`

### LOW-14: `binary_analysis` shim points at a non-existent gravity path

Evidence:

- `skg-binary-toolchain/adapters/binary_analysis/__init__.py:11` inserts `Path(__file__).resolve().parents[4] / "skg-gravity"` into `sys.path`
- from `/opt/skg/skg-binary-toolchain/adapters/binary_analysis/__init__.py`, `parents[4]` resolves to `/opt`, so the inserted path becomes `/opt/skg-gravity`
- targeted validation in this pass confirmed `/opt/skg-gravity` does not exist while the real path is `/opt/skg/skg-gravity`

Impact:

- import behavior for `analyze_binary` can depend on ambient caller `sys.path`/working directory instead of the intended shim path

Needed follow-up:

- align the shim to repo root (`parents[3]`) or import via explicit module loading from `SKG_HOME`

### LOW-15: `forge_staging` web/nginx SSH adapters are template placeholders that never consume their own collected keys

Evidence:

- `forge_staging/skg-nginx-toolchain/adapters/ssh_collect/parse.py:162-164` collects keys `ss`, `ps`, and `find`, while checks at `:67`, `:84`, `:101`, and `:118` look for `nginx_*` keys that are never set
- targeted validation in this pass monkeypatched `emit(...)` and ran `run_checks(...)` with populated `ss`/`ps`/`find`; all wickets were emitted as `unknown` with detail `not collected`
- `forge_staging/skg-web-toolchain/adapters/ssh_collect/parse.py:144` collects only `nvd_feed__cve_2007_4`, while checks at `:67`, `:84`, and `:101` look for `target_*` / `apache_*` keys that are never set
- targeted validation in this pass confirmed all web staged wickets also emit `unknown` with detail `not collected`

Impact:

- staged parser outputs are currently non-informative even when collection data exists
- if these staged files are promoted without rewrite, they can introduce silent false-indeterminate behavior

Needed follow-up:

- keep `forge_staging` explicitly non-canonical until generated checks are wired to collected keys
- require direct execution tests before promoting staged adapters into canonical toolchain paths

### LOW-16: `Silver` legacy scanner utilities have brittle resolver/Shodan handling on ordinary inputs

Evidence:

- `Silver/core/resolver.py:10` uses `socket.gethostbyaddr(hostname)` in forward-resolution flow; targeted validation in this pass showed `resolve('example.com')` returning `''`
- `Silver/modules/shodan.py:17` checks `'\"No information available\"' in data` where `data` is a dict, and `:19` then dereferences `data['vulns']`
- targeted validation in this pass (with `PYTHONPATH=Silver`) returned `KeyError: 'vulns'` for an InternetDB-style no-info payload `{'detail': 'No information available'}`

Impact:

- the legacy scanner can drop valid hostname targets and crash on routine Shodan no-info responses
- results from this auxiliary scanner are currently unreliable without caller-side guards

Needed follow-up:

- treat `Silver/` as non-canonical tooling unless hardened and tested
- if retained, align resolver logic to forward lookup and harden Shodan response parsing for missing keys

## Missing Tests / Validation Gaps

- No obvious focused test for `/collect` single-target mode and `auto_project`.
- No obvious focused test for `collect_host()` success semantics when `sensor.run()` emits zero events.
- No obvious end-to-end test for live web sensor output against the checked-in web projector/catalog.
- No obvious test for CLI web observe writing to `DISCOVERY_DIR` vs measured `EVENTS_DIR`.
- No obvious test for run-scoped auto-projection file selection via `since_run_id`.
- Install/bootstrap scripts are not obviously covered by maintained tests.
- Auxiliary/generated toolchains need explicit runtime validation beyond catalog/golden inspection.
- No direct tests were found for `skg.training.corpus`, `skg.training.scheduler`, or `skg.training.trainer`.
- `skg.intel.engagement_dataset` only surfaced in CLI mocking coverage during this pass; no direct dataset-build or integrity-analysis tests were found.
- No direct tests were found for proposal corpus hook side effects or duplicate-example prevention.
- No direct behavioral tests were found for `cmd_report`, `cmd_calibrate`, or `cmd_proposals`.
- `cmd_engage` only has a missing-subcommand usage test; build/analyze/report/clean behavior is not directly covered.
- No direct behavioral tests were found for `cmd_surface`, `cmd_web_view`, `cmd_status`, `cmd_start`, `cmd_stop`, `cmd_mode`, `cmd_identity`, `cmd_field`, or `cmd_gravity`.
- No direct tests were found for `skg-host-toolchain/adapters/msf_session/parse.py`.
- No direct behavioral tests were found for `cmd_resonance`, `cmd_derived`, `cmd_aprs`, `cmd_escape`, `cmd_lateral`, or `cmd_catalog`.
- `tests/test_dark_hypothesis_sensor.py` does not cover built-in toolchain discovery or shared proposal-lifecycle integration.
- No direct parser/behavior test was found for `skg field` on active non-host domains such as `binary`.
- No direct CLI test was found for the resonance prompt-mode helper workflow, and current parser coverage does not pin the documented `draft-prompt` / `draft-accept` mismatch.
- `tests/test_ollama_backend.py` does not cover backend availability checks, model selection, generation, or status reporting.
- No direct tests were found for `draft_prompt()` or `draft_accept()` against the real `ResonanceEngine.surface()` output shape.
- No direct tests were found for standalone `skg.resonance.cli` behavior, including the broken `drafts` path.
- No direct tests were found for `ResonanceEngine.surface()` / `save_draft()` or for resonance ingester adapter/domain completeness.
- No direct tests were found for observation-memory separation across different workloads that share one wicket/domain.
- No direct tests were found for `skg.resonance.embedder`, including TF-IDF fallback stability under incremental ingest.
- No direct tests were found for `DeltaStore.calibrate_confidence_weights()` on real transition data.
- No direct tests were found for `skg.catalog.compiler`.
- No direct tests were found for `skg-gravity/gravity_web.py` or `skg-gravity/exploit_proposals.py`.
- No direct tests were found for the `db_discovery` DE-event envelope contract.
- No direct tests were found for HTTP-only device handling in `skg-iot_firmware-toolchain/adapters/firmware_probe/probe.py`.
- No direct tests were found for the duplicate IoT firmware adapter surface in `skg-iot_firmware-toolchain/adapters/firmware_probe/__init__.py`.
- No direct tests were found for sheaf-import behavior in generated projectors that currently rely on `parents[4]` repo-root shims.
- No direct tests were found for APRS catalog-path compatibility against the current toolchain naming convention.
- No local tests were found under `skg-supply-chain-toolchain/`, despite the active `sbom_check` adapter and projector.
- No local tests were found under `skg-nginx-toolchain/`; current nginx behavior is defined by adapter/projector code and catalog only.
- No local tests were found under `skg-ai-toolchain/`, `skg-metacognition-toolchain/`, or `skg-web-toolchain/`; those roots currently rely on code/catalog review rather than toolchain-local validation.
- `skg-data-toolchain/tests/` currently contains only an empty `__init__.py`.
- No direct tests were found for `skg-metacognition-toolchain/adapters/confidence_elicitation/parse.py`, `known_unknown/parse.py`, `review_revision/parse.py`, or `projections/metacognition/run.py`; current metacognition references in `tests/test_sensor_projection_loop.py` only cover proposal metadata.
- No direct tests were found for `skg-web-toolchain/adapters/web_active/auth_scanner.py`, `gobuster_adapter.py`, `nikto_adapter.py`, `sqlmap_adapter.py`, or `transport.py`.
- No direct tests were found for `skg-web-toolchain/adapters/ssh_collect/parse.py`, even though it still lives under the canonical web toolchain tree.
- No direct tests were found for staged adapter behavior in `forge_staging/skg-nginx-toolchain/adapters/ssh_collect/parse.py` or `forge_staging/skg-web-toolchain/adapters/ssh_collect/parse.py`.
- No direct tests were found for default `DataSensor.run()` behavior without manual `_graph` / `_cfg` injection or `_events_dir` monkeypatching.
- No direct tests were found for `skg.sensors.zero_day_detector` root-path resolution (`SKG_HOME`) or version-gap matching against live wicket-id sets.
- No direct tests were found for `probe_process_surface(...)` detail-string formatting on `PR-03`, `PR-09`, and `PR-10`.
- No direct tests were found for `MsfSensor._drain_sessions(...)` dedupe behavior against persisted `seen_sessions`.
- No direct execution-path tests were found for `skg-gravity` adapters `impacket_post.py`, `ldap_enum.py`, `openssl_tls.py`, or `smbclient.py`; current coverage around these adapters is mostly static/source-level assertions.
- No direct regression was found that `db_profiler.profile_table(..., attack_path_id=...)` preserves `attack_path_id` in emitted event payloads.
- No direct regression was found for `feeds/nvd_ingester.py` multi-target behavior when two targets share one service banner/version.
- No direct regression was found that `skg_paper_evidence.py` section C executes against the current `WorkloadGraph` coupling interface.
- No direct test was found for `skg-binary-toolchain/adapters/binary_analysis/__init__.py` shim-path correctness (`parents[4]` vs repo-root path).
- No direct behavioral tests were found for `skg-aprs-toolchain/adapters/config_effective/parse.py` or `skg-aprs-toolchain/adapters/net_sandbox/parse.py`; the current APRS golden is only a three-event projector check.
- No direct behavioral tests were found for `skg-ad-lateral-toolchain/adapters/ldapdomaindump/parse.py` or `skg-ad-lateral-toolchain/adapters/manual/parse.py`; the current AD lateral golden is effectively BloodHound-only.
- No direct tests were found for `skg-ai-toolchain/adapters/ai_probe/probe.py`, `skg-nginx-toolchain/projections/nginx/run.py`, `skg-metacognition-toolchain/projections/metacognition/run.py`, or the stale root `skg-web-toolchain/projections/run.py`.
- No direct tests were found for `skg-gravity/gravity_field.py::_exec_ai_probe` or the gravity AI execution-to-projection path.
- No direct behavioral tests were found for `skg-binary-toolchain/adapters/capa_analysis/parse.py`, `skg-binary-toolchain/adapters/angr_symbolic/parse.py`, or `skg-binary-toolchain/adapters/frida_trace/parse.py`.
- No direct behavioral tests were found for `skg-host-toolchain/adapters/ssh_collect/parse.py`, `skg-host-toolchain/adapters/winrm_collect/parse.py`, or `skg-host-toolchain/adapters/nmap_scan/parse.py`; the checked-in host golden only covers the projector path.
- No CLI coverage exists for the advertised `skg data redteam` path because the parser does not expose it.
- No direct regression was found for default transition ingest in `build_engagement_db()`.
- No direct regression was found for DP-05 / `engage clean` behavior under raw-vs-prefixed workload-id drift.
- Full daemon/UI/operator flows were not validated in this pass.

## Historical Issues Now Covered by Current Tests

These should not be re-raised as current defects without new evidence:

- projector file separation per attack path/run
- AD same-domain inference requiring explicit metadata
- sensor loop overlap serialization
- explicit same-database bond weighting in data sensor

Those areas now have passing focused regressions in the current test suite.

## Blocked Deeper Validation

The following would require a later targeted pass, likely with controlled runtime setup:

- fresh-host bootstrap validation
- live daemon/UI interaction validation
- live target collection validation
- auxiliary/generated toolchain end-to-end validation
- full authority-boundary repair from discovery shell to measured-state runtime

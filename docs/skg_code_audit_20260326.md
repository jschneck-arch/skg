# SKG Code Audit

Date: 2026-03-26

Scope reviewed:
- 252 Python files under `/opt/skg`
- runtime/config/docs in `/opt/skg/config`, `/opt/skg/docs`, `/opt/skg/tests`
- critical execution paths traced through daemon boot, sensor sweep, projector ingestion, graph propagation, calibration, forge proposals, and exploit proposal generation
- verification run: `python -m compileall /opt/skg/skg /opt/skg/tests` passed; `pytest -q` passed `173 passed, 6 skipped, 3 warnings`

## Executive Summary

SKG's core runtime is not broadly broken. The daemon boots, sensors run, projections are computed, and the test suite passes. The architecture is generally sound. The main problems are concentrated in persistence correctness, control-path integration, and concurrency boundaries. Those issues are serious enough to undermine operator trust and make autonomous operation unreliable in edge cases.

Must-fix issues:
- projection outputs overwrite each other in `/opt/skg/skg/sensors/projector.py`
- coverage gaps are tracked globally by service in `/opt/skg/skg/intel/gap_detector.py`
- calibration is split across incompatible implementations in `/opt/skg/skg/cli/commands/report.py`, `/opt/skg/skg/sensors/confidence_calibrator.py`, `/opt/skg/skg/intel/confidence_calibrator.py`, and `/opt/skg/skg/sensors/context.py`
- `same_domain` inference in `/opt/skg/skg/graph/__init__.py` can create spurious cross-target edges

High-priority reliability issues:
- sensor sweeps can overlap without a concurrency guard in `/opt/skg/skg/sensors/__init__.py`
- proposal artifacts are mutable in `/opt/skg/skg/assistant/action_proposals.py` and `/opt/skg/skg-gravity/cred_reuse.py`
- dynamic toolchain registration is only partial in `/opt/skg/skg/core/domain_registry.py`, `/opt/skg/skg/sensors/projector.py`, and `/opt/skg/skg/sensors/__init__.py`
- data-sensor bond strength is ignored between `/opt/skg/skg/sensors/data_sensor.py` and `/opt/skg/skg/graph/__init__.py`
- malformed JSON is frequently handled by silent reset or silent skip in `/opt/skg/skg/intel/gap_detector.py`, `/opt/skg/skg/sensors/projector.py`, and `/opt/skg/skg/temporal/feedback.py`

What is working well:
- path management is mostly consistent through `/opt/skg/skg/core/paths.py`
- daemon domain discovery safely filters incomplete toolchains
- built-in projection dispatch is implemented and covered by tests
- the proposal queue uses unique IDs and clean archive/review flows
- gravity runtime helper paths have direct test coverage
- `/opt/skg/README.md` is broadly aligned with the actual daemon-native footprint

Recommended next steps:
- fix the four critical issues first: projection collisions, per-target gap tracking, calibration unification, and `same_domain` inference
- add a sensor-sweep lock and make assistant artifacts immutable
- complete toolchain registration so the registry is the only source of truth
- add tests for filename uniqueness, per-target gap semantics, calibration loading, concurrency, immutability, and graph edge correctness
- update the papers and docs to match the current runtime reality

## Summary

The codebase is not broadly broken. Core runtime paths boot, project, and test successfully, and the repository has a meaningful test suite. The main problems are concentrated in persistence correctness and integration boundaries rather than basic syntax or import failures.

The highest-risk defects are:
- projection artifacts are lossy and can overwrite each other
- coverage gaps are tracked globally by service instead of per target
- the calibration pipeline is split into multiple incompatible implementations and is not wired into daemon startup
- WorkloadGraph auto-inference can manufacture incorrect `same_domain` edges from generic domain labels

Most runtime code correctly uses `/opt/skg/skg/core/paths.py:15-65`, and the daemon does a good job of refusing incomplete daemon domains (`/opt/skg/skg/core/domain_registry.py:278-295`). The problems come from a smaller set of modules whose file formats, naming rules, and concurrency assumptions are not strong enough.

## Critical issues

1. Projection outputs overwrite each other across attack paths. `project_event_file()` correctly groups by `(workload_id, toolchain, attack_path_id)` in `/opt/skg/skg/sensors/projector.py:333-378`, but `project_events()` writes every result to `<domain>_<workload>_<run_id>.json` in `/opt/skg/skg/sensors/projector.py:280-285` and `/opt/skg/skg/sensors/projector.py:321-324`. The filename omits `attack_path_id`, and `_prune_interp_siblings()` in `/opt/skg/skg/sensors/projector.py:43-55` prunes by the same prefix. I reproduced this with two host attack paths for one workload and one run: two `Path` objects were returned, but only one file existed on disk and it contained only the later attack path. This is a direct correctness failure in the projection layer.

2. Gap detection deduplicates globally by service instead of per target. `detect_from_events()` builds `gaps: dict[str, dict]` keyed only by `service` in `/opt/skg/skg/intel/gap_detector.py:237-337`, and `detect_new_gaps()` persists known gaps keyed only by `svc` in `/opt/skg/skg/intel/gap_detector.py:404-432`. I reproduced this by feeding the same uncovered service on two different workloads: the first target produced a new gap, the second did not, and only the host list was merged. This conflicts with the design goal of target-specific coverage tracking and causes forge to under-report real gaps.

3. The calibration pipeline is split, incompatible, and not actually unified into runtime. The CLI path `skg calibrate` documents saving to `/var/lib/skg/calibration.json` and says it is loaded at daemon startup (`/opt/skg/skg/cli/commands/report.py:433-472`). The old sensor calibrator hardcodes that file in `/opt/skg/skg/sensors/confidence_calibrator.py:33-35` and `/opt/skg/skg/sensors/confidence_calibrator.py:68`. A second calibrator writes rank weights under `SKG_STATE_DIR/calibration/signal_weights.json` in `/opt/skg/skg/intel/confidence_calibrator.py:97-139`. The runtime confidence path actually used by sensors is `SensorContext.calibrate()` in `/opt/skg/skg/sensors/context.py:60-122`, and the daemon boot path `/opt/skg/skg/core/daemon.py:260-353` never loads either calibration file. The result is three different calibration stories: CLI export, intel weight learning, and runtime context blending. They are not one pipeline.

4. `same_domain` edges can be inferred from the wrong semantics. In `/opt/skg/skg/graph/__init__.py:565-600`, `infer_edges_from_events()` falls back from `host_meta.ad_domain` to the generic event `domain` label via `ad_domain = meta.get("ad_domain", "") or domain`. For host events this turns the string `"host"` into an inferred AD-domain bucket and creates `same_domain` edges with metadata `{"ad_domain": "host"}`. I reproduced this with two unrelated host workloads and got a synthetic `same_domain` edge. That contradicts the Work 3 description that `same_domain` means AD/LDAP domain membership (`/opt/skg/docs/SKG_Work3_Final.md:147-156`) and contaminates cross-target priors.

## Medium issues

1. Sensor sweeps can overlap with no concurrency control. `_sweep()` in `/opt/skg/skg/sensors/__init__.py:398-441` has no mutex or in-flight guard, while `trigger()` in `/opt/skg/skg/sensors/__init__.py:488-495` starts a separate thread immediately. A timed background loop plus a manual trigger can therefore overlap while sharing event files, interp files, feedback state, proposal files, and gap state. This is the most important concurrency risk in the repo.

2. Proposal artifacts are not immutable and can overwrite prior operator artifacts. `write_contract_artifact()` writes directly to `target_dir / filename_hint` in `/opt/skg/skg/assistant/action_proposals.py:45-63`. `cred_reuse` uses deterministic names like `cred_reuse_ssh_10_0_0_8_22.json` in `/opt/skg/skg-gravity/cred_reuse.py:652-667`. I reproduced two writes with the same `filename_hint`; the second replaced the first in place. The proposal queue itself uses unique proposal IDs, but the attached operator-facing artifact does not.

3. Dynamic toolchain registration is only partially dynamic. The registry detects projectors only when they match `projections/*/run.py` in `/opt/skg/skg/core/domain_registry.py:189-204` and `/opt/skg/skg/core/domain_registry.py:262-266`. The projector runtime still relies on hardcoded tables in `/opt/skg/skg/sensors/projector.py:58-82`, plus a generic discovery path in `/opt/skg/skg/sensors/projector.py:127-145` that assumes a `compute_<subdir>` function naming convention. `SensorLoop` also imports a fixed sensor set in `/opt/skg/skg/sensors/__init__.py:372-375`. This is why `load_domain_inventory()` reported `ai_target` as lacking a projector even though the projector runtime can load `/opt/skg/skg-ai-toolchain/projections/run.py`.

4. Data-topology bond strength is silently ignored. `DataSensor` passes intended bond strengths through `metadata={"strength": ...}` in `/opt/skg/skg/sensors/data_sensor.py:219-247`, but `WorkloadGraph.add_edge()` uses only the explicit `weight` argument and otherwise falls back to `PROPAGATION_WEIGHT.get(relationship, 0.1)` in `/opt/skg/skg/graph/__init__.py:230-248`. I reproduced this with a `same_database` edge carrying `metadata["strength"] = 0.6`; the stored edge weight was still `0.1`. That means the graph propagation layer is not honoring the semantics the data sensor thinks it is registering.

5. Several persistence paths fail silently on malformed JSON. `load_known_gaps()` swallows parse errors and returns `{}` in `/opt/skg/skg/intel/gap_detector.py:390-396`; `save_known_gaps()` then rewrites the state file in `/opt/skg/skg/intel/gap_detector.py:399-401`. `_load_catalog()` and event parsing in the projector silently skip malformed JSON in `/opt/skg/skg/sensors/projector.py:229-243` and `/opt/skg/skg/sensors/projector.py:349-356`. `FeedbackIngester._load_state()` does the same in `/opt/skg/skg/temporal/feedback.py:113-123`. I confirmed the gap detector case by injecting corrupted JSON; the state reset to empty with no operator-visible failure.

## Low issues / Improvements

1. `cognitive_sensor` is implemented but unwired into the normal sensor loop. It registers itself with `@register("cognitive")` in `/opt/skg/skg/sensors/cognitive_sensor.py:345-351`, but `SensorLoop._load_sensors()` never imports it in `/opt/skg/skg/sensors/__init__.py:367-375`. In normal daemon boot, the registry entry is never created unless some other path imports that module first.

2. There are legacy or unused runtime modules that no longer appear in the active call graph. A repo-wide search found no runtime imports of `/opt/skg/skg-gravity/exploit_proposals.py` outside install/test scaffolding, no imports of `/opt/skg/skg-gravity/gravity_web.py` outside docs/install references, and `/opt/skg/skg/substrate/bond.py:66-80` appears to be referenced by install/paper helper scripts rather than the live daemon/runtime. These modules may still be useful as historical reference, but they are not part of the current execution path.

3. There are high-confidence unused imports and cleanup leftovers. `/opt/skg/skg/cli/commands/system.py:2` and `/opt/skg/skg/cli/commands/system.py:10` import `sys` and `SKG_HOME` without use. `/opt/skg/skg/cli/commands/report.py:453-455` imports `ConfidenceCalibrator` but only uses `calibrate_from_engagement`.

4. Path discipline is good overall, but a few standalone paths still bypass `SKG_STATE_DIR`. The hardcoded calibration path in `/opt/skg/skg/sensors/confidence_calibrator.py:68` is the most important example. `/opt/skg/skg/sensors/cognitive_sensor.py:504-506` and `/opt/skg/skg/sensors/cognitive_sensor.py:564-565` also fall back to `/tmp/skg/...` for standalone trial/event output rather than the configured state root.

## What works

1. Filesystem path centralization is mostly solid. `/opt/skg/skg/core/paths.py:15-65` is a real single source of truth, and most runtime modules respect it.

2. Daemon domain discovery is defensively implemented. `load_daemon_domains()` in `/opt/skg/skg/core/domain_registry.py:278-295` filters out incomplete or non-daemon toolchains instead of forcing them into boot. This is one of the cleaner parts of the architecture.

3. Projection dispatch across the built-in toolchains is exercised and working for the supported shapes. The test suite covers host, AI, data, IoT, supply-chain, and binary projector paths in `/opt/skg/tests/test_sensor_projection_loop.py:388-421`, `/opt/skg/tests/test_sensor_projection_loop.py:1126-1173`, and `/opt/skg/tests/test_sensor_projection_loop.py:1244-1315`.

4. The proposal queue itself is sounder than the artifact sidecars. Proposal IDs are unique UUID-derived filenames in `/opt/skg/skg/forge/proposals.py:285-333`, `/opt/skg/skg/forge/proposals.py:352-390`, and `/opt/skg/skg/forge/proposals.py:913-949`. Accept/reject flows archive proposals cleanly in `/opt/skg/skg/forge/proposals.py:540-560` and `/opt/skg/skg/forge/proposals.py:617-639`.

5. Gravity runtime helpers have direct automated coverage. Failure reporting and follow-on proposal generation are exercised in `/opt/skg/tests/test_gravity_runtime.py:11-115`.

6. README claims about daemon-native coverage are mostly accurate. `/opt/skg/README.md:74-91` correctly says only five toolchains are daemon-native today and that the others are auxiliary or operator-invoked. That description matches the observed runtime better than the stronger claims in the papers.

## Test gaps

1. There is no test that asserts projection filenames remain unique across multiple `attack_path_id` values for the same `(domain, workload, run_id)`. The current projector tests check single-path success but not collision behavior.

2. There is no direct test for per-target gap tracking, corrupted gap-state recovery, or the semantics of dedupe in `/opt/skg/skg/intel/gap_detector.py`. Existing forge tests mock `detect_new_gaps()` instead of exercising it directly (`/opt/skg/tests/test_sensor_projection_loop.py:1518`).

3. There is no integration test that proves `skg calibrate` affects live runtime confidence, because it currently does not. The test suite does not cover daemon boot loading of calibration state or sensor emit-time use of either calibrator module.

4. There is no concurrency test for `SensorLoop.trigger()` overlapping with the timed polling loop, and no file-locking tests around proposal, gap, feedback, or graph writes.

5. There is no immutability test for assistant artifacts or credential-reuse proposal artifacts. The current tests assert that contract-backed helpers are called (`/opt/skg/tests/test_sensor_projection_loop.py:3136-3167`) but do not assert unique filenames or non-overwrite behavior.

6. There is no test that guards the `same_domain` inference rule against falling back to a generic domain label instead of real AD-domain metadata.

7. There is no test that verifies `same_database` edges carry the intended propagation weight into `WorkloadGraph`.

## Documentation mismatches

1. Work 4 claims "Thirteen domain expressions" and "211 named conditions" in `/opt/skg/docs/SKG_Work4_Final.md:17` and `/opt/skg/docs/SKG_Work4_Final.md:81-99`. On 2026-03-26, `load_domain_inventory()` returned 12 domains, and catalog counting across the repo yielded 221 wickets. The missing expression from the paper table is effectively `sysaudit`; it is not a separately registered runtime domain in the current inventory.

2. Work 4 says new observation capabilities are additive and require no substrate changes (`/opt/skg/docs/SKG_Work4_Final.md:41-42` and `/opt/skg/docs/SKG_Work4_Final.md:460-462`), but the runtime still contains hardcoded projector maps, aliases, import lists, and naming conventions in `/opt/skg/skg/sensors/projector.py:58-82`, `/opt/skg/skg/sensors/projector.py:127-145`, and `/opt/skg/skg/sensors/__init__.py:372-375`. The architecture is only partially plugin-like.

3. Work 3 says "Bonds are discovered, not declared" in `/opt/skg/docs/SKG_Work3_Final.md:147-156`, but the current runtime exposes explicit manual bond assertion through `skg target link` in `/opt/skg/skg/cli/app.py:77-98` and direct graph mutation through `/graph/edge` in `/opt/skg/skg/core/daemon.py:3852-3857`.

4. The calibration documentation in the CLI says calibration is "loaded at daemon startup" and saved to `/var/lib/skg/calibration.json` in `/opt/skg/skg/cli/commands/report.py:447-472`. The daemon boot path `/opt/skg/skg/core/daemon.py:260-353` does not do that.

5. The bond vocabulary and weights differ materially between the papers and current runtime. Work 3 and legacy modules describe `same_host`, `docker_host`, `same_compose`, `shared_cred`, `same_domain 0.60`, and `same_subnet 0.40` in `/opt/skg/docs/SKG_Work3_Final.md:149-154`, `/opt/skg/skg-gravity/gravity_web.py:14-20`, and `/opt/skg/skg/substrate/bond.py:66-80`. The live graph layer instead uses `same_identity 0.85`, `same_domain 0.35`, `credential_overlap 0.45`, and `same_subnet 0.20` in `/opt/skg/skg/graph/__init__.py:75-93` and `/opt/skg/docs/SKG_Work4_Final.md:224-260`. That may be an intentional evolution, but the docs do not present it clearly as a breaking terminology shift.

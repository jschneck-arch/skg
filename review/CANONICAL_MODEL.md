# SKG Canonical Model

Last updated: 2026-03-31 surface subject-row audit pass.

## Repository Intent

From the current root docs, SKG is intended to be a domain-agnostic, measurement-first telemetry substrate:

- observations are the primary objects
- wicket state is tri-state: `realized`, `blocked`, `unknown`
- attack paths and operator views are derived projections over measured state
- gravity ranks the next observation by expected entropy reduction
- exploitation remains operator-gated
- AI remains advisory and cannot promote derived narrative into observed state without custody

The clearest current statement of that model is spread across:

- `README.md`
- `ENGAGEMENT.md`
- `docs/SKG_ARCHITECTURE_SYNTHESIS_20260328.md`
- `docs/SKG_CANONICAL_RUNTIME_MAP.md`
- `docs/SKG_RUNTIME_UNIFICATION_PLAN.md`
- `docs/SKG_AI_ASSISTANT_CONTRACT.md`
- `docs/SKG_Work3_Final.md`
- `docs/SKG_Work4_Final.md`

## Repository As Implemented

The repository currently implements a real substrate plus a hybrid operational shell:

1. Domain toolchains define domain-specific catalogs, adapters, and projectors.
2. Sensors and toolchains emit observation artifacts into `events/`.
3. Projectors and replay paths derive interpreted realizability artifacts into `interp/`.
4. Kernel, substrate, temporal, graph, and topology modules aggregate support, collapse state, compute energy/coherence, preserve transitions, and maintain priors.
5. Gravity and proposal code rank follow-on observations and operator actions.
6. Resonance and forge provide memory, drafting, and toolchain-growth machinery.
7. The daemon/CLI still mix measured artifacts with config/discovery/bootstrap state.

Two implementation details are now clear enough to treat as part of the practical model:

- assistant outputs are explicitly classified and only custody-backed `observed_evidence` is admissible to the observation plane
- proposals are persisted operator-review artifacts whose execution may feed fresh observation events back into the substrate

That last point is the main architectural reality of the repo today: the measured substrate is real, but the runtime shell has not been fully subordinated to measured state.

## Canonical Runtime Layers

### 1. Domain Expression Layer

Canonical directories:

- `skg-*-toolchain/`

Each active toolchain generally contains:

- `contracts/catalogs/*.json`
- `adapters/*/parse.py` or `probe.py` / `collector.py`
- `projections/*/run.py` or `projections/run.py`

The adapter remains the main domain-specific boundary.

Observed support-layer drift inside this layer:

- not every checked-in toolchain root is equally complete; APRS, AD lateral, container escape, and host have local golden coverage, while AI, binary, IoT firmware, metacognition, nginx, supply chain, and web currently have no toolchain-local tests in-tree and `skg-data-toolchain/tests/` is only an empty package marker
- several thin/generated roots rely on `forge_meta.json` that explicitly records template fallbacks or missing generation backend coverage, so root metadata is not always a strong authority signal on its own
- the supply-chain toolchain is active, but its checked-in adapter/catalog contract is no longer unified: the live `sbom_check` adapter evaluates `SC-10` with different package/CVE semantics than the catalog text, and the catalog still carries `SC-11` / `SC-12` wickets that no attack path requires and the adapter never emits
- the nginx toolchain is also active, but one of its advertised evidence paths is only nominal: the SSH adapter claims to inspect error-page body text for version disclosure while collecting that probe with `curl -sI`, so the body-based branch is unreachable as written
- the metacognition toolchain is active, but it currently sits outside the normal measured-event contract in two ways: adapters emit `obs.substrate.node` records with a different envelope shape than the usual SKG event records, and its projector resolves conflicting wicket states by fixed `blocked > realized > unknown` priority rather than by recency
- the web helper surface (`auth_scanner`, `gobuster`, `nikto`, `sqlmap`) is even less canonical than the main web collector/projector path: helper mappings reuse checked-in `WB-*` ids for different meanings, some helpers emit partial manual event dicts without the shared envelope, and several use full URL strings as workload subjects
- the canonical web toolchain tree also still contains an older `adapters/ssh_collect/parse.py` path that emits legacy `W-01..W-05` Apache/APR-specific wickets instead of the current `WB-*` vocabulary; reference search only surfaced that path in itself, `forge_staging`, and older evidence/doc artifacts
- the AI probe and auxiliary binary adapters are comparatively closer to the standard measured-event contract than many other generated roots: `ai_probe`, `binary_analysis`, `capa_analysis`, `angr_symbolic`, and `frida_trace` all use the shared event envelope and programmatic `run()` entry points, but they still have little or no direct behavioral coverage in-tree

### 2. Observation and Projection Layer

Canonical directories:

- `skg/sensors/`
- `skg/cli/commands/replay.py`
- `skg/core/daemon.py`

Canonical runtime artifacts:

- `events/*.ndjson`
- `interp/*.json`
- `interp/*_interp.ndjson`

Observed drift:

- not every operator path uses those canonical artifacts consistently
- direct CLI web observation still writes discovery artifacts in some paths instead of flowing through the measured `events/` -> `interp/` path
- sensor-loop "run-scoped" projection is currently filename-based and keyed to the sweep `run_id`, but active sensors emit files with independent run-id suffixes (or none), so sweep-local projection still falls back to recent full scans
- the kernel observation loader still partially depends on filename conventions: `load_observations_for_node()` selects discovery artifacts by `node_key`-shaped filenames before it inspects payload identity, so hostname-identity nodes can miss IP-named discovery files even when the payload carries the correct stable identity
- daemon-side projection lookup still aliases only `binary <-> binary_analysis`, so measured projection endpoints can miss equivalent legacy `data` artifacts when queried through current `data_pipeline` naming
- daemon-side field-state computation is even narrower than projection lookup: its attack-path prefix mapping currently omits `binary_`, so binary paths do not participate in topology/fiber pull the way data, web, host, and other domains do
- daemon-side world modeling also trails the active score vocabulary: `_identity_manifestations()` exposes manifestation rows through `/world/{identity_key}`, but currently zeroes binary and AD manifestation scores because it only reads host/web/data/container/AI score keys
- daemon-side world modeling is also not recency-stable: `_identity_manifestations()` currently keeps the first interp row it encounters for a `(workload_id, attack_path_id)` pair rather than selecting the newest payload, so world-manifestation views can depend on directory iteration order
- daemon-side world summaries also mix manifestation and path-row concepts: `_identity_world()` reports `world_summary["manifestation_count"] = len(manifestations)`, but `manifestations` is one row per `(workload_id, attack_path_id)`, so the summary can overcount unique manifestations whenever one manifestation has multiple projected paths
- daemon target-list rows also merge two incompatible manifestation sources: the top-level `manifestations` field comes only from the measured-view index, while `world_summary.manifestation_count` comes from `_identity_world()`, so one target payload can report no top-level manifestations while still claiming manifested world state
- that contradiction is structural, not accidental: `skg.intel.surface.surface()` is intentionally row-per-path while preserving `manifestation_key`, `_surface_subject_rows()` then groups those path rows by identity and dedupes manifestation keys for CLI/report views, and daemon target/world code still places those deduped manifestations beside world summaries derived from path-shaped manifestation rows
- daemon-side identity artifact lookup is also only partially identity-faithful: `_artifact_matches_identity()` accepts raw filename token matches before checking payload identity, so `/artifacts/{identity_key}` and assistant artifact context can be polluted by misleading filenames
- the public artifact-preview endpoint is also less bounded than it claims: `_artifact_preview_payload()` limits rows/lines, but its JSON branch still returns the full parsed object for a file under the allowed runtime roots
- daemon-side field-state exposure is also opportunistic rather than authoritative: `_compute_field_state()` refreshes in the background and can return `{}` on the first cold-cache call, so `/status` and assistant context can briefly see missing field-state data rather than either stale or freshly recomputed data
- daemon-side identity history is similarly tied to current projection artifacts: `identity_timeline()` discovers workloads only by scanning `interp/`, so assistant and operator history views can go empty for identities that still have feedback history but no current interp manifestation
- assistant bundle assembly inherits that fragility and adds its own one: `_assistant_reasoning_bundle()` seeds graph context from surface paths, field rows, and `timeline.graph_neighbors`, but not from `timeline.workloads`, so assistant graph summaries can omit the selected identity or pivot onto neighbor ids instead
- assistant fallback summaries then compound that dependence on surface rows: target summaries describe `subject.paths` and `subject.manifestations`, so they can report zero active paths even when `field_state` already contains live attack-path rows
- the web domain is currently live in four incompatible forms: `WEB-*` daemon sensor output, `WB-*` active collector/auth output, `WB-30..WB-40` structured fetch output, and a checked-in catalog/projector that only defines `WB-01..WB-20`
- the gravity AI service-probe shell can also destroy valid measured events: `gravity_field._exec_ai_probe()` passes an NDJSON path into `ai_probe.probe_device()` and then rewrites that same file with summary dicts before projection, so projector intake sees malformed lines instead of `obs.attack.precondition` envelopes
- several gravity plugin adapters currently emit `obs.attack.precondition` records on a synthetic `skg-gravity` toolchain lane that the normal projector cannot resolve to a checked-in projector, so those observations can reach raw history without reaching interpreted path state
- workload identity shape is not stable across operator paths: some flows emit raw hosts, others emit `ssh::...`, `host::...`, or `web::...`
- at least part of the web split is semantic, not merely syntactic: the active collector reuses checked-in `WB-*` identifiers for different meanings than the checked-in catalog assigns them
- the dedicated replay CLI is a convenience analysis path, not a canonical kernel replay: it claims live-equivalent substrate behavior but currently collapses wicket state with a local majority-vote routine instead of the imported support/state engines

### 3. State, Projection, and Memory Layer

Canonical directories:

- `skg/identity/`
- `skg/substrate/`
- `skg/kernel/`
- `skg/graph/`
- `skg/temporal/`
- `skg/topology/`

This layer implements the actual substrate model:

- canonical workload identity parsing
- support aggregation and collapse
- path projection and realizability
- contradiction/decoherence handling
- delta history and priors
- field-local, fold, pearl, and cluster logic

Observed support-layer drift inside this layer:

- the wicket graph is real and runtime-used, but its catalog discovery and prefix-domain inference still lag current toolchain naming: AI catalog seeding misses the `ai_attack_preconditions_catalog.v1.json` file, and `DP-*`, `DE-*`, and `IF-*` wickets currently collapse to `unknown` domain inside graph-space
- `KernelStateEngine` duplicates a second stale fallback prefix map (`DA-`, `BI-`, `LA-`, `IO-` era naming), so `field_locals()` and fiber-driven scoring can collapse active `AD-*`, `BA-*`, `DP-*`, `DE-*`, and `IF-*` wickets into one `unknown` local unless explicit `domain_wickets` are supplied
- the field-functional and gravity-selection helper layers still normalize domains inconsistently: `selection.py` misses current `BA-*`, `DP-*`, and `IF-*` wavelength families in sphere inference, while `field_functional.domain_to_sphere()` still mixes old collapsed names (`binary`, `container`, `ad`) with uncollapsed current names like `data_pipeline`
- topology energy helpers still bridge current names unevenly: `FIELD_DOMAIN_TO_SPHERE` maps `binary_analysis` into `host` instead of `binary`, and `_world_states_from_surface()` still ignores `data_pipeline` and `binary_analysis` when lifting discovery surfaces into supplementary world-state
- the default coupling tables are still closer to the old domain vocabulary than the current runtime vocabulary, so current names like `data_pipeline`, `binary_analysis`, and `container_escape` can receive materially weaker inter-local coupling than their legacy equivalents unless config overrides the defaults
- the SQLite gravity mirror is only partially integrated: current runtime writes some credential/pivot/wicket snapshots into `state.db`, but no live read-side consumers were found for its query layer

### 4. Runtime Coordination Layer

Canonical directories:

- `skg/core/`
- `skg/cli/`
- `ui/`

This is the operator shell and orchestration surface. It is functionally important, but not purely canonical in the formal sense because it still merges:

- measured projection state
- config targets
- discovery surfaces
- local runtime injections

Observed shell divergence within this layer:

- `report` and `surface` partially merge measured view state, but `status` and `web` still rank raw discovery surfaces
- fold views choose between daemon and disk state primarily by row count, not freshness or explicit authority
- the generic surface summary collapses projections by `attack_path_id` across all targets and also scans loose `DISCOVERY_DIR`/`/tmp` interp artifacts, so it is not a clean per-target measured view
- the target-list shell also still contains presentation drift: `skg target list` labels its second column as `E` but currently prints `unknown_count`, so even identity-grouped subject rows are not always rendered with semantically accurate headings
- CLI surface loading is also inconsistent across commands: `surface` and `report` hydrate the latest surface through gravity runtime helpers before subject-row aggregation, while `target list` reads the raw latest-surface JSON directly, so two operator views can disagree about the visible target set before any measured-state aggregation happens
- CLI subject-row aggregation is also not identity-alias-aware: `_surface_subject_rows()` joins target-shell metadata to measured rows only by exact `identity_key`, so an IP-root discovery target and a hostname-root measured row can split into two operator rows for the same underlying node
- the daemon target-list shell has the same identity-merge weakness at its own layer: `list_targets()` merges `_all_targets_index()` and `field_surface()` by exact `identity_key`, so one node can surface as separate IP-root and hostname-root target rows even before world-summary contradictions are considered
- that daemon split is not just cosmetic: the IP-root row can retain services while the hostname-root row retains manifestations and fresh unknown mass, so daemon world summaries and later assistant context start from complementary partial rows instead of one coherent node record
- daemon profile/evidence gathering has the same exact-string weakness: `_identity_profile(identity_key)` globs discovery artifacts by the literal identity token and then filters rows with `identity_key in workload_id` string checks, so hostname-root evidence can be invisible to the IP-root sibling row created by `list_targets()`
- that exact-string profile behavior also bleeds into relation reasoning: `_identity_relations()` re-enters `_identity_profile(identity_key)` and `_identity_profile(other_ip)` for shared-credential edges, while hostname-root rows with no IP fall back to hostname text for subnet logic, so peer reasoning can diverge between the IP-root and hostname-root siblings of one node
- identity-facing history helpers are also still exact-key based: `identity_artifacts()` and `identity_timeline()` only match parsed `identity_key == requested_identity`, so alias-equivalent IP-root requests can miss hostname-root artifacts and timelines even though the daemon already has local alias helpers
- assistant selection inherits the same exact-key weakness: `_assistant_context()` builds `targets_by_identity` and measured groups keyed by exact identity strings, so an IP-root assistant selection can miss hostname-root field rows and manifestations even while `identity_world()` already resolves target rows through `_identity_matches(...)`
- the world endpoint itself is only half alias-aware: `identity_world()` uses `_identity_matches(...)` to select a target row, but then still calls `_identity_world(requested_identity, target)`, so alias-equivalent IP-root requests can return services from one identity variant and manifestations from none
- the `field` CLI still hardcodes a narrow domain enum and rejects active domains such as `binary`
- daemon projection endpoints and topology supplements still encode a binary-special alias story rather than one consistent alias layer for current-vs-legacy domain names
- the daemon field-state view also underweights binary paths specifically because it derives topology target-domains from attack-path prefixes and currently has no `binary_` case
- the assistant API surface is not an independent interpretation layer: `/assistant/explain` and `/assistant/what-if` both pass through `_assistant_prepare_context(...)` and therefore inherit the same field-state, timeline, and graph-seeding defects as the daemon context builder underneath
- the assistant artifact summary path is also only a preview view today: `_assistant_context(...)` drops the total `identity_artifacts(...).count` and carries only the preview slice length into the bundle, and the assistant API `references` block then reports those preview-sized counts as if they were totals

### 5. Gravity and Action Layer

Canonical directories:

- `skg/gravity/`
- `skg-gravity/`

Observed implementation shape:

- `skg/gravity/` holds a smaller decomposed library used by tests and runtime helpers
- `skg-gravity/gravity_field.py` remains the large operational control shell
- the operational shell treats `web_struct_fetch` and multiple legacy web exploit-path IDs as active runtime behavior, even though those path IDs are not all present in the checked-in web catalog
- the operational shell still overloads canonical host/web wicket ids for gravity-local meanings in several active adapters and dispatch paths, so a correct raw observation can still be mapped onto the wrong canonical condition
- some gravity instrument shells still diverge from the canonical event->projection path even when collection succeeds: the SSH branch currently writes host events twice into the same artifact, the sysaudit branch emits raw events without projecting them, and a dead BloodHound collector body remains embedded inside the data-profiler function
- gravity configuration and availability handling are not fully aligned with the rest of the repo: target merge still assumes dict-shaped `targets.yaml`, and BloodHound availability currently keys off CE URL reachability even though both the gravity shell and native sensor implement Neo4j fallback
- the main cycle is only partially identity-faithful today: selection is built over `identity_key`, but execution and post-run refresh still fall back to raw IP in important paths, and reported entropy reduction is not always computed from the same term set before and after execution
- the decomposed gravity library is more measured-view aware than the monolithic shell: `landscape.py` and `selection.py` explicitly consume measured view state and observed-tool overlays

### 5a. Assistant and Proposal Boundary

Canonical directories:

- `skg/core/assistant_contract.py`
- `skg/assistant/`
- `skg/forge/proposals.py`

Observed implementation shape:

- assistant outputs are classified as `observed_evidence`, `derived_advice`, `mutation_artifact`, or `reconciliation_claim`
- non-observation assistant outputs are deliberately barred from the observation plane
- contract-backed artifacts are saved under state and then wrapped as reviewable proposals
- proposal lifecycle is persistent: pending -> triggered/accepted/rejected/deferred -> executed/archive paths

### 6. Memory, Drafting, and Growth Layer

Canonical directories:

- `skg/resonance/`
- `skg/forge/`
- `skg/intel/`
- `skg/catalog/`

These are not placeholders. They implement:

- resonance memory ingestion and lookup
- draft generation / LLM pool plumbing
- gap detection
- catalog and adapter proposal generation
- engagement-telemetry ingestion into a secondary SQLite product plus DP-style integrity analysis over that product
- cross-domain redteam-to-data derivation that projects security findings into inferred `DP-*` posture
- a hook-driven training corpus, daily scheduler, and fine-tune pipeline for model adaptation

Observed operator-exposure drift in this layer:

- `engagement_dataset` is wired into the CLI under `skg engage`
- `redteam_to_data.py` advertises `skg data redteam`, but the actual CLI does not expose that subcommand
- `training/scheduler.py` advertises manual `skg train run`, but the actual CLI does not expose a `train` command
- engagement integrity and cleanup logic still reason over exact `workload_id` strings even though the runtime still emits multiple manifestation shapes for one identity
- `report` is only partially local-file-backed: surface loading has an offline path, but folds, graph, resonance, feedback, and self-audit still come from daemon endpoints and silently collapse to partial views when the daemon is unavailable
- `proposals` is not just a queue browser: its trigger path is a scenario-heavy execution shell with Metasploit orchestration, DVWA/CMDI-specific delivery logic, and a hardcoded post-session host projection path narrower than the host toolchain's own catalog
- `derived rebuild` is not currently a pure append-only substrate reconstruction: it reprojects both `SKG_STATE_DIR/events` and `DISCOVERY_DIR`, then rebuilds folds by matching current surface targets against fold-location strings
- the dark-hypothesis planner is a sidecar path: it discovers instruments only from `SKG_STATE_DIR/toolchains` and writes `cognitive_action` proposals directly into the proposal queue without using the shared actionable proposal kinds
- resonance drafting is partly sidecar too: `draft_prompt()` / `draft_accept()` exist as file-based prompt workflow helpers, but the live `skg resonance` parser exposes only `draft` / `drafts`, the no-backend path raises instructions for subcommands that do not exist, and the prompt builder currently expects a different context shape than `ResonanceEngine.surface()` returns
- the standalone `skg.resonance.cli` path has drifted away from the main CLI and engine contract: it calls `engine.list_drafts()`, but `ResonanceEngine` does not provide that method
- resonance memory ingestion is real, but some of its completeness story is aspirational: adapter discovery uses hard-coded evidence-source maps plus regex scanning, `DomainMemory.adapters` remains unpopulated, and the ingester summary currently counts processed domains as if they were newly added
- workload-aware observation history is weaker than it looks: `SensorContext` passes `workload_id` into `historical_confirmation_rate()`, but exact-wicket recall currently accepts same-wicket records before identity filtering, so confirmation history can still mix different workloads
- resonance vector memory is most trustworthy only on a stable embedder path: the TF-IDF fallback refits on every new text, which changes embedding weights over time while append-only indexes keep previously-added vectors
- `DeltaStore.calibrate_confidence_weights()` is more aspirational than live today: it claims to calibrate by evidence rank from recorded transitions, but current `WicketTransition` records do not actually carry `evidence_rank` or free-form metadata
- the standalone YAML catalog compiler is secondary rather than canonical in the current repo: it emits `attack_preconditions_catalog.v1.{domain}.json`, while the live toolchain/runtime convention is `attack_preconditions_catalog.{domain}.v1.json`
- `skg-gravity/gravity_web.py` and `skg-gravity/exploit_proposals.py` currently look like legacy sidecars: repo-wide search found no live callsites, and `exploit_proposals.py` writes to its own `state/exploit_proposals` directory instead of the shared proposal queue
- the data discovery path is hybrid and not fully on the canonical event contract: `db_discovery` emits DE-* observations without a `provenance` block or `attack_path_id`, even though the top-level CLI exposes it as a measured `skg data discover` workflow
- the IoT firmware probe has a live false-negative gate: `probe_device()` requires a spontaneous TCP banner before attempting HTTP probing, so ordinary HTTP-only devices can be marked unknown; a `probe_network_only()` fallback exists but is not wired into the main path
- the IoT firmware toolchain currently contains two materially different adapter contracts in one package: `adapters/firmware_probe/__init__.py` is an SSH/image collector with default path `firmware_rce_via_busybox_v1`, while `adapters/firmware_probe/probe.py` is a network/banner probe with default path `iot_firmware_rce_v1`
- several nested toolchain projectors attempt optional sheaf refinement by inserting `Path(__file__).resolve().parents[4]` into `sys.path`; for in-tree toolchains like host, AD lateral, IoT firmware, data, container escape, and supply chain, that resolves to `/opt`, not `/opt/skg`, so the sheaf step silently degrades unless some other import context already makes `skg` resolvable
- the APRS toolchain remains on an older contract shape than most current toolchains: both its root CLI and projector default to `contracts/catalogs/attack_preconditions_catalog.v1.json` rather than the repo-wide `{domain}.v1` naming convention
- the stale root web projector is now confirmed broken beyond naming drift: it points at a non-existent catalog file and its `latest()` helper ignores the provided `workload_id`
- the native BloodHound sensor is real and adapter-backed, but its AD identity/scoping contract is weaker than advertised: `domain_sid` is accepted as config but not enforced in collection, and the default emitted workload subject falls back to the collector endpoint hostname when no domain SID is set
- the measured surface is real and daemon-used, but its explicit domain mapping is still incomplete: current `surface()` logic under-ranks `data_pipeline` and `binary_analysis` projections because those domains are preserved from interp payloads but omitted from the score-key and label maps

## Authority Order

For future review and repair work, the practical authority order should be treated as:

1. Observed event artifacts and projector outputs
2. Delta, graph, pearl, fold, and calibrated state derived from those artifacts
3. Toolchain catalogs and runtime domain registry
4. Config targets and operator configuration
5. Discovery surfaces and bootstrap convenience state

Current code does not always follow this authority order consistently.

## Canonical vs Non-Canonical Trees

Treat as canonical for implementation review:

- `skg/`
- `skg-gravity/`
- `skg-*-toolchain/`
- `tests/`
- `ui/`
- `config/`
- `docs/`

Treat as secondary or non-canonical:

- `skg_deploy/` explicitly says it is a deployment mirror, not the canonical tree
- `*.backup/` directories
- `forge_staging/`
- stray malformed directories created by bad brace expansion under `skg-data-toolchain/` and `skg-metacognition-toolchain/`

One important activation detail:

- domain activation uses the runtime domain registry, and `_discover_projector_run()` prefers nested `projections/*/run.py` over `projections/run.py`
- this means stray root projectors can be present in-tree while the registry still selects a different nested projector as canonical at runtime

## Current Architectural Summary

The best short description of the repo as implemented today is:

SKG is a measurement-first tri-state telemetry substrate with real projection, temporal, graph, gravity, memory, assistant-contract, and forge machinery, wrapped in an operator runtime that still carries older discovery- and target-centric bootstrap assumptions, broken sweep-local projection heuristics, unstable workload identity shapes, split web observation paths, partial daemon-dependent reporting, stale CLI domain enums, dark-hypothesis sidecar proposals that are not fully lifecycle-integrated, resonance drafting paths that are both CLI-drifted and internally shape-inconsistent, observation-history scoping that is weaker than advertised, hybrid toolchain helper paths that do not always honor the canonical event/projection contract, partially unwired sidecar gravity/catalog helpers, and some scenario-specific operator shell logic.

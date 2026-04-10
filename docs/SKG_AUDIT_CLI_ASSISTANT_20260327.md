# SKG CLI and Assistant System Audit
**Date:** 2026-03-27
**Scope:** `skg/cli/` (30+ commands) + `skg/assistant/` + `bin/skg` + `skg/cli/msf.py`

---

## 1. Entry Point

**`bin/skg`**: Bootstrap script. Adds repo root to sys.path, imports `skg.cli`, calls `main()`.

**`skg/cli/app.py`**: Builds argparse tree via `build_parser()`, dispatches via `COMMAND_DISPATCH` dict in `dispatch_command()`.

**`skg/cli/__init__.py`**: Exposes `main()`.

---

## 2. Complete Command Reference

### System Management

| Command | Subcommand | Key Flags | What It Does |
|---------|-----------|-----------|--------------|
| `start` | — | — | Start gravity daemon via systemctl |
| `stop` | — | — | Stop gravity daemon |
| `status` | — | `--self-audit` | Entropy landscape + field state; optional health audit |
| `check` | — | — | Validate Python version, dependencies, tools, state dirs, LLM backends |
| `mode` | `set_mode` | `{kernel\|resonance\|unified\|anchor}`, `--reason` | Get/set operational mode |
| `identity` | `history` | — | SKG identity and coherence history |
| `core` | `coupling` | `--show\|--validate\|--learn\|--apply`, `--delta-dir`, `--out`, `--review`, `--backup`, `--yes` | Manage intra-target coupling weights |

### Target Management

| Command | Subcommand | Key Flags | What It Does |
|---------|-----------|-----------|--------------|
| `target` | `add` | `ip`, `--domain` | Add single target to field |
| `target` | `add-subnet` | `cidr`, `--deep` | Discover and add subnet targets |
| `target` | `remove` | `ip` | Remove target + all artifacts |
| `target` | `list` | — | List all targets with entropy counts |
| `target` | `link` | `ip1 ip2 bond_type` | Assert bond between targets |
| `target` | `edges` | — | Show all bonds in gravity web |
| `observe` | — | `ip`, `--with {web\|ssh\|nmap\|msf\|pcap}`, `--auth` | Trigger observation on target |

### Proposal Queue

| Command | Subcommand | Key Flags | What It Does |
|---------|-----------|-----------|--------------|
| `proposals` | `list` | `--status {all\|pending\|...}` | List operator proposal queue |
| `proposals` | `show` | `proposal_id` | Detailed proposal info |
| `proposals` | `trigger` | `proposal_id`, `--await-session` | Execute approved proposal via MSF |
| `proposals` | `accept` | `proposal_id` | Accept toolchain proposal |
| `proposals` | `reject` | `proposal_id`, `--reason` | Reject proposal |
| `proposals` | `defer` | `proposal_id`, `[days]` | Defer proposal N days |

### Gravity Field

| Command | Key Flags | What It Does |
|---------|-----------|--------------|
| `gravity` | `--cycles N`, `--target IP`, `--authorized` | Run gravity loop for N cycles |
| `surface` | — | Full attack surface across all targets |
| `field` | `workload_id`, `[domain]` | Per-workload field state visualization |
| `folds` | `list\|structural\|resolve fold_id --target IP` | Manage structural knowledge gaps |

### Intelligence & Knowledge Graph

| Command | Subcommand | Key Flags | What It Does |
|---------|-----------|-----------|--------------|
| `feed` | `nvd` | `--service` | NVD CVE feed ingestion |
| `graph` | `topology` | — | K-topology report: nodes, edges, R, clusters, entangled pairs |
| `graph` | `edges` | `wicket_id` | Neighbors, K values, phase of wicket |
| `graph` | `entangled` | — | Non-separable wicket pairs (K ≥ 0.80) |
| `graph` | `hypotheses` | — | Observable vs dark hypotheses |
| `resonance` | `status` | — | Semantic memory status |
| `resonance` | `ingest` | — | Ingest catalogs/adapters/domains |
| `resonance` | `query` | `text`, `--type`, `--k N` | Semantic search |
| `resonance` | `draft` | `domain description`, `--api-key` | LLM draft new catalog |
| `resonance` | `drafts` | — | List saved drafts |
| `resonance` | `ollama` | — | Ollama backend status |

### Asset Integrity

| Command | Subcommand | Key Flags | What It Does |
|---------|-----------|-----------|--------------|
| `audit` | `scan` | `--target IP`, `--user`, `--key/--password`, `--workload-id`, `--attack-path-id`, `--checks` | SSH audit FI/PI/LI wickets |
| `audit` | `project` | `--in events.ndjson`, `--path-id` | Project FI/PI/LI events against failure path |
| `audit` | `paths` | — | List system integrity failure paths |
| `data` | `profile` | `--url`, `--table`, `--contract`, `--attack-path-id`, `--out` | Profile DB table against DP-* wickets |
| `data` | `project` | `--in events.ndjson`, `--path-id` | Project DP-* events |
| `data` | `paths` | — | List data integrity failure paths |
| `data` | `catalog` | — | Print data catalog JSON |
| `data` | `discover` | `--host IP`, `--user`, `--password/--key`, `--workload-id`, `--tables`, `--out-dir` | SSH-discover DB services + DP assessment |
| `collect` | — | `--target IP`, `--method {ssh\|winrm}`, `--user`, `--key`, `--port`, `--auto-project` | Collect from host |

### Exploit & Attack Path

| Command | Subcommand | Key Flags | What It Does |
|---------|-----------|-----------|--------------|
| `exploit` | `propose` | `--path-id`, `--target IP`, `--port`, `--realized`, `--lhost`, `--session-id` | Generate exploit proposals |
| `exploit` | `privesc` | `--session-id`, `--target IP`, `--known` | Post-session privesc chain |
| `exploit` | `binary` | `binary_path`, `--target/--user/--key`, `--attack-path-id` | Binary analysis for BA-* wickets |
| `exploit` | `list-paths` | — | List all mapped exploit paths |
| `exploit` | `binary-catalog` | — | Print binary catalog JSON |
| `exploit` | `cred-reuse` | `--target IP`, `--authorized` | Test stored credentials |

### Specialized Toolchains

| Command | Subcommand | Key Flags | What It Does |
|---------|-----------|-----------|--------------|
| `aprs` | `paths` | — | List APRS attack paths |
| `aprs` | `ingest` | `adapter`, `--out`, `--attack-path-id`, `--run-id`, `--workload-id` | Ingest APRS runtime data |
| `aprs` | `project` | `--in events`, `--out`, `--attack-path-id` | Project APRS events |
| `aprs` | `latest` | `--interp`, `--attack-path-id` | Fetch latest APRS interp |
| `escape` | `paths` | — | List container escape paths |
| `escape` | `ingest` | `--inspect`, `--out`, etc. | Ingest container inspect data |
| `escape` | `project` | `--in`, `--out`, `--attack-path-id` | Project escape events |
| `lateral` | `paths` | — | List AD lateral paths |
| `lateral` | `ingest` | `adapter {bloodhound\|ldapdomaindump\|manual}`, etc. | Ingest AD data |
| `lateral` | `project` | `--in`, `--out`, `--attack-path-id` | Project lateral events |
| `catalog` | `compile` | `--domain`, `--description`, `--packages`, `--keywords`, `--prefix`, `--api-key`, `--min-cvss`, `--max-wickets`, `--out`, `--dry-run` | Compile new attack catalog |

### Reporting & Analysis

| Command | Subcommand | Key Flags | What It Does |
|---------|-----------|-----------|--------------|
| `report` | — | `--target IP`, `--at ISO`, `--diff-against ISO`, `--json`, `--llm` | Generate substrate report |
| `engage` | `build` | `--out DB` | Build SQLite engagement DB from telemetry |
| `engage` | `analyze` | `--db` | Analyze dataset integrity (DP-* checks) |
| `engage` | `report` | `--db`, `--out` | Full engagement report |
| `engage` | `clean` | `--db` | Repair DP-03/04/05 violations |
| `calibrate` | — | `--db`, `--report` | Learn per-sensor confidence weights |
| `derived` | `archive` | — | Archive derived interp/fold state |
| `derived` | `rebuild` | `--append` | Rebuild derived state from substrate |
| `replay` | — | `events_dir` | Replay NDJSON events through kernel |

---

## 3. CLI Utilities (`skg/cli/utils.py`)

### Daemon Communication

- `_api(method, path, data, params)`: HTTP to daemon at `127.0.0.1:5055`
- Timeout: 120s for `/collect`, `/gravity/run`; 5s for others
- `_api_required()`: exits if daemon unavailable

### Surface Management

- `_latest_surface()`: Find richest surface JSON (by targets + services count, then mtime)
- `_load_surface_data()`, `_write_surface_data()`: Read/persist surface with metadata
- `_register_target()`: Add target to surface + targets.yaml
- `_bootstrap_target_surface()`: Initial nmap scan for new target

### Toolchain Wrappers

- `_tc(tc_name, cli_script, *args)`: Call toolchain script
  - Uses `.venv/bin/python` if available, else system python3
- `_aprs()`, `_escape()`, `_lateral()`: Domain-specific shortcuts

### Health Audit

`_build_substrate_self_audit()`: Checks memory, folds, proposals, recall, feedback, local model.
Returns structured health report displayed by `skg status --self-audit`.

---

## 4. MSF Integration (`skg/cli/msf.py`)

### `queue_msf_observation_proposal()`

Creates an MSF RC proposal for a target:

```
setg RHOSTS <target_ip>
setg RPORT <port>
use auxiliary/scanner/http/sql_injection
run
use auxiliary/scanner/http/dir_scanner
run
exit
```

Calls `create_msf_action_proposal()` from assistant system. Shows interactive review prompt. Prints proposal ID + RC path.

---

## 5. Assistant System (`skg/assistant/`)

### Purpose

Automated artifact (RC script, wicket patch, catalog patch) generation for proposals. Bridges between gravity cycle demands and operator-review-ready artifacts.

### `action_proposals.py`

**`create_action_proposal()`**: Generic field action proposal
- Normalizes subject (identity_key, execution_target)
- Writes optional contract artifact
- Calls `forge.proposals.create_action()` to build proposal

**`create_msf_action_proposal()`**: MSF-specific variant
- RC text → proposal JSON
- dispatch kind = "msf_rc_script"
- Adds command hint

**`write_contract_artifact()`**: Write artifact file with validation + metadata
- Validates content against contract schema
- Writes to versioned filename with `.meta.json` sidecar
- Stores in `SKG_STATE_DIR/assistant_drafts/`

### `demands.py`

**`derive_demands(bundle)`**: Generate deterministic artifact-writing demands from gravity output.

Three demand types:
1. **observation_rc**: Draft MSF RC for highest-E identified path → entropy reduction
2. **wicket_patch**: Add wickets to cover projection/context gaps
3. **catalog_patch**: Add catalog coverage for unobservable services (structural folds)

Sorted by priority.

**`select_demand(demands, id_or_kind)`**: Pick demand by ID or kind.

### `writer.py`

**`draft_demand(demand)`**: Turn demand into artifact file.

```python
if LLM available:
    _try_llm_draft(demand)  # JSON per contract schema
else:
    _default_{observation_rc|wicket_patch|catalog_patch}(demand)
```

Validates output, saves to `SKG_STATE_DIR/assistant_drafts/`.
Returns metadata: mode (llm/deterministic), model used, artifact_path.

Deterministic fallbacks:
- `_default_observation_rc()`: RC scaffold (comments + setg + exit)
- `_default_wicket_patch()`: JSON wicket patch skeleton
- `_default_catalog_patch()`: JSON catalog patch skeleton

### `validators.py`

Validates artifact content against contract schema:

| Contract | Type | Validation |
|---------|------|------------|
| `observation_rc` | text | markers, setg, run, exit |
| `wicket_patch` | JSON | required keys, nested structures |
| `catalog_patch` | JSON | required keys, nested structures |
| `msf_rc` | text | MSF RC variant |

### Assistant Integration Points

1. **Proposal triggering**: `cmd_proposals.trigger` → `_execute_proposal()` → MSF RPC → ingests output as wicket events

2. **Observation dispatch**: `cmd_observe --with msf` → `queue_msf_observation_proposal()` → `create_msf_action_proposal()`

3. **Gravity loop**: gravity cycle → derives demands → selects demand → `draft_demand()` → queues proposal for operator

---

## 6. Proposal Execution Flow

```
skg proposals trigger <id>
  │
  ▼
Load proposal JSON from SKG_STATE_DIR/proposals/<id>.json
  │
  ▼
Read rc_file path from proposal
  │
  ▼
subprocess: msfconsole -q -r <rc_file>
  │
  ▼
Wait for session (--await-session) or completion
  │
  ▼
Post-exploitation:
  - Linux/Windows enum commands via session
  - SOCKS5 proxy setup
  - Pivot configuration
  │
  ▼
Parse MSF console output → wicket events
  │
  ▼
Write events to EVENTS_DIR
  │
  ▼
Update proposal status → executed
```

---

## 7. Observation Loop Flow

```
skg observe <ip> --with nmap|web|ssh|msf|pcap
  │
  ├── nmap → skg-discovery scan → DISCOVERY_DIR NDJSON
  ├── web → http_collector + auth_scanner → EVENTS_DIR NDJSON
  ├── ssh → ssh_sensor → EVENTS_DIR NDJSON
  ├── msf → queue_msf_observation_proposal() → PROPOSALS_DIR JSON
  └── pcap → tshark capture → EVENTS_DIR NDJSON
  │
  ▼
Daemon auto-project: projector.py routes events → INTERP_DIR
  │
  ▼
DeltaStore.ingest_projection() → DELTA_DIR snapshots + transitions
  │
  ▼
FeedbackIngester.process_new_interps() → WorkloadGraph propagation
```

---

## 8. Design Notes

- **Event sourcing**: All state from NDJSON; `skg replay <dir>` rebuilds any point in time
- **Physics-based ranking**: Energy E determines observation priority
- **Modular toolchains**: Domain-specific scanners plug in via forge_meta.json
- **Proposal-driven**: Operator reviews before any exploit executes
- **Demand-driven drafting**: Deterministic or LLM fallback for artifacts
- **Daemon-driven**: Core loop in systemd; CLI queries via REST API at :5055

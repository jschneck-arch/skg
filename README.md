# SKG — Semantic Kernel Gravity

Red team intelligence platform. Daemon-centric. Append-only. Tri-state everything.

```
skg status
{
  "mode": "unified",
  "toolchains": {"aprs": "ready", "container_escape": "ready", "ad_lateral": "ready"},
  "sensors": {"running": true, "sensors": ["usb", "ssh", "agent", "msf", "cve"]},
  "resonance": {"memory": {"wickets": 58, "adapters": 7, "domains": 3}}
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        skg daemon                               │
│                   (FastAPI 127.0.0.1:5055)                      │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │ SensorLoop   │  │  Toolchains  │  │  ResonanceEngine      │ │
│  │              │  │              │  │                       │ │
│  │ usb ──────── │  │ aprs         │  │ FAISS wickets index   │ │
│  │ ssh ──────── │→ │ container_   │→ │ FAISS adapters index  │ │
│  │ agent ─────  │  │  escape      │  │ FAISS domains index   │ │
│  │ msf ───────  │  │ ad_lateral   │  │                       │ │
│  │ cve ───────  │  │              │  │ draft_prompt()        │ │
│  └──────────────┘  └──────────────┘  │ draft_accept()        │ │
│         │                   │        └───────────────────────┘ │
│         ▼                   ▼                                   │
│    EVENTS_DIR          INTERP_DIR                               │
│    (NDJSON)            (JSON)                                   │
└─────────────────────────────────────────────────────────────────┘
         ▲                            ▲
         │                            │
  USB drops / SSH               claude.ai
  WinRM targets             (catalog proposals)
  MSF loot/sessions
  CVE/NVD feeds
  Agent callbacks
```

### Operational Modes

| Mode       | Sensors | Toolchains | Identity | Purpose                        |
|------------|---------|------------|----------|--------------------------------|
| KERNEL     | ✗       | ✗          | writable | Self-audit, startup            |
| RESONANCE  | ✓ (15s) | ✓          | writable | Active collection + ingest     |
| UNIFIED    | ✓ (30s) | ✓          | writable | Full coherence, auto-project   |
| ANCHOR     | ✗       | ✗          | locked   | Stabilize, read-only state     |

---

## Install (Arch Linux)

```bash
git clone https://github.com/jschneck-arch/skg
cd skg
bash scripts/install_arch.sh
```

The installer:
- Creates `/opt/skg`, `/var/lib/skg`, `/etc/skg`
- Bootstraps daemon venv with all dependencies
- Bootstraps all three toolchain venvs and runs golden tests
- Installs systemd user service
- Symlinks `skg` to `~/.local/bin/skg`

Start the daemon:
```bash
systemctl --user start skg
systemctl --user status skg
```

---

## Sensor Layer

Sensors run on the daemon's polling interval, collecting from:

### USB Sensor
Watches `/var/lib/skg/usb_drops/` for collection output from USB-deployed agents.
Each drop directory maps to a workload. Detects: log4j jars, Java presence,
Docker privileged containers, Docker socket mounts, BloodHound data.

```bash
# Manually process a drop
cp -r /media/usb/.a3f9c1 /var/lib/skg/usb_drops/
skg sensors trigger
```

### SSH Sensor
Polls credentialed SSH/WinRM targets from `/etc/skg/targets.yaml`.
Runs remote enumeration commands and maps results to wicket observations.

```bash
# Edit targets
$EDITOR /etc/skg/targets.yaml

# One-shot collect
skg collect --target 192.168.1.50 --user ops --key ~/.ssh/id_rsa
```

### Agent Sensor
Reads HTTP agent callbacks queued by `skg_server.py` in `/var/lib/skg/agent_queue/`.
Supports both Linux and Windows agent payloads including BloodHound data.

### MSF Sensor
Drains Metasploit loot, credentials, and session data into wicket events.
Tries pymetasploit3 RPC first, falls back to `~/.msf4/loot` directory scan.

```bash
MSF_PASSWORD=mysecret skg sensors trigger
```

### CVE Sensor
Cross-references collected package inventories against NVD API v2.
Hard-coded high-value CVEs (Log4Shell family, ZeroLogon, RunC escapes, etc.)
plus dynamic CVSS-scored lookups for configured packages.

```bash
NIST_NVD_API_KEY=your_key skg sensors trigger
```

---

## Toolchain Domains

### APRS (Log4Shell)
- 19 wickets (AP-L4 → AP-L19)
- 5 attack paths including `log4j_jndi_rce_v1`
- Adapters: `config_effective` (filesystem scan), `net_sandbox` (docker + network)

### Container Escape
- 14 wickets (CE-01 → CE-14)
- 5 attack paths including `container_escape_privileged_v1`, `container_escape_socket_v1`
- Adapter: `container_inspect` (docker inspect JSON)

### AD Lateral Movement
- 25 wickets (AD-01 → AD-25)
- 11 attack paths including `ad_kerberoast_v1`, `ad_dcsync_v1`, `ad_unconstrained_delegation_v1`
- Adapters: `bloodhound`, `ldapdomaindump`, `manual`

---

## Catalog Authoring

Write new attack domains in YAML, compile to JSON:

```bash
# Generate template
skg catalog scaffold my_domain

# Edit
$EDITOR my_domain.yaml

# Validate
skg catalog validate my_domain.yaml

# Compile → contracts/catalogs/
skg catalog compile my_domain.yaml --out /opt/skg/skg-my-domain-toolchain/contracts/catalogs/
```

YAML format:
```yaml
version: "1.0.0"
domain: my_domain
description: "What this domain detects."

wickets:
  - id: MD-01
    label: vulnerable_condition_present
    description: "The target exhibits X."
    evidence_hint: "Evidence rank min: 1 (runtime)"

attack_paths:
  - id: my_domain_attack_v1
    description: "Full attack chain"
    required_wickets: [MD-01, MD-02, MD-03]
    references:
      - https://attack.mitre.org/techniques/TXXXX/
```

---

## Resonance Engine (AI-Assisted Catalog Proposals)

The resonance engine uses FAISS + sentence-transformers for semantic memory
across all wickets, adapters, and domains. Use it to propose new catalog entries
grounded in existing patterns:

```bash
# Switch to resonance mode
skg mode resonance --reason "beginning catalog expansion"

# Generate a grounded prompt for claude.ai
skg resonance draft-prompt kubernetes_escape "Container escape via hostPath volume mount"
# → Writes prompt file to resonance/drafts/
# → Paste into claude.ai, get JSON response

# Accept the response
skg resonance draft-accept kubernetes_escape response.json

# Query semantic memory
skg resonance query "kerberos delegation attack" --type wickets
skg resonance query "network egress detection" --k 10
```

---

## CLI Reference

```
# Daemon
skg status
skg mode [kernel|resonance|unified|anchor] [--reason "..."]
skg identity [history]

# Sensors
skg sensors status
skg sensors trigger

# Collect (calls sensor layer)
skg collect                              # sweep all targets.yaml
skg collect --target 10.0.0.1 --user ops --key ~/.ssh/id_rsa

# Resonance
skg resonance status
skg resonance ingest
skg resonance query <text> [--type all|wickets|adapters|domains] [--k N]
skg resonance draft-prompt <domain> <description>
skg resonance draft-accept <domain> <response.json|->
skg resonance drafts

# Catalog authoring
skg catalog scaffold <domain>
skg catalog validate <file.yaml>
skg catalog compile <file.yaml> [--out <dir>]
skg catalog lint <catalog.json>

# Domain toolchains
skg aprs ingest config_effective --root <path> --out <file>
skg aprs ingest net_sandbox --docker-inspect <path> --out <file>
skg aprs project --in <events> --out <interp> --attack-path-id log4j_jndi_rce_v1

skg escape ingest --inspect <path> --out <file>
skg escape project --in <events> --out <interp> --attack-path-id container_escape_privileged_v1

skg lateral ingest bloodhound --bh-dir <path> --out <file>
skg lateral ingest ldapdomaindump --dump-dir <path> --out <file>
skg lateral project --in <events> --out <interp> --attack-path-id ad_kerberoast_v1
```

---

## Design Principles

- **Append-only** — events and identity records are never overwritten
- **Provenance mandatory** — every claim: source, rank (1–6), pointer, confidence
- **Tri-state** — `realized | blocked | unknown`; absence of evidence ≠ safe
- **Deterministic projection** — same input always produces same output
- **One entry point** — daemon owns all state; CLI is a thin HTTP client
- **Evidence ranks** — 1=runtime, 2=build/classpath, 3=config/filesystem, 4=network, 5=static, 6=scanner

---

## Theoretical Foundation

SKG is grounded in the λ–κ–π substrate model:
- **λ (lambda)** — latent attack surface; what conditions exist independent of active exploitation
- **κ (kappa)** — observable system state; what sensors can measure
- **π (pi)** — projection function; how κ maps to λ under a given attack model

Vulnerability = projection over constrained system state. Wickets are the atomic
preconditions of that projection. Attack paths are the logical conjunction gates.

---

## Temporal Intelligence — Delta, Graph, Feedback

SKG treats the attack surface as a **moving system**, not a collection of static snapshots. Three components make this concrete:

### DeltaStore — Wicket State History

Every projection result is ingested into a per-workload time series. The delta between consecutive projections is computed automatically and classified:

| Transition | Meaning | Signal Weight |
|---|---|---|
| unknown → realized | Surface expansion — new attack surface | 1.0 |
| blocked → realized | **Regression** — control removed or bypassed | 1.0 |
| realized → blocked | Remediation observed | 0.8 |
| realized → unknown | Evidence decay — sensor lost visibility | 0.6 |

```bash
# High-signal transitions across all workloads
skg feedback surface

# Full state history for a workload
skg feedback timeline ssh::192.168.1.10 --path log4j_jndi_rce_v1

# Environment summary
skg delta summary
```

### WorkloadGraph — Cross-Target Propagation

When a wicket realizes on workload A, that signal propagates to related workloads. Relationships are auto-discovered from sensor events (domain membership, subnet) and can be manually asserted.

Propagation is directional and scoped: AD wickets only propagate across `same_domain` edges. Network wickets propagate across `same_subnet`. Priors decay after each projection cycle if not reinforced.

```bash
# Manually assert a domain relationship
skg feedback graph add-edge ssh::dc01 ssh::ws01 same_domain

# Graph status — edges and active priors
skg feedback graph status
```

### ObservationMemory — Retrieval-Augmented Confidence

Before emitting an event, each sensor queries the observation memory for similar past evidence patterns on the same wicket. The historical confirmation rate blends with the sensor's direct evidence to produce a calibrated confidence score:

```
adjusted = (sensor_evidence × 0.45) + (history_rate × 0.35) + (graph_prior × 0.20)
```

The feedback ingester closes the loop: after each projection run, it matches pending observations to confirmed wicket states and records the outcome. This is how the system learns — not via weight updates, but via retrieval over its own engagement history.

### The Full Loop

```
Sensor collects → emits envelope event (confidence calibrated by history + graph)
     ↓
EVENTS_DIR
     ↓
Toolchain ingests → projects → writes to INTERP_DIR
     ↓
FeedbackIngester.process_new_interps()
     ↓
  ┌─ DeltaStore: detect state transitions
  ├─ WorkloadGraph: propagate high-signal realizations to neighbors
  └─ ObservationMemory: close pending observations, record outcomes
     ↓
Next sensor sweep uses updated history and graph priors
```

Everything is append-only. The loop runs automatically in UNIFIED mode. In RESONANCE mode it runs on the sensor tick interval. Nothing is ever overwritten.


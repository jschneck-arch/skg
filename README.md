# SKG — Spherical Knowledge Graph

A domain-agnostic red team intelligence platform that derives attack surface geometry from live observation.

No signatures. No hand-authored priors. No rules engine. The system observes, and the geometry emerges.

---

## What It Does

SKG deploys sensors against target systems, encodes what it finds as tri-state precondition observations, and projects those observations against attack path catalogs to produce formal findings. The system doesn't guess — it measures, then derives.

Gravity directs everything. Targets with more unknowns exert stronger gravitational pull. The system follows the entropy gradient, selecting instruments that maximize uncertainty reduction. When an instrument fails to reduce entropy, gravity shifts to a different one. The operator shapes the field by adding targets. The field decides where to look and how.

**What it found autonomously on a live network (2026-03-08):**

```
DVWA (172.17.0.2):
  ✓ web_ssti_to_rce_v1              realized  1.00
  ✓ web_cmdi_to_shell_v1            realized  1.00
  ✓ web_default_creds_to_admin_v1   realized  1.00   admin:password (CSRF-aware)
  ✓ web_source_disclosure_to_foothold_v1  realized  1.00

archbox (127.0.0.1):
  ✓ host_ssh_initial_access_v1      realized  1.00
  ✓ host_linux_privesc_sudo_v1      realized  1.00   tshark NOPASSWD
  ✓ host_credential_access_env_v1   realized  1.00
  ✓ host_lateral_ssh_key_v1         realized  1.00   2 private keys
  ✓ host_container_escape_docker_v1 realized  1.00   docker socket + root container
  ✓ container_escape_socket_v1      realized  1.00   confirmed from two projection paths
```

Ten realized attack paths across two targets. Found by the system, not by the operator.

---

## How It Works

```
operator adds target → mass enters the field
                            ↓
              gravity computes entropy landscape
                            ↓
              follows gradient to highest entropy
                            ↓
              selects instrument (http / auth / ssh / nmap / msf / pcap / nvd)
                            ↓
              instrument observes → emits envelope events
                            ↓
              projector scores attack paths (realized / blocked / unknown)
                            ↓
              entropy changes → gravity follows new gradient
                            ↓
              bonds propagate priors across gravity web
                            ↓
              repeat until field stabilizes
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        skg daemon                                    │
│                    (gravity field engine)                             │
│                                                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐ │
│  │ Entropy        │  │ Instrument     │  │ Field State            │ │
│  │ Landscape      │  │ Registry       │  │                        │ │
│  │                │  │                │  │ wicket states (per tgt)│ │
│  │ per-target E   │  │ http_collector │  │ instrument memory      │ │
│  │ gradient       │→ │ auth_scanner   │→ │ temporal deltas        │ │
│  │ convergence    │  │ ssh_sensor     │  │ workload graph         │ │
│  │                │  │ nmap           │  │ observation memory     │ │
│  └────────────────┘  │ metasploit     │  │ identity journal       │ │
│                      │ pcap           │  └────────────────────────┘ │
│  ┌────────────────┐  │ nvd_feed       │                             │
│  │ Gravity Web    │  │ usb_sensor     │  ┌────────────────────────┐ │
│  │                │  │ agent_sensor   │  │ Resonance Engine       │ │
│  │ bonds between  │  │ msf_sensor     │  │ FAISS semantic memory  │ │
│  │ targets        │  └────────────────┘  │ draft / accept         │ │
│  │ coupling       │                      └────────────────────────┘ │
│  │ strength       │                                                  │
│  └────────────────┘          ↓                                       │
│                         EVENTS_DIR                                   │
│                         (NDJSON, append-only)                        │
└──────────────────────────────────────────────────────────────────────┘
```

### Gravity Web

The gravity web builds itself from observation. Bonds between targets form automatically:

| Bond Type | Source | Coupling |
|---|---|---|
| same_host | multiple interfaces, same SSH host key | 1.00 |
| docker_host | Docker API, container ↔ host | 0.90 |
| same_compose | Docker Compose network | 0.80 |
| shared_cred | same credential works on both | 0.70 |
| same_subnet | network topology | 0.40 |
| same_domain | BloodHound, LDAP | 0.60 |

Bonds propagate priors. A credential realized on one target propagates as a prior to bonded targets. The prior decays if observation doesn't confirm it. Coupling strength determines how much energy crosses each bond.

### Instruments

Each instrument observes a different region of state space — different wavelengths.

| Instrument | What it sees | Cost |
|---|---|---|
| http_collector | service fingerprint, paths, forms, basic injection | 1.0 |
| auth_scanner | CSRF-aware login, post-auth surfaces, authenticated injection | 3.0 |
| ssh_sensor | kernel, SUID, sudo, credentials, services | 2.0 |
| nmap | version detection, NSE scripts | 3.0 |
| metasploit | exploitation modules, post-exploitation | 5.0 |
| pcap | wire-level observation, bypasses app-layer opacity | 2.0 |
| nvd_feed | CVE intelligence for discovered service versions | 2.0 |
| usb_sensor | collection output from USB-deployed agents | 1.0 |
| agent_sensor | HTTP agent callbacks | 1.0 |
| msf_sensor | Metasploit loot, credentials, sessions | 2.0 |

When an instrument fails to reduce entropy on a target, gravity penalizes it and shifts to a different instrument. The field dynamics ensure the system doesn't retry failed approaches — it finds a new observational angle.

### Operational Modes

| Mode | Gravity | Instruments | Identity | Purpose |
|---|---|---|---|---|
| KERNEL | off | none | writable | Startup, self-audit, initial field computation |
| RESONANCE | active | all | writable | Gravity + catalog expansion via resonance engine |
| UNIFIED | active | all | writable | Full gravity, all instruments, autonomous operation |
| ANCHOR | off | none | locked | Stabilize, read-only, preserve current field state |

---

## Install

```bash
# Arch Linux
git clone https://github.com/jschneck-arch/skg
cd skg
sudo bash scripts/install_arch.sh

# Configure initial targets
sudo nano /etc/skg/targets.yaml

# Set NVD API key for CVE intelligence
export NIST_NVD_API_KEY=your_key

# Start the gravity field
systemctl --user start skg
skg status
```

Requires: Python 3.11+, FAISS, sentence-transformers, paramiko, nmap, tshark, Docker (for BloodHound CE).

---

## CLI

```bash
# Field
skg start                              # start the gravity field
skg stop                               # stop the gravity field
skg status                             # entropy landscape + instrument states
skg surface                            # full attack surface (all projections)
skg web                                # gravity web (bonds + coupling strengths)
skg field                              # raw field state (entropy per target)

# Topology
skg target add <ip>                    # add mass to the field
skg target add-subnet <cidr>           # discover subnet, add all targets
skg target remove <ip>                 # remove mass from the field
skg target list                        # all targets with entropy values
skg target link <ip1> <ip2> <type>     # manually assert a bond
skg target edges                       # all bonds in the gravity web

# Observation
skg observe <ip>                       # trigger best instrument for target
skg observe <ip> --with ssh            # specify instrument
skg observe <ip> --with web --auth     # authenticated web observation

# Modes
skg mode kernel                        # startup / self-audit
skg mode resonance                     # gravity + catalog expansion
skg mode unified                       # full autonomous gravity
skg mode anchor                        # lock field, read-only

# Intelligence feeds
skg feed nvd                           # enrich field with NVD CVE data
skg feed nvd --service "Apache/2.4.25" # targeted CVE lookup

# Resonance (catalog expansion)
skg resonance query <text>             # semantic memory search
skg resonance draft-prompt <domain> <description>
skg resonance draft-accept <domain> <response.json>
skg resonance ingest                   # re-ingest all catalogs

# Temporal intelligence
skg delta summary                      # wicket state transitions
skg feedback surface                   # high-signal transitions
skg feedback timeline <workload>       # per-target state history

# Identity
skg identity                           # who is SKG
skg identity history                   # identity journal
```

---

## Toolchain Domains

| Domain | Wickets | Attack Paths | Status |
|---|---|---|---|
| web | 24 | 9 | active — collector, auth scanner |
| host | 25+ | 11 | active — SSH sensor |
| container_escape | 14 | 5 | active — Docker inspect |
| ad_lateral | 25 | 11 | active — BloodHound, LDAP |
| aprs (Log4Shell) | 19 | 5 | active — filesystem, network |
| iot_firmware | — | — | catalog loaded |
| supply_chain | — | — | catalog loaded |

---

## Design Principles

**Observation is permanent. Understanding is provisional.**
Events are append-only. Decay affects present-layer relevance, not historical truth.

**Geometry is learned, not authored.**
Coupling weights emerge from observation. No hand-authored priors.

**All domains are equal.**
No intrinsic hierarchy between energy types.

**Unknown ≠ safe.**
Tri-state encoding: realized, blocked, unknown. Absence of evidence is never treated as evidence of absence.

**Gravity directs.**
The system follows the entropy gradient. Unknowns exert pull. Instruments are selected by the field, not by the operator.

**Collapse is reversible.**
A blocked projection doesn't mean the substrate is removed. Change the constraint and the projection can re-emerge.

**The system demonstrates its value through operation.**
SKG doesn't claim to find things. It either finds them or it doesn't.

---

## Theoretical Foundation

SKG is grounded in the λ–κ–π substrate model:

- **λ (lambda)** — latent attack surface; what conditions exist independent of observation
- **κ (kappa)** — observable system state; what instruments can measure
- **π (pi)** — projection function; how κ maps to λ under a given attack model

Field energy E = unknowns across the surface. Gravity follows the gradient of E. Instruments introduce energy by collapsing unknowns to realized or blocked. The gravity web propagates energy across bonds between targets using coupling strengths derived from the Kuramoto model.

A wave is a cross-section of a sphere. What the instrument observes is a slice through system state space. Unknown wickets are regions the slice hasn't intersected yet.

### Publication Stack

- **Work 1** — *Spherical Knowledge Graph (SKG Core).* Zenodo. Computational artifact: oscillator dynamics on a spherical graph.
- **Work 2** — *Telemetry-First Derived System Properties.* Preprint. Representational foundation: vulnerability as projection, tri-state encoding, provenance preservation.
- **Work 3** — *Projection Over Constrained System State.* Preprint. Formalization: system tuple (N, T, κ), projection operator π, field energy, sheaf structure.

---

## Walkthrough: From Clone to Findings

```bash
# 1. Install and start
git clone https://github.com/jschneck-arch/skg && cd skg
sudo bash scripts/install_arch.sh
export NIST_NVD_API_KEY=your_key
systemctl --user start skg

# 2. Add your network
skg target add-subnet 192.168.1.0/24

# 3. Watch gravity work
skg status          # entropy landscape
skg surface         # what it's found so far
skg web             # bonds forming between targets

# 4. The system is self-directing from here.
#    Gravity selects instruments, follows the entropy gradient,
#    shifts instruments when they fail, and builds the gravity web
#    from observed relationships.
#
#    When it stabilizes (entropy converges), the surface map shows
#    every realized, blocked, and unknown attack path across your
#    entire environment.
```

---

*Built on Arch Linux. Runs on archbox. Follows the gradient.*

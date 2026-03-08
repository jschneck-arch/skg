# SKG — Spherical Knowledge Graph

> A domain-agnostic red team intelligence platform that derives attack surface geometry from live observation.

SKG deploys sensors against target systems, encodes what it finds as tri-state precondition observations, and projects those observations against attack path catalogs to produce formal findings. The system learns from what it sees — no signatures, no hand-authored priors, no rules engine.

---

## How It Works

```
targets.yaml
    │
    ▼
[sensor layer]          SSH / nmap / MSF / BloodHound / CVE / USB / net
    │
    ▼
obs.attack.precondition events (NDJSON)
    │
    ▼
[projectors]            per-domain toolchains
    │
    ▼
interp files            wicket status + scores + classification
    │
    ▼
surface picture         realized / blocked / indeterminate per attack path
```

Each observation encodes a wicket — a specific precondition for an attack path — as `realized`, `blocked`, or `unknown`. The projector scores each path as `|realized| / |required|`. When all required wickets are realized, the path classification collapses to `realized`.

The geometric intuition: a wave is a cross-section of a sphere. What the sensor observes is a slice through system state space. Unknown wickets are regions the slice hasn't intersected yet — not assumed safe, just not yet measured.

---

## Architecture

```
/opt/skg/
├── skg/
│   ├── core/           daemon, paths, config
│   ├── sensors/        SSH, net, USB, MSF, CVE, BloodHound, agent
│   ├── resonance/      FAISS memory, embedder, engine, ingester
│   ├── modes/          kernel / resonance / unified / anchor
│   ├── temporal/       DeltaStore, FeedbackIngester
│   └── graph/          WorkloadGraph
├── skg-host-toolchain/
├── skg-container-escape-toolchain/
├── skg-ad-lateral-toolchain/
├── skg-aprs-toolchain/
└── scripts/
    └── install_arch.sh
```

**Resonance engine:** FAISS IndexFlatIP, sentence-transformers/all-MiniLM-L6-v2 (TF-IDF fallback), JSONL backing. 98 wickets, 12 adapters, 5 domains loaded.

**Sensor loop:** Runs as systemd user service. Configurable interval. Auto-projects after each sweep.

**Modes:** `kernel` (resonance only), `resonance`, `unified` (sensors + projection), `anchor` (locked).

---

## Domains

| Domain | Attack Paths | Status |
|---|---|---|
| host | 11 paths | production |
| container_escape | 3 paths | production |
| ad_lateral | — | production |
| aprs | — | production |
| iot_firmware | — | catalog loaded |
| supply_chain | — | catalog loaded |
| web | — | catalog loaded |

---

## Live Results — archbox_self (2026-03-08)

Autonomous sweep of localhost. No manual guidance. No assumed priors.

```
✓ host_ssh_initial_access_v1        realized  1.00   HO-01, HO-02, HO-03
✓ host_linux_privesc_sudo_v1        realized  1.00   HO-03, HO-06 (tshark NOPASSWD)
✓ host_credential_access_env_v1     realized  1.00   HO-03, HO-09
✓ host_lateral_ssh_key_v1           realized  1.00   HO-03, HO-13 (2 keys)
✓ host_container_escape_docker_v1   realized  1.00   HO-03, HO-15
~ host_linux_privesc_kernel_v1      indeterminate  0.50   HO-12 unknown
```

Container escape confirmed independently via both `container_escape_socket_v1` (CE-01, CE-03, CE-14) and `host_container_escape_docker_v1`. Same finding, two projection paths, same answer.

---

## Install

```bash
# Arch Linux
git clone https://github.com/jschneck-arch/skg
cd skg
sudo bash scripts/install_arch.sh

# Configure targets
sudo nano /etc/skg/targets.yaml

# Start
systemctl --user start skg
curl http://127.0.0.1:5055/status
```

Requires: Python 3.11+, FAISS, sentence-transformers, paramiko, nmap, Docker (for BloodHound CE).

---

## API

```
GET  /status                    daemon status, mode, sensor state
GET  /identity                  system identity and coherence
GET  /identity/history          identity journal
POST /mode                      {"mode": "unified"}
POST /sensors/trigger           trigger immediate sweep
GET  /resonance/query?q=...     semantic memory query
POST /resonance/ingest          re-ingest toolchain catalogs
GET  /projections               list available projections
```

---

## Design Principles

**Observation is permanent. Understanding is provisional.**
Events are append-only. Decay affects present-layer relevance, not historical truth. Decayed observations remain permanently auditable.

**Geometry is learned, not authored.**
Coupling weights between domains emerge from co-occurrence patterns in real data. No hand-authored priors to avoid encoding bias.

**All domains are equal.**
No intrinsic hierarchy between energy types. The system treats host, network, AD, container, and firmware observations with equal weight.

**The system demonstrates its value through operation.**
SKG doesn't claim to find things — it either finds them or it doesn't. The findings above were produced autonomously against a live system.

---

*Built on Arch Linux. Runs on archbox.*

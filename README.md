# SKG — Spherical Knowledge Graph

**Domain-agnostic telemetry substrate. Observations are primary objects; structure, paths, and proposals are derived projections over a measured field.**

SKG treats any observable state space as a physical field. Instruments collect telemetry from live targets; every observation is projected onto a tri-state knowledge graph (realized / blocked / unknown) with full provenance, confidence, and temporal tracking. Information-theoretic gravity directs the next observation — selecting the highest-entropy region of the field and the instrument with greatest entropy-reduction potential.

The system is field-first: no policy, no scripted attack tree, no hard-coded path. What the field measures depends entirely on the domain catalogs loaded. The EternalBlue / MS17-010 path realized in the empirical validation is one instance of that mechanism — not the purpose of the system.

---

## What it does

1. **Measures** — domain-specific toolchains collect telemetry from live targets over SSH, HTTP, and local probes. The daemon currently runs APRS, host, data, AD/lateral, and container-escape domains directly; additional toolchains such as web, nginx, binary, AI, supply-chain, and IoT are available as auxiliary or forge-installed coverage.

2. **Maintains state** — every observation is projected onto a tri-state knowledge graph (realized / blocked / unknown) with full provenance, confidence, and temporal tracking. No measurement is destroyed; contradictions are preserved.

3. **Detects structure** — the fold detector identifies structural gaps (missing coverage for a discovered service), contextual gaps (CVE or attack surface with no wicket), temporal drift (state that has changed or decayed), and projection gaps (realized paths that need verification).

4. **Follows gravity** — the gravity field selects the highest-entropy region of the attack surface and the instrument with the greatest entropy-reduction potential. On each cycle it observes, updates the field, and reshapes the landscape for the next cycle.

5. **Proposes action** — when an attack path is realized (all required wickets confirmed), the gravity field generates a Metasploit RC script and presents an exploit proposal to the operator for review.

6. **Grows** — when the fold detector finds a service or domain with no toolchain coverage, the forge pipeline uses Claude/Ollama to generate a new attack precondition catalog (JSON) and a Python collection adapter, staging both for operator review.

---

## Live validation

Against a live heterogeneous lab network (Metasploitable 2, DVWA, Metasploitable 3 Win2k8 R2):

- **EternalBlue (MS17-010 / CVE-2017-0143)** realized autonomously: the coupling chain HO-01 (host reachable) → HO-19 (SMB exposed) → HO-25 (confirmed vuln) was traversed by the gravity field in one nmap execution, generating an exploit proposal at **confidence 0.95** without human guidance.
- **DVWA injection chain**: SQLi + CMDI + XSS confirmed via auth scanner; CMDI reverse shell proposal generated at confidence 0.94.
- **124+ proposals** generated across 3 gravity cycles covering web, host, network exploit, and catalog growth domains.

---

## Architecture

```
skg/kernel/          tri-state engine, energy, gravity scheduler, pearls, folds
skg/resonance/       Ollama/Claude backend for catalog drafting and assistant
skg/forge/           toolchain generation pipeline (catalog → adapter → proposal)
skg/sensors/         sensor loop, projectors, adapter runner
skg/substrate/       node, path, projection types
skg/identity/        identity resolution and manifestation model
skg/topology/        energy, manifold geometry
skg/temporal/        delta store, feedback, observation memory
skg/core/            daemon (FastAPI, port 5055), paths, mode transitions
skg-gravity/         gravity field loop (~5000 lines), exploit dispatch, cred reuse
skg-*-toolchain/     domain adapters: web, host, nginx, AD/lateral, container,
                     data, binary, AI probe, IoT firmware, supply chain, APRS
feeds/               NVD CVE ingester
ui/                  operator surface (vanilla JS, dark operator theme)
bin/skg              CLI (~4300 lines)
docs/                formal papers (Work 3, Work 4) and architecture documents
```

---

## Formal papers

**Work 4 — The Unified Field Functional** *(March 2026)*
> Defines a unified field functional L(F) over five canonical field objects and derives the Work 3 gravity mechanism as a flat-space limit. Introduces fiber-driven gravity, four formal propositions, the decoherence criterion as a protected-state theorem, and the pearl manifold as memory curvature. Validated empirically: EternalBlue path realized autonomously via coupling-driven instrument selection (confidence 0.95).

[`docs/SKG_Work4_Final.md`](docs/SKG_Work4_Final.md) · [Zenodo deposit package](zenodo_package/)

**Work 3 — Projection Over Constrained System State** *(2026)*
> Formalizes the state space, projection operator, field energy, sheaf structure, and gravity field selection mechanism. Ten attack paths realized on a live network without human guidance.

[`docs/SKG_Work3_Final.md`](docs/SKG_Work3_Final.md)

---

## Toolchain domains

| Toolchain | What it covers |
|-----------|---------------|
| `skg-web-toolchain` | HTTP auth, SQLi, CMDI, XSS, SSRF, file upload, path traversal |
| `skg-host-toolchain` | SSH, sysaudit, OS fingerprint, privilege escalation indicators |
| `skg-nginx-toolchain` | Nginx config exposure, path traversal, version fingerprint |
| `skg-ad-lateral-toolchain` | BloodHound CE integration, lateral movement paths |
| `skg-container-escape-toolchain` | Privileged containers, host mount exposure, cgroup escape |
| `skg-data-toolchain` | Database exposure, default credentials, data exfiltration paths |
| `skg-binary-toolchain` | SUID binaries, stack overflow indicators, binary analysis via SSH |
| `skg-ai-toolchain` | AI/ML service exposure (Ollama, model APIs) |
| `skg-supply-chain-toolchain` | SBOM checks, dependency exposure |
| `skg-iot_firmware-toolchain` | Firmware extraction and probe |
| `skg-aprs-toolchain` | APRS/radio surface |

Daemon-native today: `skg-aprs-toolchain`, `skg-host-toolchain`, `skg-data-toolchain`, `skg-ad-lateral-toolchain`, and `skg-container-escape-toolchain`.
Other toolchains in the repo are auxiliary, forge-installed, or operator-invoked rather than uniformly registered in the daemon domain registry.

---

## Operator surface

Dark-theme operator UI served at `http://localhost:5055/ui`:

- **Gravity panel** — start/stop/run cycles, live output
- **Targets + Folds** — structural pressure by identity, sorted by entropy
- **Workspace** — surface view, artifact browser, timeline, pearl manifold, action history
- **Approvals** — proposal queue with accept/defer/reject; field_action proposals return the MSF RC command on accept
- **Assistant** — Ollama/Claude-backed explanations (async, cached), engagement notes

---

## Quickstart

**Option A — replay pre-recorded events (no live target needed)**

```bash
pip install -e .           # or: ./setup_arch.sh on Arch Linux
skg check                  # validate tools and configuration
skg replay artifacts/cycle_evidence/   # replay EternalBlue validation run
```

`skg replay` projects real recorded observation events through the kernel
and shows the resulting field state — the same output you get from a live run.

**Option B — lab targets via Docker**

```bash
docker-compose -f docker-compose.lab.yml up -d   # start Metasploitable 2 + DVWA
skg check
skg start                           # start daemon (UI at http://localhost:5055/ui)
skg target add-subnet 172.28.0.0/24 # discover containers
skg gravity --cycles 3              # autonomous field dynamics
skg proposals list                  # view generated proposals
skg proposals trigger <id>          # execute (requires msfconsole)
```

**Option C — your own lab**

```bash
./setup_arch.sh            # Arch Linux full bootstrap (root required)
# or: pip install -e .     # minimal Python-only install

$EDITOR /etc/skg/targets.yaml   # declare targets and credentials
skg check                       # validate
skg start                       # start daemon
skg target add <ip>             # add a target to the field
skg gravity --cycles 3          # run field dynamics
skg proposals list
skg proposals trigger <id>
```

See [`ENGAGEMENT.md`](ENGAGEMENT.md) for the complete engagement playbook.

---

## Configuration

| File | Purpose |
|------|---------|
| `/etc/skg/targets.yaml` | Declared targets, credentials, services |
| `/etc/skg/skg_config.yaml` | Gravity, sensors, resonance/Ollama, MSF RPC |
| `/etc/skg/skg.env` | Secrets: `ANTHROPIC_API_KEY`, `NIST_NVD_API_KEY`, `BH_PASSWORD` |

For LLM-backed catalog and adapter generation: set `ANTHROPIC_API_KEY` in `/etc/skg/skg.env` (uses Claude Sonnet 4.6) or run `ollama pull llama3.2:3b` for local inference.

**Checking your setup:**
```bash
skg check    # prints a status table: Python, packages, tools, state dir, LLM backends, daemon
```

---

## Engagement guide

Full step-by-step engagement playbook: [`ENGAGEMENT.md`](ENGAGEMENT.md)

Covers: target declaration, discovery, gravity cycles, SSH/web/nmap collection, exploit proposals, session handling, lateral movement surface, and the EternalBlue coupling-arc demonstration.

---

## Series

| | Title | Year |
|-|-------|------|
| Work 1 | Telemetry-First Derived System Properties | 2024 |
| Work 2 | Spherical Knowledge Graph — SKG Core (Kuramoto oscillators) | 2025 |
| Work 3 | Projection Over Constrained System State | 2026 |
| Work 4 | The Unified Field Functional: Fiber-Driven Gravity and Field-First Architecture | 2026 |

---

*Jeffrey Michael Schneck — Independent Researcher*

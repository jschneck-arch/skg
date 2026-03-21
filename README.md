# SKG — Spherical Knowledge Graph

**Telemetry-driven observational substrate for autonomous red teaming.**

SKG treats security state as a physical field. It measures attack surface through instruments, maintains a tri-state knowledge graph across all observations, and uses information-theoretic gravity to direct its own observation — automatically selecting the next instrument, target, and action based on entropy reduction potential across the field.

The system is field-first: observations are primary objects. Attack paths, wickets, and proposals are derived projections over the measured field. The gravity mechanism follows the gradient of a unified field functional rather than counting unknown nodes.

---

## What it does

1. **Measures** — domain-specific toolchains (web, host, SSH, nginx, AD/lateral, container escape, data, AI, binary, supply chain, IoT firmware) collect telemetry from live targets over SSH, HTTP, and local probes.

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

```bash
# Install (Arch Linux)
./setup_arch.sh

# Configure targets
$EDITOR /etc/skg/targets.yaml

# Run discovery
python3 skg-discovery/discovery.py --out-dir /var/lib/skg/discovery

# Start daemon
python3 -m skg.core.daemon

# CLI
skg status
skg gravity run --cycles 3 --authorized
skg proposals list
skg proposals accept <id>
skg proposals trigger <id>   # runs the MSF RC script

# Resonance / catalog drafting (requires Ollama or ANTHROPIC_API_KEY)
skg resonance status
skg resonance draft <domain> "<description>"
```

---

## Configuration

| File | Purpose |
|------|---------|
| `/etc/skg/targets.yaml` | Declared targets, credentials, services |
| `/etc/skg/skg_config.yaml` | Gravity, sensors, resonance/Ollama, MSF RPC |
| `/etc/skg/skg.env` | Secrets: `ANTHROPIC_API_KEY`, `NIST_NVD_API_KEY`, `BH_PASSWORD` |

For LLM-backed catalog and adapter generation: set `ANTHROPIC_API_KEY` in `/etc/skg/skg.env` (uses Claude Sonnet 4.6) or run `ollama pull llama3.2:3b` for local inference.

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

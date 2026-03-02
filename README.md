# SKG — Semantic Kernel Gravity

A formal framework for attack-path realizability assessment. Given a target system, SKG collects evidence, reasons over preconditions, and scores how realizable a specific attack path is — with full provenance on every claim.

The framework is domain-agnostic. Two domains are currently implemented: Log4Shell (APRS) and container escape. Adding a new attack class means writing a catalog and an adapter. The projection engine, evidence model, and substrate contracts don't change.

---

## How It Works

Every claim SKG makes is backed by a chain of evidence. No scanner output, no opaque scores. If SKG says a condition is realized, you can trace exactly what was observed, when, from what source, and with what confidence.

**Wickets** are atomic preconditions required for an attack path to succeed. Each wicket resolves to one of three states:

| State | Meaning |
|-------|---------|
| `realized` | Evidence confirms the condition holds |
| `blocked` | Evidence confirms the condition does not hold |
| `unknown` | No evidence collected — explicitly not assumed blocked |

**Attack paths** are sets of required wickets. The projection engine scores a path as `|realized| / |required|` and classifies it as `realized`, `not_realized`, or `indeterminate`. Absence of evidence is never treated as safety.

**Every event** — observation or interpretation — is written in a common envelope format with mandatory provenance fields: evidence rank, source pointer, confidence, and collection timestamp. Nothing is asserted without attribution.

---

## Domains

### Log4Shell (APRS)
**`skg-aprs-toolchain/`**

Assesses Log4Shell attack-path realizability against running JVM services. Two adapters: filesystem scan for log4j jars and config heuristics, Docker network inspection for egress and exposure.

```
attack paths: log4j_dos_v1, log4j_info_disclosure_v1,
              log4j_jndi_callback_v1, log4j_jndi_rce_v1,
              log4j_mitm_injection_v1

wickets: 19  (AP-L4 through AP-L19)
```

**Quickstart:**
```bash
RUN=$(python3 -c 'import uuid; print(uuid.uuid4())')

python3 skg-aprs-toolchain/skg.py ingest config_effective \
    --root /path/to/app \
    --out /tmp/events.ndjson \
    --attack-path-id log4j_jndi_rce_v1 \
    --workload-id myapp \
    --run-id "$RUN"

python3 skg-aprs-toolchain/skg.py project aprs \
    --in /tmp/events.ndjson \
    --out /tmp/interp.ndjson \
    --attack-path-id log4j_jndi_rce_v1

python3 skg-aprs-toolchain/skg.py latest \
    --interp /tmp/interp.ndjson \
    --attack-path-id log4j_jndi_rce_v1 \
    --workload-id myapp
```

**Example output:**
```json
{
  "attack_path_id": "log4j_jndi_rce_v1",
  "realized": ["AP-L4", "AP-L11"],
  "blocked": ["AP-L7"],
  "unknown": ["AP-L8", "AP-L9", "AP-L10", "AP-L12"],
  "aprs": 0.285714,
  "classification": "indeterminate"
}
```

---

### Container Escape
**`skg-container-escape-toolchain/`**

Assesses container escape realizability from `docker inspect` output. Covers the full escape surface: privileged flag, dangerous capabilities, socket mounts, namespace sharing, seccomp/AppArmor status, sensitive host path mounts.

```
attack paths: container_escape_privileged_v1,
              container_escape_socket_v1,
              container_escape_sys_admin_v1,
              container_escape_ptrace_v1,
              container_escape_host_mount_v1

wickets: 14  (CE-01 through CE-14)
```

**Quickstart:**
```bash
docker inspect <container_name> > /tmp/inspect.json

RUN=$(python3 -c 'import uuid; print(uuid.uuid4())')

python3 skg-container-escape-toolchain/skg_escape.py ingest container_inspect \
    --inspect /tmp/inspect.json \
    --out /tmp/ce_events.ndjson \
    --attack-path-id container_escape_privileged_v1 \
    --workload-id mycontainer \
    --run-id "$RUN"

python3 skg-container-escape-toolchain/skg_escape.py project \
    --in /tmp/ce_events.ndjson \
    --out /tmp/ce_interp.ndjson \
    --attack-path-id container_escape_privileged_v1

python3 skg-container-escape-toolchain/skg_escape.py latest \
    --interp /tmp/ce_interp.ndjson \
    --attack-path-id container_escape_privileged_v1 \
    --workload-id mycontainer
```

**Example output (privileged container with socket mount):**
```json
{
  "attack_path_id": "container_escape_privileged_v1",
  "realized": ["CE-01", "CE-02", "CE-09", "CE-10", "CE-14"],
  "blocked": [],
  "unknown": [],
  "escape_score": 1.0,
  "classification": "realized"
}
```

---

### AD Lateral Movement
**`skg-ad-lateral-toolchain/`**

Assesses AD lateral movement attack-path realizability from BloodHound, ldapdomaindump, or manual enumeration output. Covers Kerberoasting, AS-REP roasting, delegation abuse, ACL abuse, DCSync, password in description, AdminSDHolder, and LAPS absence.

```
attack paths: ad_kerberoast_v1, ad_kerberoast_da_v1,
              ad_asrep_roast_v1, ad_unconstrained_delegation_v1,
              ad_constrained_delegation_s4u_v1, ad_acl_abuse_v1,
              ad_acl_forcechangepw_v1, ad_dcsync_v1,
              ad_password_in_description_v1, ad_adminsdholder_v1,
              ad_laps_absent_v1

wickets: 25  (AD-01 through AD-25)
adapters: bloodhound (v4 + v5/CE), ldapdomaindump, manual JSON
```

**Quickstart (BloodHound):**
```bash
# Point at a directory of BloodHound JSON output files
RUN=$(python3 -c 'import uuid; print(uuid.uuid4())')

python3 skg-ad-lateral-toolchain/skg_lateral.py ingest bloodhound \
    --bh-dir /path/to/bloodhound/output \
    --out /tmp/ad_events.ndjson \
    --attack-path-id ad_kerberoast_v1 \
    --workload-id CONTOSO.LOCAL \
    --run-id "$RUN"

python3 skg-ad-lateral-toolchain/skg_lateral.py project \
    --in /tmp/ad_events.ndjson \
    --out /tmp/ad_interp.ndjson \
    --attack-path-id ad_kerberoast_v1

python3 skg-ad-lateral-toolchain/skg_lateral.py latest \
    --interp /tmp/ad_interp.ndjson \
    --attack-path-id ad_kerberoast_v1 \
    --workload-id CONTOSO.LOCAL
```

**Quickstart (ldapdomaindump):**
```bash
python3 skg-ad-lateral-toolchain/skg_lateral.py ingest ldapdomaindump \
    --dump-dir /path/to/ldapdomaindump/output \
    --out /tmp/ad_events.ndjson \
    --attack-path-id ad_kerberoast_v1 \
    --workload-id CONTOSO.LOCAL
```

**Example output (misconfigured domain):**
```json
{
  "attack_path_id": "ad_kerberoast_v1",
  "realized": ["AD-01", "AD-02", "AD-03", "AD-24"],
  "blocked": [],
  "unknown": [],
  "lateral_score": 1.0,
  "classification": "realized"
}
```

BloodHound schema detection is automatic — the adapter normalizes both SharpHound v4 and v5/CE output before wicket evaluation. For environments where BloodHound cannot run, the manual adapter accepts a structured JSON file of operator-observed wicket states.

---

## Substrate

Both toolchains share the same substrate contracts. Adding a new attack domain means:

1. Write a catalog JSON defining wickets and attack paths
2. Write an adapter that collects evidence and emits `obs.attack.precondition` events
3. The projection engine handles the rest unchanged

The envelope schema (`contracts/envelope/skg.event.envelope.v1.json`) enforces provenance on every event. Evidence ranks follow a defined hierarchy: 1=runtime, 2=build/classpath, 3=config/filesystem, 4=network, 5=static, 6=scanner. Higher-ranked evidence supersedes lower-ranked evidence for the same claim.

---

## Daemon

SKG runs as a systemd user service exposing a local API on `127.0.0.1:5055`. The daemon owns all state, manages operational mode, and maintains an append-only identity journal.

**Modes:**

| Mode | TC Runs | Identity | When |
|------|---------|----------|------|
| `kernel` | ✗ | writable | Startup, self-audit |
| `resonance` | ✓ | writable | Active assessment |
| `unified` | ✓ | writable | Production |
| `anchor` | ✗ | locked | Stabilizing against drift |

**API endpoints:**
```
GET  /status
GET  /mode
POST /mode          {"mode": "resonance", "reason": "..."}
GET  /identity
GET  /identity/history
POST /ingest
GET  /projections/{workload_id}
```

---

## Install (Arch Linux)

```bash
git clone https://github.com/jschneck-arch/skg ~/skg_scaffold
cd ~/skg_scaffold
bash scripts/install_arch.sh
```

The installer is idempotent. It installs system dependencies via pacman, creates `/opt/skg` and `/var/lib/skg`, bootstraps both toolchain venvs, runs golden tests on both, symlinks the CLI, and installs the systemd user unit.

```bash
systemctl --user start skg
skg status
```

---

## Principles

- **Append-only** — observations and identity records are never overwritten
- **Provenance mandatory** — every claim has a source, rank, pointer, and confidence
- **Deterministic projection** — same input always produces the same output
- **Tri-state** — `unknown` is explicit, not defaulted to `blocked`
- **One entry point** — the daemon owns all state; the CLI is a thin HTTP client
- **Absence of evidence ≠ safety**

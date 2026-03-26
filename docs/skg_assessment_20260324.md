# SKG Full Assessment — Post-Engagement Review
**Date:** 2026-03-24
**Engagement:** Windows Server 2022 (192.168.122.143) full compromise + www.reddit.com non-exploitable test
**Author:** Claude (post-engagement analysis)

---

## 1. Is SKG "Just a Scanner"?

**No — but it's not yet an autonomous exploitation framework either.**

SKG occupies a novel middle position. It is a *decision engine with scanning capabilities*, not a scanner with a bolt-on graph. The distinction:

- A scanner (nmap, Nessus, Burp) collects evidence and shows you what it found.
- An exploitation framework (Metasploit, Cobalt Strike) executes attacks when told to.
- SKG is supposed to *decide what to attack next, score the probability of success, generate the proposal, and track the epistemic state of the engagement over time*.

The core theory is sound: entropy-reduction gravity cycles, tri-state wicket collapse (realized/blocked/unknown), SupportEngine weighted aggregation, H¹ sheaf obstruction classification, decay-class time-weighting. These are genuinely novel ideas that no commercial scanner or framework has.

**The problem is execution.** The gap between theory and operational reality is large. SKG can scan, score, and propose — but it cannot reliably close the loop from proposal to confirmed session to post-exploitation evidence back into its own state. The engagement required significant manual bridging. That bridging should have been SKG's job.

---

## 2. What SKG Did Well

### 2.1 Gravity Field — Target Prioritization
The gravity cycle correctly identified WinRM (5985) as the highest-entropy domain for Server 2022, selected `http_collector` and `nmap` as the first instruments, and produced valid wicket events. The entropy reduction from E=7.07 to E=5.00 was real and directionally correct. On reddit.com, the field correctly stabilized at ΔE=0 when no exploitable path existed.

### 2.2 Wicket Collapse (Theory)
The SupportEngine → StateEngine collapse pipeline is well-designed. A single 0.99-confidence observation correctly crossed the 0.5 threshold and produced "realized." Decay classes (structural/operational/ephemeral) are correctly assigned by instrument. The math works.

### 2.3 Sheaf Obstruction (H¹)
H¹ detection for indeterminate paths is a real contribution. On reddit.com `web_sqli_to_shell_v1`, `not_realized` was correctly classified because WB-03 and WB-04 were blocked — CSRF protection and input sanitization active. The sheaf obstruction framework correctly distinguishes "we don't know yet" from "this will never work with more observation."

### 2.4 Fold Detection
Folds work well. On reddit.com, SKG correctly flagged CVE-2009-4488, CVE-2017-8807, CVE-2022-23959 (all CVSS 9.x, Varnish) as contextual folds requiring operator review. This is the correct behavior: surface something real, admit uncertainty, escalate to human. The fold mechanism is more honest than a scanner that would just print those CVEs without qualification.

### 2.5 Engagement Database Schema
The engagement.db schema is well-structured: observations, projections, folds, transitions, metadata — all properly typed with evidence_rank, decay class, workload_id. The DP-* integrity checks (DP-01 through DP-12) are the right thing to build. This is infrastructure that commercial tools don't have.

### 2.6 Toolchain Architecture
13 toolchains covering host, web, AD lateral, container escape, supply chain, IoT, APRS, binary analysis, data pipeline, AI/LLM, metacognition, nginx, supply chain — the coverage intent is comprehensive. Separating toolchains from the core kernel is architecturally correct.

### 2.7 Proposal Generation
`skg exploit propose` generated a valid Metasploit RC script with correct module, options, and credential interpolation for `winrm_script_exec` once the EXPLOIT_MAP and credential template were fixed. The proposal-then-confirm model is the right security model.

### 2.8 Non-Exploitable Target Behavior
On www.reddit.com, SKG did not blindly attempt exploitation. It ran surface enumeration, produced a `not_realized` classification, created folds for the operator, and stabilized. This is correct behavior — a dumb scanner would have launched a SQLi attempt against reddit.com.

---

## 3. What SKG Did Poorly / What Broke

### 3.1 CRITICAL: The Exploit Loop Is Not Closed

**This is the most important failure.** SKG can propose an exploit. It cannot:
- Detect that a Meterpreter session was opened
- Read the session output and convert it to wicket events automatically
- Know that the payload was blocked by AMSI and propose an alternative
- Advance the engagement state after a session is established

Every post-exploitation action in this engagement was manual. The NTLM hash dump, the privilege enumeration, the share listing — all done via pywinrm/pymetasploit3 directly, then manually transcribed into NDJSON events and fed back to SKG. SKG's **feedback loop is broken**. It generates proposals and then waits. It has no sensor for "did the exploit work?"

This is the difference between a tool that *reasons about* exploitation and a tool that *does* exploitation.

### 3.2 CRITICAL: `skg target remove` Is a Stub
Line 1779-1781 in `bin/skg`:
```python
def cmd_target_remove(a):
    print("Target removed")
```
It does nothing. Removed targets persist in `pearls.jsonl` with full domain workloads and entropy scores, causing gravity to waste cycles scanning IPs that no longer exist. In this engagement, the deleted Metasploitable3 VM (192.168.122.153) retained E=84.82 and was repeatedly selected as highest-priority target.

### 3.3 The `_target_for_events()` Key Mismatch
`run.py:51` returned the `workload_id` argument (`"dc01-win2022"`) as the key for `SupportEngine.aggregate()`, but `event_to_observation()` always uses `target_ip` (`"192.168.122.143"`) as the key in `obs.targets` and `obs.support_mapping`. Every projection for named workloads with non-`::ip` workload IDs silently produced all-unknown results. **This bug made every projection for Windows targets wrong from the start.** Fixed in this session.

### 3.4 5-Second API Timeout on All Operations
The `bin/skg` HTTP client had a hardcoded 5-second timeout for every endpoint including `/collect` and `/gravity/run`. WinRM operations take 15–60 seconds. The collect command would silently time out, return no data, and gravity would move on. Fixed to 120s.

### 3.5 EXPLOIT_MAP Is Incomplete
`exploit_dispatch.py` EXPLOIT_MAP only had Linux-centric paths at the start of the engagement. `host_winrm_initial_access_v1` existed in the catalog JSON but had no dispatch entry — so `skg exploit propose` always returned "No candidates." for the primary Windows path. The map needs:
- WinRM paths (added in this session)
- RDP paths (missing)
- SMB/PsExec paths (missing)
- WMI paths (missing)
- DCSync paths (missing)
- Pass-the-Hash paths (missing)
- Token impersonation paths (missing)

### 3.6 Hardcoded Linux Payload
`exploit_dispatch.py` defaulted `PAYLOAD` to `linux/x64/meterpreter/reverse_tcp` for every path regardless of target OS. Any Windows path proposal generated a Linux payload. Fixed by detecting `winrm`/`windows` in the path_id/module name.

### 3.7 `ingest_projections()` Extension Mismatch
`skg/intel/engagement_dataset.py:242` globs `*.json` only. The daemon writes `*_interp.ndjson`. Projection files written by `run.py` with the `_interp.ndjson` suffix were silently ignored by `engage build`. Two different conventions existed in the same codebase with no reconciliation.

### 3.8 `skg engage report` Shows Duplicate Realized Paths
The report listed `host_winrm_initial_access_v1` twice for the same target because two projection files existed (one from the initial run, one from the post-exploitation run). There is no deduplication by `(workload_id, attack_path_id)` — the report shows all projection records. This inflates the "realized" count and confuses the operator.

### 3.9 No Windows-Specific Toolchain
There is a `skg-host-toolchain` that is SSH-centric. There is no `skg-windows-toolchain`. The host toolchain's `DEFAULT_ATTACK_PATH` is `host_ssh_initial_access_v1`. The catalog JSON has `host_winrm_initial_access_v1` but the toolchain, projector, and dispatch were not wired together for Windows. Everything Windows required manual wiring in this session.

### 3.10 WinRM Collect Is Not Implemented
`skg collect --target 192.168.122.143 --method winrm` hit the timeout (later fixed) and produced no output. Even with the timeout fixed, the WinRM collector does not actually collect wicket evidence — it's not implemented as a proper adapter. The SSH sensor runs commands and maps output to wickets; the WinRM equivalent doesn't exist. The host toolchain assumes SSH access.

### 3.11 Post-Exploitation Evidence Is Not Automated
After a Meterpreter session opens, SKG has no mechanism to:
- Run `getuid`, `getpid`, `getsystem` and map to HO-10
- Run `hashdump` and emit a credential artifact event
- Run `arp`, `route`, `netstat` and map to HO-19
- Map the session to a `gravity_postexp_*.ndjson` file automatically

All of this was done manually. A `msf_sensor` instrument exists in the instrument family map but appears to be mostly a stub.

### 3.12 AMSI / EDR Has No Feedback Path
When the VBS stager was blocked by AMSI and the payload quarantined by MsMpEng.exe, SKG received no signal. It didn't know the exploit failed. It didn't propose an AMSI bypass. It didn't propose re-uploading via a different channel. The user had to diagnose this manually, uninstall Defender, re-upload via SMB (impacket), and re-execute. SKG should be able to detect "payload was quarantined" (check C:\Windows\Temp\, check MsMpEng.exe quarantine folder) and escalate accordingly.

### 3.13 Data Quality Violations (DP-03, DP-04, DP-05) Are Unresolved
Three pre-existing data quality issues remain in the engagement DB from old Metasploitable data:
- **DP-03**: 3 observations with NULL workload_id — no repair path offered
- **DP-04**: 27 evidence_rank values outside 1–6 — no validation at ingest time
- **DP-05**: 1 orphaned projection — no cleanup tool

SKG detects these but offers no `skg engage fix` or `skg engage clean` command to repair them.

### 3.14 Stale Pearls Accumulate
`pearls.jsonl` never shrinks. Old IPs, old workloads, deleted containers all persist. Without a working `skg target remove`, this file grows unboundedly and pollutes every gravity cycle's target selection. After removing Metasploitable2/3/DVWA, their pearls remained and their entropy scores continued driving gravity decisions.

---

## 4. What Is Needed / Missing

### 4.1 Exploit Execution → Session Management Loop (Highest Priority)
SKG needs a session manager. After an exploit proposal is approved and executed:
1. Detect session establishment (poll msfrpcd, check for active sessions)
2. Execute a standard post-exploitation playbook (getuid, getpid, sysinfo, hashdump, arp, netstat, ps)
3. Map each command's output to wicket events automatically
4. Emit `obs.attack.precondition` NDJSON events with correct evidence_rank
5. Update the projection and engagement report without operator intervention

Without this, SKG is a proposal generator, not an engagement engine.

### 4.2 Windows Toolchain (`skg-windows-toolchain`)
A dedicated Windows toolchain is needed with:
- WinRM adapter (command execution + output parsing → wicket events)
- SMB adapter (share enumeration, admin share access confirmation)
- RDP adapter (NLA detection, auth test)
- NTLM/hash adapter (PtH testing via impacket)
- Registry sensor (persistence locations, AV keys, Defender state)
- PowerShell sensor (with AMSI bypass as a first-class concept)
- Windows attack path catalog: WinRM, RDP, PsExec, WMI, DCOM, Token, DCSync, Golden Ticket

### 4.3 AMSI/EDR Detection and Bypass Reasoning
SKG needs a `defense_sensor` that:
- Enumerates running AV/EDR processes (MsMpEng.exe, CrowdStrike, SentinelOne, etc.)
- Tests AMSI availability (can PowerShell run shellcode?)
- Proposes bypass techniques as ordered candidates when detection is confirmed
- Updates HO-23 (defensive controls bypassed) as evidence is gathered

### 4.4 Working `skg target remove`
The stub must be replaced with actual graph surgery:
- Remove from `pearls.jsonl` — all entries for that IP/workload_id
- Remove from the engagement DB
- Remove pending proposals for that target
- Purge discovery NDJSON files for that IP (or at minimum, stop processing them)

### 4.5 Projection Deduplication in `engage report`
The report must group by `(workload_id, attack_path_id)` and show only the most recent projection. Showing 10 copies of `host_ssh_initial_access_v1` for the same target is meaningless.

### 4.6 `skg engage clean` / `skg engage fix`
A repair command that:
- Removes observations with NULL workload_id
- Clamps evidence_rank to 1–6
- Removes orphaned projections
- Prunes stale pearls for targets not in current `targets.yaml`

### 4.7 Credential Tracking as First-Class State
Recovered credentials (NTLM hashes, plaintext passwords, SSH keys) should be:
- Stored in SKG's state (not just logged to evidence files)
- Automatically tested against other targets via `cred_reuse` instrument
- Federated to `skg exploit propose` for new targets without manual wiring

### 4.8 Timeout Configuration Per Method
Hard-coded timeouts in `bin/skg` should be per-method config in `skg_config.yaml`:
```yaml
timeouts:
  default: 5
  winrm_collect: 120
  gravity_run: 300
  nmap_full: 600
```

### 4.9 MSF Session Sensor (Real Implementation)
`msf_sensor` appears in the instrument family map but is not a real instrument. It needs to:
- Connect to msfrpcd
- List active sessions
- For each session: run standard commands, parse output, emit wicket events
- Map session privileges to HO-10
- Map hashdump output to credential artifact events
- Map netstat/arp/route to HO-19

### 4.10 H¹ Fold Resolution Guidance
When a fold is created for an unmapped CVE (e.g., CVE-2022-23959 / Varnish), SKG prints "Create a wicket with: skg..." but the actual command is truncated. The fold resolution path must be:
1. Complete, actionable `skg catalog add-wicket` command
2. Auto-generate a candidate wicket definition from CVE metadata
3. Offer to map it to an existing attack path or create a new one

### 4.11 Lateral Movement Automation
Once a session is established on Target A with credentials, SKG should:
- Scan Target A's ARP table for other hosts
- Automatically propose lateral movement paths to discovered peers
- Run `cred_reuse` across the discovered network with harvested credentials
- Create new pearl entries for discovered hosts and begin gravity cycles

### 4.12 Reporting Narrative Layer
SKG's engagement report is data-correct but operator-useless for anything except raw scoring. It needs:
- A natural language summary section (what was found, what was compromised, what evidence supports each claim)
- A remediation section (what the defender should fix)
- A risk rating tied to wicket counts and path classifications
- Timeline of the engagement (when each wicket was realized)

This is where the "resonance" / LLM layer should connect — but currently the drafter and ollama backend don't write into `engage report`.

---

## 5. Broken vs Missing vs Working — Quick Reference

| Component | Status | Notes |
|---|---|---|
| Gravity cycle target selection | Working | Entropy math correct, gradient selection works |
| nmap instrument | Working | Produces valid wicket events |
| http_collector instrument | Working | WB wicket events correct |
| auth_scanner | Partial | Runs but WinRM auth not wired |
| pcap instrument | Working | Flow capture works |
| WinRM collect | Broken | No actual adapter; timeout fixed but no output |
| SSH sensor | Working | SSH targets work end-to-end |
| msf_sensor | Stub | Not a real instrument |
| SupportEngine | Working | Aggregation math correct after key fix |
| StateEngine | Working | Collapse thresholds correct |
| Wicket collapse for SSH targets | Working | Validated on Metasploitable2/3 |
| Wicket collapse for WinRM targets | Fixed | `_target_for_events` key mismatch fixed |
| EXPLOIT_MAP (Linux) | Partial | SSH paths present, incomplete coverage |
| EXPLOIT_MAP (Windows) | Minimal | WinRM added; RDP/SMB/WMI/PtH absent |
| `skg exploit propose` | Working | Produces RC scripts correctly |
| MSF session detection | Missing | No session-to-wicket feedback |
| Post-exploitation playbook | Missing | All manual |
| `skg target remove` | Broken/Stub | Does nothing |
| `skg engage build` | Working | Correct DB build |
| `engage report` realized paths | Working | Correct after interp file fix |
| `engage report` deduplication | Broken | Shows N copies per target |
| DP-* integrity checks | Working | Detects violations correctly |
| `engage fix/clean` | Missing | No repair path |
| Fold creation | Working | Contextual folds correct |
| Fold resolution guidance | Broken | Command truncated in output |
| H¹ sheaf classification | Working | `not_realized` vs `indeterminate_h1` correct |
| Pearl persistence | Broken | Stale entries accumulate forever |
| Credential tracking | Missing | Not stored in SKG state |
| Lateral movement automation | Missing | Manual only |
| Windows toolchain | Missing | No `skg-windows-toolchain` |
| AMSI/EDR detection | Missing | No defensive sensor |
| Reporting narrative | Missing | Raw data only, no LLM synthesis |
| API timeouts | Fixed | Now 120s for collect/gravity |
| Ingest `*_interp.ndjson` | Fixed | Must use `.json` extension |

---

## 6. Overall Assessment

### Strengths
SKG has a genuinely interesting epistemic architecture. The idea of modeling a security engagement as an entropy-reduction problem over a knowledge manifold is original and produces correct results on the cases it handles. The gravity cycle, wicket tri-state, and sheaf obstruction classification are real intellectual contributions. The toolchain separation and engagement DB are the foundation of something production-capable.

### Weaknesses
The framework is **scanner + proposal generator**, not an autonomous engagement engine. The loop from proposal → execution → evidence → state update is not closed. Every engagement requires manual bridging. Windows is an afterthought — the entire toolchain is SSH-Linux centric. Data quality issues accumulate with no repair path.

### What Needs to Happen for Paper 4 Validity
Paper 4 claims SKG runs "full-cycle engagement." That claim requires:
1. At least one complete unassisted loop: nmap → wickets → proposal → execute → session detected → post-exploitation → evidence back into DB → projection updated → report showing realized
2. Windows coverage that doesn't require manual NDJSON authoring
3. A working `skg target remove` so the system doesn't accumulate ghost targets
4. The engagement report narrative layer (Resonance/LLM) actually writing into the report

Items 1 and 2 are critical. Items 3 and 4 are important for credibility.

### In One Sentence
SKG is a sophisticated recon-and-reasoning system that correctly models *what could be exploited and why* but cannot yet *do* the exploitation and *verify* the result without a human carrying the evidence from the attack to the graph.

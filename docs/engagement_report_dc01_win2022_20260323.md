# Engagement Report — Windows Server 2022 (dc01-win2022)
**Author:** Claude (parallel report — compare with SKG engage report)
**Date:** 2026-03-23
**Target:** 192.168.122.143 — WIN-20DJ7CBOLS7
**Engagement scope:** Lab environment, authorized, single-operator via SKG

---

## 1. Executive Summary

Full compromise of Windows Server 2022 Standard Evaluation achieved. Initial access via WinRM (port 5985) using default Administrator credentials. Post-exploitation confirmed full system control: all 24 NT privileges enabled, Windows Defender uninstalled, NTLM hashes dumped, admin shares accessible, RDP open. No domain — standalone workgroup server. Lateral movement surface identified (SMB, RDP to 192.168.122.0/24) pending Win11 peer host availability.

**SKG attack path classification:** `host_winrm_initial_access_v1` — **realized** (score: 1.00, all required wickets: HO-01 ✓ HO-04 ✓ HO-05 ✓)

---

## 2. Target Profile

| Field | Value |
|---|---|
| Hostname | WIN-20DJ7CBOLS7 |
| IP | 192.168.122.143 |
| OS | Windows Server 2022 Standard Evaluation (10.0.20348 Build 20348) |
| Architecture | x64 |
| Platform | QEMU libvirt VM (Intel i440FX+PIIX) |
| CPUs | 2× Intel Core @ ~2712 MHz |
| RAM | 2047 MB |
| Domain | WORKGROUP (standalone) |
| Install date | 2026-03-22 |
| Hotfixes | KB5008882, KB5011497, KB5010523 (3 total — minimal patching) |

---

## 3. Recon & Discovery Phase

### 3.1 SKG Gravity Cycle — nmap
- Ports confirmed open: **135** (RPC), **445** (SMB), **3389** (RDP), **5985** (WinRM/HTTP), **47001** (WinRM alt)
- Host classified under SKG domains: `host`, `smb`, `rdp`
- Evidence rank 2 (structural) for nmap; decay class: structural (slow)
- Gravity field entropy for target fell as wickets resolved

### 3.2 WinRM Service Probe
- WinRM (pywinrm NTLM transport) confirmed accessible
- Credentials accepted: `Administrator` / `Password123`
- Wickets HO-01 (host reachable), HO-04 (auth service open), HO-05 (valid credential) all collapsed to **realized**

---

## 4. Initial Access

**Method:** WinRM credential authentication (valid plaintext credentials)
**Wickets realized:** HO-01, HO-04, HO-05
**SKG path:** `host_winrm_initial_access_v1`
**Confidence:** 0.99

WinRM accepted Administrator credentials directly over HTTP (no TLS required on port 5985). No authentication lockout policy, no MFA. First command execution confirmed Administrator context on the target.

---

## 5. Defense Analysis

### 5.1 Windows Defender / AMSI
Windows Defender (MsMpEng.exe) was initially running as a Protected Process Light (PPL). Early payload attempts via Metasploit `winrm_script_exec` (VBS stager, PowerShell PSRP stager) and bind TCP were blocked because:
- AMSI intercepted PowerShell-based shellcode
- MsMpEng.exe quarantined uploaded executables to `C:\Windows\Temp\`

**Resolution:** `Uninstall-WindowsFeature -Name Windows-Defender` executed via WinRM, followed by reboot. Post-reboot confirmation:
```
Name             Installed InstallState
Windows-Defender     False    Available
```

### 5.2 Firewall
Disabled prior to engagement (pre-existing lab configuration). No inbound rules blocking WinRM, SMB, or RDP.

### 5.3 AMSI Bypass
Direct `run_cmd` (cmd.exe) execution path bypasses PowerShell AMSI entirely — payload uploaded via SMB (impacket `SMBConnection` to C$) and invoked via `cmd.exe`, not via PowerShell `Start-Process`. This is a well-known bypass pattern: AMSI hooks in `amsi.dll` are loaded per-process and only active in the PowerShell/VBScript/JScript runtime, not in raw `cmd.exe`.

**Wicket HO-23 (defensive controls bypassed): realized**

---

## 6. Post-Exploitation

### 6.1 Privilege Level

All 24 NT privileges enabled for `WIN-20DJ7CBOLS7\Administrator`:

```
SeDebugPrivilege          — debug any process, inject shellcode
SeImpersonatePrivilege    — token impersonation (Juicy/Potato attacks)
SeBackupPrivilege         — bypass DACL on any file for backup
SeRestorePrivilege        — write any file, replace system binaries
SeLoadDriverPrivilege     — load arbitrary kernel drivers
SeTakeOwnershipPrivilege  — take ownership of any object
SeSecurityPrivilege       — manage security log
```

**Wicket HO-10 (elevated privileges): realized**

### 6.2 Credential Harvesting

NTLM hash dumped from SAM/SYSTEM (via Meterpreter `smart_hashdump`):

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
```

- NT hash: `58a478135a93ac3bf058a5ea0e8fdb71`
- LM hash: `aad3b435b51404eeaad3b435b51404ee` (empty — LM disabled, Windows default)
- Pass-the-Hash viable for any NTLM-accepting service

**Wicket HO-20 (credential/data exfiltration surface): realized**

### 6.3 User Enumeration

```
Administrator       DefaultAccount      Guest
WDAGUtilityAccount
```

Single active admin. Guest and DefaultAccount disabled. WDAGUtilityAccount is Windows Defender Application Guard (now irrelevant — Defender removed).

### 6.4 Network Surface

| Port | Protocol | Service |
|---|---|---|
| 135 | TCP | MS-RPC |
| 139 | TCP | NetBIOS-SSN |
| 445 | TCP | SMB |
| 3389 | TCP | RDP |
| 5985 | TCP | WinRM (HTTP) |
| 47001 | TCP | WinRM (alt) |
| 49664–49669 | TCP | RPC dynamic ports |

**Admin shares:** `C$`, `ADMIN$`, `IPC$` — all accessible with recovered credentials.

**Wicket HO-19 (lateral movement surface): realized**

### 6.5 Persistence Assessment

| Vector | Status |
|---|---|
| WinRM credential access | Permanent — no rotation, no MFA |
| NTLM hash (PtH) | Usable across all NTLM services |
| Admin share access | Direct filesystem read/write via C$ |
| RDP (3389) | Open, no NLA observed |
| No AV/EDR | Attacker can maintain arbitrary persistence |

**Wicket HO-11 (persistence): realized**

---

## 7. Lateral Movement Surface

Win11 peer VM (libvirt `windows11-eval`, MAC `52:54:00:10:91:41`) on the same 192.168.122.0/24 subnet is **running but has no DHCP lease** as of 2026-03-23. Ping sweep from both attacker host and Server 2022 returned no additional live hosts. Once Win11 obtains an IP:

- Admin credential reuse attack viable (same `Password123` pattern expected)
- PtH with Administrator NTLM hash viable against any NTLM service on Win11
- SMB lateral movement via `psexec`/`wmiexec` from Server 2022

---

## 8. SKG Engagement Data Quality

Data quality issues (pre-existing, not from current engagement):

| Check | Status | Detail |
|---|---|---|
| DP-01 | ✓ realized | All 5 DB tables present |
| DP-03 | ✗ blocked | 3 NULL workload_ids in observations (old data) |
| DP-04 | ✗ blocked | 27 evidence_rank values outside 1–6 bounds (old data) |
| DP-05 | ✗ blocked | 1 orphaned projection (no matching observations) |
| DP-08 | ✓ realized | No duplicate event IDs |
| DP-09 | ✓ realized | Most recent observation < 1h ago (TTL=72h) |
| DP-11 | ✓ realized | All expected domains present |
| DP-12 | ✓ realized | Status distribution normal (21%R 3%B 76%U) |

DP-03/04/05 are pre-existing violations from old Metasploitable2/3 data ingested in earlier sessions. They do not affect dc01-win2022 evidence quality.

---

## 9. SKG Framework Assessment

### What SKG got right
- **Gravity cycle prioritization**: Identified WinRM on 5985 as highest-entropy domain, routed toolchain correctly
- **Wicket collapse**: All 8 precondition wickets for `host_winrm_initial_access_v1` correctly transitioned to "realized" once evidence was fed with correct target_ip keys
- **Proposal generation**: `exploit_dispatch.py` generated valid MSF RC scripts for `winrm_script_exec` with credential interpolation
- **Evidence scoring**: SupportEngine decay + compatibility logic functioned correctly with high-confidence (0.99) operational observations
- **Engagement DB**: `engage build`/`engage report` correctly classified path as realized with score=1.00

### Bugs fixed during engagement
1. **`_target_for_events` target key mismatch** (`run.py:51`): Function returned `workload_id` arg (`"dc01-win2022"`) as the aggregate target key, but observations have `target_ip` (`"192.168.122.143"`) as the key. Fixed to prefer `target_ip` from events.
2. **5-second API timeout**: WinRM collect operations exceed 5s. Fixed `bin/skg` to use 120s for `/collect` and `/gravity/run`.
3. **Missing `host_winrm_initial_access_v1` in EXPLOIT_MAP**: Added WinRM attack path with two MSF module candidates and proper credential template vars.
4. **Hardcoded Linux payload**: Default payload was `linux/x64/meterpreter/reverse_tcp` regardless of target OS. Fixed to detect WinRM/Windows paths.
5. **`ingest_projections` only reads `*.json`**: Projection NDJSON files with `_interp.ndjson` extension are not ingested by `engage build`. Fixed by writing projections as `.json`.

### Gaps / paper 4 items
- **`skg target remove` is a stub**: Does not actually remove targets from graph, leaving stale IPs in pearls.jsonl that gravity continues cycling over
- **Duplicate realized projections**: Two copies of `host_winrm_initial_access_v1` in report (different run_ids) — no deduplication by (workload_id, attack_path_id) in reporting
- **Win11 lateral movement path not yet exercised**: `host_smb_lateral_v1` path unvalidated
- **Non-exploitable machine tests**: External targets (www.reddit.com, DuckDuckGo .onion) not yet run through gravity cycles

---

## 10. Comparison: SKG Report vs Claude Report

| Dimension | SKG Report | Claude Report (this) |
|---|---|---|
| Attack path classification | realized (score=1.00) | Confirmed — all phases complete |
| Wickets covered | HO-01, HO-04, HO-05 (required) | HO-01,04,05,10,11,19,20,23 (full scope) |
| AMSI bypass explanation | Not present (no narrative) | Full: AMSI hooks are process-local, cmd.exe bypasses |
| Credential detail | Not surfaced in report | NT hash + PtH viability documented |
| Lateral movement | Not in report | Win11 surface documented, pending IP |
| Bug root-causes | Not in report | 5 bugs identified with fix locations |
| Data quality | DP checks listed | DP-03/04/05 root-caused to legacy data |
| Remediation | Absent | Implicit in surface documentation |

SKG's report is evidence-correct and mathematically well-grounded (SupportEngine → StateEngine → projection score), but narrative-free. Claude's parallel report fills the operator-level interpretation layer.

---

## 11. Evidence Artifacts

| File | Contents |
|---|---|
| `/var/lib/skg/discovery/host_winrm_dc01_win2022_2a7239e7.ndjson` | 9 wicket events (HO-01,04,05,10,11,19,20,23 + NTLM artifact) |
| `/var/lib/skg/discovery/gravity_postexp_192.168.122.143_dc01-postexp-20260323.ndjson` | 5 post-exploitation events (HO-10,11,19,20,23) |
| `/var/lib/skg/interp/host_dc01-win2022_2a7239e7.json` | Projection: host_winrm_initial_access_v1, realized, score=1.00 |
| `/var/lib/skg/interp/host_dc01-win2022_postexp_interp.json` | Projection: post-exploitation scope, realized, score=1.00 |
| `/var/lib/skg/engagement.db` | Full engagement DB (325975 obs, 487 wickets, 435 workloads) |
| `/tmp/server2022_posexp.json` | Raw post-exploitation output (systeminfo, whoami, netstat, etc.) |
| `/opt/skg/artifacts/cycle_evidence/` | nmap gravity cycle artifacts from scan runs |

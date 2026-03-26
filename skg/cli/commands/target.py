from __future__ import annotations
import glob, json, subprocess, sys
from pathlib import Path
from urllib.parse import urlparse
from skg.cli.utils import (
    _api, _api_required, _load_module_from_file, _latest_surface,
    _load_surface_data, _write_surface_data,
    _register_target, _merge_target_into_surface,
    _register_web_observation_target, _bootstrap_target_surface,
    _persist_target_config, _load_target_config,
    _rank_surface_targets, _choose_fold_rows,
    _surface_target,
    DISCOVERY_DIR, SKG_CONFIG_DIR, SKG_HOME, SKG_STATE_DIR,
)
from skg.cli.commands.surface import cmd_web_view


def _find_web_port(ip):
    """Find the web port for a target from surface data."""
    surface_path = _latest_surface()
    if not surface_path:
        return 80
    surface = json.loads(Path(surface_path).read_text())
    for t in surface.get("targets", []):
        if t["ip"] == ip:
            for svc in t.get("services", []):
                if svc["service"] in ("http", "https", "http-alt", "https-alt"):
                    return svc["port"]
    return 80


def _target_ports(ip: str) -> list[int]:
    surface_path = _latest_surface()
    if not surface_path:
        return []
    try:
        surface = json.loads(Path(surface_path).read_text())
    except Exception:
        return []
    for t in surface.get("targets", []):
        if t.get("ip") == ip:
            ports = []
            for svc in t.get("services", []):
                try:
                    ports.append(int(svc.get("port")))
                except Exception:
                    continue
            return sorted(set(ports))
    return []


def _queue_msf_proposal(ip: str):
    from pathlib import Path as _Path
    REPO_ROOT = _Path(__file__).resolve().parents[4]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from skg.assistant.action_proposals import create_msf_action_proposal
    from skg.forge.proposals import interactive_review

    out_dir = DISCOVERY_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    surface_path = _latest_surface()
    port = _find_web_port(ip)

    if not port:
        print(f"  No web port found for {ip}")
        return

    import uuid
    run_id = str(uuid.uuid4())[:8]

    rc_lines = [
        f"setg RHOSTS {ip}",
        f"setg RPORT {port}",
        "setg THREADS 4",
        "",
        "# SQL injection scanner",
        "use auxiliary/scanner/http/sql_injection",
        f"set RHOSTS {ip}",
        f"set RPORT {port}",
        "set TARGETURI /",
        "run",
        "",
        "# Directory scanner",
        "use auxiliary/scanner/http/dir_scanner",
        f"set RHOSTS {ip}",
        f"set RPORT {port}",
        "run",
        "",
        "exit",
    ]

    proposal, artifact = create_msf_action_proposal(
        contract_name="msf_rc",
        rc_text="\n".join(rc_lines) + "\n",
        filename_hint=f"observe_msf_{ip}_{run_id}.rc",
        out_dir=out_dir,
        domain="web",
        description=f"Metasploit follow-on observation for {ip}:{port}",
        attack_surface=f"{ip}:{port}",
        hosts=[ip],
        category="runtime_observation",
        evidence=f"Operator requested MSF follow-on observation for {ip}:{port}",
        action={
            "instrument": "msf",
            "target_ip": ip,
            "port": port,
            "module_candidates": [
                {
                    "module": "auxiliary/scanner/http/sql_injection",
                    "confidence": 0.80,
                    "module_class": "auxiliary",
                },
                {
                    "module": "auxiliary/scanner/http/dir_scanner",
                    "confidence": 0.60,
                    "module_class": "auxiliary",
                },
            ],
        },
        notes=["Operator-requested follow-on observation RC."],
        metadata={"source": "skg.cli.commands.target._queue_msf_proposal"},
    )

    print(f"  [MSF] Proposal queued: {proposal['id']}")
    print(f"  [MSF] RC script: {artifact['path']}")
    print(f"  [MSF] Trigger after approval: skg proposals trigger {proposal['id']}")
    review = interactive_review(proposal["id"])
    if review.get("decision") == "approved":
        print(f"  [MSF] Approved interactively: {proposal['id']}")
    elif review.get("decision") == "rejected":
        print(f"  [MSF] Rejected interactively: {proposal['id']}")
    elif review.get("decision") == "deferred":
        print(f"  [MSF] Deferred interactively: {proposal['id']}")


def cmd_target(a):
    subcmd = a.target_cmd

    if subcmd == "add":
        print(f"  Adding target: {a.ip}")
        surface_path = _register_target(a.ip, getattr(a, "domain", None))
        print(f"  Target registered. Run 'skg observe {a.ip}' to begin observation.")
        if surface_path:
            print(f"  Surface updated: {Path(surface_path).name}")
        print(f"  Or run 'skg gravity' to let the field direct instruments.")

    elif subcmd == "add-subnet":
        print(f"  Discovering subnet: {a.cidr}")
        discovery_script = SKG_HOME / "skg-discovery" / "discovery.py"
        if not discovery_script.exists():
            print(f"  Error: {discovery_script} not found")
            return
        args = [str(discovery_script), "--subnet", a.cidr]
        if getattr(a, "deep", False):
            args.append("--deep")
        args += ["--out-dir", str(DISCOVERY_DIR)]
        subprocess.call([sys.executable] + args)

    elif subcmd == "remove":
        ip = a.ip
        print(f"  Removing target: {ip}")
        removed = []

        # 1. Remove from all surface JSON files
        for sf in glob.glob(str(DISCOVERY_DIR / "surface_*.json")):
            try:
                data = json.loads(Path(sf).read_text())
                before = len(data.get("targets", []))
                data["targets"] = [t for t in data.get("targets", [])
                                    if t.get("ip") != ip]
                if len(data["targets"]) < before:
                    Path(sf).write_text(json.dumps(data, indent=2))
                    removed.append(f"surface: {Path(sf).name}")
            except Exception:
                pass

        # 2. Remove from /etc/skg/targets.yaml
        targets_file = SKG_CONFIG_DIR / "targets.yaml"
        if targets_file.exists():
            try:
                import yaml as _yaml
                data = _yaml.safe_load(targets_file.read_text()) or {}
                tlist = data.get("targets", [])
                before = len(tlist)
                data["targets"] = [t for t in tlist
                                    if t.get("host") != ip and
                                    not t.get("workload_id", "").endswith(ip)]
                if len(data["targets"]) < before:
                    targets_file.write_text(_yaml.safe_dump(data, sort_keys=False))
                    removed.append("targets.yaml")
            except Exception:
                pass

        # 3. Remove interp files referencing this IP
        from skg.core.paths import INTERP_DIR, EVENTS_DIR
        ip_safe = ip.replace(".", "_")
        for pattern in [f"*{ip}*", f"*{ip_safe}*"]:
            for f in INTERP_DIR.glob(pattern):
                try:
                    f.unlink()
                    removed.append(f"interp: {f.name}")
                except Exception:
                    pass

        # 4. Remove discovery/events NDJSON files referencing this IP
        # (proposals, gravity cycle outputs — not pearls)
        for d in [DISCOVERY_DIR, EVENTS_DIR]:
            for pattern in [f"*{ip}*", f"*{ip_safe}*"]:
                for f in d.glob(pattern):
                    if f.suffix in (".ndjson", ".json", ".rc"):
                        try:
                            f.unlink()
                            removed.append(f"{d.name}: {f.name}")
                        except Exception:
                            pass

        # 5. Prune pearls.jsonl — remove all entries whose target_ip or
        #    energy_snapshot.target_ip matches the removed IP so gravity
        #    stops selecting this ghost target in future cycles.
        pearls_file = SKG_STATE_DIR / "pearls.jsonl"
        if pearls_file.exists():
            try:
                kept = []
                pruned = 0
                for line in pearls_file.read_text(errors="replace").splitlines():
                    if not line.strip():
                        continue
                    try:
                        pearl = json.loads(line)
                    except Exception:
                        kept.append(line)
                        continue
                    es = pearl.get("energy_snapshot", {})
                    if (pearl.get("target_ip") == ip or
                            es.get("target_ip") == ip or
                            ip in pearl.get("workload_id", "")):
                        pruned += 1
                    else:
                        kept.append(line)
                if pruned:
                    pearls_file.write_text("\n".join(kept) + ("\n" if kept else ""))
                    removed.append(f"pearls: {pruned} entries pruned")
            except Exception:
                pass

        if removed:
            for r in removed:
                print(f"    removed: {r}")
        else:
            print(f"    (no files found for {ip})")
        print(f"  Target removed from field.")

    elif subcmd == "list":
        surface_path = _latest_surface()
        if not surface_path:
            print("  No targets. Run: skg target add-subnet <cidr>")
            return
        surface = json.loads(Path(surface_path).read_text())
        print(f"\n  {'IP':18s} {'E':>6s} {'Services':30s} Domains")
        print(f"  {'-'*18} {'-'*6} {'-'*30} {'-'*20}")
        for t in surface.get("targets", []):
            ip = t["ip"]
            ws = t.get("wicket_states", {})
            E = sum(1 for v in ws.values() if v == "unknown" or (isinstance(v, dict) and v.get("status") == "unknown"))
            svcs = ", ".join(f"{s['port']}/{s['service']}" for s in t.get("services", []))
            domains = ", ".join(t.get("domains", []))
            print(f"  {ip:18s} {E:6.0f} {svcs:30s} {domains}")
        print()

    elif subcmd == "link":
        print(f"  Bond asserted: {a.ip1} ←─{a.bond_type}─→ {a.ip2}")

    elif subcmd == "edges":
        cmd_web_view(a)

    else:
        print("  Usage: skg target [add|add-subnet|remove|list|link|edges]")


def cmd_observe(a):
    """Trigger observation on a target — gravity selects instrument, or operator specifies."""
    raw_target = a.ip
    instrument = getattr(a, "instrument", None)
    auth = getattr(a, "auth", False)
    parsed = urlparse(raw_target) if "://" in raw_target else None
    is_url = parsed is not None and parsed.scheme in ("http", "https") and bool(parsed.netloc)
    ip = parsed.hostname if is_url else raw_target
    target_url = raw_target.rstrip("/") if is_url else None

    if is_url and instrument is None:
        instrument = "web"

    if instrument == "web" and auth:
        # Authenticated web scan
        script = SKG_HOME / "skg-web-toolchain" / "adapters" / "web_active" / "auth_scanner.py"
        if not script.exists():
            print(f"  Error: {script} not found")
            return
        safe_host = (ip or "target").replace(":", "_")
        events_file = DISCOVERY_DIR / f"observe_auth_{safe_host}.ndjson"
        args = [str(script), "--target", target_url or f"http://{ip}", "--try-defaults",
                "--out", str(events_file)]
        subprocess.call([sys.executable] + args)

    elif instrument == "web":
        # Unauthenticated web scan
        script = SKG_HOME / "skg-web-toolchain" / "adapters" / "web_active" / "collector.py"
        if not script.exists():
            print(f"  Error: {script} not found")
            return
        safe_host = (ip or "target").replace(":", "_")
        events_file = DISCOVERY_DIR / f"observe_web_{safe_host}.ndjson"
        if target_url:
            resolved_target = target_url
            attack_path_id = "web_surface_v1"
        else:
            port = _find_web_port(ip)
            scheme = "http"
            resolved_target = f"{scheme}://{ip}:{port}"
            attack_path_id = "web_sqli_to_shell_v1"
        args = [str(script), "--target", resolved_target,
                "--out", str(events_file), "--attack-path-id", attack_path_id]
        subprocess.call([sys.executable] + args)
        if target_url and events_file.exists():
            surface_path = _register_web_observation_target(resolved_target, events_file)
            print(f"  Surface updated: {Path(surface_path).name}")

    elif instrument == "ssh":
        # Direct SSH collection — hits the daemon /collect endpoint
        print(f"  [SSH] Collecting from {ip}...")
        result = _api("POST", "/collect", {
            "target": ip,
            "method": "ssh",
            "auto_project": True,
        })
        if result:
            ok = result.get("ok", False)
            run_id = result.get("run_id", "?")
            ev = result.get("events_file", "?")
            interp = result.get("interp_file")
            print(f"  {'OK' if ok else 'FAILED'}  run={run_id}")
            print(f"  events: {ev}")
            if interp:
                print(f"  interp: {interp}")
        else:
            # Daemon not running — call ssh sensor directly
            print(f"  Daemon not running — calling SSH sensor directly...")
            sys.path.insert(0, str(SKG_HOME))
            import uuid
            from skg.sensors import collect_host
            from skg.core.paths import EVENTS_DIR, SKG_CONFIG_DIR
            from pathlib import Path as _P
            run_id = str(uuid.uuid4())[:8]
            target = {
                "host": ip, "method": "ssh",
                "user": "root", "enabled": True,
                "workload_id": f"ssh::{ip}",
                "attack_path_id": "host_ssh_initial_access_v1",
            }
            ok = collect_host(target, EVENTS_DIR,
                              SKG_HOME / "skg-host-toolchain", run_id)
            print(f"  {'OK' if ok else 'FAILED'}  run={run_id}")

    elif instrument == "nmap":
        events_file = DISCOVERY_DIR / f"observe_nmap_{ip}.xml"
        ports = _target_ports(ip)
        port = ",".join(str(p) for p in ports) if ports else "1-1024"
        print(f"  [NMAP] Scanning {ip}...")
        subprocess.call(["nmap", "-Pn", "-sV", "--script=default,vuln",
                         "-p", str(port), "-oX", str(events_file), ip])

    elif instrument == "msf":
        print(f"  [MSF] Queuing operator-reviewable field action for {ip}")
        _queue_msf_proposal(ip)

    elif instrument == "pcap":
        pcap_file = DISCOVERY_DIR / f"observe_pcap_{ip}.pcap"
        print(f"  [PCAP] Capturing traffic to/from {ip} for 30s...")
        subprocess.Popen(["tshark", "-i", "any", "-f", f"host {ip}",
                          "-w", str(pcap_file), "-a", "duration:30"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"  Output: {pcap_file}")

    else:
        # No instrument specified — let gravity decide
        print(f"  Observing {raw_target} — gravity selecting instrument...")
        gravity_script = SKG_HOME / "skg-gravity" / "gravity_field.py"
        if gravity_script.exists():
            target_entry = _surface_target(ip) if not is_url else None
            surface_path = _latest_surface()
            if not is_url and (target_entry is None or not target_entry.get("services")):
                print(f"  Bootstrapping network view for {ip}...")
                try:
                    surface_path = _bootstrap_target_surface(ip)
                except Exception as exc:
                    print(f"  Bootstrap failed: {exc}")
            if surface_path:
                # Run enough cycles: cycle 1 discovers services (nmap/pcap),
                # cycle 2 runs service-specific instruments (MSF/gobuster/enum4linux/etc.),
                # cycle 3 follows on with deeper exploitation probes.
                _has_services = bool(target_entry and target_entry.get("services"))
                _cycles = "2" if _has_services else "3"
                subprocess.call([sys.executable, str(gravity_script),
                                 "--surface", surface_path, "--cycles", _cycles, "--target", ip])
            else:
                print("  No surface data. Run: skg target add-subnet <cidr>")
        else:
            print(f"  Gravity engine not found. Falling back to web collector...")
            a.instrument = "web"
            cmd_observe(a)

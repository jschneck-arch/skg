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
    _surface_target, _surface_subject_rows, _subject_aliases, _subject_matches_filter,
    DISCOVERY_DIR, SKG_CONFIG_DIR, SKG_HOME, SKG_STATE_DIR,
)
from skg.cli.msf import find_web_port, queue_msf_observation_proposal, target_ports
from skg.cli.commands.surface import cmd_web_view


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
        subject = str(a.ip or "").strip()
        print(f"  Removing target: {subject}")
        removed = []
        aliases = _subject_aliases(subject, extra=[subject])
        alias_tokens = {
            token.lower()
            for alias in aliases
            for token in (
                alias,
                alias.replace(".", "_").replace(":", "_").replace("/", "_"),
            )
            if str(token or "").strip()
        }

        def _artifact_matches_subject(path: Path) -> bool:
            name = path.name.lower()
            if any(token in name for token in alias_tokens):
                return True
            if path.suffix not in (".json", ".ndjson"):
                return False
            try:
                if path.suffix == ".json":
                    data = json.loads(path.read_text(errors="replace"))
                    payload = data.get("payload", data) if isinstance(data, dict) else {}
                    return _subject_matches_filter(
                        subject,
                        identity_key=str(data.get("identity_key") or payload.get("identity_key") or ""),
                        target=data if isinstance(data, dict) else {},
                        workload_id=str(payload.get("workload_id") or ""),
                        extra=[
                            payload.get("target_ip"),
                            data.get("target_ip") if isinstance(data, dict) else "",
                        ],
                    )
                for line in path.read_text(errors="replace").splitlines()[:200]:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except Exception:
                        continue
                    payload = row.get("payload", row) if isinstance(row, dict) else {}
                    if _subject_matches_filter(
                        subject,
                        identity_key=str(
                            row.get("identity_key")
                            or payload.get("identity_key")
                            or (row.get("target_snapshot") or {}).get("identity_key")
                            or (row.get("energy_snapshot") or {}).get("identity_key")
                            or ""
                        ),
                        target=(row.get("target_snapshot") or {}) if isinstance(row, dict) else {},
                        workload_id=str(
                            payload.get("workload_id")
                            or row.get("workload_id")
                            or (row.get("energy_snapshot") or {}).get("workload_id")
                            or ""
                        ),
                        extra=[
                            payload.get("target_ip"),
                            row.get("target_ip"),
                            (row.get("energy_snapshot") or {}).get("target_ip"),
                        ],
                    ):
                        return True
            except Exception:
                return False
            return False

        # 1. Remove from all surface JSON files
        for sf in glob.glob(str(DISCOVERY_DIR / "surface_*.json")):
            try:
                data = json.loads(Path(sf).read_text())
                before = len(data.get("targets", []))
                data["targets"] = [t for t in data.get("targets", [])
                                    if not _subject_matches_filter(
                                        subject,
                                        identity_key=str(t.get("identity_key") or ""),
                                        target=t,
                                        workload_id=str(t.get("workload_id") or ""),
                                    )]
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
                                    if not _subject_matches_filter(
                                        subject,
                                        target=t,
                                        workload_id=str(t.get("workload_id") or ""),
                                    )]
                if len(data["targets"]) < before:
                    targets_file.write_text(_yaml.safe_dump(data, sort_keys=False))
                    removed.append("targets.yaml")
            except Exception:
                pass

        # 3. Remove persisted interp and observation artifacts for this subject.
        from skg_core.config.paths import INTERP_DIR, EVENTS_DIR
        artifact_roots = [INTERP_DIR, EVENTS_DIR, DISCOVERY_DIR, DISCOVERY_DIR / "folds"]
        seen_paths = set()
        for root in artifact_roots:
            if not root.exists():
                continue
            for f in root.glob("*"):
                if not f.is_file() or f in seen_paths:
                    continue
                seen_paths.add(f)
                if f.suffix not in (".ndjson", ".json", ".rc", ".pcap", ".xml", ".txt", ".log"):
                    continue
                if not _artifact_matches_subject(f):
                    continue
                try:
                    f.unlink()
                    removed.append(f"{root.name}: {f.name}")
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
                    if _subject_matches_filter(
                        subject,
                        identity_key=str(
                            pearl.get("identity_key")
                            or (pearl.get("target_snapshot") or {}).get("identity_key")
                            or (pearl.get("energy_snapshot") or {}).get("identity_key")
                            or ""
                        ),
                        target=pearl.get("target_snapshot") or {},
                        workload_id=str(
                            pearl.get("workload_id")
                            or (pearl.get("energy_snapshot") or {}).get("workload_id")
                            or ""
                        ),
                        extra=[
                            pearl.get("target_ip"),
                            (pearl.get("energy_snapshot") or {}).get("target_ip"),
                        ],
                    ):
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
            print(f"    (no files found for {subject})")
        print(f"  Target removed from field.")

    elif subcmd == "list":
        surface_path = _latest_surface()
        if not surface_path:
            print("  No targets. Run: skg target add-subnet <cidr>")
            return
        # Use the same hydrated surface-loading path as `surface` and `report`
        try:
            from skg.gravity.runtime import _hydrate_surface_from_latest_nmap
            surface = _hydrate_surface_from_latest_nmap(surface_path)
        except Exception:
            surface = json.loads(Path(surface_path).read_text())
        try:
            from skg.intel.surface import surface as build_measured_surface
            measured_surface = build_measured_surface(interp_dir=SKG_STATE_DIR / "interp")
        except Exception:
            measured_surface = {"workloads": [], "view_nodes": [], "summary": {}}
        rows = _surface_subject_rows(measured_surface=measured_surface, target_surface=surface)
        print(f"\n  {'Node':18s} {'Unk':>6s} {'Services':30s} Domains")
        print(f"  {'-'*18} {'-'*6} {'-'*30} {'-'*20}")
        for row in rows:
            label = row.get("identity_key") or row.get("ip") or "unknown"
            svcs = ", ".join(f"{s.get('port')}/{s.get('service')}" for s in row.get("services", []))
            domains = ", ".join(row.get("domains", []))
            print(f"  {label:18s} {int(row.get('unknown_count', 0)):6d} {svcs:30s} {domains}")
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
        # Canonical authenticated web scan via service-owned runtime wrapper.
        safe_host = (ip or "target").replace(":", "_")
        events_file = DISCOVERY_DIR / f"observe_auth_{safe_host}.ndjson"
        try:
            from skg_services.gravity.web_runtime import collect_auth_surface_events_to_file
        except Exception as exc:
            print(f"  Error: canonical web auth runtime unavailable: {exc}")
            return

        resolved_target = target_url or f"http://{ip}"
        try:
            events = collect_auth_surface_events_to_file(
                resolved_target,
                out_path=events_file,
                attack_path_id="web_sqli_to_shell_v1",
                workload_id=f"web::{ip or 'unknown'}",
                try_defaults=True,
                timeout=10.0,
            )
            print(f"  [WEB-AUTH] Canonical runtime wrote {len(events)} event(s) to {events_file}")
        except Exception as exc:
            print(f"  Error: canonical web auth collection failed: {exc}")
            return

    elif instrument == "web":
        # Canonical unauthenticated web scan via service-owned runtime wrapper.
        safe_host = (ip or "target").replace(":", "_")
        events_file = DISCOVERY_DIR / f"observe_web_{safe_host}.ndjson"
        if target_url:
            resolved_target = target_url
            attack_path_id = "web_surface_v1"
        else:
            port = find_web_port(ip)
            scheme = "http"
            resolved_target = f"{scheme}://{ip}:{port}"
            attack_path_id = "web_sqli_to_shell_v1"
        try:
            from skg_services.gravity.web_runtime import collect_surface_events_to_file
        except Exception as exc:
            print(f"  Error: canonical web runtime unavailable: {exc}")
            return

        try:
            events = collect_surface_events_to_file(
                resolved_target,
                out_path=events_file,
                attack_path_id=attack_path_id,
                workload_id=f"web::{ip or 'unknown'}",
                timeout=8.0,
            )
            print(f"  [WEB] Canonical runtime wrote {len(events)} event(s) to {events_file}")
        except Exception as exc:
            print(f"  Error: canonical web collection failed: {exc}")
            return

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
            from skg_core.config.paths import EVENTS_DIR, SKG_CONFIG_DIR
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
        ports = target_ports(ip)
        port = ",".join(str(p) for p in ports) if ports else "1-1024"
        print(f"  [NMAP] Scanning {ip}...")
        subprocess.call(["nmap", "-Pn", "-sV", "--script=default,vuln",
                         "-p", str(port), "-oX", str(events_file), ip])

    elif instrument == "msf":
        print(f"  [MSF] Queuing operator-reviewable field action for {ip}")
        queue_msf_observation_proposal(ip, source="skg.cli.commands.target.cmd_observe")

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

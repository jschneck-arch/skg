from __future__ import annotations
import subprocess, sys
from pathlib import Path
from skg.cli.utils import (
    _api, _latest_surface, _load_surface_data,
    _rank_surface_targets, _choose_fold_rows, _proposal_backlog,
    _print_what_matters_now, _load_folds_offline,
    _target_state_counts, _print_substrate_self_audit,
    _api_required,
    DISCOVERY_DIR, SKG_HOME, SKG_STATE_DIR,
)
import json
from skg_services.gravity.path_policy import IDENTITY_FILE


def cmd_start(a):
    """Start the gravity field (daemon)."""
    r = subprocess.run(["systemctl", "start", "skg"], capture_output=True)
    if r.returncode == 0:
        print("  Gravity field started.")
        # Show quick status
        import time; time.sleep(1)
        cmd_status(a)
    else:
        print(f"  Failed to start: {r.stderr.decode().strip()}")
        print("  Try: systemctl status skg")


def cmd_stop(a):
    """Stop the gravity field (daemon)."""
    r = subprocess.run(["systemctl", "stop", "skg"], capture_output=True)
    if r.returncode == 0:
        print("  Gravity field stopped.")
    else:
        print(f"  Failed to stop: {r.stderr.decode().strip()}")


def cmd_status(a):
    """Show field state — entropy landscape + instruments."""
    # Try daemon first
    d = _api("GET", "/status")
    if d:
        print(f"  Status  : {d.get('status', '?')}")
        print(f"  Mode    : {d.get('mode', '?')} — {d.get('mode_description', '')}")
        print(f"  Started : {d.get('started_at', '?')}")
        print()
        print("  Toolchains:")
        for domain, status in d.get("toolchains", {}).items():
            print(f"    {domain}: {status}")
        print()
        rs = d.get("resonance", {})
        if rs.get("ready"):
            mem = rs.get("memory", {})
            print(f"  Resonance: ready ({rs.get('embedder','?')})")
            print(f"    wickets={mem.get('wickets',0)} "
                  f"adapters={mem.get('adapters',0)} "
                  f"domains={mem.get('domains',0)}")
        print()
        i = d.get('identity', {})
        if i:
            print(f"  Identity: {i.get('name','?')} v{i.get('version','?')} | "
                  f"coherence={i.get('coherence','?')} | sessions={i.get('sessions','?')}")
        print()

    # Show surface state regardless of daemon
    surface_path = _latest_surface()
    if surface_path:
        surface = json.loads(Path(surface_path).read_text())
        meta = surface.get("meta", {})
        targets = surface.get("targets", [])
        fold_rows = _choose_fold_rows(_api("GET", "/folds") or {})
        backlog = _proposal_backlog()

        print(f"  Surface: {Path(surface_path).name}")
        print(f"    Hosts: {meta.get('hosts_found', '?')}")
        print(f"    Targets: {meta.get('targets_classified', '?')}")
        print(f"    Docker: {meta.get('docker_containers', '?')}")
        gravity_state = (d or {}).get("gravity_state", {}) if isinstance(d, dict) else {}
        if gravity_state:
            print(f"    Gravity: cycle={gravity_state.get('cycle', '?')} "
                  f"E={gravity_state.get('total_entropy', '?')} "
                  f"Unresolved={gravity_state.get('total_unknowns', '?')} "
                  f"Field+={gravity_state.get('field_pull_boost', '?')}")
        print()

        _print_what_matters_now(surface, fold_rows, backlog)
        print()

        # Compute entropy landscape
        print(f"  Entropy Landscape:")
        print(f"  {'IP':18s} {'E':>6s} {'Base':>6s} {'Field+':>7s} {'Real':>5s} {'Blk':>5s} {'Comp':>6s} {'Decoh':>7s}  Domains")
        print(f"  {'-'*18} {'-'*6} {'-'*6} {'-'*7} {'-'*5} {'-'*5} {'-'*6} {'-'*7}  {'-'*20}")

        field_map = {}
        persistence_map = {}
        fiber_clusters = {}
        anchored_field_pull = None
        try:
            field = _api("GET", "/topology/field") or {}
            for sphere, row in (field.get("spheres") or {}).items():
                field_map[sphere] = float((row or {}).get("gravity_pull", 0.0) or 0.0)
                persistence_map[sphere] = float((row or {}).get("pearl_persistence", 0.0) or 0.0)
        except Exception:
            field_map = {}
        if not field_map:
            try:
                from skg.topology.energy import anchored_field_pull, compute_field_fibers, compute_field_topology
                field = compute_field_topology(DISCOVERY_DIR, SKG_STATE_DIR / "interp").as_dict()
                for sphere, row in (field.get("spheres") or {}).items():
                    field_map[sphere] = float((row or {}).get("gravity_pull", 0.0) or 0.0)
                    persistence_map[sphere] = float((row or {}).get("pearl_persistence", 0.0) or 0.0)
                fiber_clusters = {c.anchor: c for c in compute_field_fibers()}
            except Exception:
                field_map = {}
                persistence_map = {}
                fiber_clusters = {}
        else:
            try:
                from skg.topology.energy import anchored_field_pull, compute_field_fibers
                fiber_clusters = {c.anchor: c for c in compute_field_fibers()}
            except Exception:
                fiber_clusters = {}

        for t in targets:
            ip = t["ip"]
            counts = _target_state_counts(t)
            unknown = counts["unknown"]
            realized = counts["realized"]
            blocked = counts["blocked"]
            compatibility = counts["compatibility_score_mean"]
            decoherence = counts["decoherence_total"]
            target_domains = list(t.get("domains", []))
            domains = ", ".join(target_domains)
            field_pull = round(
                anchored_field_pull(ip, target_domains, field_map, fiber_clusters, sphere_persistence=persistence_map)
                if anchored_field_pull is not None else 0.0,
                3,
            )
            E = unknown + field_pull
            if E > 0 or realized > 0 or blocked > 0:
                print(f"  {ip:18s} {E:6.1f} {unknown:6d} {field_pull:7.3f} {realized:5d} {blocked:5d} {compatibility:6.3f} {decoherence:7.3f}  {domains}")
        print()
    else:
        print("  No surface data. Run: skg target add-subnet <cidr>")

    if getattr(a, "self_audit", False):
        print()
        _print_substrate_self_audit()


def cmd_mode(a):
    if a.set_mode:
        result = _api("POST", "/mode", {"mode": a.set_mode, "reason": a.reason or ""})
        if result:
            t = result.get("transition", {})
            print(f"  Mode: {t.get('from','?')} → {t.get('to','?')}")
            if t.get("reason"):
                print(f"  Reason: {t['reason']}")
        else:
            print(f"  Mode set to {a.set_mode} (daemon not running — will apply on start)")
    else:
        result = _api("GET", "/mode")
        if result:
            print(f"  Mode: {result.get('mode','?')}")
            print(f"  {result.get('description','')}")
        else:
            print("  Daemon not running. Mode will be read from skg_config.yaml on start.")


def cmd_identity(a):
    if getattr(a, "subcommand", None) == "history":
        result = _api_required("GET", "/identity/history")
        for r in result:
            print(f"  [{r['timestamp']}] mode={r['mode']} "
                  f"coherence={r['coherence']} src={r['source']}")
    else:
        result = _api("GET", "/identity")
        if result:
            for k, v in result.items():
                if k not in ("timestamp", "source"):
                    print(f"  {k}: {v}")
        else:
            # Read from identity journal directly
            journal = IDENTITY_FILE
            if journal.exists():
                lines = [l.strip() for l in journal.read_text().splitlines() if l.strip()]
                if lines:
                    identity = json.loads(lines[-1])
                    for k, v in identity.items():
                        if k not in ("timestamp", "source"):
                            print(f"  {k}: {v}")
            else:
                print("  No identity data. Start the daemon: skg start")

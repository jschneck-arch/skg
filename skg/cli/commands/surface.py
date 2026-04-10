from __future__ import annotations
import glob, json, sys
from pathlib import Path
from skg.cli.utils import (
    _api, _latest_surface, _load_surface_data, _proposal_backlog,
    _choose_fold_rows, _rank_surface_targets, _print_what_matters_now,
    _choose_fold_summary, _load_folds_offline,
    _load_recall_summary, _iso_now, _interp_payload, _projection_rank,
    _load_module_from_file, _surface_subject_rows, _subject_matches_filter, _fold_identity_key,
    DISCOVERY_DIR, SKG_HOME, SKG_STATE_DIR, INTERP_DIR, EVENTS_DIR,
)
import os
from skg.identity import parse_workload_ref


def _print_folds_offline():
    """Read fold state from disk when daemon is not running."""
    folds_dir = DISCOVERY_DIR / "folds"
    if not folds_dir.exists():
        print("  No fold state. Run: skg gravity --cycles 1")
        return
    total = 0
    for fold_file in sorted(folds_dir.glob("folds_*.json")):
        try:
            folds = json.loads(fold_file.read_text())
            for fold in folds:
                label = _fold_identity_key(fold) or fold_file.stem.replace("folds_", "").replace("_", ".")
                print(f"  {label:18s} {fold.get('id','?')[:12]:12s} [{fold.get('fold_type','?'):12s}] "
                      f"p={fold.get('discovery_probability',0):.2f}  "
                      f"{fold.get('detail','')[:70]}")
                total += 1
        except Exception:
            continue
    if total == 0:
        print("  No folds detected yet. Run: skg gravity --cycles 1")
    else:
        print(f"\n  Total: {total} folds")


def _resolve_fold_offline(subject_key: str, fold_id: str):
    folds_dir = DISCOVERY_DIR / "folds"
    if not folds_dir.exists():
        return None
    for fold_file in sorted(folds_dir.glob("folds_*.json")):
        folds = json.loads(fold_file.read_text())
        matching_scope = [
            f for f in folds
            if _subject_matches_filter(
                subject_key,
                identity_key=_fold_identity_key(f),
                workload_id=str(f.get("workload_id") or ""),
                manifestation_key=str(f.get("location") or ""),
                extra=[f.get("target_ip")],
            )
        ]
        if not matching_scope:
            continue
        matches = [f for f in matching_scope if f.get("id", "") == fold_id or f.get("id", "").startswith(fold_id)]
        if len(matches) > 1 and fold_id not in {f.get("id", "") for f in matches}:
            return {"error": f"ambiguous fold id prefix for {subject_key}"}
        if not matches:
            return {"error": f"fold {fold_id} not found for {subject_key}"}
        target_full_id = matches[0].get("id", "")
        remaining = [f for f in folds if f.get("id", "") != target_full_id]
        fold_file.write_text(json.dumps(remaining, indent=2))
        remaining_weight = round(sum(float(f.get("gravity_weight", 0.0)) for f in remaining), 4)
        return {
            "ok": True,
            "resolved": target_full_id,
            "remaining_folds": len(remaining),
            "remaining_gravity_weight": remaining_weight,
        }
    return None


def cmd_surface(a):
    """Show full attack surface — all projections across all targets."""
    surface_path = _latest_surface()
    if not surface_path:
        print("  No surface data. Run: skg target add-subnet <cidr>")
        return

    try:
        gravity_runtime = _load_module_from_file(
            "skg_gravity_runtime_surface",
            SKG_HOME / "skg-gravity" / "gravity_field.py",
        )
        surface = gravity_runtime._hydrate_surface_from_latest_nmap(surface_path)
        if not surface:
            surface = json.loads(Path(surface_path).read_text())
    except Exception:
        surface = json.loads(Path(surface_path).read_text())

    try:
        from skg.intel.surface import surface as build_measured_surface
        measured_surface = build_measured_surface(interp_dir=INTERP_DIR)
    except Exception:
        measured_surface = {"workloads": [], "view_nodes": [], "summary": {}}
    rows = _surface_subject_rows(measured_surface=measured_surface, target_surface=surface)

    print(f"\n{'='*70}")
    print(f"  SKG ATTACK SURFACE")
    print(f"{'='*70}\n")

    for row in rows:
        label = row.get("identity_key") or row.get("ip") or "unknown"
        domains = ", ".join(row.get("domains", []))
        services = ", ".join(f"{s.get('port')}/{s.get('service')}" for s in row.get("services", []))

        if not row.get("unknown_count") and not row.get("services") and not row.get("manifestations"):
            continue

        display_kind = row.get("kind") or row.get("os", "?")
        print(f"  {label}  [{display_kind:8s}]  {services}")
        print(f"  {'':18s}  domains: {domains}")
        if row.get("manifestations"):
            print(f"  {'':18s}  manifests: {', '.join(row.get('manifestations', [])[:6])}")
        print(
            f"  {'':18s}  realized: {int(row.get('realized_count', 0))}  "
            f"blocked: {int(row.get('blocked_count', 0))}  unknown: {int(row.get('unknown_count', 0))}"
        )
        if row.get("realized_sample"):
            print(f"  {'':18s}  ✓ {', '.join(sorted(row.get('realized_sample', []))[:10])}")
        print()

    # Show projection results from the canonical interp directory only.
    # DISCOVERY_DIR and /tmp are excluded: they may contain stale or unrelated
    # artifacts that should not pollute the operator surface view (MED-17 fix).
    interp_files = sorted(
        set(
            glob.glob(str(SKG_STATE_DIR / "interp" / "*_interp.ndjson")) +
            glob.glob(str(SKG_STATE_DIR / "interp" / "*.json"))
        ),
        key=os.path.getmtime,
        reverse=True,
    )
    if interp_files:
        print(f"  {'─'*66}")
        print(f"  Attack Path Projections:")
        # Key by (workload_id, attack_path_id) so different targets with the same
        # path ID each get their own row (MED-17 fix).
        best_by_subject_apid: dict[tuple[str, str], tuple[int, dict]] = {}
        for ef in interp_files:
            try:
                recs = []
                if ef.endswith(".json"):
                    recs = [json.loads(Path(ef).read_text())]
                else:
                    with open(ef) as f:
                        recs = [json.loads(line.strip()) for line in f if line.strip()]
                for rec in recs:
                    payload = _interp_payload(rec)
                    apid = payload.get("attack_path_id", "")
                    if not apid:
                        continue
                    subject = payload.get("workload_id") or payload.get("target_ip") or ""
                    key = (subject, apid)
                    rank = _projection_rank(payload)
                    current = best_by_subject_apid.get(key)
                    if current is None or rank > current[0]:
                        best_by_subject_apid[key] = (rank, payload)
            except Exception:
                continue
        for (subject, apid), (_, payload) in best_by_subject_apid.items():
            cls = payload.get("classification", "?")
            score = payload.get("aprs", payload.get("lateral_score",
                    payload.get("escape_score", payload.get("host_score",
                    payload.get("web_score", payload.get("ai_score", 0))))))
            marker = "✓" if cls == "realized" else "~" if cls == "indeterminate" else "✗"
            subject_label = f" [{subject}]" if subject else ""
            print(f"    {marker} {apid:40s}{subject_label:20s} {cls:15s} {score:.0%}")
    print()


def cmd_web_view(a):
    """Show the gravity web — bonds between targets."""
    surface_path = _latest_surface()
    if not surface_path:
        print("  No surface data.")
        return

    surface = json.loads(Path(surface_path).read_text())
    targets = surface.get("targets", [])
    fold_rows = _choose_fold_rows(_api("GET", "/folds") or {})
    backlog = _proposal_backlog()
    ranked = _rank_surface_targets(surface, fold_rows)

    # Auto-discover bonds from observed topology
    bonds = []
    ips_by_subnet = {}
    docker_containers = []

    for t in targets:
        ip = t["ip"]
        for svc in t.get("services", []):
            pass

        # Group by subnet
        parts = ip.rsplit(".", 1)
        if len(parts) == 2:
            subnet = parts[0] + ".0/24"
            ips_by_subnet.setdefault(subnet, []).append(ip)

    # Same-subnet bonds
    for subnet, ips in ips_by_subnet.items():
        for i, ip1 in enumerate(ips):
            for ip2 in ips[i+1:]:
                bonds.append((ip1, ip2, "same_subnet", 0.40))

    # Docker bonds — detect from container info or matching bridge IPs
    bridge_172_17 = [t["ip"] for t in targets if t["ip"].startswith("172.17.")]
    bridge_172_18 = [t["ip"] for t in targets if t["ip"].startswith("172.18.")]

    # Gateway IPs are likely the same host
    gateways = [t["ip"] for t in targets if t["ip"].endswith(".0.1")]
    if len(gateways) > 1:
        for i, gw1 in enumerate(gateways):
            for gw2 in gateways[i+1:]:
                bonds.append((gw1, gw2, "same_host", 1.00))

    # .1 gateway to containers on same bridge
    for gw in gateways:
        prefix = ".".join(gw.split(".")[:2])
        for t in targets:
            if t["ip"].startswith(prefix) and t["ip"] != gw:
                bonds.append((gw, t["ip"], "docker_host", 0.90))

    # Same compose network (172.18.x.x targets)
    if len(bridge_172_18) > 1:
        for i, ip1 in enumerate(bridge_172_18):
            if ip1.endswith(".0.1"):
                continue
            for ip2 in bridge_172_18[i+1:]:
                if ip2.endswith(".0.1"):
                    continue
                bonds.append((ip1, ip2, "same_compose", 0.80))

    # Check for shared credentials from event files
    cred_map = {}  # cred_hash → [ips]
    for ef in glob.glob(str(DISCOVERY_DIR / "gravity_auth_*.ndjson")) + \
              glob.glob("/tmp/*auth*.ndjson"):
        try:
            with open(ef) as f:
                for line in f:
                    event = json.loads(line.strip())
                    payload = event.get("payload", {})
                    if payload.get("wicket_id") == "WB-08" and payload.get("status") == "realized":
                        detail = payload.get("detail", "")
                        # Extract IP from workload_id or filename
                        wid = payload.get("workload_id", "")
                        ip = parse_workload_ref(wid).get("identity_key", "")
                        if ip and detail:
                            cred_key = detail.split(":")[-1].strip() if ":" in detail else detail
                            cred_map.setdefault(cred_key, []).append(ip)
        except Exception:
            continue

    for cred, ips in cred_map.items():
        unique_ips = list(set(ips))
        if len(unique_ips) > 1:
            for i, ip1 in enumerate(unique_ips):
                for ip2 in unique_ips[i+1:]:
                    bonds.append((ip1, ip2, "shared_cred", 0.70))

    # Same-host detection: targets sharing a /24 prefix with a gateway (.1) IP
    # on multiple bridge networks are likely the same physical machine
    gw_prefixes = set()
    for t in targets:
        if t["ip"].endswith(".1"):
            gw_prefixes.add(".".join(t["ip"].split(".")[:3]))
    multi_net_ips = [t["ip"] for t in targets
                     if sum(1 for p in gw_prefixes if t["ip"].startswith(p + ".")) > 1]
    if len(multi_net_ips) > 1:
        for i, ip1 in enumerate(multi_net_ips):
            for ip2 in multi_net_ips[i+1:]:
                existing = {(b[0], b[1]) for b in bonds}
                if (ip1, ip2) not in existing and (ip2, ip1) not in existing:
                    bonds.append((ip1, ip2, "same_host", 1.00))

    # Deduplicate bonds (keep strongest)
    bond_map = {}
    for ip1, ip2, btype, strength in bonds:
        key = tuple(sorted([ip1, ip2]))
        if key not in bond_map or bond_map[key][2] < strength:
            bond_map[key] = (btype, strength, strength)

    print(f"\n{'='*70}")
    print(f"  GRAVITY WEB — {len(targets)} nodes, {len(bond_map)} bonds")
    print(f"{'='*70}\n")

    print("  Field Context:")
    for row in ranked[:5]:
        services = ", ".join(f"{s.get('port')}/{s.get('service')}" for s in row["services"][:6]) or "none"
        domains = ", ".join(row["domains"]) or "none"
        fold_note = f", folds={row['folds']} (+{row['fold_weight']:.1f})" if row["folds"] else ""
        print(f"    {row['ip']:18s} [{row['kind']}] E≈{row['priority']:.1f} unk={row['unknown']}{fold_note}")
        print(f"      services: {services}")
        print(f"      domains : {domains}")
    print(f"    proposals: pending={backlog['pending_total']} toolchains={backlog['pending_toolchain_generation']} growth={backlog['pending_catalog_growth']} actions={backlog['pending_field_action']} errors={backlog['error_total']}")
    print()

    print("  Bonds:")

    for (ip1, ip2), (btype, strength, _) in sorted(bond_map.items(), key=lambda x: -x[1][1]):
        print(f"  {ip1:18s} ←─{btype:14s}─→ {ip2:18s}  strength: {strength:.2f}")

    print()


def cmd_folds(a):
    """
    Show active folds — missing structural knowledge that adds to field energy.

    Folds represent regions of state space the system knows it cannot evaluate:
      structural  — service running with no toolchain (dark attack surface)
      projection  — implied attack path not yet catalogued
      contextual  — CVE with no wicket mapping
      temporal    — evidence past decay TTL, condition may have changed

    Each fold adds to E. Gravity pulls harder toward targets with high fold
    weight. Resolve folds to reduce E and improve field coverage.
    """
    subcmd = getattr(a, "folds_cmd", None) or "list"

    if subcmd == "list":
        result = _api("GET", "/folds")
        if not result:
            print("  Daemon not running — reading fold state from disk...")
            _print_folds_offline()
            return
        summary = result.get("summary", {})
        folds   = result.get("folds", [])
        print(f"\n  Active folds: {summary.get('total', 0)}")
        print(f"  Total gravity weight: {summary.get('total_gravity_weight', 0.0):.2f}")
        by_type = summary.get("by_type", {})
        for ft, count in sorted(by_type.items()):
            print(f"    {ft:14s}: {count}")
        print()
        if folds:
            print(f"  {'Node':18s} {'ID':12s} {'Type':12s} {'p':>5s} {'Φ':>5s}  Detail")
            print(f"  {'-'*18} {'-'*12} {'-'*12} {'-'*5} {'-'*5}  {'-'*50}")
            for fold in folds[:20]:
                print(f"  {(_fold_identity_key(fold) or fold.get('target_ip','?')):18s} "
                      f"{fold.get('id','?')[:12]:12s} "
                      f"{fold.get('fold_type','?'):12s} "
                      f"{fold.get('discovery_probability',0):5.2f} "
                      f"{fold.get('gravity_weight',0):5.2f}  "
                      f"{fold.get('detail','')[:60]}")
        else:
            print("  No active folds.")
        print()
        print(f"  {result.get('note','')}")

    elif subcmd == "structural":
        result = _api("GET", "/folds/structural")
        if not result:
            print("  Daemon not running.")
            return
        folds = result.get("folds", [])
        print(f"\n  Structural folds: {result.get('count', 0)}")
        print(f"  Action: {result.get('action','')}")
        print()
        for fold in folds:
            print(f"  {(_fold_identity_key(fold) or fold.get('target_ip','?')):18s}  {fold.get('id','?')[:12]:12s} Φ={fold.get('gravity_weight',0):.2f}")
            print(f"    {fold.get('detail','')[:100]}")
            print()

    elif subcmd == "resolve":
        if not a.fold_id or not a.target:
            print("  Usage: skg folds resolve <fold_id> --target <identity>")
            return
        result = _api("POST", f"/folds/resolve/{a.fold_id}",
                      params={"identity_key": a.target, "target_ip": a.target})
        if result and result.get("ok"):
            print(f"  Fold {a.fold_id} resolved.")
            print(f"  Remaining folds: {result.get('remaining_folds', '?')}")
            print(f"  Remaining gravity weight: {result.get('remaining_gravity_weight', '?')}")
        else:
            offline = _resolve_fold_offline(a.target, a.fold_id)
            if offline and offline.get("ok"):
                print(f"  Fold {a.fold_id} resolved.")
                print(f"  Remaining folds: {offline.get('remaining_folds', '?')}")
                print(f"  Remaining gravity weight: {offline.get('remaining_gravity_weight', '?')}")
                return
            if offline and offline.get("error"):
                print(f"  Failed: {offline['error']}")
                return
            err = result.get("error", "unknown") if result else "daemon not running"
            print(f"  Failed: {err}")

    else:
        print("  Usage: skg folds [list|structural|resolve]")


def cmd_field(a):
    """Display projection engine field state for a workload."""
    import math as _math
    wid    = a.workload_id
    domain = getattr(a, "domain", "host") or "host"
    result = _api("GET", f"/projections/{wid}/field", params={"domain": domain})
    if not result:
        print("  Daemon not running. Use 'skg surface' for offline field state.")
        return

    E     = result.get("E", 0.0)
    E_max = _math.log2(3)
    fill  = int((1.0 - min(E, E_max) / E_max) * 30)
    bar   = "#" * fill + "-" * (30 - fill)

    cls = result.get("classification", "?")
    print(f"\n  Path     : {result.get('attack_path_id','?')}")
    print(f"  Workload : {wid}  |  Domain: {domain}")
    print(f"  E = {E:.4f}  [{bar}]")
    print(f"  {result.get('n_realized',0)}R {result.get('n_blocked',0)}B "
          f"{result.get('n_unknown',0)}U / {result.get('n_required',0)} required")
    print(f"  Classification: {cls}")
    print()

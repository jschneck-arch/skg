from __future__ import annotations
import json, sys
from pathlib import Path
from skg.cli.utils import (
    _api, _latest_surface, _load_surface_data,
    _load_recall_summary, _pearl_brief, _cluster_pearls,
    _describe_next_collapse, _fold_brief_why,
    _parse_report_timestamp, _load_target_snapshot_from_pearls,
    _diff_target_snapshots, _infer_identity_properties_from_target,
    _active_identity_properties, _print_substrate_self_audit,
    _build_substrate_self_audit, _load_folds_offline,
    _load_module_from_file, _choose_fold_rows, _iso_now,
    _surface_subject_rows, _subject_matches_filter, _fold_identity_key,
    DISCOVERY_DIR, SKG_HOME, SKG_STATE_DIR, EVENTS_DIR, INTERP_DIR,
)
from skg_services.gravity.path_policy import CVE_DIR


def cmd_report(a):
    surface_path = _latest_surface()
    if not surface_path:
        print("  No surface data. Run: skg target add-subnet <cidr>")
        return

    try:
        gravity_runtime = _load_module_from_file(
            "skg_gravity_runtime_report",
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

    target_filter = getattr(a, "target", None)
    at_ts = _parse_report_timestamp(getattr(a, "at", None))
    diff_ts = _parse_report_timestamp(getattr(a, "diff_against", None))
    targets = _surface_subject_rows(measured_surface=measured_surface, target_surface=surface)
    if target_filter:
        targets = [
            t for t in targets
            if _subject_matches_filter(
                target_filter,
                identity_key=t.get("identity_key", ""),
                target=t,
                extra=t.get("manifestations", []),
            )
        ]
        if not targets:
            print(f"  Node not found in surface: {target_filter}")
            return

    _folds_raw = _api("GET", "/folds")
    if _folds_raw is None:
        print("  Warning: SKG daemon not running — fold/proposal data unavailable (offline mode)")
    fold_result = _folds_raw or {"folds": []}
    all_folds = _choose_fold_rows(fold_result)
    if target_filter:
        filtered = []
        for f in all_folds:
            if _subject_matches_filter(
                target_filter,
                identity_key=_fold_identity_key(f),
                workload_id=str(f.get("workload_id") or ""),
                manifestation_key=str(f.get("location") or ""),
                extra=[f.get("target_ip"), (f.get("why") or {}).get("workload_id")],
            ):
                filtered.append(f)
        all_folds = filtered

    sys.path.insert(0, str(SKG_HOME))
    from skg.forge import proposals as _forge_proposals
    proposals = _forge_proposals.list_proposals(status="all")
    if target_filter:
        proposals = [
            p for p in proposals
            if _subject_matches_filter(
                target_filter,
                identity_key=str(p.get("identity_key") or ""),
                target={"host": (p.get("hosts") or [None])[0]},
                workload_id=str((p.get("action") or {}).get("workload_id") or ""),
                extra=list(p.get("hosts") or []),
            )
        ]

    pearls = []
    pearls_path = SKG_STATE_DIR / "pearls.jsonl"
    if pearls_path.exists():
        for line in pearls_path.read_text(errors="replace").splitlines()[-100:]:
            if not line.strip():
                continue
            try:
                pearl = json.loads(line)
            except Exception:
                continue
            if target_filter and not _subject_matches_filter(
                target_filter,
                identity_key=str((pearl.get("target_snapshot") or {}).get("identity_key") or ""),
                target=pearl.get("target_snapshot") or {},
                workload_id=str(pearl.get("workload_id") or ""),
                extra=[
                    pearl.get("target_ip"),
                    (pearl.get("energy_snapshot", {}) or {}).get("target_ip"),
                ],
            ):
                continue
            pearls.append(pearl)

    report = {
        "generated_at": _iso_now(),
        "surface": Path(surface_path).name,
        "target_filter": target_filter,
        "targets": [],
        "summary": {
            "target_count": len(targets),
            "targets_with_unknowns": 0,
            "total_unknown": 0,
            "total_realized": 0,
            "total_blocked": 0,
        },
        "folds": {
            "count": len(all_folds),
            "high_weight": sorted(
                all_folds,
                key=lambda f: float(f.get("gravity_weight", 0.0)),
                reverse=True,
            )[:10],
        },
        "proposals": {
            "count": len(proposals),
            "pending": sum(1 for p in proposals if p.get("status") == "pending"),
            "accepted_preserved_existing": sum(1 for p in proposals if p.get("status") == "accepted_preserved_existing"),
            "active": [
                p for p in proposals
                if p.get("status") in {"pending", "triggered", "accepted_preserved_existing"}
            ][:8],
            "history": [
                p for p in proposals
                if p.get("status") not in {"pending", "triggered", "accepted_preserved_existing"}
            ][:8],
            "recent": proposals[:12],
        },
        "pearls": {
            "count": len(pearls),
            "recent": pearls[-10:],
            "clusters": _cluster_pearls(pearls[-25:]),
        },
        "recall": _load_recall_summary(target_filter=target_filter),
        "self_audit": _build_substrate_self_audit(),
    }

    kernel_states_by_target = {}
    if target_filter:
        try:
            from skg.kernel.engine import KernelStateEngine
            kernel_engine = KernelStateEngine(
                discovery_dir=DISCOVERY_DIR,
                events_dir=SKG_STATE_DIR / "events",
                cve_dir=CVE_DIR,
            )
            scoped_identity = targets[0].get("identity_key", target_filter) if targets else target_filter
            kernel_states_by_target[scoped_identity] = kernel_engine.states_with_detail(scoped_identity)
        except Exception:
            kernel_states_by_target = {}

    for t in targets:
        ws = kernel_states_by_target.get(t.get("identity_key")) or {}
        realized = [k for k, v in ws.items() if v == "realized" or (isinstance(v, dict) and v.get("status") == "realized")]
        blocked = [k for k, v in ws.items() if v == "blocked" or (isinstance(v, dict) and v.get("status") == "blocked")]
        unknown = [k for k, v in ws.items() if v == "unknown" or (isinstance(v, dict) and v.get("status") == "unknown")]
        if ws:
            unresolved_rows = [v for v in ws.values() if isinstance(v, dict) and v.get("status") == "unknown"]
            compatibility_values = [float(v.get("compatibility_score", 0.0) or 0.0) for v in unresolved_rows]
            decoherence_values = [float(v.get("decoherence", 0.0) or 0.0) for v in unresolved_rows]
            unresolved_reasons: dict[str, int] = {}
            for row in unresolved_rows:
                reason = str(row.get("unresolved_reason") or "unmeasured")
                unresolved_reasons[reason] = unresolved_reasons.get(reason, 0) + 1
            realized_count = len(realized)
            blocked_count = len(blocked)
            unknown_count = len(unknown)
            compatibility_score_mean = round(sum(compatibility_values) / len(compatibility_values), 3) if compatibility_values else 0.0
            decoherence_total = round(sum(decoherence_values), 3)
            realized_sample = sorted(realized)[:15]
        else:
            unresolved_reasons = dict(t.get("unresolved_reasons", {}) or {})
            realized_count = int(t.get("realized_count", 0) or 0)
            blocked_count = int(t.get("blocked_count", 0) or 0)
            unknown_count = int(t.get("unknown_count", 0) or 0)
            compatibility_score_mean = float(t.get("compatibility_score_mean", 0.0) or 0.0)
            decoherence_total = float(t.get("decoherence_total", 0.0) or 0.0)
            realized_sample = list(t.get("realized_sample", []) or [])[:15]
        report["targets"].append({
            "identity_key": t.get("identity_key"),
            "ip": t.get("ip"),
            "kind": t.get("kind") or t.get("os"),
            "domains": t.get("domains", []),
            "services": t.get("services", []),
            "manifestations": t.get("manifestations", []),
            "realized_count": realized_count,
            "blocked_count": blocked_count,
            "unknown_count": unknown_count,
            "unresolved_reasons": unresolved_reasons,
            "compatibility_score_mean": compatibility_score_mean,
            "decoherence_total": decoherence_total,
            "realized_sample": realized_sample,
        })
        report["summary"]["total_unknown"] += unknown_count
        report["summary"]["total_realized"] += realized_count
        report["summary"]["total_blocked"] += blocked_count
        if unknown_count:
            report["summary"]["targets_with_unknowns"] += 1

    if target_filter and report["targets"]:
        scoped_target = report["targets"][0]
        scoped_folds = report["folds"]["high_weight"][:5]
        scoped_proposals = report["proposals"]["recent"][:6]
        report["interpretation"] = {
            "identity_properties": _active_identity_properties({
                "identity_properties": _infer_identity_properties_from_target(scoped_target),
            }),
            "evidence": [
                f"{svc.get('port')}/{svc.get('service')}"
                for svc in scoped_target.get("services", [])[:8]
            ],
            "top_mismatch": _fold_brief_why(scoped_folds[0]) if scoped_folds else None,
            "hypotheses": list((scoped_folds[0].get("hypotheses", []) if scoped_folds else [])[:3]),
            "next_collapse": _describe_next_collapse(scoped_target, scoped_folds, scoped_proposals),
            "recent_memory": [c.get("summary") for c in report["pearls"]["clusters"][-3:]],
        }
    else:
        report["interpretation"] = None

    if getattr(a, "json_out", False):
        print(json.dumps(report, indent=2))
        return

    historical_pearl = _load_target_snapshot_from_pearls(target_filter, at_ts=at_ts) if target_filter and at_ts else None
    historical_snapshot = (historical_pearl or {}).get("target_snapshot") if historical_pearl else None
    diff_pearl = _load_target_snapshot_from_pearls(target_filter, at_ts=diff_ts) if target_filter and diff_ts else None
    diff_snapshot = (diff_pearl or {}).get("target_snapshot") if diff_pearl else None

    print(f"\n{'='*70}")
    print("  SKG REPORT")
    print(f"{'='*70}")
    print(f"  Generated : {report['generated_at']}")
    print(f"  Surface   : {report['surface']}")
    if target_filter:
        print(f"  Node      : {target_filter}")
        if at_ts:
            print(f"  As-Of     : {at_ts.isoformat()}")
            if not historical_snapshot:
                print("  Note      : no pearl-backed node snapshot exists for that time yet; showing current surface with historical scope only")
    else:
        print(f"  Nodes     : {report['summary']['target_count']} total, {report['summary']['targets_with_unknowns']} with unresolved state")
        print(f"  State     : {report['summary']['total_realized']} realized, {report['summary']['total_blocked']} blocked, {report['summary']['total_unknown']} unknown")
    print()

    if historical_snapshot:
        historical_services = ", ".join(
            f"{svc.get('port')}/{svc.get('service')}"
            for svc in historical_snapshot.get("services", [])[:12]
        ) or "none"
        print("  Historical Snapshot:")
        print(f"    kind     : {historical_snapshot.get('kind','?')}")
        print(f"    domains  : {', '.join(historical_snapshot.get('domains', [])) or 'none'}")
        print(f"    services : {historical_services}")
        props = historical_snapshot.get("identity_properties", {}) or {}
        if props:
            active_props = [k for k, v in props.items() if v is True]
            if active_props:
                print(f"    properties: {', '.join(active_props[:8])}")
        print()

    ranked_targets = sorted(
        report["targets"],
        key=lambda t: (t["unknown_count"], t["blocked_count"], t["realized_count"]),
        reverse=True,
    )

    if not target_filter:
        print("  Priority Targets:")
        for t in ranked_targets[:5]:
            services = ", ".join(f"{s.get('port')}/{s.get('service')}" for s in t.get("services", [])[:8]) or "none"
            domains = ", ".join(t.get("domains", [])) or "none"
            label = t.get("identity_key") or t.get("ip") or "unknown"
            print(f"    {label:18s} [{(t.get('kind') or '?'):12s}] {t['unknown_count']}U {t['blocked_count']}B {t['realized_count']}R")
            print(f"      services: {services}")
            print(f"      domains : {domains}")
        print()

    for t in ranked_targets if target_filter else ranked_targets[:3]:
        services = ", ".join(f"{s.get('port')}/{s.get('service')}" for s in t.get("services", [])[:12])
        domains = ", ".join(t.get("domains", []))
        label = t.get("identity_key") or t.get("ip") or "unknown"
        print(f"  {label}  [{(t.get('kind') or '?'):12s}]")
        print(f"    services : {services}")
        print(f"    domains  : {domains}")
        if t.get("manifestations"):
            print(f"    manifests: {', '.join(t.get('manifestations', [])[:6])}")
        print(f"    state    : {t['realized_count']} realized, {t['blocked_count']} blocked, {t['unknown_count']} unknown")
        if t.get("unknown_count"):
            reasons = t.get("unresolved_reasons", {}) or {}
            if reasons:
                reason_text = ", ".join(f"{k}={v}" for k, v in sorted(reasons.items()))
                print(f"    unresolved: {reason_text}")
            print(f"    measurement: compatibility={float(t.get('compatibility_score_mean', 0.0)):.3f} decoherence={float(t.get('decoherence_total', 0.0)):.3f}")
        if t.get("realized_sample"):
            print(f"    realized : {', '.join(t['realized_sample'][:10])}")
        print()

    if target_filter and report.get("interpretation"):
        interp = report["interpretation"]
        print("  Interpretation:")
        props = ", ".join(interp.get("identity_properties", [])[:8]) or "no strong identity properties yet"
        evidence = ", ".join(interp.get("evidence", [])[:8]) or "no direct service evidence yet"
        print(f"    identity : {props}")
        print(f"    evidence : {evidence}")
        if interp.get("top_mismatch"):
            print(f"    mismatch : {interp['top_mismatch']}")
        for hyp in interp.get("hypotheses", [])[:2]:
            print(f"    maybe    : {hyp[:120]}")
        for mem in interp.get("recent_memory", [])[:2]:
            print(f"    memory   : {mem}")
        print(f"    next     : {interp.get('next_collapse')}")
        print()

    if target_filter and diff_snapshot and report["targets"]:
        current_snapshot = {
            "ip": report["targets"][0].get("ip"),
            "kind": report["targets"][0].get("kind"),
            "domains": report["targets"][0].get("domains", []),
            "services": report["targets"][0].get("services", []),
            "identity_properties": _infer_identity_properties_from_target(report["targets"][0]),
        }
        diff = _diff_target_snapshots(diff_snapshot, current_snapshot)
        print(f"  Diff vs {diff_ts.isoformat()}:")
        if diff.get("domains_added") or diff.get("domains_removed"):
            print(f"    domains  : +{', '.join(diff.get('domains_added', [])) or 'none'}  -{', '.join(diff.get('domains_removed', [])) or 'none'}")
        if diff.get("services_added") or diff.get("services_removed"):
            print(f"    services : +{', '.join(diff.get('services_added', [])) or 'none'}  -{', '.join(diff.get('services_removed', [])) or 'none'}")
        for change in diff.get("property_changes", [])[:6]:
            print(f"    property : {change['property']}  {change['before']} -> {change['after']}")
        print()

    print(f"  Folds      : {report['folds']['count']}")
    for fold in report["folds"]["high_weight"][:5]:
        print(f"    {_fold_identity_key(fold) or fold.get('target_ip','?')} [{fold.get('fold_type','?')}] Φ={float(fold.get('gravity_weight',0.0)):.2f} {fold.get('detail','')[:80]}")
    print()

    print(f"  Proposals  : {report['proposals']['count']} total, {report['proposals']['pending']} pending")
    active_props = report["proposals"]["active"]
    history_props = report["proposals"]["history"]
    if active_props:
        print("    active:")
    for proposal in active_props[:4]:
        print(f"      {proposal.get('id','')[:12]} {proposal.get('status',''):22s} {proposal.get('proposal_kind',''):16s} {proposal.get('description','')[:70]}")
        growth = ((proposal.get("recall") or {}).get("growth_memory") or {})
        reasons = growth.get("proposal_reasons", []) or []
        if reasons:
            print(f"        memory   growth={growth.get('delta', 0.0):.3f} via {', '.join(reasons[:4])}")
    if history_props:
        print("    recent history:")
    for proposal in history_props[:4]:
        print(f"    {proposal.get('id','')[:12]} {proposal.get('status',''):22s} {proposal.get('proposal_kind',''):16s} {proposal.get('description','')[:70]}")
    print()

    recall = report["recall"]
    print(f"  Recall     : {recall['confirmed']} confirmed, {recall['pending']} pending", end="")
    if recall["confirmation_rate"] is not None:
        print(f", confirmation={recall['confirmation_rate']:.3f}")
    else:
        print()
    for dom in recall["by_domain"][:4]:
        rate = dom["confirmation_rate"]
        rate_s = f"{rate:.3f}" if rate is not None else "n/a"
        print(f"    {dom['domain']:16s} confirmed={dom['confirmed']:<3d} realized={dom['realized']:<3d} rate={rate_s}")
    for rec in recall["recent"][:3]:
        print(f"    recent {str(rec.get('workload_id','?')):20s} {str(rec.get('projection_confirmed','?')):10s} "
              f"{str(rec.get('wicket_id') or '?'):12s} {rec.get('evidence_text','')[:72]}")
    print()

    print(f"  Pearls     : {report['pearls']['count']} recent for scope")
    for cluster in report["pearls"]["clusters"][-5:]:
        start_ts = str(cluster.get("start_ts", "?")).replace("T", " ")[:19]
        end_ts = str(cluster.get("end_ts", "?")).replace("T", " ")[:19]
        span = start_ts if start_ts == end_ts else f"{start_ts} -> {end_ts}"
        print(f"    {span:41s} {cluster.get('summary','')}")
    print(f"  Self-audit : folds={report['self_audit']['folds'].get('total',0)} pending_proposals={report['self_audit']['proposals'].get('pending_total',0)} persisted_pearls={report['self_audit']['pearls'].get('persisted',0)}")
    if not target_filter:
        print(f"  Views      : skg report --target <ip> | skg surface | skg web | skg status --self-audit")
    print()

    if getattr(a, "llm", False):
        try:
            from skg.resonance.ollama_backend import OllamaBackend
            backend = OllamaBackend()
            if backend.available():
                llm_view = {
                    "generated_at": report["generated_at"],
                    "surface": report["surface"],
                    "target_filter": report["target_filter"],
                    "targets": [
                        {
                            "identity_key": t.get("identity_key"),
                            "ip": t.get("ip"),
                            "kind": t.get("kind"),
                            "domains": t.get("domains", []),
                            "services": [
                                f"{svc.get('port')}/{svc.get('service')}"
                                for svc in t.get("services", [])[:12]
                            ],
                            "state": {
                                "realized": t.get("realized_count", 0),
                                "blocked": t.get("blocked_count", 0),
                                "unknown": t.get("unknown_count", 0),
                            },
                            "realized_sample": t.get("realized_sample", [])[:8],
                        }
                        for t in report["targets"][:3]
                    ],
                    "folds": [
                        {
                            "target": _fold_identity_key(f) or f.get("target_ip"),
                            "type": f.get("fold_type"),
                            "weight": float(f.get("gravity_weight", 0.0)),
                            "detail": (f.get("detail", "")[:160]),
                        }
                        for f in report["folds"]["high_weight"][:5]
                    ],
                    "proposals": {
                        "count": report["proposals"]["count"],
                        "pending": report["proposals"]["pending"],
                        "accepted_preserved_existing": report["proposals"]["accepted_preserved_existing"],
                        "recent": [
                            {
                                "id": p.get("id", "")[:12],
                                "status": p.get("status"),
                                "kind": p.get("proposal_kind"),
                                "description": (p.get("description", "")[:120]),
                                "growth_memory": ((p.get("recall") or {}).get("growth_memory") or {}),
                            }
                            for p in report["proposals"]["recent"][:6]
                        ],
                    },
                    "pearls": {
                        "count": report["pearls"]["count"],
                    },
                    "recall": {
                        "confirmed": report["recall"]["confirmed"],
                        "pending": report["recall"]["pending"],
                        "confirmation_rate": report["recall"]["confirmation_rate"],
                        "by_domain": report["recall"]["by_domain"][:4],
                        "recent": report["recall"]["recent"][:3],
                    },
                    "self_audit": {
                        "folds": report["self_audit"]["folds"].get("total", 0),
                        "pending_proposals": report["self_audit"]["proposals"].get("pending_total", 0),
                        "persisted_pearls": report["self_audit"]["pearls"].get("persisted", 0),
                        "ollama_model": report["self_audit"]["ollama"].get("selected"),
                    },
                }
                llm_prompt = (
                    "You are summarizing SKG substrate state. "
                    "Use 4-6 short bullets. Be concise and factual. "
                    "Do not invent findings. Mention target state, major folds, proposal state, "
                    "and what matters next.\n\n"
                    + json.dumps(llm_view, indent=2)
                )
                summary = backend.generate(llm_prompt, num_predict=192)
                print("  TinyLlama Summary:")
                for line in summary.strip().splitlines()[:12]:
                    print(f"    {line}")
                print()
            else:
                print("  TinyLlama Summary: ollama unavailable")
                print()
        except Exception as exc:
            print(f"  TinyLlama Summary failed: {exc}")
            print()


def cmd_calibrate(a):
    """
    Learn per-sensor confidence weights from engagement history.

    Reads the engagement database (built by `skg engage build`) and
    computes empirical precision for each sensor source:

      precision(source) = 1 - P(evidence_decay within 3 cycles of surface_expansion)

    A sensor that frequently produces realizations that reverse themselves
    gets a lower calibration factor. The calibrated confidence is:

      calibrated_conf = raw_conf * precision / assumed_reliability

    Saved under the configured state root and loaded by the runtime
    sensor confidence context.

    This closes the confidence calibration gap: the system's certainty
    claims become empirically grounded rather than hand-tuned.
    """
    sys.path.insert(0, str(SKG_HOME))
    from skg.sensors.confidence_calibrator import (
        calibrate_from_engagement,
    )

    db_path = Path(a.db)
    if not db_path.exists():
        print(f"\n  Database not found: {db_path}")
        print(f"  Build it first: skg engage build --out {db_path}")
        return

    print(f"\n  Calibrating from: {db_path}")
    save = not getattr(a, "report", False)
    cal  = calibrate_from_engagement(db_path, save=save)

    print(f"\n{cal.report()}")

    if save:
        from skg.sensors.confidence_calibrator import CALIBRATION_PATH
        print(f"\n  Saved → {CALIBRATION_PATH}")
        print("  Runtime sensors reload this file automatically on the next calibration-aware emit.")
    else:
        print(f"\n  (Report only — not saved. Remove --report to save.)")


def cmd_engage(a):
    """
    Engagement dataset — build a SQLite database from all red team telemetry
    and apply data integrity analysis to it.

    The engagement data itself is a data product. Every obs.attack.precondition
    event, every projection result, every delta transition, every gravity cycle
    produces records. Those records have required fields, referential integrity
    constraints, freshness TTLs, and distribution properties.

    'skg engage build'    — ingest all telemetry into engagement.db
    'skg engage analyze'  — run DP-* integrity checks against the DB
    'skg engage report'   — full report: integrity + realized paths + H¹ obstructions
    'skg engage clean'    — repair DP-03/04/05 violations in engagement.db
    """
    sys.path.insert(0, str(SKG_HOME))
    from skg.intel.engagement_dataset import (
        build_engagement_db, analyze_engagement_integrity,
        generate_engagement_report,
    )

    subcmd = getattr(a, "engage_cmd", None)

    if not subcmd:
        print("  Usage: skg engage [build|analyze|report|clean]")
        return

    if subcmd == "build":
        db = getattr(a, "out", str(SKG_STATE_DIR / "engagement.db"))
        print(f"\n  Building engagement dataset: {db}")
        summary = build_engagement_db(db, verbose=True)
        print(f"\n  Done. Run: skg engage report --db {db}")

    elif subcmd == "analyze":
        db = getattr(a, "db", str(SKG_STATE_DIR / "engagement.db"))
        if not Path(db).exists():
            print(f"  Database not found: {db}")
            print(f"  Build it first: skg engage build --out {db}")
            return
        analyze_engagement_integrity(db, verbose=True)

    elif subcmd == "report":
        db      = getattr(a, "db",  str(SKG_STATE_DIR / "engagement.db"))
        out_path = getattr(a, "out", None)
        if not Path(db).exists():
            print(f"\n  Building engagement database first...")
            build_engagement_db(db, verbose=True)
        generate_engagement_report(db, out_path=out_path)

    elif subcmd == "clean":
        import sqlite3 as _sqlite3
        db = getattr(a, "db", str(SKG_STATE_DIR / "engagement.db"))
        if not Path(db).exists():
            print(f"  Database not found: {db}")
            print(f"  Build it first: skg engage build --out {db}")
            return
        print(f"\n  Cleaning engagement database: {db}")
        conn = _sqlite3.connect(db)
        try:
            # DP-03: remove observations with NULL required fields
            r = conn.execute(
                "DELETE FROM observations WHERE workload_id IS NULL OR workload_id = ''"
            )
            null_wid = r.rowcount
            r = conn.execute(
                "DELETE FROM observations WHERE wicket_id IS NULL OR wicket_id = ''"
            )
            null_wkid = r.rowcount
            r = conn.execute(
                "DELETE FROM observations WHERE status IS NULL OR status = ''"
            )
            null_status = r.rowcount

            # DP-04: clamp evidence_rank to 1-6
            r = conn.execute(
                "UPDATE observations SET evidence_rank = MAX(1, MIN(6, evidence_rank)) "
                "WHERE evidence_rank NOT BETWEEN 1 AND 6"
            )
            clamped = r.rowcount

            # DP-05: remove projections with no matching identity in observations.
            # Uses node_key (stable identity) first so that different workload_id
            # manifestations of the same host are not incorrectly deleted.
            r = conn.execute("""
                DELETE FROM projections
                WHERE node_key NOT IN (
                    SELECT DISTINCT node_key FROM observations WHERE node_key != ''
                )
                AND workload_id NOT IN (
                    SELECT DISTINCT workload_id FROM observations
                )
            """)
            orphaned = r.rowcount

            conn.commit()
            print(f"    DP-03 (null workload_id):  removed {null_wid} rows")
            print(f"    DP-03 (null wicket_id):    removed {null_wkid} rows")
            print(f"    DP-03 (null status):        removed {null_status} rows")
            print(f"    DP-04 (evidence_rank):     clamped {clamped} rows")
            print(f"    DP-05 (orphaned projections): removed {orphaned} rows")
            print(f"\n  Run 'skg engage analyze' to verify all checks pass.")
        finally:
            conn.close()

    else:
        # Default: build + report inline
        db = str(SKG_STATE_DIR / "engagement.db")
        print(f"\n  Building engagement dataset...")
        build_engagement_db(db, verbose=True)
        generate_engagement_report(db)

from __future__ import annotations
import json, os, sys
from pathlib import Path
from skg.cli.utils import (
    _api, _api_required, _resonance_engine,
    DISCOVERY_DIR, SKG_HOME, SKG_STATE_DIR, CVE_DIR,
)
try:
    from skg.core.paths import INTERP_DIR
except ImportError:
    INTERP_DIR = SKG_STATE_DIR / "interp"


def cmd_feed(a):
    subcmd = a.feed_cmd

    if subcmd == "nvd":
        nvd_script = SKG_HOME / "feeds" / "nvd_ingester.py"
        if not nvd_script.exists():
            print(f"  Error: {nvd_script} not found")
            return

        api_key = os.environ.get("NIST_NVD_API_KEY", "")
        if not api_key:
            # Try loading from /etc/skg/skg.env (systemd daemon env file)
            _env_file = Path("/etc/skg/skg.env")
            if _env_file.exists():
                for _line in _env_file.read_text().splitlines():
                    _line = _line.strip()
                    if _line.startswith("NIST_NVD_API_KEY="):
                        api_key = _line.split("=", 1)[1].strip().strip('"').strip("'")
                        if api_key:
                            print(f"  [feed] Loaded NIST_NVD_API_KEY from /etc/skg/skg.env")
                        break
        if not api_key:
            print("  Error: Set NIST_NVD_API_KEY environment variable")
            print("         or add NIST_NVD_API_KEY=<key> to /etc/skg/skg.env")
            return

        import subprocess
        service = getattr(a, "service", None)
        if service:
            args = [str(nvd_script), "--service", service,
                    "--out", str(CVE_DIR / "cve_manual.ndjson")]
        else:
            args = [str(nvd_script), "--auto", "--out-dir", str(CVE_DIR)]

        subprocess.call([sys.executable] + args, env={**os.environ})

    else:
        print("  Usage: skg feed [nvd]")


def cmd_graph(a):
    """
    Wicket knowledge graph — Kuramoto phase dynamics on the semantic space.

    The wicket graph maps relationships between attack preconditions.
    Edges are Kuramoto coupling constants K. Phase dynamics propagate
    state across the graph when wickets collapse.

    'skg graph topology'       — global R, cluster R, entangled pairs
    'skg graph edges <wicket>' — neighbors, K values, current phase
    'skg graph entangled'      — all non-separable pairs (K ≥ 0.80)
    """
    sys.path.insert(0, str(SKG_HOME))
    from skg.kernel.wicket_graph import get_wicket_graph

    subcmd = getattr(a, "graph_cmd", "topology")
    graph  = get_wicket_graph()

    if subcmd == "topology":
        report = graph.topology_report()
        print(f"\n  Wicket Knowledge Graph — K-Topology")
        print(f"  {'─'*50}")
        print(f"  Nodes     : {report['nodes']}  Edges: {report['edges']}")
        print(f"  R (global): {report['R_global']:.4f}  "
              f"{'← fully dark' if report['R_global'] < 0.2 else '← synchronizing' if report['R_global'] < 0.7 else '← coherent'}")
        print(f"  Realized  : {report['n_realized']}   "
              f"Blocked: {report['n_blocked']}   Unknown: {report['n_unknown']}")

        if report["clusters"]:
            print(f"\n  Synchronization Clusters (K ≥ {0.60:.2f})")
            print(f"  {'Cluster':>12s}  {'R':>6s}  {'Size':>5s}  {'Real':>5s}  Wickets")
            for label, c in sorted(report["clusters"].items(),
                                   key=lambda x: -x[1]["R"])[:12]:
                wlist = " ".join(c["wickets"][:6])
                if len(c["wickets"]) > 6:
                    wlist += f" +{len(c['wickets'])-6}"
                print(f"  {label[:12]:>12s}  {c['R']:6.4f}  {c['size']:5d}  "
                      f"{c['realized']:5d}  {wlist}")

        if report["entangled"]:
            print(f"\n  Entangled Pairs (K ≥ {0.80:.2f})")
            for ep in report["entangled"][:10]:
                print(f"    {ep['a']:8s} ⊗ {ep['b']:8s}  K={ep['K']:.3f}")

        if report["top_gradient"]:
            print(f"\n  Phase Gradient — Top Gravity Signals")
            for g in report["top_gradient"][:8]:
                bar = "▓" * int(g["torque"] * 20)
                print(f"    {g['wicket']:8s}  {g['domain']:20s}  τ={g['torque']:.3f}  {bar}")
        print()

    elif subcmd == "edges":
        wid = getattr(a, "wicket_id", None)
        if not wid:
            print("  Usage: skg graph edges <wicket_id>")
            return
        edges = graph.edges_for(wid)
        node  = graph._nodes.get(wid)
        if node:
            print(f"\n  {wid}  [{node.domain}]  "
                  f"phase={node.phase:.3f}  state={node.state}  ω={node.omega:.2f}")
        if not edges:
            print("  No edges found.")
            return
        print(f"  {'Neighbor':10s}  {'Dir':3s}  {'Type':12s}  {'K':>6s}  "
              f"{'Phase':>7s}  State")
        print(f"  {'─'*10}  {'─'*3}  {'─'*12}  {'─'*6}  {'─'*7}  {'─'*10}")
        for e in edges:
            print(f"  {e['neighbor']:10s}  {e['direction']:3s}  {e['type']:12s}  "
                  f"{e['K']:6.3f}  {e['phase'] or 0.0:7.3f}  {e['state']}")
        print()

    elif subcmd == "entangled":
        pairs = graph.entangled_pairs()
        if not pairs:
            print("  No entangled pairs found.")
            return
        print(f"\n  Entangled Pairs — non-separable wicket couplings (K ≥ {0.80:.2f})")
        print(f"  {'Wicket A':10s}  {'Wicket B':10s}  {'K':>6s}  "
              f"{'Domain A':15s}  {'Domain B':15s}")
        print(f"  {'─'*10}  {'─'*10}  {'─'*6}  {'─'*15}  {'─'*15}")
        for a_id, b_id, K in pairs:
            da = graph._nodes[a_id].domain if a_id in graph._nodes else "?"
            db = graph._nodes[b_id].domain if b_id in graph._nodes else "?"
            print(f"  {a_id:10s}  {b_id:10s}  {K:6.3f}  {da:15s}  {db:15s}")
        print()

    elif subcmd == "hypotheses":
        # Need live states to compute torques — load from latest engagement
        try:
            from skg.kernel.engine import KernelStateEngine
            from skg.core.paths import DISCOVERY_DIR, EVENTS_DIR, CVE_DIR
            import glob as _glob

            # Register instrument wavelengths from sidecar written by gravity cycle.
            _wl_path = SKG_STATE_DIR / "instrument_wavelengths.json"
            if _wl_path.exists():
                graph.register_instruments(json.loads(_wl_path.read_text()))

            # Collect all known states across targets
            kernel = KernelStateEngine(DISCOVERY_DIR, EVENTS_DIR, CVE_DIR)
            from skg.cli.utils import _latest_surface
            surface_path = _latest_surface()
            all_states: dict = {}
            if surface_path:
                surface = json.loads(Path(surface_path).read_text())
                for tgt in surface.get("targets", []):
                    tip = tgt.get("ip") or tgt.get("host", "")
                    if tip:
                        all_states.update(kernel.states_with_detail(tip))

            graph.sync_phases(all_states)
            for wid, ws in all_states.items():
                if isinstance(ws, dict) and ws.get("status") == "realized":
                    graph.collapse(wid, "realized", steps=3)

            hyps = graph.hypotheses(min_torque=0.3)
            if not hyps:
                print("  No significant hypotheses (all torques below threshold).")
                print("  Run an engagement to generate observations.")
                return

            dark   = [h for h in hyps if h["is_dark"]]
            bright = [h for h in hyps if not h["is_dark"]]

            if bright:
                print(f"\n  Observable Hypotheses — instrument can confirm")
                print(f"  {'Wicket':10s}  {'τ':>6s}  {'Domain':20s}  {'Instruments':30s}  Label")
                print(f"  {'─'*10}  {'─'*6}  {'─'*20}  {'─'*30}  {'─'*20}")
                for h in bright[:10]:
                    insts = ", ".join(h["instruments"][:3])
                    print(f"  {h['wicket_id']:10s}  {h['torque']:6.3f}  "
                          f"{h['domain']:20s}  {insts:30s}  {h['label'][:30]}")

            if dark:
                print(f"\n  ◈ Dark Hypotheses — no instrument can see here")
                print(f"  {'Wicket':10s}  {'τ':>6s}  {'Domain':20s}  {'Capable (unavail)':25s}  Label")
                print(f"  {'─'*10}  {'─'*6}  {'─'*20}  {'─'*25}  {'─'*20}")
                for h in dark[:10]:
                    cap = ", ".join(h["all_capable"][:2]) or "none"
                    print(f"  {h['wicket_id']:10s}  {h['torque']:6.3f}  "
                          f"{h['domain']:20s}  {cap:25s}  {h['label'][:30]}")
                print(f"\n  Dark hypotheses are structural folds —")
                print(f"  the field predicts these exist but the instrument set cannot confirm them.")
                print(f"  Create toolchain: skg catalog compile --domain <domain> --description '<label>'")
        except Exception as exc:
            print(f"  Error computing hypotheses: {exc}")
            import traceback; traceback.print_exc()
        print()

    else:
        print("  Usage: skg graph [topology|edges <wicket_id>|entangled|hypotheses]")


def cmd_resonance(a):
    subcmd = a.resonance_cmd

    if subcmd == "status":
        engine = _resonance_engine()
        print(json.dumps(engine.status(), indent=2))

    elif subcmd == "ingest":
        sys.path.insert(0, str(SKG_HOME))
        from skg.resonance.ingester import ingest_all
        engine = _resonance_engine()
        print("[*] Ingesting catalogs, adapters, domains into resonance memory...")
        summary = ingest_all(engine, SKG_HOME)
        domains = summary.get("domains", {})
        w = summary.get("wickets_added", sum(v.get("new_wickets", 0) for v in domains.values()))
        a = summary.get("adapters_added", sum(v.get("new_adapters", 0) for v in domains.values()))
        d = summary.get("domains_added", len(domains))
        processed = summary.get("toolchains_processed", sorted(domains.keys()))
        print(f"  Wickets   : {w}")
        print(f"  Adapters  : {a}")
        print(f"  Domains   : {d}")
        print(f"  Toolchains: {', '.join(processed)}")
        if summary.get("errors"):
            for e in summary["errors"]:
                print(f"  [WARN] {e}")

    elif subcmd == "query":
        engine = _resonance_engine()
        k = getattr(a, "k", 5) or 5
        qtype = getattr(a, "type", "all") or "all"
        if qtype in ("wickets", "all"):
            results = engine.query_wickets(a.text, k=k)
            print(f"\n=== Wickets (top {len(results)}) ===")
            for rec, score in results:
                print(f"  [{score:.3f}] {rec.record_id}")
                print(f"    {rec.label}")
                print(f"    {rec.description[:80]}")
        if qtype in ("adapters", "all"):
            results = engine.query_adapters(a.text, k=k)
            print(f"\n=== Adapters (top {len(results)}) ===")
            for rec, score in results:
                print(f"  [{score:.3f}] {rec.record_id}")
                print(f"    {'; '.join(rec.evidence_sources[:2])}")
        if qtype in ("domains", "all"):
            results = engine.query_domains(a.text, k=min(k, 3))
            print(f"\n=== Domains (top {len(results)}) ===")
            for rec, score in results:
                print(f"  [{score:.3f}] {rec.domain} — {rec.description[:80]}")

    elif subcmd == "draft":
        from skg.resonance.drafter import draft_catalog
        engine = _resonance_engine()
        print(f"[*] Drafting catalog for: {a.domain}")
        result = draft_catalog(engine, a.domain, a.description,
                               api_key=getattr(a, "api_key", None))
        errors = result["validation_errors"]
        if errors:
            print(f"\n[WARN] Validation issues ({len(errors)}):")
            for e in errors:
                print(f"  - {e}")
        else:
            print("\n[OK] Draft passed validation")
        ctx = result["context_used"]
        print(f"\n[*] Context: {ctx['wickets_surfaced']} wickets, "
              f"{ctx['adapters_surfaced']} adapters, "
              f"{ctx['domains_surfaced']} domains surfaced")
        print(f"[*] Wickets proposed:      {len(result['catalog'].get('wickets', {}))}")
        print(f"[*] Attack paths proposed: {len(result['catalog'].get('attack_paths', {}))}")
        print(f"\n[*] Draft saved: {result['draft_path']}")

    elif subcmd == "drafts":
        engine = _resonance_engine()
        drafts_dir = getattr(engine, "_drafts_dir", None)
        if not drafts_dir or not drafts_dir.exists():
            print("  No resonance drafts directory present.")
            return

        import json as _json
        from pathlib import Path

        pending = []
        accepted = []
        prompts = []

        for path in sorted(drafts_dir.glob("pending_*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
            try:
                data = _json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            pending.append((path, data))

        for path in sorted(drafts_dir.glob("draft_*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
            try:
                data = _json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            accepted.append((path, data))

        for path in sorted(drafts_dir.glob("prompt_*.txt"), key=lambda f: f.stat().st_mtime, reverse=True):
            prompts.append(path)

        if not pending and not accepted and not prompts:
            print("  No resonance drafts stored.")
            return

        print("  Resonance drafts:\n")

        if pending:
            print(f"  Pending ({len(pending)}):")
            for path, data in pending[:15]:
                domain = data.get("domain", "?")
                status = data.get("status", "awaiting_response")
                drafted_at = data.get("drafted_at", "?")
                desc = (data.get("description", "") or "")[:70]
                print(f"    {path.name:38s}  {status:18s}  {domain:18s}  {drafted_at}")
                if desc:
                    print(f"      {desc}")

        if accepted:
            print(f"\n  Saved drafts ({len(accepted)}):")
            for path, data in accepted[:15]:
                domain = data.get("domain", "?")
                catalog = data.get("catalog", {}) if isinstance(data.get("catalog"), dict) else {}
                wickets = len(catalog.get("wickets", {}) or {})
                paths = len(catalog.get("attack_paths", {}) or {})
                saved_at = data.get("saved_at", "?")
                print(f"    {path.name:38s}  {domain:18s}  wickets={wickets:<3d} paths={paths:<3d}  {saved_at}")

        if prompts:
            print(f"\n  Prompt files ({len(prompts)}):")
            for path in prompts[:10]:
                print(f"    {path.name}")

        interp_dir = INTERP_DIR
        if interp_dir.exists():
            recent = sorted(interp_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)[:5]
            if recent:
                print(f"\n  Recent interpretations ({len(recent)} shown):")
                for f in recent:
                    try:
                        d = _json.loads(f.read_text())
                        p = d.get("payload", {})
                        cls_ = p.get("classification", "?")
                        ap = p.get("attack_path_id", "?")
                        print(f"    {f.name:50s}  {cls_:16s}  {ap}")
                    except Exception:
                        print(f"    {f.name}")

    elif subcmd == "ollama":
        from skg.resonance.ollama_backend import OllamaBackend
        backend = OllamaBackend()
        status = backend.status()
        print(f"  Available : {'yes' if status.get('available') else 'no'}")
        print(f"  URL       : {status.get('url', '?')}")
        print(f"  Selected  : {status.get('selected_model') or '(none)'}")
        print(f"  Configured: {status.get('configured_model') or '(auto)'}")
        print(f"  Temp      : {status.get('temperature', '?')}")
        models = status.get("models", [])
        if models:
            print(f"  Models    : {', '.join(models)}")
        elif status.get("available"):
            print("  Models    : none")
        if status.get("error"):
            print(f"  Error     : {status['error']}")

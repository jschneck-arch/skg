from __future__ import annotations
import json, os, sys
from pathlib import Path
from skg.cli.utils import (
    _api, _api_required, _load_skg_env_value, _resonance_engine,
    DISCOVERY_DIR, SKG_CONFIG_DIR, SKG_HOME, SKG_STATE_DIR, CVE_DIR,
)
try:
    from skg_core.config.paths import INTERP_DIR
except ImportError:
    INTERP_DIR = SKG_STATE_DIR / "interp"


def cmd_feed(a):
    subcmd = a.feed_cmd

    if subcmd == "nvd":
        nvd_script = SKG_HOME / "feeds" / "nvd_ingester.py"
        if not nvd_script.exists():
            print(f"  Error: {nvd_script} not found")
            return

        api_key = _load_skg_env_value("NIST_NVD_API_KEY")
        if api_key and "NIST_NVD_API_KEY" not in os.environ:
            print(f"  [feed] Loaded NIST_NVD_API_KEY from {SKG_CONFIG_DIR / 'skg.env'}")
        if not api_key:
            print("  Error: Set NIST_NVD_API_KEY environment variable")
            print(f"         or add NIST_NVD_API_KEY=<key> to {SKG_CONFIG_DIR / 'skg.env'}")
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

    subcmd = getattr(a, "graph_cmd", None) or "topology"
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
            from skg_core.config.paths import DISCOVERY_DIR, EVENTS_DIR
            from skg_services.gravity.path_policy import CVE_DIR
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
        if qtype in ("corpus", "all"):
            results = engine.query_corpus(a.text, k=k)
            print(f"\n=== Corpus (top {len(results)}) ===")
            for rec, score in results:
                print(f"  [{score:.3f}] {rec.source_kind}:{rec.source_ref}")
                print(f"    {rec.title[:100]}")
                print(f"    {rec.text[:120]}")

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

    elif subcmd == "ask":
        from skg.resonance.orchestrator import LayeredAssistant

        engine = _resonance_engine()
        assistant = LayeredAssistant.from_config(engine)
        result = assistant.ask(
            a.text,
            prefer=getattr(a, "prefer", None),
            k_each=getattr(a, "k", None),
        )

        if getattr(a, "json_out", False):
            print(json.dumps(result, indent=2))
            return

        counts = result.get("context_counts", {})
        print(f"  Route      : {result.get('route')} ({result.get('route_reason')})")
        print(f"  Model      : {result.get('model_used')}")
        print(f"  Fallback   : {'yes' if result.get('fallback_used') else 'no'}")
        print(f"  Latency    : {result.get('latency_s')}s")
        print(
            f"  Context    : wickets={counts.get('wickets', 0)} "
            f"adapters={counts.get('adapters', 0)} "
            f"domains={counts.get('domains', 0)} "
            f"corpus={counts.get('corpus', 0)}"
        )

        if getattr(a, "show_context", False):
            preview = result.get("context_preview", []) or []
            print("\n  Context preview:")
            if preview:
                for line in preview:
                    print(f"    - {line}")
            else:
                print("    - (none)")

        print("\n" + (result.get("response") or ""))

    elif subcmd == "mcp-status":
        status = _api("GET", "/resonance/mcp/status")
        if status is None:
            from skg.resonance.mcp_threading import MCPThreadingOrchestrator

            engine = _resonance_engine()
            mcp = MCPThreadingOrchestrator.from_config(engine)
            status = mcp.status()

        if getattr(a, "json_out", False):
            print(json.dumps(status, indent=2))
            return

        cfg = status.get("config", {}) or {}
        print("[*] Layered MCP threading")
        print(f"  Enabled      : {'yes' if status.get('enabled') else 'no'}")
        print(f"  Source truth : {status.get('source_of_truth')}")
        print(f"  k_each       : {cfg.get('k_each')}")
        print(f"  adapter_k    : {cfg.get('adapter_k')}")
        print(f"  max_workers  : {cfg.get('max_workers')}")
        print(
            f"  capabilities : {'on' if cfg.get('capability_scan') else 'off'} "
            f"(help={cfg.get('max_help_cmds')} man={cfg.get('max_man_cmds')})"
        )
        print(
            f"  selector     : top_n={cfg.get('selector_top_n')} "
            f"min_score={cfg.get('selector_min_score')} "
            f"advisory_only={'yes' if cfg.get('advisory_only') else 'no'}"
        )
        assistant = status.get("assistant", {})
        if isinstance(assistant, dict):
            backend = assistant.get("backend", {})
            if isinstance(backend, dict):
                print(
                    f"  Backend      : {'available' if backend.get('available') else 'unavailable'} "
                    f"model={backend.get('selected_model') or backend.get('configured_model') or '(auto)'}"
                )

    elif subcmd == "mcp-thread":
        payload = {
            "query": a.text,
            "theta": getattr(a, "theta", "general"),
            "prefer": getattr(a, "prefer", None),
            "k_each": getattr(a, "k", None),
            "max_workers": getattr(a, "max_workers", None),
        }
        result = _api("POST", "/resonance/mcp/thread", data=payload)
        if result is None:
            from skg.resonance.mcp_threading import MCPThreadingOrchestrator

            engine = _resonance_engine()
            mcp = MCPThreadingOrchestrator.from_config(engine)
            result = mcp.thread(
                payload["query"],
                theta=payload["theta"],
                prefer=payload["prefer"],
                k_each=payload["k_each"],
                max_workers=payload["max_workers"],
            )

        if getattr(a, "json_out", False):
            print(json.dumps(result, indent=2))
            return

        execution = result.get("execution", {}) if isinstance(result.get("execution"), dict) else {}
        threads = result.get("threads", {}) if isinstance(result.get("threads"), dict) else {}
        memory = threads.get("memory", {}) if isinstance(threads.get("memory"), dict) else {}
        instruments = threads.get("instruments", {}) if isinstance(threads.get("instruments"), dict) else {}
        decision = threads.get("instrument_decision", {}) if isinstance(threads.get("instrument_decision"), dict) else {}
        reasoner = threads.get("reasoner", {}) if isinstance(threads.get("reasoner"), dict) else {}
        verification = threads.get("verification", {}) if isinstance(threads.get("verification"), dict) else {}

        print("[*] MCP threaded query")
        print(f"  Source truth : {result.get('source_of_truth')}")
        print(f"  Mode         : {execution.get('mode')}")
        print(f"  Elapsed      : {execution.get('elapsed_s')}s")
        counts = memory.get("counts", {}) if isinstance(memory.get("counts"), dict) else {}
        print(
            f"  Memory       : wickets={counts.get('wickets', 0)} "
            f"adapters={counts.get('adapters', 0)} "
            f"domains={counts.get('domains', 0)} "
            f"corpus={counts.get('corpus', 0)}"
        )
        print(f"  Instruments  : {instruments.get('count', 0)}")
        selected = list(decision.get("selected_adapters", []) or [])
        print(f"  SKG select   : {', '.join(selected) if selected else '(none)'}")
        print(
            f"  Reasoner     : route={reasoner.get('route')} model={reasoner.get('model_used')} "
            f"advisory_only={'yes' if reasoner.get('advisory_only') else 'no'}"
        )
        print(
            f"  Grounding    : mentions_known={verification.get('mentions_known_instrument')} "
            f"mentions_selected={verification.get('mentions_selected_instrument')} "
            f"pool={verification.get('instrument_pool', 0)}"
        )
        print("\n" + (reasoner.get("response") or ""))

    elif subcmd == "sphere-status":
        status = _api("GET", "/resonance/sphere/status")
        if status is None:
            from skg.resonance.sphere_gpu import SphereGPU
            engine = _resonance_engine()
            sphere = SphereGPU.from_config(engine)
            status = sphere.status()
        if getattr(a, "json_out", False):
            print(json.dumps(status, indent=2))
            return

        print("[*] SphereGPU v0")
        print(f"  Virtual cores : {status.get('virtual_cores')}")
        limits = status.get("shell_limits", {})
        print(
            f"  Shell limits  : inner={limits.get('inner', 0)} "
            f"mid={limits.get('mid', 0)} outer={limits.get('outer', 0)}"
        )
        cache = status.get("cache", {})
        print(
            f"  Cache         : {cache.get('entries', 0)}/{cache.get('max_size', 0)} entries"
        )
        stats = status.get("stats", {})
        print(
            f"  Jobs          : requests={stats.get('requests_total', 0)} "
            f"executed={stats.get('jobs_total', 0)} "
            f"hits={stats.get('cache_hits', 0)} misses={stats.get('cache_misses', 0)}"
        )
        guard = status.get("resource_guard", {}) or {}
        print(
            f"  Guard         : {'on' if guard.get('enabled') else 'off'} "
            f"downgrades={stats.get('guard_downgrades', 0)}"
        )
        auto_local = status.get("auto_local_corpus", {}) or {}
        print(
            f"  Auto corpus   : {'on' if auto_local.get('enabled') else 'off'} "
            f"running={'yes' if auto_local.get('running') else 'no'} "
            f"interval={auto_local.get('interval_s', 0)}s"
        )
        micro_local = status.get("micro_local_corpus", {}) or {}
        print(
            f"  Micro corpus  : {'on' if micro_local.get('enabled') else 'off'} "
            f"ttl={micro_local.get('ttl_s', 0)}s "
            f"runs={micro_local.get('runs_total', 0)} "
            f"applied={micro_local.get('applied_runs', 0)}"
        )

    elif subcmd == "sphere-ask":
        payload = {
            "query": a.text,
            "r": getattr(a, "r", 0.35),
            "theta": getattr(a, "theta", "general"),
            "phi": getattr(a, "phi", 0.5),
            "stream": getattr(a, "stream", 0),
            "k_each": getattr(a, "k", None),
        }
        result = _api("POST", "/resonance/sphere/ask", data=payload)
        if result is None:
            from skg.resonance.sphere_gpu import SphereGPU, SpherePoint
            engine = _resonance_engine()
            sphere = SphereGPU.from_config(engine)
            point = SpherePoint.from_values(
                r=payload["r"],
                theta=payload["theta"],
                phi=payload["phi"],
                stream=payload["stream"],
            )
            result = sphere.infer(
                query=payload["query"],
                point=point,
                k_each=payload["k_each"],
            )
        if getattr(a, "json_out", False):
            print(json.dumps(result, indent=2))
            return

        sphere_meta = result.get("sphere", {})
        counts = result.get("context_counts", {})
        print(
            f"  Sphere     : shell={sphere_meta.get('shell')} prefer={sphere_meta.get('prefer')} "
            f"r={sphere_meta.get('r')} theta={sphere_meta.get('theta')} phi={sphere_meta.get('phi')}"
        )
        print(f"  Route      : {result.get('route')} ({result.get('route_reason')})")
        print(f"  Model      : {result.get('model_used')}")
        print(f"  Cache hit  : {'yes' if result.get('cache_hit') else 'no'}")
        print(f"  Queue wait : {sphere_meta.get('queue_wait_s')}s")
        print(f"  Latency    : {result.get('latency_s')}s")
        micro = sphere_meta.get("micro_local_index", {}) or {}
        print(
            f"  Micro index: {'ran' if micro.get('started') else 'not-ran'} "
            f"({micro.get('reason', 'n/a')})"
        )
        auto = sphere_meta.get("auto_local_index", {}) or {}
        print(
            f"  Auto index : {'started' if auto.get('started') else 'not-started'} "
            f"({auto.get('reason', 'n/a')})"
        )
        print(
            f"  Context    : wickets={counts.get('wickets', 0)} "
            f"adapters={counts.get('adapters', 0)} "
            f"domains={counts.get('domains', 0)} "
            f"corpus={counts.get('corpus', 0)}"
        )
        if getattr(a, "show_context", False):
            preview = result.get("context_preview", []) or []
            print("\n  Context preview:")
            if preview:
                for line in preview:
                    print(f"    - {line}")
            else:
                print("    - (none)")
        print("\n" + (result.get("response") or ""))

    elif subcmd == "sphere-batch":
        in_path = Path(getattr(a, "infile"))
        if not in_path.exists():
            print(f"  Error: input file not found: {in_path}")
            return

        raw = in_path.read_text(encoding="utf-8", errors="replace").strip()
        jobs: list[dict] = []
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    jobs = [x for x in parsed if isinstance(x, dict)]
                elif isinstance(parsed, dict):
                    jobs = [parsed]
            except Exception:
                # JSONL fallback
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(item, dict):
                        jobs.append(item)

        requests = []
        for item in jobs:
            text = str(item.get("text") or item.get("query") or "").strip()
            if not text:
                continue
            requests.append(
                {
                    "query": text,
                    "r": item.get("r", 0.35),
                    "theta": str(item.get("theta", "general")),
                    "phi": item.get("phi", 0.5),
                    "stream": item.get("stream", 0),
                    "k_each": item.get("k") or item.get("k_each"),
                }
            )

        if not requests:
            print("  No valid jobs found in input.")
            return

        api_payload = {
            "requests": requests,
            "max_workers": getattr(a, "max_workers", None),
        }
        api_result = _api("POST", "/resonance/sphere/batch", data=api_payload)
        if api_result is None:
            from skg.resonance.sphere_gpu import SphereGPU
            engine = _resonance_engine()
            sphere = SphereGPU.from_config(engine)
            results = sphere.infer_batch(requests, max_workers=getattr(a, "max_workers", None))
            status = sphere.status()
        else:
            results = list(api_result.get("results", []) or [])
            status = dict(api_result.get("status", {}) or {})

        if getattr(a, "json_out", False):
            print(json.dumps({"results": results, "status": status}, indent=2))
            return

        print(f"[*] Sphere batch complete ({len(results)} jobs)")
        for idx, res in enumerate(results, start=1):
            s = res.get("sphere", {})
            print(
                f"  [{idx:02d}] shell={s.get('shell')} prefer={s.get('prefer')} "
                f"route={res.get('route')} model={res.get('model_used')} "
                f"cache={'hit' if res.get('cache_hit') else 'miss'} latency={res.get('latency_s')}s"
            )
        stats = status.get("stats", {})
        print(
            f"  Totals: requests={stats.get('requests_total', 0)} executed={stats.get('jobs_total', 0)} "
            f"hits={stats.get('cache_hits', 0)} misses={stats.get('cache_misses', 0)}"
        )

    elif subcmd == "index-local":
        from skg.resonance.local_corpus import index_local_corpus

        engine = _resonance_engine()
        result = index_local_corpus(
            engine,
            pearls=not bool(getattr(a, "no_pearls", False)),
            help_cmds=getattr(a, "help_cmds", ""),
            man_cmds=getattr(a, "man_cmds", ""),
            code_root=getattr(a, "code_root", None),
            max_code_files=getattr(a, "max_code_files", 120),
            chunk_chars=getattr(a, "chunk_chars", 900),
            max_pearl_records=getattr(a, "max_pearl_records", 500),
        )
        totals = result.get("totals", {})
        print("[*] Local corpus indexing complete")
        print(f"  Added   : {totals.get('added', 0)}")
        print(f"  Skipped : {totals.get('skipped', 0)} (already present)")
        print(f"  Sources : {totals.get('sources', 0)}")
        print(f"  Code root: {result.get('code_root')}")
        per = result.get("summary", {})
        for key in ("pearls", "help", "man", "code"):
            item = per.get(key, {})
            print(
                f"  {key:7s}: sources={item.get('sources', 0)} "
                f"added={item.get('added', 0)} skipped={item.get('skipped', 0)}"
            )

    elif subcmd == "capabilities":
        result = _api("GET", "/resonance/local-capabilities")
        if result is None:
            from skg.resonance.local_corpus import discover_local_capabilities

            result = discover_local_capabilities()

        if getattr(a, "json_out", False):
            print(json.dumps(result, indent=2))
            return

        help_cmds = list(result.get("available_help_commands", []) or [])
        man_cmds = list(result.get("available_man_commands", []) or [])
        print("[*] Local capability scan")
        print(f"  CWD            : {result.get('cwd')}")
        print(f"  Code root      : {result.get('code_root')} (exists={result.get('code_root_exists')})")
        print(f"  Pearls         : {result.get('pearls_path')} (exists={result.get('pearls_exists')})")
        print(f"  Help commands  : {len(help_cmds)}")
        if help_cmds:
            print(f"    {', '.join(help_cmds[:20])}")
        print(
            f"  Man commands   : {len(man_cmds)} "
            f"(renderer={'yes' if result.get('has_man_renderer') else 'no'})"
        )
        if man_cmds:
            print(f"    {', '.join(man_cmds[:20])}")

    elif subcmd == "index-smart":
        payload = {
            "query": getattr(a, "query", "") or "",
            "theta": getattr(a, "theta", "general") or "general",
            "force": bool(getattr(a, "force", False)),
        }
        result = _api("POST", "/resonance/index-smart", data=payload)
        if result is None:
            from skg.resonance.local_corpus import smart_index_local_corpus

            engine = _resonance_engine()
            result = smart_index_local_corpus(
                engine,
                query=payload["query"],
                theta=payload["theta"],
                force=payload["force"],
            )

        if getattr(a, "json_out", False):
            print(json.dumps(result, indent=2))
            return

        plan = result.get("plan", {})
        print("[*] Smart local corpus indexing")
        print(f"  Due        : {'yes' if result.get('due') else 'no'}")
        print(f"  Skipped    : {'yes' if result.get('skipped') else 'no'}")
        if result.get("reason"):
            print(f"  Reason     : {result.get('reason')}")
        print(f"  Query      : {result.get('query') or '(none)'}")
        print(f"  Theta      : {result.get('theta') or '(none)'}")
        print(f"  Help plan  : {', '.join(plan.get('help_cmds', []) or []) or '(none)'}")
        print(f"  Man plan   : {', '.join(plan.get('man_cmds', []) or []) or '(none)'}")
        indexed = result.get("result", {}) if isinstance(result.get("result"), dict) else {}
        totals = indexed.get("totals", {}) if isinstance(indexed.get("totals"), dict) else {}
        if totals:
            print(f"  Added      : {totals.get('added', 0)}")
            print(f"  Skipped rec: {totals.get('skipped', 0)}")
            print(f"  Sources    : {totals.get('sources', 0)}")

    elif subcmd == "index-micro":
        payload = {
            "query": getattr(a, "query", "") or "",
            "theta": getattr(a, "theta", "general") or "general",
            "force": bool(getattr(a, "force", False)),
        }
        result = _api("POST", "/resonance/index-micro", data=payload)
        if result is None:
            from skg.resonance.local_corpus import micro_index_local_corpus

            engine = _resonance_engine()
            result = micro_index_local_corpus(
                engine,
                query=payload["query"],
                theta=payload["theta"],
                force=payload["force"],
            )

        if getattr(a, "json_out", False):
            print(json.dumps(result, indent=2))
            return

        selected = result.get("selected", {}) if isinstance(result.get("selected"), dict) else {}
        due = result.get("due", {}) if isinstance(result.get("due"), dict) else {}
        totals = result.get("totals", {}) if isinstance(result.get("totals"), dict) else {}
        print("[*] Micro local corpus indexing")
        print(f"  Query      : {result.get('query') or '(none)'}")
        print(f"  Theta      : {result.get('theta') or '(none)'}")
        print(f"  Skipped    : {'yes' if result.get('skipped') else 'no'}")
        if result.get("reason"):
            print(f"  Reason     : {result.get('reason')}")
        print(f"  Selected   : help={', '.join(selected.get('help', []) or []) or '(none)'}")
        print(f"  Selected   : man={', '.join(selected.get('man', []) or []) or '(none)'}")
        print(f"  Selected   : code={', '.join(selected.get('code', []) or []) or '(none)'}")
        print(f"  Due        : help={', '.join(due.get('help', []) or []) or '(none)'}")
        print(f"  Due        : man={', '.join(due.get('man', []) or []) or '(none)'}")
        print(f"  Due        : code={', '.join(due.get('code', []) or []) or '(none)'}")
        print(f"  Added      : {totals.get('added', 0)}")
        print(f"  Skipped rec: {totals.get('skipped', 0)}")
        print(f"  Sources    : {totals.get('sources', 0)}")

    elif subcmd == "drafts":
        engine = _resonance_engine()
        drafts_dir = getattr(engine, "_drafts_dir", None)
        if not drafts_dir or not drafts_dir.exists():
            print("  No resonance drafts directory present.")
            return

        import json as _json

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

    elif subcmd == "draft-prompt":
        from skg.resonance.drafter import draft_prompt
        engine = _resonance_engine()
        print(f"[*] Building prompt for domain: {a.domain}")
        result = draft_prompt(engine, a.domain, a.description)
        ctx = result["context_used"]
        print(f"[*] Context: {ctx['wickets_surfaced']} wickets, "
              f"{ctx['adapters_surfaced']} adapters, "
              f"{ctx['domains_surfaced']} domains surfaced")
        print(f"\n[*] Prompt written to: {result['prompt_path']}")
        print(f"[*] Pending marker   : {result['pending_path']}")
        print("\n--- Prompt preview (first 500 chars) ---")
        print(result["prompt"][:500])
        print("--- (paste full file into claude.ai, then run: skg resonance draft-accept) ---")

    elif subcmd == "draft-accept":
        from skg.resonance.drafter import draft_accept
        engine = _resonance_engine()
        print(f"[*] Accepting draft response for domain: {a.domain}")
        result = draft_accept(engine, a.domain, a.response)
        errors = result["validation_errors"]
        if errors:
            print(f"\n[WARN] Validation issues ({len(errors)}):")
            for e in errors:
                print(f"  - {e}")
        else:
            print("\n[OK] Draft passed validation")
        print(f"[*] Wickets proposed:      {len(result['catalog'].get('wickets', {}))}")
        print(f"[*] Attack paths proposed: {len(result['catalog'].get('attack_paths', {}))}")
        print(f"\n[*] Draft saved: {result['draft_path']}")

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

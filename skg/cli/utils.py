from __future__ import annotations
import glob, importlib.util, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import urllib.request, urllib.error
from skg.core.paths import (
    SKG_HOME, SKG_STATE_DIR, DISCOVERY_DIR, CVE_DIR, SKG_CONFIG_DIR,
    EVENTS_DIR, INTERP_DIR, IDENTITY_FILE,
)
API = "http://127.0.0.1:5055"


def _api(method, path, data=None, params=None):
    if params:
        import urllib.parse as _uparse
        url = f"{API}{path}?" + _uparse.urlencode({k:v for k,v in params.items() if v is not None})
    else:
        url  = f"{API}{path}"
    body = json.dumps(data).encode() if data else None
    hdrs = {"Content-Type": "application/json"} if body else {}
    req  = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    _timeout = 120 if path in ("/collect", "/gravity/run") else 5
    try:
        with urllib.request.urlopen(req, timeout=_timeout) as r:
            return json.loads(r.read())
    except urllib.error.URLError:
        return None  # Daemon not running — not always an error
    except urllib.error.HTTPError as e:
        print(f"Error: {json.loads(e.read()).get('detail', str(e))}")
        sys.exit(1)


def _api_required(method, path, data=None, params=None):
    """Like _api but exits if daemon isn't running."""
    result = _api(method, path, data, params)
    if result is None:
        print("Error: SKG daemon not running.  Start: systemctl start skg")
        sys.exit(1)
    return result


def _tc(tc_name, cli_script, *args):
    tc_dir = SKG_HOME / tc_name
    py     = tc_dir / ".venv" / "bin" / "python"
    cli    = tc_dir / cli_script
    if not py.exists():
        # Fall back to system python
        py = Path(sys.executable)
    if not cli.exists():
        print(f"Error: {cli} not found")
        return 1
    return subprocess.call([str(py), str(cli)] + list(args), cwd=str(tc_dir))


def _aprs(*args):    return _tc("skg-aprs-toolchain",             "skg.py",         *args)
def _escape(*args):  return _tc("skg-container-escape-toolchain", "skg_escape.py",  *args)
def _lateral(*args): return _tc("skg-ad-lateral-toolchain",       "skg_lateral.py", *args)


def _resonance_engine():
    repo_root = SKG_HOME
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from skg.resonance.engine import ResonanceEngine
    from skg.core.paths import RESONANCE_DIR
    engine = ResonanceEngine(RESONANCE_DIR)
    engine.boot()
    return engine


def _latest_surface() -> str:
    """Find the best current surface JSON, preferring richer observed target sets."""
    surfaces = glob.glob(str(DISCOVERY_DIR / "surface_*.json"))
    if not surfaces:
        return ""

    def _score(path: str) -> tuple[int, int, float]:
        try:
            data = json.loads(Path(path).read_text())
            targets = data.get("targets", []) or []
            target_count = sum(1 for t in targets if t.get("ip") or t.get("host"))
            service_count = sum(len(t.get("services", []) or []) for t in targets)
            return (target_count + service_count, target_count, os.path.getmtime(path))
        except Exception:
            return (0, 0, os.path.getmtime(path))

    return max(surfaces, key=_score)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_surface_data() -> tuple[dict, str]:
    surface_path = _latest_surface()
    if surface_path:
        try:
            surface = json.loads(Path(surface_path).read_text())
            _ensure_local_runtime_targets(surface)
            return surface, surface_path
        except Exception:
            pass
    surface = {"meta": {"generated_at": _iso_now()}, "targets": []}
    _ensure_local_runtime_targets(surface)
    return surface, surface_path


def _write_surface_data(surface: dict, surface_path: str = "") -> str:
    _ensure_local_runtime_targets(surface)
    target_path = Path(surface_path) if surface_path else (DISCOVERY_DIR / f"surface_{os.urandom(4).hex()}.json")
    meta = surface.setdefault("meta", {})
    meta["generated_at"] = _iso_now()
    meta["targets_classified"] = len(surface.get("targets", []))
    target_path.write_text(json.dumps(surface, indent=2))
    return str(target_path)


def _ensure_local_runtime_targets(surface: dict) -> None:
    """Inject configured local runtime endpoints as observable targets."""
    try:
        import yaml
        from urllib.parse import urlparse

        cfg_path = SKG_HOME / "config" / "skg_config.yaml"
        cfg = yaml.safe_load(cfg_path.read_text()) or {}
        resonance = cfg.get("resonance", {}) or {}
        ollama = resonance.get("ollama", {}) or {}
        url = str(ollama.get("url") or "").strip()
        if not url:
            return
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip().lower()
        if host not in {"127.0.0.1", "localhost"}:
            return
        ip = "127.0.0.1"
        port = int(parsed.port or 11434)
        model = str(ollama.get("model") or "").strip()
        banner = "Ollama API" + (f" ({model})" if model else "")
        svc = {"port": port, "service": "ollama", "banner": banner}

        targets = surface.setdefault("targets", [])
        existing = next((t for t in targets if (t.get("ip") or t.get("host")) == ip), None)
        if existing is None:
            targets.append({
                "ip": ip,
                "host": ip,
                "hostname": "localhost",
                "os": "local",
                "kind": "local-ai-service",
                "services": [svc],
                "domains": ["ai_target", "web"],
                "applicable_attack_paths": [],
            })
            return

        existing["host"] = existing.get("host") or ip
        existing["ip"] = existing.get("ip") or ip
        existing["hostname"] = existing.get("hostname") or "localhost"
        existing["os"] = existing.get("os") or "local"
        existing["kind"] = existing.get("kind") or "local-ai-service"
        services = existing.setdefault("services", [])
        if not any(int(s.get("port", 0) or 0) == port for s in services):
            services.append(svc)
        domains = set(existing.get("domains", []) or [])
        domains.update({"ai_target", "web"})
        existing["domains"] = sorted(domains)
    except Exception:
        return


def _surface_target(ip: str) -> dict | None:
    surface, _ = _load_surface_data()
    for target in surface.get("targets", []):
        if target.get("ip") == ip:
            return target
    return None


def _interp_payload(rec: dict) -> dict:
    if isinstance(rec, dict) and isinstance(rec.get("payload"), dict):
        return rec["payload"]
    return rec if isinstance(rec, dict) else {}


def _projection_rank(payload: dict) -> tuple[int, float]:
    cls = payload.get("classification", "")
    score = payload.get("aprs", payload.get("lateral_score",
            payload.get("escape_score", payload.get("host_score",
            payload.get("web_score", payload.get("ai_score", 0.0))))))
    if cls == "realized":
        return (3, float(score))
    if cls == "not_realized":
        return (2, float(score))
    if cls == "indeterminate":
        return (1, float(score))
    return (0, float(score))


def _load_module_from_file(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _register_target(ip: str, domain: str | None = None) -> str:
    surface, surface_path = _load_surface_data()
    targets = surface.setdefault("targets", [])
    existing = next((t for t in targets if t.get("ip") == ip), None)
    if existing is None:
        existing = {
            "ip": ip,
            "os": "unknown",
            "kind": "unknown",
            "services": [],
            "domains": [],
            "applicable_attack_paths": [],
        }
        targets.append(existing)
    if domain and domain not in existing.setdefault("domains", []):
        existing["domains"].append(domain)
        existing["domains"] = sorted(set(existing["domains"]))
    _persist_target_config(ip, domain)
    return _write_surface_data(surface, surface_path)


def _merge_target_into_surface(target: dict) -> str:
    surface, surface_path = _load_surface_data()
    targets = surface.setdefault("targets", [])
    existing = next((t for t in targets if t.get("ip") == target.get("ip")), None)
    if existing is None:
        targets.append(target)
    else:
        existing.update(target)
    return _write_surface_data(surface, surface_path)


def _register_web_observation_target(target_url: str, events_file: Path | None = None) -> str:
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url
    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)
    service = "https" if scheme == "https" else "http"
    discovery = _load_module_from_file("skg_discovery_cli_runtime", SKG_HOME / "skg-discovery" / "discovery.py")
    classified = discovery.classify_target(
        host,
        [(port, service, host)],
        os_guess="external-web",
        is_container=False,
    )
    load_states = getattr(discovery, "_load_latest_wicket_states_for_ip")
    try:
        wicket_states = load_states(host, DISCOVERY_DIR)
    except Exception:
        wicket_states = {}
    classified["wicket_states"] = wicket_states
    classified["source_url"] = target_url
    classified["kind"] = classified.get("kind") or "external-web"
    if "web" not in classified.get("domains", []):
        classified["domains"] = sorted(set(classified.get("domains", []) + ["web"]))
    return _merge_target_into_surface(classified)


def _persist_target_config(ip: str, domain: str | None = None) -> None:
    targets_file = SKG_CONFIG_DIR / "targets.yaml"
    if not targets_file.exists():
        return
    try:
        import yaml
        data = yaml.safe_load(targets_file.read_text()) or {}
        targets = data.setdefault("targets", [])
        existing = next((t for t in targets if t.get("host") == ip), None)
        if existing is None:
            entry = {"host": ip, "enabled": True}
            if domain:
                entry["domain"] = domain
            targets.append(entry)
            targets_file.write_text(yaml.safe_dump(data, sort_keys=False))
    except Exception:
        pass


def _load_target_config(ip: str) -> dict | None:
    targets_file = SKG_CONFIG_DIR / "targets.yaml"
    if not targets_file.exists():
        return None
    try:
        import yaml
        data = yaml.safe_load(targets_file.read_text()) or {}
        for target in data.get("targets", []):
            if target.get("host") == ip or target.get("workload_id", "").endswith(ip):
                return target
    except Exception:
        return None
    return None


def _bootstrap_target_surface(ip: str) -> str:
    discovery_module = _load_module_from_file(
        "skg_discovery_bootstrap",
        SKG_HOME / "skg-discovery" / "discovery.py",
    )
    services = discovery_module.scan_ports(ip)
    target = discovery_module.classify_target(ip, services, os_guess="unknown", is_container=ip.startswith(("172.17.", "172.18.")))
    surface, surface_path = _load_surface_data()
    targets = [t for t in surface.get("targets", []) if t.get("ip") != ip]
    targets.append(target)
    surface["targets"] = sorted(targets, key=lambda t: t.get("ip", ""))
    return _write_surface_data(surface, surface_path)


def _run_python(script_path, *args, env_extra=None):
    """Run a Python script with optional extra env vars."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.call([sys.executable, str(script_path)] + list(args), env=env)


def _proposal_backlog() -> dict:
    proposals_dir = SKG_STATE_DIR / "proposals"
    counts = {
        "pending_total": 0,
        "pending_toolchain_generation": 0,
        "pending_catalog_growth": 0,
        "pending_field_action": 0,
        "error_total": 0,
    }
    if not proposals_dir.exists():
        return counts

    for proposal_file in proposals_dir.glob("*.json"):
        try:
            proposal = json.loads(proposal_file.read_text())
        except Exception:
            continue
        status = proposal.get("status", "")
        kind = proposal.get("proposal_kind", "")
        if status == "pending":
            counts["pending_total"] += 1
            if kind == "toolchain_generation":
                counts["pending_toolchain_generation"] += 1
            elif kind == "catalog_growth":
                counts["pending_catalog_growth"] += 1
            elif kind == "field_action":
                counts["pending_field_action"] += 1
        if str(status).startswith("error"):
            counts["error_total"] += 1
    return counts


def _fold_summary_offline() -> dict:
    folds_dir = DISCOVERY_DIR / "folds"
    total = 0
    by_type = {}
    total_weight = 0.0
    if not folds_dir.exists():
        return {"total": 0, "by_type": {}, "total_gravity_weight": 0.0}

    for fold_file in folds_dir.glob("folds_*.json"):
        try:
            folds = json.loads(fold_file.read_text())
        except Exception:
            continue
        for fold in folds:
            total += 1
            fold_type = fold.get("fold_type", "unknown")
            by_type[fold_type] = by_type.get(fold_type, 0) + 1
            try:
                total_weight += float(fold.get("gravity_weight", 0.0))
            except Exception:
                pass
    return {
        "total": total,
        "by_type": by_type,
        "total_gravity_weight": round(total_weight, 4),
    }


def _choose_fold_summary(api_folds: dict | None) -> dict:
    offline = _fold_summary_offline()
    online = (api_folds or {}).get("summary") or {}
    if offline.get("total", 0) >= online.get("total", 0):
        return offline
    return online


def _load_folds_offline() -> list[dict]:
    folds_dir = DISCOVERY_DIR / "folds"
    rows = []
    if not folds_dir.exists():
        return rows
    for fold_file in folds_dir.glob("folds_*.json"):
        try:
            rows.extend(json.loads(fold_file.read_text()))
        except Exception:
            continue
    return rows


def _choose_fold_rows(api_folds: dict | None) -> list[dict]:
    offline = _load_folds_offline()
    online = (api_folds or {}).get("folds") or []
    if len(offline) >= len(online):
        return offline
    return online


def _target_state_counts(target: dict) -> dict:
    ws = target.get("wicket_states", {})
    unknown = sum(1 for v in ws.values() if v == "unknown" or (isinstance(v, dict) and v.get("status") == "unknown"))
    realized = sum(1 for v in ws.values() if v == "realized" or (isinstance(v, dict) and v.get("status") == "realized"))
    blocked = sum(1 for v in ws.values() if v == "blocked" or (isinstance(v, dict) and v.get("status") == "blocked"))
    unresolved_rows = [v for v in ws.values() if isinstance(v, dict) and v.get("status") == "unknown"]
    unresolved_reasons = {}
    compatibility_values = []
    decoherence_values = []
    for row in unresolved_rows:
        reason = str(row.get("unresolved_reason") or "unmeasured")
        unresolved_reasons[reason] = unresolved_reasons.get(reason, 0) + 1
        compatibility_values.append(float(row.get("compatibility_score", 0.0) or 0.0))
        decoherence_values.append(float(row.get("decoherence", 0.0) or 0.0))
    return {
        "unknown": unknown,
        "realized": realized,
        "blocked": blocked,
        "unresolved_reasons": unresolved_reasons,
        "compatibility_score_mean": round(sum(compatibility_values) / len(compatibility_values), 3) if compatibility_values else 0.0,
        "decoherence_total": round(sum(decoherence_values), 3),
    }


def _rank_surface_targets(surface: dict, folds: list[dict] | None = None) -> list[dict]:
    fold_weight_by_ip = {}
    fold_count_by_ip = {}
    for fold in folds or []:
        ip = fold.get("target_ip") or fold.get("location", "").split("::")[-1]
        if not ip:
            continue
        fold_count_by_ip[ip] = fold_count_by_ip.get(ip, 0) + 1
        try:
            fold_weight_by_ip[ip] = fold_weight_by_ip.get(ip, 0.0) + float(fold.get("gravity_weight", 0.0))
        except Exception:
            pass

    ranked = []
    for target in surface.get("targets", []):
        counts = _target_state_counts(target)
        ip = target.get("ip", "")
        ranked.append({
            "ip": ip,
            "kind": target.get("kind") or target.get("os") or "?",
            "domains": target.get("domains", []),
            "services": target.get("services", []),
            "unknown": counts["unknown"],
            "realized": counts["realized"],
            "blocked": counts["blocked"],
            "unresolved_reasons": counts["unresolved_reasons"],
            "compatibility_score_mean": counts["compatibility_score_mean"],
            "decoherence_total": counts["decoherence_total"],
            "folds": fold_count_by_ip.get(ip, 0),
            "fold_weight": round(fold_weight_by_ip.get(ip, 0.0), 2),
            "priority": counts["unknown"] + fold_weight_by_ip.get(ip, 0.0),
        })
    ranked.sort(key=lambda row: (row["priority"], row["unknown"], row["realized"]), reverse=True)
    return ranked


def _print_what_matters_now(surface: dict, fold_rows: list[dict], backlog: dict) -> None:
    ranked = _rank_surface_targets(surface, fold_rows)
    focus = [row for row in ranked if row["priority"] > 0][:5]
    print("  What Matters Now:")
    if not focus:
        print("    no active targets with unresolved structure")
    else:
        for row in focus:
            services = ", ".join(f"{s.get('port')}/{s.get('service')}" for s in row["services"][:6]) or "none"
            domains = ", ".join(row["domains"]) or "none"
            fold_note = f", folds={row['folds']} (+{row['fold_weight']:.1f})" if row["folds"] else ""
            print(f"    {row['ip']:18s} [{row['kind']}] E≈{row['priority']:.1f} unk={row['unknown']}{fold_note}")
            reasons = row.get("unresolved_reasons", {}) or {}
            if reasons:
                reason_text = ", ".join(f"{k}={v}" for k, v in sorted(reasons.items())[:4])
                print(f"      unresolved: {reason_text}")
            print(f"      measurement: compatibility={float(row.get('compatibility_score_mean', 0.0)):.3f} decoherence={float(row.get('decoherence_total', 0.0)):.3f}")
            print(f"      services: {services}")
            print(f"      domains : {domains}")
    print(f"    proposals: pending={backlog['pending_total']} toolchains={backlog['pending_toolchain_generation']} growth={backlog['pending_catalog_growth']} actions={backlog['pending_field_action']} errors={backlog['error_total']}")


def _load_recall_summary(target_filter: str | None = None, limit: int = 8) -> dict:
    records_path = SKG_STATE_DIR / "resonance" / "records" / "observations.jsonl"
    pending_path = SKG_STATE_DIR / "resonance" / "records" / "observations_pending.jsonl"

    records = []
    pending = 0

    def _matches(rec: dict) -> bool:
        if not target_filter:
            return True
        wid = str(rec.get("workload_id", ""))
        cond = str(rec.get("wicket_id", ""))
        evidence = str(rec.get("evidence_text", ""))
        return target_filter in wid or target_filter in cond or target_filter in evidence

    if pending_path.exists():
        for line in pending_path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if _matches(rec):
                pending += 1

    if records_path.exists():
        for line in records_path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if _matches(rec):
                records.append(rec)

    confirmed = [r for r in records if r.get("projection_confirmed") is not None]
    realized = [r for r in confirmed if r.get("projection_confirmed") == "realized"]

    by_domain = {}
    for rec in confirmed:
        dom = rec.get("domain") or "unknown"
        stats = by_domain.setdefault(dom, {"confirmed": 0, "realized": 0})
        stats["confirmed"] += 1
        if rec.get("projection_confirmed") == "realized":
            stats["realized"] += 1

    domain_rates = []
    for dom, stats in by_domain.items():
        domain_rates.append({
            "domain": dom,
            "confirmed": stats["confirmed"],
            "realized": stats["realized"],
            "confirmation_rate": round(stats["realized"] / stats["confirmed"], 3) if stats["confirmed"] else None,
        })
    domain_rates.sort(key=lambda x: (x["confirmed"], x["realized"]), reverse=True)

    recent = sorted(confirmed, key=lambda r: r.get("ts", ""), reverse=True)[:limit]
    recent_view = [{
        "ts": rec.get("ts"),
        "workload_id": rec.get("workload_id"),
        "wicket_id": rec.get("wicket_id"),
        "domain": rec.get("domain"),
        "source_kind": rec.get("source_kind"),
        "projection_confirmed": rec.get("projection_confirmed"),
        "confidence_at_emit": rec.get("confidence_at_emit"),
        "evidence_text": (rec.get("evidence_text", "") or "")[:120],
    } for rec in recent]

    return {
        "count": len(records),
        "pending": pending,
        "confirmed": len(confirmed),
        "realized": len(realized),
        "confirmation_rate": round(len(realized) / len(confirmed), 3) if confirmed else None,
        "by_domain": domain_rates[:6],
        "recent": recent_view,
    }


def _pearl_brief(pearl: dict) -> str:
    state_changes = pearl.get("state_changes", []) or []
    reason_changes = pearl.get("reason_changes", []) or []
    projection_changes = pearl.get("projection_changes", []) or []
    target_snapshot = pearl.get("target_snapshot", {}) or {}
    fold_context = pearl.get("fold_context", []) or []

    if state_changes:
        first = state_changes[0]
        wid = first.get("wicket_id") or first.get("node_id") or "?"
        from_state = first.get("from") or first.get("from_state", "?")
        to_state = first.get("to") or first.get("to_state", "?")
        count = len(state_changes)
        return f"{wid} {from_state}->{to_state}" + (f" (+{count-1} more)" if count > 1 else "")
    if projection_changes:
        first = projection_changes[0]
        if first.get("kind") == "domain_shift":
            added = ", ".join(first.get("added", [])[:4]) or "none"
            removed = ", ".join(first.get("removed", [])[:4]) or "none"
            return f"domains +{added} -{removed}"
        if first.get("kind") == "service_shift":
            added = ", ".join(first.get("added", [])[:4]) or "none"
            return f"services +{added}"
        ap = first.get("attack_path_id", "?")
        cls = first.get("classification", "?")
        return f"{ap} => {cls}"
    if target_snapshot:
        props = _active_identity_properties(target_snapshot)
        if props:
            return f"identity {', '.join(props[:4])}"
    if fold_context:
        fold = fold_context[0]
        detail = fold.get("detail", "") or ""
        return detail[:72]
    if reason_changes:
        first = reason_changes[0]
        inst = first.get("instrument") or "instrument"
        success = "ok" if first.get("success") else "note"
        why = first.get("reason") or first.get("detail") or f"{inst} {success}"
        return str(why)[:72]
    return "state remembered"


def _active_identity_properties(snapshot: dict) -> list[str]:
    props = (snapshot or {}).get("identity_properties", {}) or {}
    return [k for k, v in props.items() if v is True]


def _fold_brief_why(fold: dict) -> str:
    why = fold.get("why", {}) or {}
    mismatch = why.get("mismatch")
    if mismatch == "observed_vulnerability_without_mapping":
        cve = why.get("cve_id", "?")
        svc = why.get("service", "?")
        return f"{cve} is observed on {svc}, but SKG has no wicket mapping"
    if mismatch in {"observed_service_implies_missing_toolchain", "observed_service_without_toolchain"}:
        svc = why.get("service", "?")
        return f"{svc} is observed, but SKG has no toolchain coverage for it"
    if mismatch == "observed_surface_implies_missing_path":
        ap = why.get("attack_path_id", "?")
        svc = why.get("service", "?")
        return f"{svc} suggests attack path {ap}, but SKG cannot yet express it"
    if mismatch == "recent_observation_implies_missing_path":
        ap = why.get("attack_path_id", "?")
        return f"recent observation suggests {ap}, but current structure is incomplete"
    if mismatch == "stale_realized_evidence":
        wid = why.get("wicket_id", "?")
        return f"{wid} was previously realized, but its evidence is now stale"
    detail = fold.get("detail", "") or ""
    return detail[:120]


def _describe_next_collapse(target: dict, folds: list[dict], proposals: list[dict]) -> str:
    pending = [p for p in proposals if p.get("status") == "pending"]
    if pending:
        first = pending[0]
        desc = first.get("description", "")[:110]
        if first.get("proposal_kind") == "toolchain_generation":
            return f"operator review of toolchain growth: {desc}"
        return f"operator review/action: {desc}"
    for fold in folds:
        for step in (fold.get("discriminators", []) or [])[:2]:
            if step:
                return step
    services = target.get("services", []) or []
    ports = {svc.get("port") for svc in services}
    names = {(svc.get("service") or "").lower() for svc in services}
    if any(p in {80, 443, 8080, 8443, 8008, 8009} for p in ports) or any(n in {"http", "https"} for n in names):
        return "collect deeper web evidence to collapse remaining WB-* uncertainty"
    if any(p in {22} for p in ports) or "host" in set(target.get("domains", []) or []):
        return "collect deeper host evidence to collapse remaining HO/FI/PI/LI uncertainty"
    if any(p in {3306, 5432, 6379, 27017} for p in ports) or "data_pipeline" in set(target.get("domains", []) or []):
        return "collect deeper data evidence to collapse remaining DP-* uncertainty"
    return "follow the highest-energy unresolved fold"


def _pearl_signature(pearl: dict) -> tuple:
    target_snapshot = pearl.get("target_snapshot", {}) or {}
    fold_context = pearl.get("fold_context", []) or []
    state_changes = pearl.get("state_changes", []) or []
    projection_changes = pearl.get("projection_changes", []) or []

    identity = tuple(sorted(_active_identity_properties(target_snapshot)[:6]))
    domains = tuple(sorted((target_snapshot.get("domains", []) or [])[:6]))
    services = tuple(
        sorted(
            f"{svc.get('port')}/{svc.get('service')}"
            for svc in (target_snapshot.get("services", []) or [])[:6]
        )
    )
    top_fold = ""
    if fold_context:
        top_fold = str((fold_context[0].get("why", {}) or {}).get("mismatch") or fold_context[0].get("fold_type") or "")
    state_shape = tuple(
        sorted(
            f"{change.get('wicket_id','?')}:{change.get('to') or change.get('to_state') or '?'}"
            for change in state_changes[:4]
        )
    )
    projection_shape = tuple(
        sorted(
            f"{change.get('kind','?')}:{','.join(change.get('added', [])[:4])}"
            for change in projection_changes[:4]
        )
    )
    return (identity, domains, services, top_fold, state_shape, projection_shape)


def _summarize_pearl_cluster(cluster: list[dict]) -> str:
    if not cluster:
        return ""
    first = cluster[-1]
    count = len(cluster)
    target_snapshot = first.get("target_snapshot", {}) or {}
    fold_context = first.get("fold_context", []) or []
    projection_changes = first.get("projection_changes", []) or []
    state_changes = first.get("state_changes", []) or []

    if state_changes:
        return _pearl_brief(first) + (f" x{count}" if count > 1 else "")
    if projection_changes:
        return _pearl_brief(first) + (f" x{count}" if count > 1 else "")
    if fold_context:
        return _fold_brief_why(fold_context[0])[:96] + (f" x{count}" if count > 1 else "")
    if target_snapshot:
        props = _active_identity_properties(target_snapshot)
        if props:
            return f"identity stabilized around {', '.join(props[:4])}" + (f" x{count}" if count > 1 else "")
    return _pearl_brief(first) + (f" x{count}" if count > 1 else "")


def _cluster_pearls(pearls: list[dict], limit: int = 5) -> list[dict]:
    clusters = []
    current = []
    current_sig = None
    for pearl in pearls:
        sig = _pearl_signature(pearl)
        if current and sig != current_sig:
            clusters.append({
                "count": len(current),
                "start_ts": current[0].get("timestamp"),
                "end_ts": current[-1].get("timestamp"),
                "summary": _summarize_pearl_cluster(current),
            })
            current = []
        current.append(pearl)
        current_sig = sig
    if current:
        clusters.append({
            "count": len(current),
            "start_ts": current[0].get("timestamp"),
            "end_ts": current[-1].get("timestamp"),
            "summary": _summarize_pearl_cluster(current),
        })
    return clusters[-limit:]


def _parse_report_timestamp(raw: str | None):
    if not raw:
        return None
    try:
        from datetime import datetime, timezone
        ts = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except Exception:
        return None


def _load_target_snapshot_from_pearls(target_filter: str, at_ts=None) -> dict | None:
    pearls_path = SKG_STATE_DIR / "pearls.jsonl"
    if not pearls_path.exists() or not target_filter:
        return None
    chosen = None
    chosen_ts = None
    for line in pearls_path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            pearl = json.loads(line)
        except Exception:
            continue
        snap = pearl.get("target_snapshot", {}) or {}
        target_ip = snap.get("ip") or pearl.get("energy_snapshot", {}).get("target_ip")
        if target_ip != target_filter:
            continue
        ts = _parse_report_timestamp(pearl.get("timestamp"))
        if at_ts and (ts is None or ts > at_ts):
            continue
        if chosen_ts is None or (ts and ts > chosen_ts):
            chosen = pearl
            chosen_ts = ts
    return chosen


def _diff_target_snapshots(before: dict, after: dict) -> dict:
    if not before or not after:
        return {}
    before_services = {(svc.get("port"), svc.get("service")) for svc in before.get("services", [])}
    after_services = {(svc.get("port"), svc.get("service")) for svc in after.get("services", [])}
    before_domains = set(before.get("domains", []) or [])
    after_domains = set(after.get("domains", []) or [])
    before_props = before.get("identity_properties", {}) or {}
    after_props = after.get("identity_properties", {}) or {}
    prop_changes = []
    for key in sorted(set(before_props) | set(after_props)):
        if before_props.get(key) != after_props.get(key):
            prop_changes.append({
                "property": key,
                "before": before_props.get(key),
                "after": after_props.get(key),
            })
    return {
        "domains_added": sorted(after_domains - before_domains),
        "domains_removed": sorted(before_domains - after_domains),
        "services_added": [f"{p}/{s}" for p, s in sorted(after_services - before_services)],
        "services_removed": [f"{p}/{s}" for p, s in sorted(before_services - after_services)],
        "property_changes": prop_changes,
    }


def _infer_identity_properties_from_target(target: dict) -> dict:
    services = target.get("services", []) or []
    domains = set(target.get("domains", []) or [])
    ports = {svc.get("port") for svc in services}
    names = {(svc.get("service") or "").lower() for svc in services}
    return {
        "externally_observable_only": bool(services) and not any(p in {22, 139, 445, 3306, 5432} for p in ports),
        "network_reachable_only": (target.get("kind") or target.get("os")) == "external-web",
        "host_semantics_unconfirmed": 22 not in ports and "host" not in domains,
        "container_semantics_present": "container_escape" in domains,
        "data_semantics_present": "data_pipeline" in domains or any(p in {3306, 5432, 6379, 27017} for p in ports),
        "interactive_surface_present": any(p in {80, 443, 8080, 8443, 8008, 8009} for p in ports),
        "auth_surface_present": any("auth" in n or p in {22, 443} for n, p in [(svc.get("service", "").lower(), svc.get("port")) for svc in services]),
        "service_names": sorted(n for n in names if n),
    }


def _print_substrate_self_audit():
    print("  Substrate Self-Audit:")

    resonance = _api("GET", "/resonance/status") or {}
    feedback = _api("GET", "/feedback/status") or {}
    graph = _api("GET", "/graph/status") or {}
    folds = _api("GET", "/folds") or {}
    ollama = _api("GET", "/resonance/ollama/status") or {}

    resonance_memory = resonance.get("memory", {})
    observations = resonance_memory.get("observations") or {}
    pending_obs = observations.get("pending_observations", 0)
    confirmation_rate = observations.get("confirmation_rate")
    confirmation_display = "n/a" if confirmation_rate is None else f"{confirmation_rate:.3f}"

    if resonance:
        print(f"    resonance.ready        : {'yes' if resonance.get('ready') else 'no'}")
        print(f"    resonance.memory       : wickets={resonance_memory.get('wickets', 0)} adapters={resonance_memory.get('adapters', 0)} domains={resonance_memory.get('domains', 0)}")
    else:
        print("    resonance.ready        : offline")

    print(f"    observations.pending   : {pending_obs}")
    print(f"    recall.confirmation    : {confirmation_display}")

    if feedback:
        print(f"    feedback.processed     : {feedback.get('processed_interps', 0)}")
        print(f"    feedback.last_run      : {feedback.get('last_run') or 'never'}")
    else:
        print("    feedback.status        : offline")

    if graph:
        edge_count = graph.get("edge_count", graph.get("edges", "?"))
        node_count = graph.get("node_count", graph.get("nodes", "?"))
        print(f"    graph.state            : nodes={node_count} edges={edge_count}")

    fold_summary = _choose_fold_summary(folds)
    print(f"    folds.active           : {fold_summary.get('total', 0)}")
    by_type = fold_summary.get("by_type", {})
    if by_type:
        print("    folds.by_type          : " + ", ".join(f"{k}={v}" for k, v in sorted(by_type.items())))

    backlog = _proposal_backlog()
    print(f"    proposals.pending      : {backlog['pending_total']}")
    print(f"    proposals.toolchains   : {backlog['pending_toolchain_generation']}")
    print(f"    proposals.growth       : {backlog['pending_catalog_growth']}")
    print(f"    proposals.actions      : {backlog['pending_field_action']}")
    print(f"    proposals.errors       : {backlog['error_total']}")

    pearls_path = SKG_STATE_DIR / "pearls.jsonl"
    if pearls_path.exists():
        try:
            pearl_count = sum(1 for line in pearls_path.read_text(errors='replace').splitlines() if line.strip())
        except Exception:
            pearl_count = "?"
        print(f"    pearls.persisted       : {pearl_count}")
    else:
        print("    pearls.persisted       : 0 (ledger not yet persisted)")

    if ollama:
        models = ollama.get("models", [])
        selected = ollama.get("selected_model") or "(none)"
        available = "yes" if ollama.get("available") else "no"
        models_display = ", ".join(models[:3]) if models else "none"
        print(f"    ollama.available       : {available}")
        print(f"    ollama.selected        : {selected}")
        print(f"    ollama.models          : {models_display}")
    else:
        print("    ollama.status          : offline")


def _build_substrate_self_audit() -> dict:
    resonance = _api("GET", "/resonance/status") or {}
    feedback = _api("GET", "/feedback/status") or {}
    graph = _api("GET", "/graph/status") or {}
    folds = _api("GET", "/folds") or {}
    ollama = _api("GET", "/resonance/ollama/status") or {}
    fold_summary = _choose_fold_summary(folds)
    backlog = _proposal_backlog()
    pearls_path = SKG_STATE_DIR / "pearls.jsonl"
    pearl_count = 0
    if pearls_path.exists():
        try:
            pearl_count = sum(1 for line in pearls_path.read_text(errors='replace').splitlines() if line.strip())
        except Exception:
            pearl_count = 0
    return {
        "resonance": resonance,
        "feedback": feedback,
        "graph": graph,
        "folds": fold_summary,
        "proposals": backlog,
        "pearls": {"persisted": pearl_count},
        "ollama": ollama,
    }

"""
skg :: gravity.py

Semantic Kernel Gravity — the self-directing reasoning loop.

This version fixes three core runtime issues:
  1. Surface refresh: each cycle can reload the latest surface snapshot
  2. Target scoping: gravity can operate on a single requested target
  3. Authorization boundary: exploit-capable actions are gated
"""

import json
import sys
import time
import uuid
import glob
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# Add web collector to path
WEB_ADAPTER_PATH = Path("/opt/skg/skg-web-toolchain/adapters/web_active")
if WEB_ADAPTER_PATH.exists():
    sys.path.insert(0, str(WEB_ADAPTER_PATH))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Helpers ─────────────────────────────────────────────────────────────

def latest_surface_path(discovery_dir: str = "/var/lib/skg/discovery") -> str | None:
    surfaces = glob.glob(f"{discovery_dir}/surface_*.json")
    if not surfaces:
        return None
    return max(surfaces, key=lambda p: Path(p).stat().st_mtime)


def load_surface(surface_path: str | None = None,
                 discovery_dir: str = "/var/lib/skg/discovery") -> tuple[dict, str]:
    """
    Load a surface snapshot. If surface_path is None, uses the latest surface.
    Returns (surface_dict, resolved_path).
    """
    resolved = surface_path or latest_surface_path(discovery_dir)
    if not resolved:
        raise FileNotFoundError("No surface_*.json found in discovery directory")
    return json.loads(Path(resolved).read_text()), resolved


def filter_surface_to_target(surface: dict, target_ip: str | None) -> dict:
    """
    Return a copy of the surface limited to a single target if target_ip is set.
    """
    if not target_ip:
        return surface

    filtered = dict(surface)
    filtered_targets = [t for t in surface.get("targets", []) if t.get("ip") == target_ip]
    filtered["targets"] = filtered_targets
    return filtered


def action_class(strategy: str) -> str:
    """
    Coarse action classes for authorization policy.
    """
    mapping = {
        "403_no_forms": "passive",
        "spa_no_forms": "passive",
        "no_injection_tested": "active_validation",
        "service_version_known": "passive",
        "metasploit_aux": "exploit_capable",
        "metasploit_exploit": "exploit_capable",
    }
    return mapping.get(strategy, "passive")


def action_authorized(strategy: str,
                      authorized_actions: set[str] | None = None,
                      allow_exploit: bool = False) -> bool:
    """
    Determine whether an action is authorized to execute.
    """
    cls = action_class(strategy)
    if cls != "exploit_capable":
        return True
    if allow_exploit:
        return True
    if authorized_actions and strategy in authorized_actions:
        return True
    return False


# ── Catalog loader ───────────────────────────────────────────────────────

def load_all_catalogs() -> dict:
    """Load all toolchain catalogs from /opt/skg/."""
    catalogs = {}
    for catalog_file in glob.glob("/opt/skg/skg-*-toolchain/contracts/catalogs/*.json"):
        try:
            data = json.loads(Path(catalog_file).read_text())
            domain = data.get("domain", Path(catalog_file).stem)
            catalogs[domain] = data
        except Exception:
            continue
    return catalogs


def wicket_criticality(catalogs: dict) -> dict:
    """
    Compute criticality score for each wicket — how many attack paths
    it gates across all domains.
    """
    scores = defaultdict(int)
    for _, catalog in catalogs.items():
        for _, ap in catalog.get("attack_paths", {}).items():
            for wid in ap.get("required_wickets", []):
                scores[wid] += 1
    return dict(scores)


# ── Gravity computation ──────────────────────────────────────────────────

def compute_target_gravity(target: dict, criticality: dict) -> dict:
    wicket_states = target.get("wicket_states", {})
    unknowns = [wid for wid, state in wicket_states.items() if state == "unknown"]
    realized = [wid for wid, state in wicket_states.items() if state == "realized"]
    blocked = [wid for wid, state in wicket_states.items() if state == "blocked"]

    unknown_gravity = sum(criticality.get(wid, 1) for wid in unknowns)
    partial_bonus = len(realized) * 0.5 if realized and unknowns else 0
    path_count = len(target.get("attack_paths", []))
    path_factor = 1.0 + (path_count / 10.0)

    total_gravity = (unknown_gravity + partial_bonus) * path_factor

    return {
        "ip": target["ip"],
        "gravity": round(total_gravity, 2),
        "unknowns": len(unknowns),
        "realized": len(realized),
        "blocked": len(blocked),
        "path_count": path_count,
        "unknown_wickets": unknowns,
        "realized_wickets": realized,
        "domains": target.get("domains", []),
        "services": target.get("services", []),
    }


# ── Gap analysis ─────────────────────────────────────────────────────────

RESOLUTION_STRATEGIES = {
    "403_no_forms": {
        "description": "Root returns 403/forbidden — try alternate entry points",
        "actions": [
            {"type": "probe_paths", "paths": [
                "/login", "/login.php", "/login.html", "/signin",
                "/ui/login", "/ui", "/app", "/index.html",
                "/api/v1", "/api/v2", "/api", "/graphql",
                "/console", "/dashboard", "/portal",
                "/wp-login.php", "/user/login", "/auth/login",
                "/Account/Login", "/_login", "/sign-in",
            ]},
        ],
    },
    "spa_no_forms": {
        "description": "SPA detected (301 redirect, minimal HTML) — JavaScript renders the UI",
        "actions": [
            {"type": "probe_paths", "paths": [
                "/api", "/api/v1", "/api/v2", "/graphql",
                "/api/auth/login", "/api/login", "/api/session",
                "/auth", "/oauth", "/token",
            ]},
            {"type": "probe_api", "methods": ["GET", "POST", "OPTIONS"]},
        ],
    },
    "no_injection_tested": {
        "description": "No forms or parameters found to test injection against",
        "actions": [
            {"type": "param_discovery", "techniques": [
                "common_params",
                "path_params",
            ]},
        ],
    },
    "service_version_known": {
        "description": "Service version identified — check CVE database",
        "actions": [
            {"type": "cve_lookup"},
        ],
    },
}

COMMON_PARAMS = [
    ("id", "1"), ("page", "1"), ("search", "test"), ("q", "test"),
    ("user", "admin"), ("name", "test"), ("file", "index"),
    ("cat", "1"), ("dir", ""), ("action", "view"),
    ("type", "1"), ("lang", "en"), ("url", "http://localhost"),
    ("redirect", "/"), ("next", "/"), ("return", "/"),
    ("cmd", "id"), ("exec", "id"), ("command", "ls"),
    ("ping", "127.0.0.1"), ("query", "test"), ("item", "1"),
]


def _get_wicket_detail(wicket_states: dict, wid: str) -> str:
    val = wicket_states.get(wid, "")
    if isinstance(val, dict):
        return val.get("detail", "")
    return ""


def _load_event_details(ip: str, discovery_dir: str = "/var/lib/skg/discovery") -> dict:
    """
    Load wicket details from event NDJSON files for a target IP.
    Merges both web_events_* and gravity_* streams. Latest observation wins.
    """
    details = {}

    patterns = [
        f"{discovery_dir}/web_events_{ip}_*.ndjson",
        f"{discovery_dir}/gravity_http_{ip}_*.ndjson",
        f"{discovery_dir}/gravity_auth_{ip}_*.ndjson",
        f"{discovery_dir}/gravity_events_{ip}_*.ndjson",
    ]

    files = []
    for pat in patterns:
        files.extend(glob.glob(pat))
    files = sorted(set(files), key=lambda p: Path(p).stat().st_mtime)

    latest_ts = {}
    for ef in files:
        try:
            with open(ef) as f:
                for line in f:
                    event = json.loads(line.strip())
                    payload = event.get("payload", {})
                    wid = payload.get("wicket_id")
                    if not wid:
                        continue
                    ts = event.get("ts", "")
                    if wid in latest_ts and ts <= latest_ts[wid]:
                        continue
                    latest_ts[wid] = ts
                    details[wid] = {
                        "status": payload.get("status", "unknown"),
                        "detail": payload.get("detail", ""),
                        "ts": ts,
                        "source_file": ef,
                    }
        except Exception:
            continue
    return details


def analyze_gaps(target_gravity: dict, wicket_states: dict, service_info: list) -> list:
    actions = []
    unknowns = set(target_gravity["unknown_wickets"])
    ip = target_gravity["ip"]

    event_details = _load_event_details(ip)

    def get_detail(wid):
        if wid in event_details:
            return event_details[wid].get("detail", "")
        return _get_wicket_detail(wicket_states, wid)

    wb01_detail = get_detail("WB-01")
    wb06_detail = get_detail("WB-06")
    wb09_detail = get_detail("WB-09")

    if "403" in str(wb01_detail) and "WB-06" in unknowns:
        actions.append({
            "strategy": "403_no_forms",
            "target": ip,
            "priority": "high",
            "reason": "Root returns 403, need to find alternate entry points",
            **RESOLUTION_STRATEGIES["403_no_forms"],
        })
    elif "301" in str(wb01_detail) and "WB-06" in unknowns:
        actions.append({
            "strategy": "spa_no_forms",
            "target": ip,
            "priority": "high",
            "reason": "SPA detected — API endpoints may exist behind the redirect",
            **RESOLUTION_STRATEGIES["spa_no_forms"],
        })
    elif "WB-06" in unknowns and ("200" in str(wb01_detail) or "realized" in str(wicket_states.get("WB-01", ""))):
        actions.append({
            "strategy": "403_no_forms",
            "target": ip,
            "priority": "medium",
            "reason": "Service reachable but login form not found — try alternate paths",
            **RESOLUTION_STRATEGIES["403_no_forms"],
        })

    if "WB-09" in unknowns and "0 forms" in str(wb09_detail):
        actions.append({
            "strategy": "no_injection_tested",
            "target": ip,
            "priority": "medium",
            "reason": "No input surfaces found — need parameter discovery",
            **RESOLUTION_STRATEGIES["no_injection_tested"],
        })

    for svc in service_info:
        banner = svc.get("banner", "")
        if any(c.isdigit() for c in banner):
            actions.append({
                "strategy": "service_version_known",
                "target": ip,
                "priority": "medium",
                "reason": f"Service version identified: {banner[:60]}",
                "service": svc,
                **RESOLUTION_STRATEGIES["service_version_known"],
            })

    return actions


# ── Action execution ─────────────────────────────────────────────────────

def execute_probe_paths(transport, base_url: str, paths: list,
                        out_path: Path, attack_path_id: str,
                        run_id: str, workload_id: str) -> list:
    from collector import emit, parse_html

    findings = []
    for path in paths:
        url = base_url.rstrip("/") + path
        resp = transport.request("GET", url)

        if resp.error or resp.status in (0, 404):
            continue

        if resp.status in (200, 301, 302):
            parsed = parse_html(resp.text)
            if parsed.forms:
                for form in parsed.forms:
                    has_password = any(i["type"] == "password" for i in form["inputs"])
                    findings.append({
                        "path": path,
                        "status": resp.status,
                        "forms": len(parsed.forms),
                        "has_login": has_password,
                        "inputs": [i["name"] for i in form["inputs"] if i["name"]],
                    })

                if any(f["has_login"] for f in findings):
                    emit(out_path, "WB-06", "realized", 1, "runtime",
                         url, 0.9,
                         attack_path_id, run_id, workload_id,
                         {"detail": f"Login form found at {path}"})

            ct = resp.header("content-type", "")
            if "json" in ct or "api" in path:
                findings.append({
                    "path": path,
                    "status": resp.status,
                    "type": "api",
                    "content_type": ct,
                    "preview": resp.text[:200],
                })
                emit(out_path, "WB-23", "realized", 1, "runtime",
                     url, 0.8,
                     attack_path_id, run_id, workload_id,
                     {"detail": f"API endpoint found: {path} ({ct})"})

    return findings


def execute_param_discovery(transport, base_url: str,
                            out_path: Path, attack_path_id: str,
                            run_id: str, workload_id: str) -> list:
    from collector import emit, SQLI_ERROR_PATTERNS

    findings = []
    base = base_url.rstrip("/")

    for param_name, param_value in COMMON_PARAMS:
        url = f"{base}/?{param_name}={param_value}"
        resp = transport.request("GET", url)
        if resp.error or resp.status in (0, 404):
            continue

        sqli_url = f"{base}/?{param_name}={param_value}'"
        sqli_resp = transport.request("GET", sqli_url)
        if sqli_resp.error:
            continue

        for pat in SQLI_ERROR_PATTERNS:
            if pat.search(sqli_resp.text):
                findings.append({
                    "param": param_name,
                    "type": "sqli_error",
                    "url": sqli_url,
                })
                emit(out_path, "WB-09", "realized", 1, "runtime",
                     sqli_url, 0.85,
                     attack_path_id, run_id, workload_id,
                     {"detail": f"SQLi via discovered param {param_name}"})
                break

        if not findings or findings[-1].get("param") != param_name:
            true_url = f"{base}/?{param_name}={param_value}' OR '1'='1"
            false_url = f"{base}/?{param_name}={param_value}' OR '1'='2"
            resp_t = transport.request("GET", true_url)
            resp_f = transport.request("GET", false_url)
            if (not resp_t.error and not resp_f.error and
                    abs(len(resp_t.body) - len(resp_f.body)) > 50):
                findings.append({
                    "param": param_name,
                    "type": "sqli_boolean",
                    "url": true_url,
                    "diff": abs(len(resp_t.body) - len(resp_f.body)),
                })

    return findings


# ── Gravity loop ─────────────────────────────────────────────────────────

def gravity_cycle(surface_path: str | None,
                  out_dir: str,
                  cycle_num: int = 1,
                  proxy: str = None,
                  target_ip: str | None = None,
                  discovery_dir: str = "/var/lib/skg/discovery",
                  allow_exploit: bool = False,
                  authorized_actions: set[str] | None = None) -> dict:
    """
    One cycle of the gravity loop: observe → orient → decide → act.
    Reloads the latest surface at the start of each cycle.
    """
    surface, resolved_surface_path = load_surface(surface_path, discovery_dir=discovery_dir)
    surface = filter_surface_to_target(surface, target_ip)

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())

    catalogs = load_all_catalogs()
    criticality = wicket_criticality(catalogs)

    print(f"\n{'='*70}")
    print(f"  GRAVITY CYCLE {cycle_num}")
    print(f"  Run: {run_id[:8]}")
    print(f"  Time: {iso_now()}")
    print(f"  Surface: {resolved_surface_path}")
    if target_ip:
        print(f"  Target scope: {target_ip}")
    print(f"{'='*70}\n")

    print("[OBSERVE] Computing gravitational field...")
    gravity_map = []
    for target in surface.get("targets", []):
        g = compute_target_gravity(target, criticality)
        gravity_map.append(g)

    gravity_map.sort(key=lambda x: x["gravity"], reverse=True)

    print()
    print("  Target Gravity Map:")
    print(f"  {'IP':18s} {'Gravity':>8s} {'Unknown':>8s} {'Realized':>8s} {'Paths':>6s}  Domains")
    print(f"  {'-'*18} {'-'*8} {'-'*8} {'-'*8} {'-'*6}  {'-'*20}")
    for g in gravity_map:
        domains = ", ".join(g["domains"])
        print(f"  {g['ip']:18s} {g['gravity']:8.1f} {g['unknowns']:8d} "
              f"{g['realized']:8d} {g['path_count']:6d}  {domains}")
    print()

    print("[ORIENT] Analyzing gaps on highest-gravity targets...")
    all_actions = []

    focus_targets = gravity_map if target_ip else gravity_map[:5]

    for g in focus_targets:
        if g["gravity"] == 0:
            continue

        wicket_states = {}
        services = []
        for t in surface.get("targets", []):
            if t["ip"] == g["ip"]:
                wicket_states = t.get("wicket_states", {})
                services = t.get("services", [])
                break

        actions = analyze_gaps(g, wicket_states, services)
        if actions:
            print(f"\n  {g['ip']} (gravity: {g['gravity']}):")
            for a in actions:
                print(f"    [{a['priority']:6s}] {a['strategy']}: {a['reason']}")
            all_actions.extend(actions)

    if not all_actions:
        print("  No actionable gaps found — surface is as mapped as current tools allow.")
        return {"cycle": cycle_num, "actions_taken": 0, "gravity_map": gravity_map}

    print(f"\n[DECIDE] {len(all_actions)} actions identified.")

    priority_order = {"high": 0, "medium": 1, "low": 2}
    all_actions.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 3))

    print("[ACT] Executing resolution strategies...\n")
    actions_taken = 0
    blocked_actions = []

    try:
        from transport import HttpTransport
    except ImportError:
        print("  [!] Web transport not available — cannot execute probes")
        return {"cycle": cycle_num, "actions_taken": 0, "gravity_map": gravity_map}

    for action in all_actions:
        ip = action["target"]
        strategy = action["strategy"]

        if not action_authorized(strategy, authorized_actions=authorized_actions, allow_exploit=allow_exploit):
            print(f"  [{strategy}] → {ip}")
            print("    Authorization required: exploit-capable action not approved")
            blocked_actions.append({
                "target": ip,
                "strategy": strategy,
                "class": action_class(strategy),
            })
            continue

        web_port = None
        web_scheme = "http"
        for t in surface.get("targets", []):
            if t["ip"] == ip:
                for svc in t.get("services", []):
                    if svc["service"] in ("http", "https", "http-alt", "https-alt"):
                        web_port = svc["port"]
                        if "https" in svc["service"]:
                            web_scheme = "https"
                        break
                break

        if not web_port:
            continue

        base_url = f"{web_scheme}://{ip}:{web_port}"
        events_file = out_path / f"gravity_events_{ip}_{web_port}.ndjson"
        transport = HttpTransport(proxy=proxy, timeout=8.0)
        workload_id = f"web::{ip}:{web_port}"

        print(f"  [{strategy}] → {base_url}")

        if strategy in ("403_no_forms", "spa_no_forms"):
            probe_paths = []
            for act in action.get("actions", []):
                if act["type"] == "probe_paths":
                    probe_paths = act["paths"]

            findings = execute_probe_paths(
                transport, base_url, probe_paths,
                events_file, "web_sqli_to_shell_v1",
                run_id, workload_id
            )

            if findings:
                print(f"    Found {len(findings)} entry points:")
                for f in findings[:5]:
                    detail = f"login={f.get('has_login', False)}" if "has_login" in f else f.get("type", "")
                    print(f"      {f['path']} — {detail}")
                actions_taken += 1

                login_paths = [f["path"] for f in findings if f.get("has_login")]
                if login_paths:
                    print("    Deepening: testing injection on discovered forms...")
                    try:
                        from collector import phase4_inject, parse_html
                        from urllib.parse import urljoin

                        for lp in login_paths[:3]:
                            url = base_url.rstrip("/") + lp
                            resp = transport.request("GET", url)
                            if not resp.error:
                                parsed = parse_html(resp.text)
                                if parsed.forms:
                                    for form in parsed.forms:
                                        form["page"] = url
                                        action_url = form.get("action", "")
                                        form["resolved_action"] = urljoin(url, action_url) if action_url else url

                                    ctx = {
                                        "base_url": base_url,
                                        "forms": parsed.forms,
                                        "links": [],
                                        "params": [],
                                        "login_found": True,
                                        "api_endpoints": [],
                                    }
                                    phase4_inject(
                                        transport, ctx, events_file,
                                        "web_sqli_to_shell_v1",
                                        run_id, workload_id
                                    )
                                    actions_taken += 1
                    except Exception as e:
                        print(f"    [!] Deepening failed: {e}")

            else:
                print(f"    No new entry points found on {len(probe_paths)} probed paths")

        elif strategy == "no_injection_tested":
            findings = execute_param_discovery(
                transport, base_url,
                events_file, "web_sqli_to_shell_v1",
                run_id, workload_id
            )
            if findings:
                print(f"    Found {len(findings)} injectable parameters:")
                for f in findings[:5]:
                    print(f"      ?{f['param']} — {f['type']}")
                actions_taken += 1
            else:
                print("    No injectable parameters discovered")

        elif strategy == "service_version_known":
            svc = action.get("service", {})
            banner = svc.get("banner", "")
            print(f"    Service: {banner}")
            print("    [TODO] CVE lookup requires NVD API key — flagging for feed pipeline")
            actions_taken += 1

    print(f"\n{'='*70}")
    print(f"  CYCLE {cycle_num} COMPLETE")
    print(f"  Actions executed: {actions_taken}")
    if blocked_actions:
        print(f"  Actions awaiting authorization: {len(blocked_actions)}")
    print(f"  New events in: {out_path}/gravity_events_*.ndjson")
    print(f"{'='*70}\n")

    return {
        "cycle": cycle_num,
        "actions_taken": actions_taken,
        "blocked_actions": blocked_actions,
        "gravity_map": [{"ip": g["ip"], "gravity": g["gravity"],
                         "unknowns": g["unknowns"], "realized": g["realized"]}
                        for g in gravity_map],
        "actions": [{"target": a["target"], "strategy": a["strategy"],
                     "priority": a["priority"]} for a in all_actions],
        "surface_path": resolved_surface_path,
        "target_scope": target_ip,
    }


def gravity_loop(surface_path: str | None,
                 out_dir: str,
                 max_cycles: int = 3,
                 proxy: str = None,
                 target_ip: str | None = None,
                 discovery_dir: str = "/var/lib/skg/discovery",
                 allow_exploit: bool = False,
                 authorized_actions: set[str] | None = None):
    """
    Run multiple gravity cycles until no further actions are available.
    Reloads the latest surface each cycle.
    """
    print("[SKG-GRAVITY] Starting gravity loop")
    if surface_path:
        print(f"[SKG-GRAVITY] Initial surface: {surface_path}")
    else:
        print("[SKG-GRAVITY] Initial surface: auto")
    print(f"[SKG-GRAVITY] Max cycles: {max_cycles}")
    if target_ip:
        print(f"[SKG-GRAVITY] Target scope: {target_ip}")

    for i in range(1, max_cycles + 1):
        result = gravity_cycle(
            surface_path=surface_path,
            out_dir=out_dir,
            cycle_num=i,
            proxy=proxy,
            target_ip=target_ip,
            discovery_dir=discovery_dir,
            allow_exploit=allow_exploit,
            authorized_actions=authorized_actions,
        )

        surface_path = latest_surface_path(discovery_dir) or surface_path

        if result["actions_taken"] == 0 and not result.get("blocked_actions"):
            print(f"\n[SKG-GRAVITY] Surface stabilized after {i} cycles — no further actions available.")
            break

        if i < max_cycles:
            print("[SKG-GRAVITY] Pausing 2s before next cycle...")
            time.sleep(2)

    print("\n[SKG-GRAVITY] Loop complete.")


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SKG Gravity Engine — self-directing attack surface reasoning")
    parser.add_argument("--surface", default=None,
                        help="Path to surface JSON from discovery")
    parser.add_argument("--auto", action="store_true",
                        help="Find the latest surface file automatically")
    parser.add_argument("--cycles", type=int, default=3,
                        help="Max gravity cycles (default: 3)")
    parser.add_argument("--proxy", default=None,
                        help="Proxy for web probes")
    parser.add_argument("--out-dir", dest="out_dir",
                        default="/var/lib/skg/discovery",
                        help="Output directory")
    parser.add_argument("--target-ip", dest="target_ip", default=None,
                        help="Restrict gravity to a single target IP")
    parser.add_argument("--allow-exploit", action="store_true",
                        help="Allow exploit-capable actions if present")
    parser.add_argument("--authorize-action", action="append", default=[],
                        help="Authorize a specific action strategy by name")
    args = parser.parse_args()

    surface_path = args.surface
    if args.auto or not surface_path:
        surface_path = latest_surface_path(args.out_dir)
        if not surface_path:
            print("[!] No surface files found. Run discovery first.")
            sys.exit(1)
        print(f"[SKG-GRAVITY] Using latest surface: {surface_path}")

    gravity_loop(
        surface_path,
        args.out_dir,
        max_cycles=args.cycles,
        proxy=args.proxy,
        target_ip=args.target_ip,
        discovery_dir=args.out_dir,
        allow_exploit=args.allow_exploit,
        authorized_actions=set(args.authorize_action or []),
    )


if __name__ == "__main__":
    main()

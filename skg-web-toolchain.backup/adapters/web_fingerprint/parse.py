#!/usr/bin/env python3
"""
adapter: web_fingerprint
========================
Evaluates web collection data against web wickets.
Consumes output from skg.sensors.web_sensor.collect_target().

Input: collection dict (in-memory) or JSON file via --in flag.
Output: NDJSON obs.attack.precondition events.

All 20 web wickets evaluated per target.
"""
import argparse, json, re, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN = "skg-web-toolchain"
SOURCE_ID = "adapter.web_fingerprint"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

SENSITIVE_PATHS = {
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local",
    "/.env.production", "/backup.zip", "/backup.tar.gz",
    "/db.sql", "/dump.sql", "/id_rsa", "/id_ecdsa", "/.htpasswd",
}

ADMIN_PATHS = {
    "/admin", "/admin/", "/administrator", "/wp-admin", "/wp-login.php",
    "/manager/html", "/manager/text", "/console", "/jmx-console",
    "/web-console", "/jenkins", "/jenkins/", "/grafana/login",
    "/kibana", "/phpmyadmin", "/pma", "/adminer", "/adminer.php",
    "/script", "/scriptText",
}

API_DOC_PATHS = {
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/swagger.json", "/openapi.json", "/api-docs",
}

DEBUG_PATHS = {
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/beans",
    "/metrics", "/server-status", "/server-info", "/nginx_status",
    "/_cat", "/_cat/indices", "/_cluster/health",
    "/v1/sys/health", "/v1/catalog/services",
}

CMS_TECHS = {"wordpress", "drupal", "joomla"}


def get_version() -> str:
    return VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path, wicket_id, status, evidence_rank,
         evidence_source_kind, pointer, confidence,
         attack_path_id, run_id, workload_id, extra_payload=None):
    now = iso_now()
    event = {
        "id": str(uuid.uuid4()), "ts": now,
        "type": "obs.attack.precondition",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN,
                   "version": get_version()},
        "payload": {"wicket_id": wicket_id, "status": status,
                    "attack_path_id": attack_path_id, "run_id": run_id,
                    "workload_id": workload_id, **(extra_payload or {})},
        "provenance": {"evidence_rank": evidence_rank,
                       "evidence": {"source_kind": evidence_source_kind,
                                    "pointer": pointer, "collected_at": now,
                                    "confidence": confidence}},
    }
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def _hit_paths(probe_hits: list[dict]) -> set[str]:
    return {h["path"] for h in probe_hits if h.get("status") not in (404, None)}


def _hit_200(probe_hits: list[dict]) -> set[str]:
    return {h["path"] for h in probe_hits if h.get("status") == 200}


# ---------------------------------------------------------------------------
# Check functions — one per wicket
# ---------------------------------------------------------------------------

def check_WB_01(c, out, apid, run_id, wid):
    """WB-01: web_reachable"""
    status = "realized" if c.get("reachable") else "blocked"
    sc = c.get("status_code", "")
    emit(out, "WB-01", status, 3, "http_request", f"root_get:{sc}",
         0.99, apid, run_id, wid,
         {"detail": f"HTTP {sc} from {c.get('url','')}"})


def check_WB_02(c, out, apid, run_id, wid):
    """WB-02: server_version_leaked"""
    server = c.get("server_header", "")
    # Realized if Server header has version component
    has_version = bool(re.search(r"/[\d.]+", server))
    status = "realized" if (server and has_version) else \
             "blocked" if not server else "unknown"
    emit(out, "WB-02", status, 3, "response_header", "Server",
         0.95, apid, run_id, wid,
         {"detail": server or "header absent"})


def check_WB_03(c, out, apid, run_id, wid):
    """WB-03: stack_leaked"""
    leaky = c.get("leaky_headers", {})
    powered_by = leaky.get("X-Powered-By", "")
    aspnet     = leaky.get("X-AspNet-Version", "")
    if powered_by or aspnet:
        status = "realized"
        detail = powered_by or aspnet
    else:
        status = "blocked"
        detail = "no stack-leaking headers"
    emit(out, "WB-03", status, 3, "response_header", "X-Powered-By",
         0.95, apid, run_id, wid, {"detail": detail})


def check_WB_04(c, out, apid, run_id, wid):
    """WB-04: security_headers_absent"""
    missing = c.get("security_headers", {}).get("missing", [])
    critical_missing = [h for h in missing if h in (
        "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"
    )]
    if len(critical_missing) >= 2:
        status = "realized"
    elif critical_missing:
        status = "realized"
    else:
        status = "blocked"
    emit(out, "WB-04", status, 3, "response_headers", "security_header_audit",
         0.90, apid, run_id, wid,
         {"detail": f"missing: {', '.join(missing[:5])}" if missing else "all present",
          "missing_count": len(missing)})


def check_WB_05(c, out, apid, run_id, wid):
    """WB-05: admin_interface_exposed"""
    hit200 = _hit_200(c.get("probe_hits", []))
    exposed = hit200 & ADMIN_PATHS
    if exposed:
        status = "realized"
        detail = f"accessible: {', '.join(sorted(exposed)[:3])}"
    else:
        all_hit = _hit_paths(c.get("probe_hits", []))
        # 401/403 on admin paths — present but protected
        protected = ADMIN_PATHS & all_hit - hit200
        status = "blocked" if protected else "unknown"
        detail = f"protected: {', '.join(sorted(protected)[:3])}" if protected else "not found"
    emit(out, "WB-05", status, 2, "http_probe", "admin_path_probe",
         0.90, apid, run_id, wid, {"detail": detail,
                                    "exposed_paths": list(exposed) if exposed else []})


def check_WB_06(c, out, apid, run_id, wid):
    """WB-06: api_docs_exposed"""
    hit200 = _hit_200(c.get("probe_hits", []))
    exposed = hit200 & API_DOC_PATHS
    status = "realized" if exposed else "unknown"
    emit(out, "WB-06", status, 3, "http_probe", "api_doc_probe",
         0.88, apid, run_id, wid,
         {"detail": f"exposed: {', '.join(sorted(exposed))}" if exposed else "not found"})


def check_WB_07(c, out, apid, run_id, wid):
    """WB-07: debug_endpoint_exposed"""
    hit200 = _hit_200(c.get("probe_hits", []))
    exposed = hit200 & DEBUG_PATHS
    # Check if actuator returned sensitive content
    sensitive = False
    for h in c.get("probe_hits", []):
        if h.get("path") in DEBUG_PATHS and h.get("status") == 200:
            snippet = h.get("body_snippet", "")
            if any(kw in snippet.lower() for kw in
                   ["password", "secret", "key", "token", "datasource", "env"]):
                sensitive = True

    if exposed and sensitive:
        status = "realized"
        conf = 0.95
    elif exposed:
        status = "realized"
        conf = 0.85
    else:
        status = "unknown"
        conf = 0.7

    emit(out, "WB-07", status, 2, "http_probe", "debug_endpoint_probe",
         conf, apid, run_id, wid,
         {"detail": f"exposed: {', '.join(sorted(exposed))}" if exposed else "not found",
          "sensitive_content": sensitive})


def check_WB_08(c, out, apid, run_id, wid):
    """WB-08: git_exposure"""
    for h in c.get("probe_hits", []):
        if h.get("path") == "/.git/HEAD" and h.get("status") == 200:
            snippet = h.get("body_snippet", "")
            if "ref:" in snippet or "refs/" in snippet:
                emit(out, "WB-08", "realized", 2, "http_probe", "/.git/HEAD",
                     0.98, apid, run_id, wid,
                     {"detail": snippet[:80]})
                return
    status = "blocked" if any(h.get("path") == "/.git/HEAD"
                               for h in c.get("probe_hits", [])) else "unknown"
    emit(out, "WB-08", status, 2, "http_probe", "/.git/HEAD",
         0.85, apid, run_id, wid, {"detail": "not accessible"})


def check_WB_09(c, out, apid, run_id, wid):
    """WB-09: env_file_exposed"""
    env_paths = {"/.env", "/.env.local", "/.env.production"}
    for h in c.get("probe_hits", []):
        if h.get("path") in env_paths and h.get("status") == 200:
            snippet = h.get("body_snippet", "")
            # Check for key=value pattern typical of .env
            if re.search(r"[A-Z_]+=", snippet):
                emit(out, "WB-09", "realized", 1, "http_probe", h["path"],
                     0.99, apid, run_id, wid,
                     {"detail": f".env exposed at {h['path']}",
                      "snippet": snippet[:200]})
                return
    # Check other config files
    for h in c.get("probe_hits", []):
        if h.get("path") in {"/config.json", "/appsettings.json",
                               "/web.config"} and h.get("status") == 200:
            emit(out, "WB-09", "realized", 1, "http_probe", h["path"],
                 0.90, apid, run_id, wid,
                 {"detail": f"config exposed at {h['path']}"})
            return
    emit(out, "WB-09", "unknown", 3, "http_probe", "env_file_probe",
         0.80, apid, run_id, wid, {"detail": "no env/config exposure found"})


def check_WB_10(c, out, apid, run_id, wid):
    """WB-10: default_credentials — static inference only (no active auth attempt)"""
    # Cannot safely test default creds without explicit engagement scope
    # Mark as unknown — operator must verify manually or with targeted test
    emit(out, "WB-10", "unknown", 1, "static_inference", "default_cred_heuristic",
         0.5, apid, run_id, wid,
         {"detail": "Manual verification required — see auth_surfaces for targets",
          "auth_surfaces": c.get("auth_surfaces", [])[:5]})


def check_WB_11(c, out, apid, run_id, wid):
    """WB-11: tls_weak_or_missing"""
    url = c.get("url", "")
    if url.startswith("http://") and not url.startswith("https://"):
        emit(out, "WB-11", "realized", 3, "url_scheme", "http_no_tls",
             0.99, apid, run_id, wid, {"detail": "HTTP only — no TLS"})
        return
    tls = c.get("tls", {})
    if tls.get("error"):
        emit(out, "WB-11", "unknown", 3, "tls_inspect", "tls_error",
             0.6, apid, run_id, wid, {"detail": tls["error"]})
        return
    issues = []
    if tls.get("weak_protocol"):
        issues.append(f"weak protocol: {tls.get('protocol')}")
    if tls.get("expired"):
        issues.append("certificate expired")
    elif tls.get("expiring_soon"):
        days = tls.get("days_until_expiry", "?")
        issues.append(f"certificate expiring in {days} days")
    if issues:
        emit(out, "WB-11", "realized", 3, "tls_inspect", "tls_weakness",
             0.93, apid, run_id, wid, {"detail": "; ".join(issues)})
    else:
        emit(out, "WB-11", "blocked", 3, "tls_inspect", "tls_ok",
             0.90, apid, run_id, wid,
             {"detail": f"TLS OK ({tls.get('protocol','?')}), "
              f"expires in {tls.get('days_until_expiry','?')} days"})


def check_WB_12(c, out, apid, run_id, wid):
    """WB-12: cors_wildcard"""
    if c.get("cors_open"):
        status = "realized"
        detail = "Access-Control-Allow-Origin: *"
    elif c.get("cors_origin"):
        status = "unknown"
        detail = f"CORS: {c['cors_origin']}"
    else:
        status = "blocked"
        detail = "no CORS header"
    emit(out, "WB-12", status, 3, "response_header", "CORS",
         0.92, apid, run_id, wid, {"detail": detail})


def check_WB_13(c, out, apid, run_id, wid):
    """WB-13: cve_version_match"""
    cves = c.get("version_cves", [])
    if cves:
        emit(out, "WB-13", "realized", 3, "version_fingerprint", "server_header",
             0.85, apid, run_id, wid,
             {"detail": f"CVE match: {', '.join(cves)}",
              "matched_cves": cves,
              "server": c.get("server_header", "")})
    else:
        emit(out, "WB-13", "unknown", 3, "version_fingerprint", "server_header",
             0.7, apid, run_id, wid,
             {"detail": f"no CVE match for: {c.get('server_header','(no server header)')}"})


def check_WB_14(c, out, apid, run_id, wid):
    """WB-14: auth_surface_present"""
    surfaces = c.get("auth_surfaces", [])
    if surfaces:
        status = "realized"
        detail = f"auth surfaces: {', '.join(surfaces[:3])}"
    else:
        status = "unknown"
        detail = "no auth surface detected in probe set"
    emit(out, "WB-14", status, 3, "http_probe", "auth_surface_probe",
         0.88, apid, run_id, wid, {"detail": detail,
                                    "auth_paths": surfaces[:5]})


def check_WB_15(c, out, apid, run_id, wid):
    """WB-15: cms_detected"""
    techs = set(c.get("technologies", []))
    found = techs & CMS_TECHS
    if found:
        status = "realized"
        detail = f"CMS detected: {', '.join(found)}"
    else:
        status = "unknown"
        detail = "no CMS detected"
    emit(out, "WB-15", status, 3, "tech_fingerprint", "body_header_analysis",
         0.88, apid, run_id, wid, {"detail": detail})


def check_WB_16(c, out, apid, run_id, wid):
    """WB-16: onion_service_active"""
    method = c.get("method", "")
    if method == "onion":
        status = "realized" if c.get("reachable") else "blocked"
        detail = f"onion reachable={c.get('reachable')} via Tor"
    else:
        status = "unknown"
        detail = "not an onion target"
    emit(out, "WB-16", status, 2, "network_transport", "tor_socks5",
         0.95, apid, run_id, wid, {"detail": detail})


def check_WB_17(c, out, apid, run_id, wid):
    """WB-17: sensitive_path_exposed"""
    hit200 = _hit_200(c.get("probe_hits", []))
    exposed = hit200 & SENSITIVE_PATHS
    # Exclude /.git/HEAD (covered by WB-08) and .env (covered by WB-09)
    exposed -= {"/.git/HEAD", "/.git/config", "/.env", "/.env.local"}
    if exposed:
        status = "realized"
        detail = f"sensitive paths: {', '.join(sorted(exposed)[:3])}"
    else:
        status = "unknown"
        detail = "no sensitive paths exposed"
    emit(out, "WB-17", status, 1, "http_probe", "sensitive_path_probe",
         0.95, apid, run_id, wid, {"detail": detail,
                                    "exposed": list(sorted(exposed))})


def check_WB_18(c, out, apid, run_id, wid):
    """WB-18: redirect_chain_present"""
    chain = c.get("redirect_chain", [])
    if len(chain) > 2:
        status = "realized"
        detail = f"{len(chain)} redirects: {' → '.join(str(u)[:40] for u in chain[:3])}"
    else:
        status = "blocked"
        detail = f"{len(chain)} redirect(s) — normal"
    emit(out, "WB-18", status, 3, "http_response", "redirect_chain",
         0.85, apid, run_id, wid, {"detail": detail})


def check_WB_19(c, out, apid, run_id, wid):
    """WB-19: elasticsearch_unauth"""
    es_paths = {"/_cat", "/_cat/indices", "/_cluster/health", "/_nodes"}
    hit200 = _hit_200(c.get("probe_hits", []))
    exposed = hit200 & es_paths
    if exposed:
        # Check if it actually returned ES data
        for h in c.get("probe_hits", []):
            if h.get("path") in es_paths and h.get("status") == 200:
                snippet = h.get("body_snippet", "")
                if any(kw in snippet for kw in ["health", "index", "shards", "green", "yellow"]):
                    emit(out, "WB-19", "realized", 1, "http_probe", h["path"],
                         0.97, apid, run_id, wid,
                         {"detail": f"ES unauthenticated at {h['path']}"})
                    return
        emit(out, "WB-19", "realized", 1, "http_probe", "es_probe",
             0.85, apid, run_id, wid,
             {"detail": f"ES paths accessible: {', '.join(sorted(exposed))}"})
    else:
        emit(out, "WB-19", "unknown", 3, "http_probe", "es_probe",
             0.70, apid, run_id, wid, {"detail": "no ES endpoints found"})


def check_WB_20(c, out, apid, run_id, wid):
    """WB-20: jenkins_script_console"""
    all_hit = _hit_paths(c.get("probe_hits", []))
    jenkins_paths = {"/script", "/scriptText", "/jenkins", "/jenkins/"}
    found = all_hit & jenkins_paths
    hit200 = _hit_200(c.get("probe_hits", []))
    script_200 = hit200 & {"/script", "/scriptText"}

    if script_200:
        status = "realized"
        detail = f"Jenkins script console accessible: {', '.join(script_200)}"
        conf = 0.98
    elif found & {"/script", "/scriptText"}:
        status = "realized"  # 403 still means Jenkins is present
        detail = f"Jenkins script console present (protected): {', '.join(found & {'/script','/scriptText'})}"
        conf = 0.85
    elif "jenkins" in c.get("technologies", []) or found:
        status = "realized"
        detail = f"Jenkins detected: {', '.join(found) or 'via fingerprint'}"
        conf = 0.80
    else:
        status = "unknown"
        detail = "Jenkins not detected"
        conf = 0.70
    emit(out, "WB-20", status, 1, "http_probe", "jenkins_probe",
         conf, apid, run_id, wid, {"detail": detail})


CHECK_FUNCTIONS = [
    check_WB_01, check_WB_02, check_WB_03, check_WB_04, check_WB_05,
    check_WB_06, check_WB_07, check_WB_08, check_WB_09, check_WB_10,
    check_WB_11, check_WB_12, check_WB_13, check_WB_14, check_WB_15,
    check_WB_16, check_WB_17, check_WB_18, check_WB_19, check_WB_20,
]


def run_checks(collection: dict, out: Path, attack_path_id: str,
               run_id: str, workload_id: str):
    """Run all 20 check functions against collected web data."""
    for fn in CHECK_FUNCTIONS:
        try:
            fn(collection, out, attack_path_id, run_id, workload_id)
        except Exception as exc:
            import logging
            logging.getLogger("skg.adapter.web").warning(
                f"{fn.__name__} failed: {exc}"
            )


def main():
    p = argparse.ArgumentParser(description="Web fingerprint adapter")
    p.add_argument("--in",  dest="infile",  required=True,
                   help="JSON collection file from web_sensor")
    p.add_argument("--out", dest="outfile", required=True,
                   help="Output NDJSON event file")
    p.add_argument("--attack-path-id", default="web_initial_access_v1")
    p.add_argument("--workload-id",    default=None)
    p.add_argument("--run-id",         default=None)
    a = p.parse_args()

    collection = json.loads(Path(a.infile).read_text())
    run_id = a.run_id or str(uuid.uuid4())[:8]
    wid = a.workload_id or collection.get("workload_id", "unknown")
    out = Path(a.outfile)

    run_checks(collection, out, a.attack_path_id, run_id, wid)
    print(f"[web_fingerprint] {wid}: events written to {out}")


if __name__ == "__main__":
    main()

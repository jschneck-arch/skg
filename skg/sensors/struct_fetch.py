"""
skg.sensors.struct_fetch
========================
Structured data fetcher — pulls JSON, JSONL, XML, YAML from web endpoints
and routes the parsed content into the SKG observation event stream.

Domain agnostic: any structured endpoint can be ingested. The fetcher
maps discovered keys/fields to wicket preconditions via the catalog and
emits obs.attack.precondition events for any realized/blocked conditions.

Supported formats:
  - JSON        (.json endpoints, Content-Type: application/json)
  - JSONL       (newline-delimited JSON, one event per line)
  - XML/HTML    (XML/SOAP/XMLRPC endpoints, Content-Type: text/xml, application/xml)
  - YAML        (.yaml/.yml endpoints, Content-Type: text/yaml)
  - OpenAPI     (swagger.json, openapi.json — structured API schema)

Wellknown structured endpoints probed per target:
  /openapi.json, /swagger.json, /api/v1/health, /api/v1/config,
  /api/v1/info, /api/v1/version, /config.json, /config.yaml,
  /debug/vars, /metrics, /actuator/health, /actuator/env,
  /actuator/configprops, /.well-known/security.txt,
  /robots.txt (parsed for path exposure), /sitemap.xml

Emitted wickets:
  WB-30  exposed_api_schema       — OpenAPI/Swagger schema exposed without auth
  WB-31  config_endpoint_exposed  — config.json/yaml accessible
  WB-32  debug_endpoint_exposed   — /debug/vars, /actuator/env accessible
  WB-33  health_endpoint_exposed  — health/status endpoints leak version
  WB-34  metrics_exposed          — Prometheus/metrics endpoint open
  WB-35  xmlrpc_exposed           — XML-RPC endpoint active
  WB-36  security_txt_present     — /.well-known/security.txt present
  WB-37  version_disclosed        — version string in structured response
  WB-38  credentials_in_config    — password/secret/token/key found in config
  WB-39  internal_ip_disclosed    — private IP found in structured response
  WB-40  jsonl_event_stream       — JSONL event stream exposed
"""
from __future__ import annotations

import json
import re
import socket
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen
from urllib.parse import urljoin, urlparse

TOOLCHAIN = "skg-web-toolchain"
SOURCE_ID = "adapter.struct_fetch"

# Wellknown structured endpoints to probe
WELLKNOWN_PATHS = [
    # OpenAPI / Swagger
    ("/openapi.json",        "json",   "WB-30", "OpenAPI schema"),
    ("/swagger.json",        "json",   "WB-30", "Swagger schema"),
    ("/api-docs",            "json",   "WB-30", "API docs"),
    ("/v1/api-docs",         "json",   "WB-30", "API docs v1"),
    ("/v2/api-docs",         "json",   "WB-30", "API docs v2"),
    # Config
    ("/config.json",         "json",   "WB-31", "config.json"),
    ("/config.yaml",         "yaml",   "WB-31", "config.yaml"),
    ("/config.yml",          "yaml",   "WB-31", "config.yml"),
    ("/app/config.json",     "json",   "WB-31", "app config"),
    ("/settings.json",       "json",   "WB-31", "settings.json"),
    # Debug / metrics
    ("/debug/vars",          "json",   "WB-32", "Go debug/vars"),
    ("/actuator/env",        "json",   "WB-32", "Spring actuator env"),
    ("/actuator/configprops","json",   "WB-32", "Spring configprops"),
    ("/metrics",             "text",   "WB-34", "Prometheus metrics"),
    ("/actuator/metrics",    "json",   "WB-34", "Spring metrics"),
    # Health / version
    ("/health",              "json",   "WB-33", "health endpoint"),
    ("/api/v1/health",       "json",   "WB-33", "API health"),
    ("/actuator/health",     "json",   "WB-33", "Spring health"),
    ("/api/v1/version",      "json",   "WB-37", "version endpoint"),
    ("/version",             "json",   "WB-37", "version endpoint"),
    ("/info",                "json",   "WB-37", "info endpoint"),
    ("/actuator/info",       "json",   "WB-37", "Spring info"),
    # XML-RPC
    ("/xmlrpc.php",          "xml",    "WB-35", "WordPress XMLRPC"),
    ("/xmlrpc",              "xml",    "WB-35", "XMLRPC endpoint"),
    ("/RPC2",                "xml",    "WB-35", "XML-RPC2"),
    # Security
    ("/.well-known/security.txt", "text", "WB-36", "security.txt"),
    ("/robots.txt",          "text",   None,    "robots.txt"),
    ("/sitemap.xml",         "xml",    None,    "sitemap"),
    # JSONL streams
    ("/events",              "jsonl",  "WB-40", "event stream"),
    ("/stream",              "jsonl",  "WB-40", "data stream"),
    ("/api/events",          "jsonl",  "WB-40", "API events"),
]

# Sensitive key patterns in JSON/YAML
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth[_-]?token)", re.I),
]

# Private IP pattern
PRIVATE_IP_RE = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event(
    wicket_id: str,
    status: str,
    rank: int,
    confidence: float,
    detail: str,
    workload_id: str,
    run_id: str,
    target_ip: str,
    attack_path_id: str = "web_sqli_to_shell_v1",
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "ts": _now(),
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": "0.1.0",
        },
        "payload": {
            "wicket_id": wicket_id,
            "status": status,
            "workload_id": workload_id,
            "detail": str(detail)[:500],
            "attack_path_id": attack_path_id,
            "run_id": run_id,
            "observed_at": _now(),
            "target_ip": target_ip,
        },
        "provenance": {
            "evidence_rank": rank,
            "evidence": {
                "source_kind": "http_structured",
                "pointer": f"http://{target_ip}",
                "collected_at": _now(),
                "confidence": confidence,
            },
        },
    }


def _fetch(url: str, timeout: float = 8.0) -> Tuple[Optional[bytes], Optional[str], int]:
    """Fetch URL, return (body_bytes, content_type, status_code)."""
    try:
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 SKG-Struct-Fetch/1.0",
            "Accept": "application/json, application/xml, text/yaml, text/plain, */*",
        })
        with urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type", "")
            body = resp.read(512 * 1024)  # cap at 512KB
            return body, ct, resp.status
    except Exception:
        return None, None, 0


def _detect_format(path: str, declared_fmt: str, content_type: str, body: bytes) -> str:
    """Infer actual format from content_type and body prefix."""
    ct = (content_type or "").lower()
    if "json" in ct or body[:2] in (b'{"', b'[{', b'[\n'):
        # Check if it's JSONL (multiple JSON objects on separate lines)
        lines = body.decode(errors="replace").splitlines()
        json_lines = 0
        for line in lines[:10]:
            line = line.strip()
            if line and line.startswith("{") and line.endswith("}"):
                try:
                    json.loads(line)
                    json_lines += 1
                except Exception:
                    pass
        if json_lines >= 2:
            return "jsonl"
        return "json"
    if "xml" in ct or body[:5] in (b"<?xml", b"<soap", b"<SOAP", b"<rpc>"):
        return "xml"
    if "yaml" in ct or path.endswith((".yaml", ".yml")):
        return "yaml"
    return declared_fmt


def _parse_json(body: bytes) -> Optional[Any]:
    try:
        return json.loads(body.decode(errors="replace"))
    except Exception:
        return None


def _parse_jsonl(body: bytes) -> List[Any]:
    results = []
    for line in body.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except Exception:
            pass
    return results


def _parse_xml(body: bytes) -> Optional[ET.Element]:
    try:
        return ET.fromstring(body.decode(errors="replace"))
    except Exception:
        return None


def _parse_yaml(body: bytes) -> Optional[Any]:
    try:
        import yaml
        return yaml.safe_load(body.decode(errors="replace"))
    except Exception:
        return None


def _flatten_values(data: Any, depth: int = 0) -> List[str]:
    """Recursively extract all string values from a nested structure."""
    if depth > 6:
        return []
    results = []
    if isinstance(data, dict):
        for k, v in data.items():
            results.append(str(k))
            results.extend(_flatten_values(v, depth + 1))
    elif isinstance(data, list):
        for item in data[:100]:
            results.extend(_flatten_values(item, depth + 1))
    elif isinstance(data, str):
        results.append(data)
    return results


def _flatten_keys(data: Any, depth: int = 0) -> List[Tuple[str, Any]]:
    """Recursively extract (key, value) pairs."""
    if depth > 6:
        return []
    results = []
    if isinstance(data, dict):
        for k, v in data.items():
            results.append((str(k), v))
            results.extend(_flatten_keys(v, depth + 1))
    elif isinstance(data, list):
        for item in data[:100]:
            results.extend(_flatten_keys(item, depth + 1))
    return results


def _analyze_structured(
    data: Any,
    fmt: str,
    path: str,
    base_wicket: Optional[str],
    workload_id: str,
    run_id: str,
    target_ip: str,
    base_url: str,
) -> List[dict]:
    """Analyze parsed structured data and emit wicket events."""
    events: List[dict] = []

    # Base wicket for the endpoint being accessible
    if base_wicket:
        events.append(_event(
            wicket_id=base_wicket,
            status="realized",
            rank=3,
            confidence=0.85,
            detail=f"{fmt.upper()} endpoint accessible at {path}",
            workload_id=workload_id,
            run_id=run_id,
            target_ip=target_ip,
        ))

    if data is None:
        return events

    all_values = _flatten_values(data)
    all_kv = _flatten_keys(data)
    combined_text = " ".join(all_values)

    # WB-37: version disclosure
    version_re = re.compile(r"\b(\d+\.\d+[\.\d]*(?:-[a-zA-Z0-9]+)?)\b")
    version_keys = {"version", "ver", "release", "build", "revision", "tag", "v"}
    for k, v in all_kv:
        if k.lower() in version_keys and v and isinstance(v, str) and version_re.search(v):
            events.append(_event(
                "WB-37", "realized", 3, 0.80,
                f"Version disclosed in {fmt}: {k}={v[:80]}",
                workload_id, run_id, target_ip,
            ))
            break

    # WB-38: credentials in config
    for k, v in all_kv:
        if any(p.search(k) for p in SENSITIVE_PATTERNS):
            val_str = str(v)[:40] if v else ""
            if val_str and val_str not in ("", "null", "None", '""', "''"):
                events.append(_event(
                    "WB-38", "realized", 2, 0.90,
                    f"Sensitive key in {fmt} response: {k}={val_str}",
                    workload_id, run_id, target_ip,
                ))
                break  # one is enough, don't spam

    # WB-39: internal IP disclosure
    private_matches = PRIVATE_IP_RE.findall(combined_text)
    if private_matches:
        unique_ips = list(set(private_matches))
        events.append(_event(
            "WB-39", "realized", 3, 0.75,
            f"Internal IPs in {fmt} response: {unique_ips[:5]}",
            workload_id, run_id, target_ip,
        ))

    # WB-30: OpenAPI schema — extract endpoint count and auth info
    if base_wicket == "WB-30" and isinstance(data, dict):
        paths = data.get("paths", {})
        if isinstance(paths, dict):
            n_paths = len(paths)
            security = data.get("security", data.get("securityDefinitions", {}))
            has_auth = bool(security)
            events.append(_event(
                "WB-30", "realized", 2, 0.92,
                f"OpenAPI schema: {n_paths} paths, auth_required={has_auth}",
                workload_id, run_id, target_ip,
            ))

    return events


def _analyze_xml_element(
    root: ET.Element,
    path: str,
    base_wicket: Optional[str],
    workload_id: str,
    run_id: str,
    target_ip: str,
) -> List[dict]:
    """Analyze parsed XML for wicket evidence."""
    events: List[dict] = []

    if base_wicket:
        events.append(_event(
            base_wicket, "realized", 3, 0.80,
            f"XML endpoint accessible at {path}",
            workload_id, run_id, target_ip,
        ))

    # Check for XMLRPC
    tag = (root.tag or "").lower()
    if any(x in tag for x in ("methodcall", "methodresponse", "xmlrpc")):
        events.append(_event(
            "WB-35", "realized", 2, 0.88,
            f"XML-RPC endpoint confirmed at {path}: root={root.tag}",
            workload_id, run_id, target_ip,
        ))

    # Version in XML
    version_re = re.compile(r"\b\d+\.\d+")
    xml_text = ET.tostring(root, encoding="unicode")
    if version_re.search(xml_text):
        events.append(_event(
            "WB-37", "realized", 4, 0.65,
            f"Version string in XML response at {path}",
            workload_id, run_id, target_ip,
        ))

    # Sensitive data
    for p in SENSITIVE_PATTERNS:
        if p.search(xml_text):
            events.append(_event(
                "WB-38", "realized", 2, 0.85,
                f"Sensitive keyword in XML response at {path}",
                workload_id, run_id, target_ip,
            ))
            break

    return events


def fetch_and_ingest(
    base_url: str,
    target_ip: str,
    workload_id: str,
    run_id: str,
    attack_path_id: str = "web_sqli_to_shell_v1",
    extra_paths: Optional[List[str]] = None,
    timeout: float = 8.0,
) -> Tuple[List[dict], List[str]]:
    """
    Probe all wellknown structured endpoints on base_url.

    Returns:
        (events, probed_urls) — list of observation events and list of URLs probed.
    """
    all_events: List[dict] = []
    probed: List[str] = []

    paths_to_probe = list(WELLKNOWN_PATHS)
    if extra_paths:
        for p in extra_paths:
            paths_to_probe.append((p, "json", None, "custom"))

    for path, declared_fmt, base_wicket, description in paths_to_probe:
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        probed.append(url)

        body, content_type, status = _fetch(url, timeout=timeout)
        if body is None or status == 0:
            continue

        if status == 404:
            # 404 confirms the endpoint is blocked
            if base_wicket:
                all_events.append(_event(
                    base_wicket, "blocked", 4, 0.60,
                    f"Endpoint {path} returned 404",
                    workload_id, run_id, target_ip,
                ))
            continue

        if status not in (200, 201, 206):
            continue

        fmt = _detect_format(path, declared_fmt, content_type or "", body)

        if fmt == "json":
            data = _parse_json(body)
            evs = _analyze_structured(
                data, "json", path, base_wicket,
                workload_id, run_id, target_ip, base_url,
            )
            all_events.extend(evs)

        elif fmt == "jsonl":
            records = _parse_jsonl(body)
            if records:
                all_events.append(_event(
                    "WB-40", "realized", 3, 0.80,
                    f"JSONL stream at {path}: {len(records)} records",
                    workload_id, run_id, target_ip,
                ))
            # Also analyze each record for sensitive data
            for rec in records[:5]:
                evs = _analyze_structured(
                    rec, "jsonl", path, None,
                    workload_id, run_id, target_ip, base_url,
                )
                all_events.extend(evs)

        elif fmt == "xml":
            root = _parse_xml(body)
            if root is not None:
                evs = _analyze_xml_element(
                    root, path, base_wicket,
                    workload_id, run_id, target_ip,
                )
                all_events.extend(evs)

        elif fmt == "yaml":
            data = _parse_yaml(body)
            evs = _analyze_structured(
                data, "yaml", path, base_wicket,
                workload_id, run_id, target_ip, base_url,
            )
            all_events.extend(evs)

        elif fmt == "text" and path == "/metrics":
            # Prometheus metrics — check if accessible
            if body and len(body) > 100:
                all_events.append(_event(
                    "WB-34", "realized", 3, 0.82,
                    f"Prometheus metrics exposed at {path}: {len(body)} bytes",
                    workload_id, run_id, target_ip,
                ))

    return all_events, probed


def ingest_url(
    url: str,
    target_ip: str,
    workload_id: str,
    run_id: str,
    fmt: Optional[str] = None,
    timeout: float = 10.0,
) -> List[dict]:
    """
    Fetch and ingest a single arbitrary URL as structured data.
    Auto-detects format (JSON/JSONL/XML/YAML). Emits observation events.

    Usage: for ingesting operator-specified URLs or spidered links.
    """
    body, content_type, status = _fetch(url, timeout=timeout)
    if body is None or status == 0:
        return []

    path = urlparse(url).path
    detected_fmt = _detect_format(path, fmt or "json", content_type or "", body)

    if detected_fmt == "json":
        data = _parse_json(body)
        return _analyze_structured(data, "json", path, None, workload_id, run_id, target_ip, url)
    elif detected_fmt == "jsonl":
        records = _parse_jsonl(body)
        events = []
        for rec in records[:20]:
            events.extend(_analyze_structured(rec, "jsonl", path, None, workload_id, run_id, target_ip, url))
        return events
    elif detected_fmt == "xml":
        root = _parse_xml(body)
        if root is not None:
            return _analyze_xml_element(root, path, None, workload_id, run_id, target_ip)
        return []
    elif detected_fmt == "yaml":
        data = _parse_yaml(body)
        return _analyze_structured(data, "yaml", path, None, workload_id, run_id, target_ip, url)
    return []

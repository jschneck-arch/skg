from __future__ import annotations

import base64
import json
import shutil
import socket
import ssl
import subprocess
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def canonical_web_adapter_available() -> bool:
    try:
        from skg_domain_web.adapters.web_nikto_findings.run import map_nikto_findings_to_events
        from skg_domain_web.adapters.web_auth_assessment.run import map_auth_assessment_to_events
        from skg_domain_web.adapters.web_surface_fingerprint.run import map_surface_profile_to_events
    except Exception:
        return False
    return (
        callable(map_surface_profile_to_events)
        and callable(map_nikto_findings_to_events)
        and callable(map_auth_assessment_to_events)
    )


def canonical_web_auth_runtime_available() -> bool:
    return canonical_web_adapter_available()


def _require_surface_mapper():
    try:
        from skg_domain_web.adapters.web_surface_fingerprint.run import map_surface_profile_to_events
    except Exception as exc:
        raise RuntimeError(
            "Canonical web domain adapter unavailable: "
            "skg_domain_web.adapters.web_surface_fingerprint.run"
        ) from exc
    return map_surface_profile_to_events


def _require_nikto_mapper():
    try:
        from skg_domain_web.adapters.web_nikto_findings.run import map_nikto_findings_to_events
    except Exception as exc:
        raise RuntimeError(
            "Canonical web domain adapter unavailable: "
            "skg_domain_web.adapters.web_nikto_findings.run"
        ) from exc
    return map_nikto_findings_to_events


def _require_auth_assessment_mapper():
    try:
        from skg_domain_web.adapters.web_auth_assessment.run import map_auth_assessment_to_events
    except Exception as exc:
        raise RuntimeError(
            "Canonical web domain adapter unavailable: "
            "skg_domain_web.adapters.web_auth_assessment.run"
        ) from exc
    return map_auth_assessment_to_events


def _load_auth_runtime_policy() -> dict[str, Any]:
    try:
        from skg_domain_web.policies import load_auth_runtime_policy
    except Exception as exc:
        raise RuntimeError(
            "Canonical web policy unavailable: skg_domain_web.policies.load_auth_runtime_policy"
        ) from exc
    payload = load_auth_runtime_policy()
    return payload if isinstance(payload, dict) else {}


def _host_from_target(target: str) -> str:
    parsed = urlparse(str(target))
    if parsed.hostname:
        return parsed.hostname
    return str(target).strip()


def _normalize_target_url(target: str) -> str:
    raw = str(target or "").strip()
    if "://" not in raw:
        return f"http://{raw}"
    return raw


def _default_workload_id(target: str) -> str:
    host = _host_from_target(target) or "unknown"
    return f"web::{host}"


def _headers_dict(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if hasattr(headers, "items"):
        pairs = list(headers.items())
    elif isinstance(headers, dict):
        pairs = list(headers.items())
    else:
        return {}
    out: dict[str, str] = {}
    for key, value in pairs:
        out[str(key).strip()] = str(value)
    return out


def _headers_lower(headers: dict[str, str]) -> dict[str, str]:
    return {str(k).strip().lower(): str(v) for k, v in headers.items()}


def _http_request(url: str, *, timeout: float, headers: dict[str, str] | None = None) -> dict[str, Any]:
    req_headers = {
        "User-Agent": "skg-services/web-runtime",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update({str(k): str(v) for k, v in headers.items()})

    req = Request(url, headers=req_headers, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            return {
                "reachable": True,
                "status": int(getattr(resp, "status", 200) or 200),
                "url": str(resp.geturl() or url),
                "headers": _headers_dict(getattr(resp, "headers", None)),
                "error": "",
            }
    except HTTPError as exc:
        return {
            "reachable": True,
            "status": int(exc.code or 0),
            "url": str(exc.geturl() or url),
            "headers": _headers_dict(getattr(exc, "headers", None)),
            "error": "",
        }
    except URLError as exc:
        return {
            "reachable": False,
            "status": 0,
            "url": url,
            "headers": {},
            "error": str(exc.reason or exc),
        }
    except Exception as exc:
        return {
            "reachable": False,
            "status": 0,
            "url": url,
            "headers": {},
            "error": str(exc),
        }


def _expired(not_after: str) -> bool:
    value = str(not_after or "").strip()
    if not value:
        return False
    try:
        dt = parsedate_to_datetime(value)
    except Exception:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < datetime.now(timezone.utc)


def _probe_tls(host: str, port: int, *, timeout: float) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                version = str(tls_sock.version() or "")
                cipher_name = ""
                cipher_bits = 0
                cipher = tls_sock.cipher()
                if isinstance(cipher, tuple):
                    cipher_name = str(cipher[0] or "")
                    try:
                        cipher_bits = int(cipher[2] or 0)
                    except Exception:
                        cipher_bits = 0

                cert = tls_sock.getpeercert() or {}
                not_after = str(cert.get("notAfter") or "")
                subject = tuple(cert.get("subject") or ())
                issuer = tuple(cert.get("issuer") or ())

                issues: list[str] = []
                if version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
                    issues.append(f"weak protocol: {version}")
                if cipher_bits and cipher_bits < 128:
                    issues.append(f"low bit strength: {cipher_bits}")
                if _expired(not_after):
                    issues.append("certificate expired")
                if subject and issuer and subject == issuer:
                    issues.append("self-signed certificate")

                return {
                    "tls_version": version,
                    "cipher_name": cipher_name,
                    "cipher_bits": cipher_bits,
                    "notAfter": not_after,
                    "certificate_expired": _expired(not_after),
                    "self_signed": bool(subject and issuer and subject == issuer),
                    "issues": issues,
                    "error": "",
                }
    except Exception as exc:
        return {
            "error": str(exc),
            "issues": [],
        }


def collect_surface_profile(
    target: str,
    *,
    timeout: float = 8.0,
    request_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    base_url = _normalize_target_url(target)
    parsed = urlparse(base_url)
    scheme = str(parsed.scheme or "http").lower()
    host = str(parsed.hostname or "")
    if not host:
        raise ValueError(f"Invalid web target: {target}")
    port = int(parsed.port or (443 if scheme == "https" else 80))

    initial = _http_request(base_url, timeout=timeout, headers=request_headers)
    headers = _headers_dict(initial.get("headers"))
    headers_lower = _headers_lower(headers)
    cors_probe_headers = {"Origin": "https://evil.example.com"}
    if request_headers:
        cors_probe_headers.update({str(k): str(v) for k, v in request_headers.items()})

    cors = _http_request(
        base_url,
        timeout=timeout,
        headers=cors_probe_headers,
    )
    cors_headers = _headers_lower(_headers_dict(cors.get("headers")))

    profile: dict[str, Any] = {
        "base_url": str(initial.get("url") or base_url),
        "scheme": scheme,
        "host": host,
        "port": port,
        "reachable": bool(initial.get("reachable")),
        "error": str(initial.get("error") or ""),
        "response_headers": headers,
        "source_kind": "surface.profile",
        "cors": {
            "acao": str(cors_headers.get("access-control-allow-origin", "")),
            "acac": str(cors_headers.get("access-control-allow-credentials", "")),
        },
    }

    if scheme == "https":
        profile["tls"] = _probe_tls(host, port, timeout=timeout)
    else:
        profile["tls"] = {}

    missing_security_headers = [
        key
        for key in (
            "content-security-policy",
            "x-frame-options",
            "strict-transport-security",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        )
        if key not in headers_lower
    ]
    profile["missing_security_headers"] = missing_security_headers
    return profile


def _write_events(events: list[dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def collect_surface_events(
    target: str,
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    timeout: float = 8.0,
    source_id: str = "adapter.web_surface_runtime",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    mapper = _require_surface_mapper()
    profile = collect_surface_profile(target, timeout=timeout)
    return mapper(
        profile,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        source_id=source_id,
        toolchain=toolchain,
    )


def collect_surface_events_to_file(
    target: str,
    *,
    out_path: Path | str,
    attack_path_id: str,
    run_id: str | None = None,
    workload_id: str | None = None,
    timeout: float = 8.0,
    source_id: str = "adapter.web_surface_runtime",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    rid = str(run_id or uuid.uuid4().hex[:8])
    wid = str(workload_id or _default_workload_id(target))
    events = collect_surface_events(
        target,
        attack_path_id=attack_path_id,
        run_id=rid,
        workload_id=wid,
        timeout=timeout,
        source_id=source_id,
        toolchain=toolchain,
    )
    _write_events(events, Path(out_path))
    return events


def _basic_auth_header(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _auth_succeeded(status_code: int, reachable: bool) -> bool:
    if not reachable:
        return False
    return int(status_code or 0) not in {401, 403}


def _default_credentials_from_policy(policy: dict[str, Any]) -> list[tuple[str, str]]:
    rows = policy.get("default_credentials")
    if not isinstance(rows, list):
        return []
    creds: list[tuple[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        username = str(row.get("username") or "").strip()
        password = str(row.get("password") or "").strip()
        if username:
            creds.append((username, password))
    return creds


def _attempt_auth(
    target: str,
    *,
    timeout: float,
    username: str = "",
    password: str = "",
    try_defaults: bool = False,
) -> tuple[dict[str, Any], dict[str, str] | None]:
    policy = _load_auth_runtime_policy()
    max_default_attempts = int(policy.get("max_default_attempts") or 10)

    candidates: list[tuple[str, str, bool]] = []
    explicit_user = str(username or "").strip()
    explicit_pass = str(password or "")
    if explicit_user:
        candidates.append((explicit_user, explicit_pass, False))

    if try_defaults:
        for user, secret in _default_credentials_from_policy(policy)[:max_default_attempts]:
            if explicit_user and user == explicit_user and secret == explicit_pass:
                continue
            candidates.append((user, secret, True))

    if not candidates:
        return (
            {
                "auth_attempted": False,
                "authenticated": False,
                "username": "",
                "method": "none",
                "used_default_credential": False,
                "status_code": 0,
                "detail": "No auth credentials provided",
            },
            None,
        )

    for user, secret, is_default in candidates:
        req_headers = _basic_auth_header(user, secret)
        response = _http_request(_normalize_target_url(target), timeout=timeout, headers=req_headers)
        reachable = bool(response.get("reachable"))
        status_code = int(response.get("status") or 0)
        if _auth_succeeded(status_code, reachable):
            return (
                {
                    "auth_attempted": True,
                    "authenticated": True,
                    "username": user,
                    "method": "basic",
                    "used_default_credential": bool(is_default),
                    "status_code": status_code,
                    "detail": f"HTTP basic auth accepted for {user}",
                },
                req_headers,
            )

    return (
        {
            "auth_attempted": True,
            "authenticated": False,
            "username": candidates[0][0],
            "method": "basic",
            "used_default_credential": False,
            "status_code": 401,
            "detail": "HTTP basic auth failed for all attempted credentials",
        },
        None,
    )


def collect_auth_surface_events(
    target: str,
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    username: str = "",
    password: str = "",
    try_defaults: bool = True,
    timeout: float = 10.0,
    source_id: str = "adapter.web_auth_runtime",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    surface_mapper = _require_surface_mapper()
    auth_mapper = _require_auth_assessment_mapper()

    auth_result, auth_headers = _attempt_auth(
        target,
        timeout=timeout,
        username=username,
        password=password,
        try_defaults=try_defaults,
    )
    profile = collect_surface_profile(target, timeout=timeout, request_headers=auth_headers)
    if auth_result.get("authenticated"):
        profile["source_kind"] = "surface.profile.authenticated"

    surface_events = surface_mapper(
        profile,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        source_id=source_id,
        toolchain=toolchain,
    )
    auth_events = auth_mapper(
        auth_result,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        source_id=source_id,
        toolchain=toolchain,
    )
    return [*surface_events, *auth_events]


def collect_auth_surface_events_to_file(
    target: str,
    *,
    out_path: Path | str,
    attack_path_id: str,
    run_id: str | None = None,
    workload_id: str | None = None,
    username: str = "",
    password: str = "",
    try_defaults: bool = True,
    timeout: float = 10.0,
    source_id: str = "adapter.web_auth_runtime",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    rid = str(run_id or uuid.uuid4().hex[:8])
    wid = str(workload_id or _default_workload_id(target))
    events = collect_auth_surface_events(
        target,
        attack_path_id=attack_path_id,
        run_id=rid,
        workload_id=wid,
        username=username,
        password=password,
        try_defaults=try_defaults,
        timeout=timeout,
        source_id=source_id,
        toolchain=toolchain,
    )
    _write_events(events, Path(out_path))
    return events


def _parse_nikto_json(path: Path, target_url: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not path.exists():
        return findings

    try:
        raw = path.read_text(encoding="utf-8")
    except Exception:
        return findings

    try:
        payload = json.loads(raw)
        if isinstance(payload, list):
            payload = payload[0] if payload else {}
        if not isinstance(payload, dict):
            payload = {}

        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities and isinstance(payload.get("host"), dict):
            vulnerabilities = payload["host"].get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

        for row in vulnerabilities:
            if not isinstance(row, dict):
                continue
            msg = str(row.get("msg") or row.get("message") or "").strip()
            url = str(row.get("url") or target_url)
            if msg:
                findings.append({"msg": msg, "url": url})
        return findings
    except Exception:
        pass

    for line in raw.splitlines():
        text = str(line or "").strip()
        if not text.startswith("+ "):
            continue
        if text.startswith("+ No "):
            continue
        msg = text[2:].strip()
        if msg:
            findings.append({"msg": msg, "url": target_url})
    return findings


def _run_nikto_scan(
    target_url: str,
    out_dir: Path,
    *,
    timeout: float = 180.0,
    max_time: int = 120,
) -> list[dict[str, str]]:
    if shutil.which("nikto") is None:
        return []

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"nikto_{uuid.uuid4().hex[:8]}.json"
    cmd = [
        "nikto",
        "-h",
        target_url,
        "-Format",
        "json",
        "-output",
        str(out_file),
        "-Tuning",
        "12345789",
        "-timeout",
        "10",
        "-nointeractive",
        "-maxtime",
        str(max_time),
    ]
    if str(target_url).startswith("https://"):
        cmd.append("-ssl")

    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout, check=False, text=True)
    except subprocess.TimeoutExpired:
        pass

    return _parse_nikto_json(out_file, target_url)


def collect_nikto_events(
    target_url: str,
    *,
    out_dir: Path | str,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "adapter.web_nikto_runtime",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    mapper = _require_nikto_mapper()
    findings = _run_nikto_scan(str(target_url), Path(out_dir))
    if not findings:
        return []
    return mapper(
        findings,
        attack_path_id=attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
        source_id=source_id,
        toolchain=toolchain,
    )


def collect_nikto_events_to_file(
    target_url: str,
    *,
    out_path: Path | str,
    out_dir: Path | str,
    attack_path_id: str,
    run_id: str | None = None,
    workload_id: str | None = None,
    source_id: str = "adapter.web_nikto_runtime",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    rid = str(run_id or uuid.uuid4().hex[:8])
    wid = str(workload_id or _default_workload_id(target_url))
    events = collect_nikto_events(
        target_url,
        out_dir=out_dir,
        attack_path_id=attack_path_id,
        run_id=rid,
        workload_id=wid,
        source_id=source_id,
        toolchain=toolchain,
    )
    _write_events(events, Path(out_path))
    return events


def _load_web_toolchain_adapter(relative_py: str, module_name: str):
    """
    Load a skg-web-toolchain adapter by path relative to SKG_HOME.

    Centralises the spec_from_file_location pattern so gravity_field.py no
    longer needs to know about adapter paths — it just calls the collect_*
    functions here.
    """
    import importlib.util as _ilu
    from skg.core.paths import SKG_HOME
    path = Path(SKG_HOME) / "skg-web-toolchain" / relative_py
    spec = _ilu.spec_from_file_location(module_name, path)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def collect_gobuster_events(
    target_url: str,
    *,
    out_file: "Path | str",
    workload_id: str | None = None,
    wordlist: str | None = None,
) -> "list[dict[str, Any]]":
    """Run gobuster against target_url and return SKG precondition events."""
    mod = _load_web_toolchain_adapter(
        "adapters/web_active/gobuster_adapter.py", "gobuster_adapter"
    )
    return mod.run_gobuster(target_url, Path(out_file), wordlist=wordlist)


def collect_gobuster_events_to_file(
    target_url: str,
    *,
    out_path: "Path | str",
    workload_id: str | None = None,
    wordlist: str | None = None,
) -> "list[dict[str, Any]]":
    """Run gobuster and write events to out_path (NDJSON). Returns event list."""
    events = collect_gobuster_events(
        target_url,
        out_file=out_path,
        workload_id=workload_id,
        wordlist=wordlist,
    )
    # Adapter already writes to out_file; ensure file exists even if empty.
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("")
    return events


def collect_sqlmap_events(
    target_url: str,
    *,
    out_dir: "Path | str",
    forms: bool = True,
    level: int = 2,
    risk: int = 1,
) -> "list[dict[str, Any]]":
    """Run sqlmap against target_url and return SKG precondition events."""
    mod = _load_web_toolchain_adapter(
        "adapters/web_active/sqlmap_adapter.py", "sqlmap_adapter"
    )
    return mod.run_sqlmap(target_url, Path(out_dir), forms=forms, level=level, risk=risk)


def collect_sqlmap_events_to_file(
    target_url: str,
    *,
    out_path: "Path | str",
    forms: bool = True,
    level: int = 2,
    risk: int = 1,
) -> "list[dict[str, Any]]":
    """Run sqlmap and write events to out_path dir. Returns event list."""
    out_dir = Path(out_path).parent
    return collect_sqlmap_events(
        target_url, out_dir=out_dir, forms=forms, level=level, risk=risk
    )


__all__ = [
    "canonical_web_adapter_available",
    "canonical_web_auth_runtime_available",
    "collect_auth_surface_events",
    "collect_auth_surface_events_to_file",
    "collect_gobuster_events",
    "collect_gobuster_events_to_file",
    "collect_nikto_events",
    "collect_nikto_events_to_file",
    "collect_sqlmap_events",
    "collect_sqlmap_events_to_file",
    "collect_surface_events",
    "collect_surface_events_to_file",
    "collect_surface_profile",
]

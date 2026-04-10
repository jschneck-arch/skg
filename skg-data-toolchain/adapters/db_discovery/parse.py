"""
adapters/db_discovery/parse.py
================================
SSH-based database service discovery and exposure assessment.

Enumerates database services listening on a target host, tests default and
harvested credentials, checks bind addresses and auth configuration, and
emits obs.attack.precondition events for DE-* wickets from the db_exposure
catalog — without requiring a pre-configured data_sources.yaml.

Credential reuse: reads harvested credentials from the SKG state store
(HO-18 wicket payload) so that any password discovered on this host by
the host-toolchain adapter is automatically tested against any DB found.

Evidence ranks emitted:
  rank 1 (runtime) — live query result (auth success, SHOW DATABASES)
  rank 2 (harvested) — from SKG state store (harvested creds)
  rank 3 (config/binary) — config file read, process cmdline, version string
  rank 4 (network) — port listening confirmation

Usage (standalone):
  python parse.py --host 192.168.1.10 --user msfadmin --password msfadmin \\
                  --out /var/lib/skg/events/db_discovery.ndjson

  python parse.py --host 192.168.1.10 --user msfadmin --key ~/.ssh/id_rsa \\
                  --harvested-creds /var/lib/skg/state/harvested_creds.json \\
                  --workload-id metasploitable2 --out events.ndjson
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

try:
    import paramiko
    _HAVE_PARAMIKO = True
except ImportError:
    _HAVE_PARAMIKO = False

TOOLCHAIN    = "skg-data-toolchain"
SOURCE_ID    = "adapter.db_discovery"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# Database ports to probe
_DB_PORTS = {
    3306:  "mysql",
    5432:  "postgresql",
    27017: "mongodb",
    6379:  "redis",
    1433:  "mssql",
    1521:  "oracle",
    5984:  "couchdb",
    9200:  "elasticsearch",
}

# Table names suggesting sensitive data
_SENSITIVE_RE = re.compile(
    r"\b(user|account|password|passwd|credential|token|secret|auth|"
    r"payment|credit_card|card|ssn|social_security|health|medical|"
    r"salary|personal|session|api_key|private)\b",
    re.IGNORECASE,
)

# Config file locations per DB engine
_CONFIG_PATHS = {
    "mysql": [
        "/etc/mysql/my.cnf",
        "/etc/mysql/mysql.conf.d/mysqld.cnf",
        "/etc/my.cnf",
        "/etc/my.cnf.d/server.cnf",
    ],
    "postgresql": [
        "/etc/postgresql/*/main/postgresql.conf",
        "/var/lib/pgsql/data/postgresql.conf",
    ],
    "mongodb": [
        "/etc/mongod.conf",
        "/etc/mongodb.conf",
    ],
    "redis": [
        "/etc/redis/redis.conf",
        "/etc/redis.conf",
    ],
}


# ── Utilities ──────────────────────────────────────────────────────────────

def get_version() -> str:
    try:
        return VERSION_FILE.read_text().strip()
    except Exception:
        return "0.1.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ev(wicket_id: str, status: str, rank: int, confidence: float,
        detail: str, workload_id: str, run_id: str,
        source_kind: str = "db_discovery_runtime",
        pointer: str = "",
        attack_path_id: str = "") -> dict:
    now = iso_now()
    payload: dict = {
        "wicket_id":   wicket_id,
        "status":      status,
        "rank":        rank,
        "confidence":  confidence,
        "detail":      detail,
        "workload_id": workload_id,
        "run_id":      run_id,
        "observed_at": now,
    }
    if attack_path_id:
        payload["attack_path_id"] = attack_path_id
    return {
        "id":   str(uuid.uuid4()),
        "ts":   now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version":   get_version(),
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": rank,
            "evidence": {
                "source_kind": source_kind,
                "pointer":     pointer,
                "collected_at": now,
                "confidence":   round(confidence, 4),
            },
        },
    }


def _run(ssh: "paramiko.SSHClient", cmd: str, timeout: int = 15) -> str:
    """Execute command over SSH, return stdout or 'ERROR: <msg>'."""
    try:
        _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if out:
            return out
        if err:
            return err
        return ""
    except Exception as exc:
        return f"ERROR: {exc}"


# ── SSH connection ─────────────────────────────────────────────────────────

def _connect(host: str, port: int, user: str,
             password: str | None, key: str | None) -> "paramiko.SSHClient":
    if not _HAVE_PARAMIKO:
        raise RuntimeError("paramiko not installed")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict[str, Any] = {
        "hostname": host, "port": port, "username": user,
        "timeout": 15, "allow_agent": False, "look_for_keys": False,
    }
    if key:
        kwargs["key_filename"] = str(Path(key).expanduser().resolve())
    elif password:
        kwargs["password"] = password
    ssh.connect(**kwargs)
    return ssh


# ── Collection ────────────────────────────────────────────────────────────

def collect(host: str, ssh_port: int, user: str,
            password: str | None, key: str | None,
            harvested_creds: list[dict] | None = None) -> dict[str, Any]:
    """
    Connect to target via SSH and enumerate DB services and exposure.
    Returns a raw data dict consumed by the check_* functions.
    """
    try:
        ssh = _connect(host, ssh_port, user, password, key)
    except Exception as exc:
        return {"error": str(exc)}

    data: dict[str, Any] = {
        "host": host,
        "listening_ports": {},    # port -> "engine"
        "versions": {},           # engine -> version string
        "bind_addresses": {},     # engine -> bind addr string from config
        "auth_disabled": {},      # engine -> bool
        "default_cred_result": {},   # engine -> dict(user, pass, success, db_list)
        "harvested_cred_result": {}, # engine -> list of {user, pass, success, db_list}
        "config_text": {},        # engine -> config file text
        "sensitive_tables": {},   # engine -> list of table names
        "file_priv_users": [],    # list of mysql users with FILE priv
        "super_priv_users": [],   # list of users with SUPER/superuser
        "errors": [],
    }

    # ── 1. Port scan via ss ──────────────────────────────────────────────
    ss_out = _run(ssh, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    for port, engine in _DB_PORTS.items():
        if f":{port} " in ss_out or f":{port}\n" in ss_out or f":{port}\t" in ss_out:
            data["listening_ports"][port] = engine
        # Also try a direct TCP probe via bash /dev/tcp
        if port not in data["listening_ports"]:
            probe = _run(ssh,
                f"(echo > /dev/tcp/127.0.0.1/{port}) 2>/dev/null && echo open || echo closed",
                timeout=5)
            if "open" in probe:
                data["listening_ports"][port] = engine

    # ── 2. Version banners ───────────────────────────────────────────────
    if 3306 in data["listening_ports"]:
        ver = _run(ssh, "mysql --version 2>&1 | head -1")
        if "ERROR" not in ver and ver:
            data["versions"]["mysql"] = ver

    if 5432 in data["listening_ports"]:
        ver = _run(ssh, "psql --version 2>&1 | head -1")
        if "ERROR" not in ver and ver:
            data["versions"]["postgresql"] = ver

    if 27017 in data["listening_ports"]:
        ver = _run(ssh, "mongod --version 2>&1 | head -1")
        if "ERROR" not in ver and ver:
            data["versions"]["mongodb"] = ver

    if 6379 in data["listening_ports"]:
        ver = _run(ssh, "redis-server --version 2>&1 | head -1")
        if "ERROR" not in ver and ver:
            data["versions"]["redis"] = ver

    # ── 3. Config files ──────────────────────────────────────────────────
    for engine, paths in _CONFIG_PATHS.items():
        if not any(p == engine or data["listening_ports"].get(p) == engine
                   for p in data["listening_ports"]):
            continue
        for cfg_path in paths:
            if "*" in cfg_path:
                # Expand glob via ls
                ls_out = _run(ssh, f"ls {cfg_path} 2>/dev/null | head -3")
                if ls_out and "ERROR" not in ls_out and "No such" not in ls_out:
                    for line in ls_out.splitlines():
                        line = line.strip()
                        if line:
                            cfg_text = _run(ssh, f"cat {line} 2>/dev/null")
                            if cfg_text and "ERROR" not in cfg_text:
                                data["config_text"][engine] = cfg_text
                                break
            else:
                cfg_text = _run(ssh, f"cat {cfg_path} 2>/dev/null")
                if cfg_text and "ERROR" not in cfg_text and "No such" not in cfg_text:
                    data["config_text"][engine] = cfg_text
                    break

    # ── 4. Bind addresses from config ────────────────────────────────────
    if "mysql" in data["config_text"]:
        m = re.search(r"bind[-_]address\s*=\s*(\S+)", data["config_text"]["mysql"])
        if m:
            data["bind_addresses"]["mysql"] = m.group(1)

    if "postgresql" in data["config_text"]:
        m = re.search(r"listen_addresses\s*=\s*'([^']+)'",
                      data["config_text"]["postgresql"])
        if m:
            data["bind_addresses"]["postgresql"] = m.group(1)

    if "redis" in data["config_text"]:
        m = re.search(r"^bind\s+(.+)$", data["config_text"]["redis"], re.MULTILINE)
        if m:
            data["bind_addresses"]["redis"] = m.group(1)

    # ── 5. Auth disabled check ───────────────────────────────────────────
    if "mysql" in data["config_text"]:
        data["auth_disabled"]["mysql"] = "skip-grant-tables" in data["config_text"]["mysql"]

    if "mongodb" in data["config_text"]:
        cfg = data["config_text"]["mongodb"]
        # authorization: disabled (yaml) or --noauth (old style)
        data["auth_disabled"]["mongodb"] = (
            re.search(r"authorization\s*:\s*disabled", cfg, re.IGNORECASE) is not None
            or "noauth" in cfg.lower()
        )

    if "redis" in data["config_text"]:
        cfg = data["config_text"]["redis"]
        data["auth_disabled"]["redis"] = (
            "requirepass" not in cfg
            or re.search(r"^#\s*requirepass", cfg, re.MULTILINE) is not None
        )

    # ── 6. Default credential test ───────────────────────────────────────
    _DEFAULT_CREDS = [
        ("mysql",      3306,  "mysql -u root -h 127.0.0.1 --password='' -e 'SHOW DATABASES;' 2>&1",
         "root", ""),
        ("mysql",      3306,  "mysql -u root -h 127.0.0.1 -proot -e 'SHOW DATABASES;' 2>&1",
         "root", "root"),
        ("mysql",      3306,  "mysql -u root -h 127.0.0.1 -ptoor -e 'SHOW DATABASES;' 2>&1",
         "root", "toor"),
        ("postgresql", 5432,  "PGPASSWORD=postgres psql -U postgres -h 127.0.0.1 -c '\\l' 2>&1",
         "postgres", "postgres"),
        ("postgresql", 5432,  "PGPASSWORD='' psql -U postgres -h 127.0.0.1 -c '\\l' 2>&1",
         "postgres", ""),
        ("redis",      6379,  "redis-cli -h 127.0.0.1 PING 2>&1",
         "", ""),
    ]

    for engine, port, cmd, uname, pwd in _DEFAULT_CREDS:
        if port not in data["listening_ports"]:
            continue
        if engine in data["default_cred_result"] and \
                data["default_cred_result"][engine].get("success"):
            continue  # Already found a working default cred
        out = _run(ssh, cmd)
        success = (
            "Access denied" not in out
            and "authentication failed" not in out.lower()
            and "ERROR" not in out
            and bool(out)
        )
        if engine == "redis":
            success = "PONG" in out
        if success:
            # Collect DB list from output
            db_list: list[str] = []
            for line in out.splitlines():
                line = line.strip()
                if line and "|" not in line and "+" not in line and "(" not in line:
                    db_list.append(line)
            data["default_cred_result"][engine] = {
                "user": uname, "password": pwd,
                "success": True, "db_list": db_list, "raw": out[:500],
            }

    # ── 7. Harvested credential reuse ────────────────────────────────────
    for cred in (harvested_creds or []):
        c_user = cred.get("username", "")
        c_pass = cred.get("password", "")
        if not c_user or not c_pass:
            continue

        for port, engine in data["listening_ports"].items():
            if engine not in ("mysql", "postgresql"):
                continue
            if engine == "mysql":
                cmd = (f"mysql -u {c_user} -h 127.0.0.1 -p{c_pass} "
                       f"-e 'SHOW DATABASES;' 2>&1")
            else:
                cmd = (f"PGPASSWORD={c_pass} psql -U {c_user} -h 127.0.0.1 "
                       f"-c '\\l' 2>&1")
            out = _run(ssh, cmd)
            success = (
                "Access denied" not in out
                and "authentication failed" not in out.lower()
                and "ERROR" not in out
                and bool(out)
            )
            if success:
                db_list = [l.strip() for l in out.splitlines()
                           if l.strip() and "|" not in l and "+" not in l]
                if engine not in data["harvested_cred_result"]:
                    data["harvested_cred_result"][engine] = []
                data["harvested_cred_result"][engine].append({
                    "user": c_user, "password": c_pass,
                    "success": True, "db_list": db_list,
                })

    # ── 8. Sensitive table enumeration ───────────────────────────────────
    # Only run if we have working auth
    def _working_session(engine: str) -> str | None:
        if engine in data["default_cred_result"] and \
                data["default_cred_result"][engine].get("success"):
            r = data["default_cred_result"][engine]
            return r["user"], r["password"]
        if engine in data["harvested_cred_result"]:
            for r in data["harvested_cred_result"][engine]:
                if r.get("success"):
                    return r["user"], r["password"]
        return None

    for port, engine in data["listening_ports"].items():
        creds = _working_session(engine)
        if not creds:
            continue
        uname, pwd = creds
        if engine == "mysql":
            cmd = (f"mysql -u {uname} -h 127.0.0.1 "
                   f"{'-p' + pwd if pwd else '--password='} "
                   f"-e 'SELECT table_schema, table_name FROM information_schema.tables "
                   f"WHERE table_schema NOT IN (\"information_schema\",\"mysql\","
                   f"\"performance_schema\",\"sys\");' 2>&1")
            out = _run(ssh, cmd)
            if out and "ERROR" not in out:
                data["sensitive_tables"]["mysql"] = [
                    line.strip() for line in out.splitlines()
                    if _SENSITIVE_RE.search(line)
                ]
        elif engine == "postgresql":
            cmd = (f"PGPASSWORD={pwd} psql -U {uname} -h 127.0.0.1 "
                   f"-c 'SELECT table_catalog, table_name FROM information_schema.tables "
                   f"WHERE table_schema NOT IN (''information_schema'', ''pg_catalog'');' 2>&1")
            out = _run(ssh, cmd)
            if out and "ERROR" not in out:
                data["sensitive_tables"]["postgresql"] = [
                    line.strip() for line in out.splitlines()
                    if _SENSITIVE_RE.search(line)
                ]

    # ── 9. FILE and SUPER privilege check (MySQL) ────────────────────────
    if 3306 in data["listening_ports"]:
        creds = _working_session("mysql")
        if creds:
            uname, pwd = creds
            file_cmd = (
                f"mysql -u {uname} -h 127.0.0.1 "
                f"{'-p' + pwd if pwd else '--password='} "
                f"-e 'SELECT user, File_priv, Super_priv "
                f"FROM mysql.user WHERE File_priv=\"Y\" OR Super_priv=\"Y\";' 2>&1"
            )
            priv_out = _run(ssh, file_cmd)
            if priv_out and "ERROR" not in priv_out and "Access denied" not in priv_out:
                for line in priv_out.splitlines():
                    line = line.strip()
                    if not line or line.startswith(("user", "+", "-")):
                        continue
                    parts = [p.strip() for p in line.split("\t")]
                    if len(parts) >= 3:
                        uname_col, file_p, super_p = parts[0], parts[1], parts[2]
                        if file_p.upper() == "Y":
                            data["file_priv_users"].append(uname_col)
                        if super_p.upper() == "Y":
                            data["super_priv_users"].append(uname_col)

    ssh.close()
    return data


# ── Wicket checks ─────────────────────────────────────────────────────────

def check_de_01(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-01: db_service_listening"""
    if data.get("error"):
        return []
    ports = data.get("listening_ports", {})
    if ports:
        engines = ", ".join(f"{e} ({p})" for p, e in sorted(ports.items()))
        return [_ev("DE-01", "realized", 4, 0.90,
                    f"DB services listening: {engines}",
                    workload_id, run_id, pointer=f"ssh://{data['host']}:ss")]
    # If no ports found, emit blocked (no DB service on this host)
    return [_ev("DE-01", "blocked", 4, 0.75,
                "No database service ports found (checked 3306,5432,27017,6379,1433)",
                workload_id, run_id, pointer=f"ssh://{data['host']}:ss")]


def check_de_02(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-02: db_version_disclosed"""
    events = []
    for engine, ver in data.get("versions", {}).items():
        events.append(_ev("DE-02", "realized", 3, 0.85,
                          f"{engine} version: {ver}",
                          workload_id, run_id,
                          pointer=f"ssh://{data['host']}:{engine}"))
    if not events and data.get("listening_ports"):
        events.append(_ev("DE-02", "unknown", 3, 0.50,
                          "DB services found but version not obtainable",
                          workload_id, run_id))
    return events


def check_de_03(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-03: default_credentials_accepted"""
    events = []
    for engine, result in data.get("default_cred_result", {}).items():
        if result.get("success"):
            events.append(_ev(
                "DE-03", "realized", 1, 0.95,
                f"{engine}: default credential accepted "
                f"({result['user']}/{repr(result['password'])})",
                workload_id, run_id,
                pointer=f"ssh://{data['host']}:{engine}:default_auth",
            ))
    # For each DB found with no successful default cred, emit blocked
    for port, engine in data.get("listening_ports", {}).items():
        if engine in ("mysql", "postgresql", "redis") and \
                engine not in data.get("default_cred_result", {}):
            events.append(_ev("DE-03", "blocked", 1, 0.80,
                               f"{engine}: no default credentials accepted",
                               workload_id, run_id))
    return events


def check_de_04(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-04: cred_reuse_success"""
    events = []
    for engine, results in data.get("harvested_cred_result", {}).items():
        for r in results:
            if r.get("success"):
                events.append(_ev(
                    "DE-04", "realized", 2, 0.95,
                    f"{engine}: harvested credential accepted ({r['user']})",
                    workload_id, run_id,
                    pointer=f"ssh://{data['host']}:{engine}:cred_reuse",
                ))
    if not events and data.get("listening_ports"):
        events.append(_ev("DE-04", "unknown", 2, 0.50,
                          "No harvested credentials available to test",
                          workload_id, run_id))
    return events


def check_de_05(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-05: remote_access_allowed"""
    events = []
    for engine, bind in data.get("bind_addresses", {}).items():
        is_loopback = bind.strip() in ("127.0.0.1", "::1", "localhost")
        status = "blocked" if is_loopback else "realized"
        events.append(_ev(
            "DE-05", status, 3,
            0.90 if status == "realized" else 0.85,
            f"{engine} bind address: {bind}",
            workload_id, run_id,
            pointer=f"ssh://{data['host']}:{engine}:config",
        ))
    if not events and data.get("listening_ports"):
        events.append(_ev("DE-05", "unknown", 3, 0.45,
                          "Config not readable; bind address unknown",
                          workload_id, run_id))
    return events


def check_de_06(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-06: databases_enumerable"""
    events = []
    # Check default cred results for DB lists
    for engine, result in data.get("default_cred_result", {}).items():
        if result.get("success") and result.get("db_list"):
            dbs = result["db_list"][:10]
            events.append(_ev(
                "DE-06", "realized", 1, 0.95,
                f"{engine}: {len(dbs)} databases enumerated: {dbs}",
                workload_id, run_id,
                pointer=f"ssh://{data['host']}:{engine}:show_databases",
            ))
    for engine, results in data.get("harvested_cred_result", {}).items():
        if engine in [e for e, r in data.get("default_cred_result", {}).items()
                      if r.get("success")]:
            continue  # Already covered
        for r in results:
            if r.get("success") and r.get("db_list"):
                events.append(_ev(
                    "DE-06", "realized", 1, 0.90,
                    f"{engine}: {len(r['db_list'])} databases via cred reuse",
                    workload_id, run_id,
                ))
    if not events and data.get("listening_ports"):
        events.append(_ev("DE-06", "unknown", 1, 0.40,
                          "No authenticated session — cannot enumerate databases",
                          workload_id, run_id))
    return events


def check_de_07(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-07: sensitive_tables_visible"""
    events = []
    for engine, tables in data.get("sensitive_tables", {}).items():
        if tables:
            events.append(_ev(
                "DE-07", "realized", 1, 0.90,
                f"{engine}: {len(tables)} sensitive tables found: {tables[:5]}",
                workload_id, run_id,
                pointer=f"ssh://{data['host']}:{engine}:table_enum",
            ))
        else:
            events.append(_ev("DE-07", "blocked", 1, 0.75,
                               f"{engine}: no sensitive table names found",
                               workload_id, run_id))
    if not events and data.get("listening_ports"):
        events.append(_ev("DE-07", "unknown", 1, 0.40,
                          "No authenticated session — table enumeration skipped",
                          workload_id, run_id))
    return events


def check_de_08(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-08: auth_disabled"""
    events = []
    for engine, disabled in data.get("auth_disabled", {}).items():
        status = "realized" if disabled else "blocked"
        conf = 0.88 if disabled else 0.80
        events.append(_ev(
            "DE-08", status, 3, conf,
            f"{engine}: authentication {'disabled' if disabled else 'enabled'} in config",
            workload_id, run_id,
            pointer=f"ssh://{data['host']}:{engine}:config",
        ))
    if not events and data.get("listening_ports"):
        events.append(_ev("DE-08", "unknown", 3, 0.40,
                          "Config not readable; auth status unknown",
                          workload_id, run_id))
    return events


def check_de_09(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-09: db_config_readable"""
    events = []
    for engine, cfg in data.get("config_text", {}).items():
        if cfg:
            events.append(_ev(
                "DE-09", "realized", 3, 0.90,
                f"{engine} config readable ({len(cfg)} bytes)",
                workload_id, run_id,
                pointer=f"ssh://{data['host']}:{engine}:config_file",
            ))
    for port, engine in data.get("listening_ports", {}).items():
        if engine in _CONFIG_PATHS and engine not in data.get("config_text", {}):
            events.append(_ev("DE-09", "blocked", 3, 0.70,
                               f"{engine} config not readable (permission denied or not found)",
                               workload_id, run_id))
    return events


def check_de_10(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-10: db_user_with_file_priv"""
    file_users = data.get("file_priv_users", [])
    if file_users:
        return [_ev(
            "DE-10", "realized", 2, 0.92,
            f"MySQL users with FILE privilege: {file_users}",
            workload_id, run_id,
            pointer=f"ssh://{data['host']}:mysql:user_privs",
        )]
    if 3306 in data.get("listening_ports", {}):
        if data.get("default_cred_result", {}).get("mysql", {}).get("success") or \
                data.get("harvested_cred_result", {}).get("mysql"):
            return [_ev("DE-10", "blocked", 2, 0.80,
                        "No MySQL users with FILE privilege found",
                        workload_id, run_id)]
        return [_ev("DE-10", "unknown", 2, 0.40,
                    "MySQL found but no auth — FILE privilege unknown",
                    workload_id, run_id)]
    return []


def check_de_11(data: dict, workload_id: str, run_id: str) -> list[dict]:
    """DE-11: db_user_with_super_priv"""
    super_users = data.get("super_priv_users", [])
    if super_users:
        return [_ev(
            "DE-11", "realized", 2, 0.90,
            f"MySQL users with SUPER privilege: {super_users}",
            workload_id, run_id,
            pointer=f"ssh://{data['host']}:mysql:user_privs",
        )]
    if 3306 in data.get("listening_ports", {}):
        if data.get("default_cred_result", {}).get("mysql", {}).get("success") or \
                data.get("harvested_cred_result", {}).get("mysql"):
            return [_ev("DE-11", "blocked", 2, 0.75,
                        "No MySQL users with SUPER privilege found",
                        workload_id, run_id)]
        return [_ev("DE-11", "unknown", 2, 0.40,
                    "MySQL found but no auth — SUPER privilege unknown",
                    workload_id, run_id)]
    return []


# ── Helpers for combined run ───────────────────────────────────────────────

def _build_db_url(engine: str, host: str, port: int, user: str,
                  password: str, db_name: str) -> str:
    """Build a SQLAlchemy-compatible URL for a discovered database."""
    pw_part = f":{password}" if password else ""
    if engine == "mysql":
        return f"mysql+pymysql://{user}{pw_part}@{host}:{port}/{db_name}"
    elif engine == "postgresql":
        return f"postgresql://{user}{pw_part}@{host}:{port}/{db_name}"
    return ""


def _get_working_creds(data: dict, engine: str) -> tuple[str, str] | None:
    """Return (user, password) for the first working session for this engine."""
    dr = data.get("default_cred_result", {}).get(engine, {})
    if dr.get("success"):
        return dr["user"], dr["password"]
    for r in data.get("harvested_cred_result", {}).get(engine, []):
        if r.get("success"):
            return r["user"], r["password"]
    return None


def _profile_discovered_tables(
    data: dict,
    run_id: str,
    profile_tables: list[str] | None = None,
    max_tables: int = 5,
) -> list[dict]:
    """
    After SSH discovery finds working DB auth, run data quality profiling
    (DP-* wickets) on the discovered tables.

    Bridges db_discovery (DE-*) and db_profiler (DP-*) into one pass:
      - DE-* events establish that the DB is reachable and accessible
      - DP-* events profile actual data quality inside those databases

    profile_tables: explicit list to profile; if None, uses tables from
                    sensitive_tables + first tables in each DB.
    max_tables: cap to avoid running profiling on hundreds of tables.
    """
    profiler_path = Path(__file__).resolve().parents[2] / "adapters" / "db_profiler" / "profile.py"
    if not profiler_path.exists():
        return []

    import importlib.util
    spec = importlib.util.spec_from_file_location("skg_db_profiler", profiler_path)
    profiler = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(profiler)
    except Exception:
        return []

    _DB_DEFAULT_PORTS = {"mysql": 3306, "postgresql": 5432}
    all_dp_events: list[dict] = []
    host = data.get("host", "unknown")

    for port, engine in data.get("listening_ports", {}).items():
        if engine not in _DB_DEFAULT_PORTS:
            continue

        creds = _get_working_creds(data, engine)
        if not creds:
            continue

        user, password = creds
        db_list_raw = (
            data.get("default_cred_result", {}).get(engine, {}).get("db_list", [])
            or next(
                (r.get("db_list", []) for r in
                 data.get("harvested_cred_result", {}).get(engine, [])
                 if r.get("success")), []
            )
        )
        # Filter system databases
        _skip_dbs = {"information_schema", "mysql", "performance_schema",
                     "sys", "postgres", "template0", "template1"}
        user_dbs = [d for d in db_list_raw if d.lower() not in _skip_dbs][:3]

        if not user_dbs:
            continue

        for db_name in user_dbs:
            # Determine which tables to profile
            tables_to_profile: list[str] = []
            if profile_tables:
                tables_to_profile = profile_tables[:max_tables]
            else:
                # Prefer sensitive tables, then fall through to first few
                sens = data.get("sensitive_tables", {}).get(engine, [])
                # sensitive_tables entries are "schema.table" or just "table"
                tables_to_profile = [
                    t.split(".")[-1] for t in sens
                    if db_name.lower() in t.lower() or "." not in t
                ][:max_tables]

            if not tables_to_profile:
                continue

            url = _build_db_url(engine, "127.0.0.1", port, user, password, db_name)
            if not url:
                continue

            for table in tables_to_profile:
                workload_id = f"{engine}::{host}::{db_name}.{table}"
                try:
                    evs = profiler.profile_table(
                        url=url,
                        table=table,
                        workload_id=workload_id,
                        run_id=run_id,
                    )
                    all_dp_events.extend(evs)
                except Exception:
                    pass

    return all_dp_events


# ── Main entry point ───────────────────────────────────────────────────────

def run(host: str, ssh_port: int, user: str, password: str | None,
        key: str | None, workload_id: str, run_id: str | None = None,
        harvested_creds: list[dict] | None = None) -> list[dict]:
    """Full collection + all wicket checks. Returns list of event dicts."""
    run_id = run_id or str(uuid.uuid4())
    data = collect(host, ssh_port, user, password, key, harvested_creds)
    if data.get("error"):
        return []
    events: list[dict] = []
    for fn in [check_de_01, check_de_02, check_de_03, check_de_04,
               check_de_05, check_de_06, check_de_07, check_de_08,
               check_de_09, check_de_10, check_de_11]:
        try:
            events.extend(fn(data, workload_id, run_id))
        except Exception as exc:
            pass
    return events


def run_with_profiling(
    host: str, ssh_port: int, user: str, password: str | None,
    key: str | None, workload_id: str, run_id: str | None = None,
    harvested_creds: list[dict] | None = None,
    profile_tables: list[str] | None = None,
) -> tuple[list[dict], list[dict]]:
    """
    Combined DE-* security discovery + DP-* data quality profiling.

    Phase 1: SSH discovery — find DB services, test auth, check exposure.
             Returns DE-* wicket events.
    Phase 2: If auth succeeded, run db_profiler on found tables.
             Returns DP-* wicket events.

    Returns (de_events, dp_events) — callers can combine or keep separate.
    Gravity field uses this to update both the security field and the
    data quality field in one instrument run.
    """
    run_id = run_id or str(uuid.uuid4())
    raw = collect(host, ssh_port, user, password, key, harvested_creds)
    if raw.get("error"):
        return [], []

    de_events: list[dict] = []
    for fn in [check_de_01, check_de_02, check_de_03, check_de_04,
               check_de_05, check_de_06, check_de_07, check_de_08,
               check_de_09, check_de_10, check_de_11]:
        try:
            de_events.extend(fn(raw, workload_id, run_id))
        except Exception:
            pass

    dp_events = _profile_discovered_tables(raw, run_id, profile_tables)
    return de_events, dp_events


def main() -> None:
    p = argparse.ArgumentParser(description="SKG DB discovery adapter")
    p.add_argument("--host",             required=True)
    p.add_argument("--ssh-port",         type=int, default=22)
    p.add_argument("--user",             required=True)
    p.add_argument("--password",         default=None)
    p.add_argument("--key",              default=None)
    p.add_argument("--workload-id",      default="unknown")
    p.add_argument("--run-id",           default=None)
    p.add_argument("--harvested-creds",  default=None,
                   help="Path to JSON file with [{username,password},...] pairs")
    p.add_argument("--out",              required=True)
    a = p.parse_args()

    harvested: list[dict] | None = None
    if a.harvested_creds:
        try:
            harvested = json.loads(Path(a.harvested_creds).read_text())
        except Exception as exc:
            print(f"[db_discovery] warning: could not load harvested creds: {exc}",
                  file=sys.stderr)

    events = run(
        host=a.host, ssh_port=a.ssh_port, user=a.user,
        password=a.password, key=a.key, workload_id=a.workload_id,
        run_id=a.run_id, harvested_creds=harvested,
    )

    out_path = Path(a.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    print(f"[db_discovery] wrote {len(events)} events → {a.out}")


if __name__ == "__main__":
    main()

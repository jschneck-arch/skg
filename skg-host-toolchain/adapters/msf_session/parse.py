#!/usr/bin/env python3
"""
adapter: msf_session
====================
Connects to Metasploit RPC (msfrpcd), pulls active sessions, loot, and
credentials from the MSF database, and emits obs.attack.precondition
events for host wickets.

Falls back to a JSON dump file if the RPC is not available (useful for
offline analysis of previously exported MSF data).

Evidence ranks:
  rank 1 = runtime (active sessions, live loot from meterpreter)
  rank 2 = harvested artifacts (creds, hashes from loot files)

Usage (live RPC):
  python parse.py \\
    --rpc-host 127.0.0.1 --rpc-port 55553 --rpc-password msf \\
    --out /tmp/msf_events.ndjson \\
    --attack-path-id host_msf_post_exploitation_v1

Usage (offline JSON dump):
  python parse.py \\
    --json-dump /tmp/msf_export.json \\
    --out /tmp/msf_events.ndjson \\
    --attack-path-id host_msf_post_exploitation_v1
"""

import argparse, json, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN = "skg-host-toolchain"
SOURCE_ID = "adapter.msf_session"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"


def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path: Path, wicket_id: str, status: str,
         evidence_rank: int, source_kind: str, pointer: str, confidence: float,
         attack_path_id: str, run_id: str, workload_id: str,
         notes: str = "", attributes: dict = None):
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
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN, "version": get_version()},
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


# ---------------------------------------------------------------------------
# Transport layer — tries pymetasploit3, falls back to JSON
# ---------------------------------------------------------------------------

def _connect_rpc(host: str, port: int, password: str, ssl: bool = False):
    """Try to connect to MSF RPC. Returns client or raises."""
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
        client = MsfRpcClient(password, server=host, port=port, ssl=ssl)
        return client
    except ImportError:
        raise RuntimeError("pymetasploit3 not installed — pip install pymetasploit3")


def _get_sessions_rpc(client) -> list[dict]:
    """Get active sessions from MSF RPC."""
    sessions = []
    try:
        raw = client.sessions.list
        for sid, sinfo in raw.items():
            sessions.append({
                "id": str(sid),
                "type": sinfo.get("type", "unknown"),
                "tunnel_peer": sinfo.get("tunnel_peer", ""),
                "target_host": sinfo.get("target_host", sinfo.get("tunnel_peer", "").split(":")[0]),
                "via_exploit": sinfo.get("via_exploit", ""),
                "platform": sinfo.get("platform", ""),
                "username": sinfo.get("username", ""),
                "info": sinfo.get("info", ""),
            })
    except Exception as e:
        print(f"[WARN] Could not list sessions: {e}", flush=True)
    return sessions


def _get_creds_rpc(client) -> list[dict]:
    """Get credentials from MSF database."""
    creds = []
    try:
        for cred in client.db.creds():
            creds.append({
                "host": cred.get("host", ""),
                "service_name": cred.get("service_name", ""),
                "service_port": cred.get("service_port", 0),
                "username": cred.get("username", ""),
                "private_type": cred.get("private_type", ""),
                "origin_type": cred.get("origin_type", ""),
            })
    except Exception as e:
        print(f"[WARN] Could not list creds: {e}", flush=True)
    return creds


def _get_loot_rpc(client) -> list[dict]:
    """Get loot entries from MSF database."""
    loot_list = []
    try:
        for item in client.db.loots():
            loot_list.append({
                "host": item.get("host", ""),
                "ltype": item.get("ltype", ""),
                "name": item.get("name", ""),
                "content_type": item.get("content_type", ""),
                "info": item.get("info", ""),
            })
    except Exception as e:
        print(f"[WARN] Could not list loot: {e}", flush=True)
    return loot_list


def _get_hosts_rpc(client) -> list[dict]:
    """Get discovered hosts from MSF database."""
    hosts = []
    try:
        for h in client.db.hosts():
            hosts.append({
                "address": h.get("address", ""),
                "os_name": h.get("os_name", ""),
                "os_flavor": h.get("os_flavor", ""),
                "purpose": h.get("purpose", ""),
            })
    except Exception as e:
        print(f"[WARN] Could not list hosts: {e}", flush=True)
    return hosts


# ---------------------------------------------------------------------------
# Wicket emitters
# ---------------------------------------------------------------------------

def process_sessions(sessions: list[dict], out_path: Path,
                     attack_path_id: str, run_id: str,
                     default_wid: str, pointer: str):
    if not sessions:
        emit(out_path, "HO-17", "unknown", 1, "msf_rpc", pointer, 0.4,
             attack_path_id, run_id, default_wid,
             "No active MSF sessions found.")
        return

    for sess in sessions:
        target = sess.get("target_host") or sess.get("tunnel_peer", "").split(":")[0] or default_wid
        # Normalize to host::{ip} so identity joins with CLI and daemon paths.
        wid = f"host::{target}" if target and "::" not in target else target

        emit(out_path, "HO-17", "realized", 1, "msf_session", pointer, 0.99,
             attack_path_id, run_id, wid,
             f"Active MSF session {sess['id']} — {sess.get('type', '?')} on {target}",
             {
                 "session_id": sess["id"],
                 "session_type": sess.get("type", "unknown"),
                 "target": target,
                 "username": sess.get("username", ""),
                 "platform": sess.get("platform", ""),
                 "via_exploit": sess.get("via_exploit", ""),
             })

        # If we have a session with uid=0 context, also assert root access
        username = sess.get("username", "")
        if username in ("root", "SYSTEM", "NT AUTHORITY\\SYSTEM"):
            emit(out_path, "HO-10", "realized", 1, "msf_session", pointer, 0.95,
                 attack_path_id, run_id, wid,
                 f"Session running as {username}.",
                 {"username": username})


def process_creds(creds: list[dict], out_path: Path,
                  attack_path_id: str, run_id: str,
                  default_wid: str, pointer: str):
    if not creds:
        return

    # Group by host, normalizing to host::{ip} identity shape.
    by_host: dict[str, list] = {}
    for c in creds:
        raw = c.get("host") or default_wid
        h = f"host::{raw}" if raw and "::" not in raw else raw
        by_host.setdefault(h, []).append(c)

    for host, host_creds in by_host.items():
        cred_types = list({c.get("private_type", "unknown") for c in host_creds})
        emit(out_path, "HO-18", "realized", 2, "msf_creds_db", pointer, 0.9,
             attack_path_id, run_id, host,
             f"{len(host_creds)} credential(s) harvested for {host}.",
             {
                 "credential_count": len(host_creds),
                 "credential_types": cred_types,
                 "usernames": list({c.get("username", "") for c in host_creds if c.get("username")})[:10],
             })

        # Password reuse potential: if creds from one host look like domain creds
        domain_creds = [c for c in host_creds if "\\" in c.get("username", "")]
        if domain_creds:
            emit(out_path, "HO-22", "unknown", 2, "msf_creds_db", pointer, 0.6,
                 attack_path_id, run_id, host,
                 "Domain credential format observed; password reuse across hosts possible.",
                 {"domain_usernames": [c.get("username") for c in domain_creds[:5]]})


def process_loot(loot_items: list[dict], out_path: Path,
                 attack_path_id: str, run_id: str,
                 default_wid: str, pointer: str):
    if not loot_items:
        return

    by_host: dict[str, list] = {}
    for item in loot_items:
        raw = item.get("host") or default_wid
        h = f"host::{raw}" if raw and "::" not in raw else raw
        by_host.setdefault(h, []).append(item)

    for host, items in by_host.items():
        loot_types = list({i.get("ltype", "unknown") for i in items})

        # Loot can include sshkey, passwd, shadow, etc.
        has_ssh_key = any("ssh" in (i.get("ltype", "") + i.get("name", "")).lower() for i in items)
        has_passwd = any(
            any(k in (i.get("name", "") + i.get("ltype", "")).lower()
                for k in ("passwd", "shadow", "sam", "ntds"))
            for i in items
        )

        if has_ssh_key:
            emit(out_path, "HO-13", "realized", 2, "msf_loot", pointer, 0.85,
                 attack_path_id, run_id, host,
                 "SSH key material found in MSF loot for this host.",
                 {"loot_types": loot_types})

        if has_passwd:
            emit(out_path, "HO-09", "realized", 2, "msf_loot", pointer, 0.85,
                 attack_path_id, run_id, host,
                 "Password/hash file found in MSF loot (passwd/shadow/SAM/NTDS).",
                 {"loot_types": loot_types})


def process_hosts(hosts: list[dict], out_path: Path,
                  attack_path_id: str, run_id: str, pointer: str):
    for h in hosts:
        ip = h.get("address", "unknown")
        wid = f"host::{ip}" if ip and "::" not in ip else ip
        os_name = (h.get("os_name", "") + " " + h.get("os_flavor", "")).strip().lower()

        emit(out_path, "HO-01", "realized", 4, "msf_hosts_db", pointer, 0.8,
             attack_path_id, run_id, wid,
             f"MSF database entry for {ip} — os: {os_name or 'unknown'}",
             {"os": os_name, "purpose": h.get("purpose", "")})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="SKG MSF session adapter")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--rpc-host", help="MSF RPC host (default: 127.0.0.1)")
    group.add_argument("--json-dump", help="Path to exported MSF data JSON")
    ap.add_argument("--rpc-port", type=int, default=55553)
    ap.add_argument("--rpc-password", default="msf")
    ap.add_argument("--rpc-ssl", action="store_true", default=False)
    ap.add_argument("--out", required=True)
    ap.add_argument("--attack-path-id", default="host_msf_post_exploitation_v1")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--workload-id", default="msf_workspace")
    args = ap.parse_args()

    rid = args.run_id or str(uuid.uuid4())
    out_path = Path(args.out).expanduser().resolve()

    if args.rpc_host:
        pointer = f"msfrpc://{args.rpc_host}:{args.rpc_port}"
        print(f"[*] Connecting to MSF RPC at {args.rpc_host}:{args.rpc_port}", flush=True)
        try:
            client = _connect_rpc(args.rpc_host, args.rpc_port,
                                   args.rpc_password, args.rpc_ssl)
        except Exception as e:
            print(f"[WARN] MSF RPC connection failed: {e}", flush=True)
            emit(out_path, "HO-17", "unknown", 1, "msf_rpc", pointer, 0.3,
                 args.attack_path_id, rid, args.workload_id,
                 f"MSF RPC connection failed: {e}")
            return 1

        sessions = _get_sessions_rpc(client)
        creds    = _get_creds_rpc(client)
        loot     = _get_loot_rpc(client)
        hosts    = _get_hosts_rpc(client)
        print(f"[*] MSF: {len(sessions)} sessions, {len(creds)} creds, "
              f"{len(loot)} loot items, {len(hosts)} hosts", flush=True)

    else:
        pointer = f"file://{Path(args.json_dump).resolve()}"
        data = json.loads(Path(args.json_dump).read_text(encoding="utf-8"))
        sessions = data.get("sessions", [])
        creds    = data.get("creds", [])
        loot     = data.get("loot", [])
        hosts    = data.get("hosts", [])
        print(f"[*] Loaded MSF dump: {len(sessions)} sessions, {len(creds)} creds, "
              f"{len(loot)} loot items, {len(hosts)} hosts", flush=True)

    process_hosts(hosts, out_path, args.attack_path_id, rid, pointer)
    process_sessions(sessions, out_path, args.attack_path_id, rid, args.workload_id, pointer)
    process_creds(creds, out_path, args.attack_path_id, rid, args.workload_id, pointer)
    process_loot(loot, out_path, args.attack_path_id, rid, args.workload_id, pointer)

    print(f"[OK] MSF ingestion complete → {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

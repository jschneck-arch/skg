#!/usr/bin/env python3
"""
adapter: capa_analysis
========================================
Uses Mandiant FLARE capa to identify named capabilities and ATT&CK technique
mappings within a target binary. capa runs locally on the analyst machine;
the binary is fetched from the target via SFTP.

Collection pipeline:
  1. SSH/SFTP to target, download binary to local temp file
  2. Run: capa --json <local_binary>
  3. Parse matched rules for capability names and ATT&CK technique IDs
  4. Emit BA-07 and BA-08 wicket events

Wicket map:
  BA-07  capability_identified      capa matched ≥ 1 named capability rule
  BA-08  attck_technique_confirmed  capa mapped ≥ 1 ATT&CK technique ID

Evidence ranks:
  rank 2 = harvested (capability rules matched against binary)
  rank 3 = config/binary attributes (static analysis; no execution)

Usage:
  python parse.py \\
    --host 192.168.1.50 --user root --key ~/.ssh/id_rsa \\
    --binary /usr/local/bin/target_app \\
    --out /tmp/capa_events.ndjson \\
    --attack-path-id binary_offensive_capability_v1 \\
    --workload-id vuln-binary-host
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-binary-toolchain"
SOURCE_ID = "adapter.capa_analysis"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# Namespaces that indicate clearly offensive tradecraft
_OFFENSIVE_NAMESPACES = frozenset({
    "anti-analysis",
    "collection",
    "command-and-control",
    "credential-access",
    "defense-evasion",
    "discovery",
    "execution",
    "exfiltration",
    "impact",
    "lateral-movement",
    "persistence",
    "privilege-escalation",
})


def _version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(out_path: Path, wicket_id: str, status: str,
          evidence_rank: int, source_kind: str, pointer: str, confidence: float,
          attack_path_id: str, run_id: str, workload_id: str,
          notes: str = "", attributes: dict | None = None) -> None:
    now = _now()
    payload: dict = {
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
            "version": _version(),
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
    with open(out_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------------------
# capa execution & parsing
# ---------------------------------------------------------------------------

def _run_capa(local_binary: Path, timeout: int = 120) -> dict | None:
    """Run capa --json against a local binary. Returns parsed JSON or None."""
    capa_bin = shutil.which("capa")
    if not capa_bin:
        return None
    try:
        proc = subprocess.run(
            [capa_bin, "--json", str(local_binary)],
            capture_output=True,
            timeout=timeout,
        )
        raw = proc.stdout.decode("utf-8", errors="replace").strip()
        if not raw:
            return None
        # capa may emit non-JSON lines before the JSON block; find the opening brace
        brace = raw.find("{")
        if brace > 0:
            raw = raw[brace:]
        return json.loads(raw)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


def _extract_capabilities(capa_json: dict) -> tuple[list[str], list[dict]]:
    """
    Returns:
        capability_names: list of matched rule names
        attack_entries:   list of {tactic, technique, subtechnique, id} dicts
    """
    rules = capa_json.get("rules", {})
    capability_names: list[str] = []
    attack_entries: list[dict] = []
    seen_ids: set[str] = set()

    for rule_name, rule_data in rules.items():
        meta = rule_data.get("meta", {})
        # A rule counts as a capability if it has any matches
        matches = rule_data.get("matches", {})
        if not matches:
            continue

        capability_names.append(rule_name)

        # Collect ATT&CK entries — handle v3/v4/v5/v7 field shapes
        attack_list = meta.get("attack", []) or meta.get("tactics", [])
        for entry in attack_list:
            technique_id = entry.get("id", "") or entry.get("technique_id", "")
            if technique_id and technique_id not in seen_ids:
                seen_ids.add(technique_id)
                attack_entries.append({
                    "tactic": entry.get("tactic", ""),
                    "technique": entry.get("technique", ""),
                    "subtechnique": entry.get("subtechnique", ""),
                    "id": technique_id,
                })

    return capability_names, attack_entries


def _namespace_of(rule_data: dict) -> str:
    return rule_data.get("meta", {}).get("namespace", "")


def _offensive_capabilities(capa_json: dict, names: list[str]) -> list[str]:
    """Filter capability names that belong to offensive namespaces."""
    rules = capa_json.get("rules", {})
    out: list[str] = []
    for name in names:
        ns = _namespace_of(rules.get(name, {}))
        root = ns.split("/")[0].lower() if ns else ""
        if root in _OFFENSIVE_NAMESPACES:
            out.append(name)
    return out


# ---------------------------------------------------------------------------
# Check functions
# ---------------------------------------------------------------------------

def check_ba_07(
    capa_json: dict | None,
    out: Path,
    binary: str,
    apid: str,
    run_id: str,
    wid: str,
) -> list[str]:
    """BA-07: capability_identified — capa matched ≥ 1 named capability rule."""
    pointer = f"binary://{binary}/capa"

    if capa_json is None:
        _emit(out, "BA-07", "unknown", 3, "capa", pointer, 0.20, apid, run_id, wid,
              "capa not available or failed to execute; capability analysis skipped.")
        return []

    names, _ = _extract_capabilities(capa_json)
    offensive = _offensive_capabilities(capa_json, names)

    if not names:
        _emit(out, "BA-07", "blocked", 2, "capa", pointer, 0.80, apid, run_id, wid,
              "capa matched no capability rules; binary appears benign or stripped.",
              {"total_rules_matched": 0})
        return []

    confidence = min(0.95, 0.60 + len(offensive) * 0.05)
    _emit(out, "BA-07", "realized", 2, "capa", pointer, confidence, apid, run_id, wid,
          f"{len(names)} capability rule(s) matched; {len(offensive)} in offensive namespaces.",
          {
              "total_capabilities": len(names),
              "offensive_capabilities": len(offensive),
              "sample_capabilities": names[:10],
              "offensive_sample": offensive[:5],
          })
    return names


def check_ba_08(
    capa_json: dict | None,
    out: Path,
    binary: str,
    apid: str,
    run_id: str,
    wid: str,
) -> None:
    """BA-08: attck_technique_confirmed — capa mapped ≥ 1 ATT&CK technique ID."""
    pointer = f"binary://{binary}/capa/attack"

    if capa_json is None:
        _emit(out, "BA-08", "unknown", 3, "capa", pointer, 0.20, apid, run_id, wid,
              "capa not available; ATT&CK technique mapping skipped.")
        return

    _, attack_entries = _extract_capabilities(capa_json)

    if not attack_entries:
        _emit(out, "BA-08", "blocked", 2, "capa", pointer, 0.75, apid, run_id, wid,
              "capa found no ATT&CK technique mappings in matched rules.",
              {"attack_technique_count": 0})
        return

    technique_ids = [e["id"] for e in attack_entries]
    tactics = sorted({e["tactic"] for e in attack_entries if e["tactic"]})
    confidence = min(0.95, 0.70 + len(attack_entries) * 0.02)

    _emit(out, "BA-08", "realized", 2, "capa", pointer, confidence, apid, run_id, wid,
          f"{len(technique_ids)} ATT&CK technique(s) confirmed: {', '.join(technique_ids[:8])}",
          {
              "technique_ids": technique_ids,
              "tactics_covered": tactics,
              "technique_details": attack_entries[:15],
          })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(
    host: str,
    user: str,
    workload_id: str,
    run_id: str,
    *,
    password: str | None = None,
    key: str | None = None,
    ssh_port: int = 22,
    timeout: int = 30,
    binary: str = "",
    attack_path_id: str = "binary_offensive_capability_v1",
) -> list[dict]:
    """
    Programmatic entry point. Connects via SSH/SFTP, downloads the target binary,
    runs capa locally, and returns all BA-07/BA-08 events as a list.
    """
    import paramiko

    if not shutil.which("capa"):
        return []

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw: dict = {
        "hostname": host, "port": ssh_port,
        "username": user, "timeout": timeout,
    }
    if key:
        connect_kw["key_filename"] = str(Path(key).expanduser().resolve())
    elif password:
        connect_kw["password"] = password

    try:
        client.connect(**connect_kw)
    except Exception:
        return []

    candidates: list[str] = []
    if binary:
        candidates = [binary]
    else:
        try:
            _, out, _ = client.exec_command(
                "find / -perm -4000 -type f 2>/dev/null | head -8", timeout=20
            )
            candidates = [l.strip() for l in out.read().decode("utf-8", errors="replace").splitlines() if l.strip()]
        except Exception:
            candidates = []
    if not candidates:
        candidates = ["/bin/su"]

    all_events: list[dict] = []
    sftp = client.open_sftp()

    for bin_path in candidates:
        with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as tf:
            local_path = Path(tf.name)
        out_path = local_path.with_suffix(".ndjson")
        try:
            sftp.get(bin_path, str(local_path))
            capa_json = _run_capa(local_path, timeout=120)
            check_ba_07(capa_json, out_path, bin_path, attack_path_id, run_id, workload_id)
            check_ba_08(capa_json, out_path, bin_path, attack_path_id, run_id, workload_id)
            if out_path.exists():
                for line in out_path.read_text().splitlines():
                    line = line.strip()
                    if line:
                        try:
                            all_events.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass
        finally:
            local_path.unlink(missing_ok=True)
            out_path.unlink(missing_ok=True)

    sftp.close()
    client.close()
    return all_events


def main() -> None:
    p = argparse.ArgumentParser(
        description="capa adapter — emits BA-07/BA-08 wicket events."
    )
    p.add_argument("--host",           required=True)
    p.add_argument("--user",           required=True)
    p.add_argument("--password",       default=None)
    p.add_argument("--key",            default=None)
    p.add_argument("--port",           type=int, default=22)
    p.add_argument("--timeout",        type=int, default=30)
    p.add_argument("--binary",         required=True)
    p.add_argument("--out",            required=True)
    p.add_argument("--attack-path-id", required=True, dest="attack_path_id")
    p.add_argument("--workload-id",    default=None,  dest="workload_id")
    p.add_argument("--run-id",         default=None,  dest="run_id")
    args = p.parse_args()

    run_id      = args.run_id      or str(uuid.uuid4())
    workload_id = args.workload_id or f"{args.host}:{args.binary}"
    out_path    = Path(args.out)

    events = run(
        args.host, args.user, workload_id, run_id,
        password=args.password, key=args.key,
        ssh_port=args.port, timeout=args.timeout,
        binary=args.binary, attack_path_id=args.attack_path_id,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    print(f"[capa_analysis] {len(events)} events written to {out_path}")


if __name__ == "__main__":
    main()

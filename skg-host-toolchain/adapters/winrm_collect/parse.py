#!/usr/bin/env python3
"""
adapter: winrm_collect
======================
Connects to a Windows host via WinRM (pywinrm), executes a curated
PowerShell command suite, and emits obs.attack.precondition events
for host wickets on the Windows surface.

Evidence ranks:
  rank 1 = runtime (whoami, Get-Process, running state)
  rank 2 = installed artifacts (Get-Package, registry)
  rank 3 = configuration (policies, scheduled tasks, services)
  rank 4 = network (open ports, SMB/RDP exposure)

Usage:
  python parse.py \\
    --host 192.168.1.100 --user Administrator --password P@ssw0rd \\
    --out /tmp/win_events.ndjson \\
    --attack-path-id host_winrm_initial_access_v1 \\
    --workload-id DC01
"""

import argparse, json, re, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN = "skg-host-toolchain"
SOURCE_ID = "adapter.winrm_collect"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

AV_EDR_PROCS = {
    "crowdstrike", "falcon", "carbonblack", "cylance", "sentinel", "defender",
    "malwarebytes", "sophos", "kaspersky", "avast", "avg", "eset", "mcafee",
    "symantec", "norton", "webroot", "bitdefender",
}


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


def _ps(session, cmd: str) -> tuple[str, int]:
    """Run a PowerShell command via WinRM session."""
    try:
        result = session.run_ps(cmd)
        out = result.std_out.decode("utf-8", errors="replace").strip() if result.std_out else ""
        return out, result.status_code
    except Exception as e:
        return "", -1


def eval_ho04_winrm(host: str, port: int, out: Path, apid: str, rid: str, wid: str):
    emit(out, "HO-04", "realized", 1, "winrm_auth", f"winrm://{host}:{port}", 0.95,
         apid, rid, wid, f"WinRM service confirmed accessible on {host}:{port}.",
         {"port": port})


def eval_ho05_credential(host: str, user: str, out: Path, apid: str, rid: str, wid: str):
    emit(out, "HO-05", "realized", 1, "winrm_auth", f"winrm://{host}", 0.99,
         apid, rid, wid, f"WinRM credential valid for '{user}'.",
         {"user": user})


def eval_ho10_admin(session, host: str, out: Path, apid: str, rid: str, wid: str):
    stdout, rc = _ps(session, "whoami /groups /fo csv 2>&1 | Select-String 'S-1-5-32-544|Domain Admins'")
    if rc != 0 or not stdout:
        stdout2, _ = _ps(session, "[Security.Principal.WindowsIdentity]::GetCurrent().Groups | %{$_.Value}")
        is_admin = "S-1-5-32-544" in stdout2  # Administrators SID
    else:
        is_admin = bool(stdout)

    if is_admin:
        emit(out, "HO-10", "realized", 1, "winrm_command", f"winrm://{host}/whoami", 0.95,
             apid, rid, wid, "User is member of local Administrators group.",
             {"is_local_admin": True})
    else:
        emit(out, "HO-10", "unknown", 1, "winrm_command", f"winrm://{host}/whoami", 0.7,
             apid, rid, wid, "User does not appear to be local Administrator.")


def eval_ho09_cred_in_env(session, host: str, out: Path, apid: str, rid: str, wid: str):
    stdout, _ = _ps(session, "Get-ChildItem Env: | Select-Object Name,Value | ConvertTo-Json")
    cred_patterns = [r"(?i)(password|passwd|secret|token|api.?key|aws.?secret)"]
    hits = []
    for pat in cred_patterns:
        matches = re.findall(pat, stdout)
        hits.extend(matches)

    if hits:
        emit(out, "HO-09", "realized", 1, "winrm_command", f"winrm://{host}/env", 0.8,
             apid, rid, wid, "Credential indicator found in environment variables.",
             {"env_key_patterns": list(set(hits))[:10]})
    else:
        emit(out, "HO-09", "unknown", 1, "winrm_command", f"winrm://{host}/env", 0.4,
             apid, rid, wid, "No obvious credential patterns in environment variables.")


def eval_ho11_vuln_packages(session, host: str, out: Path, apid: str, rid: str, wid: str):
    stdout, rc = _ps(session,
        "Get-Package | Select-Object Name,Version | ConvertTo-Json -Compress 2>&1 | Select-Object -First 200")
    if rc == 0 and stdout:
        try:
            pkgs = json.loads(stdout) if stdout.startswith("[") else []
            count = len(pkgs) if isinstance(pkgs, list) else 0
        except Exception:
            count = len(stdout.splitlines())
        emit(out, "HO-11", "unknown", 2, "winrm_command", f"winrm://{host}/packages", 0.5,
             apid, rid, wid,
             f"Package list collected ({count} entries). CVE cross-reference required.",
             {"package_count": count, "packages_sample": stdout[:500]})
    else:
        # Try wmic fallback
        stdout2, _ = _ps(session, "wmic product get Name,Version /format:csv 2>&1 | Select-Object -First 50")
        emit(out, "HO-11", "unknown", 2, "winrm_command", f"winrm://{host}/packages", 0.35,
             apid, rid, wid, "Package enumeration partially successful; CVE cross-reference required.",
             {"wmic_sample": stdout2[:300]})


def eval_ho19_smb(session, host: str, out: Path, apid: str, rid: str, wid: str):
    stdout, _ = _ps(session,
        "Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in 445,139} | Select-Object LocalAddress,LocalPort")
    if stdout and ("445" in stdout or "139" in stdout):
        emit(out, "HO-19", "realized", 1, "winrm_command", f"winrm://{host}/netstat", 0.9,
             apid, rid, wid, "SMB (445/139) is listening on this host.",
             {"listening_ports": [445, 139]})
    else:
        emit(out, "HO-19", "unknown", 1, "winrm_command", f"winrm://{host}/netstat", 0.5,
             apid, rid, wid, "Could not confirm SMB listener state via WinRM.")


def eval_ho20_rdp(session, host: str, out: Path, apid: str, rid: str, wid: str):
    stdout, _ = _ps(session,
        "Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -eq 3389} | Select-Object LocalAddress,LocalPort")
    if stdout and "3389" in stdout:
        emit(out, "HO-20", "realized", 1, "winrm_command", f"winrm://{host}/netstat", 0.9,
             apid, rid, wid, "RDP (3389) is listening on this host.")
    else:
        emit(out, "HO-20", "unknown", 1, "winrm_command", f"winrm://{host}/netstat", 0.5,
             apid, rid, wid, "RDP listener not confirmed; may be firewalled or disabled.")


def eval_ho23_av_edr(session, host: str, out: Path, apid: str, rid: str, wid: str):
    stdout, _ = _ps(session, "Get-Process | Select-Object Name | ConvertTo-Json -Compress 2>&1")
    procs_lower = stdout.lower()
    found = [av for av in AV_EDR_PROCS if av in procs_lower]

    if not found:
        emit(out, "HO-23", "realized", 1, "winrm_command", f"winrm://{host}/processes", 0.7,
             apid, rid, wid, "No known AV/EDR processes detected.")
    else:
        emit(out, "HO-23", "blocked", 1, "winrm_command", f"winrm://{host}/processes", 0.8,
             apid, rid, wid, f"AV/EDR process detected: {found[0]}",
             {"av_edr_found": found[:5]})


def eval_ho24_domain_joined(session, host: str, out: Path, apid: str, rid: str, wid: str):
    stdout, _ = _ps(session,
        "(Get-WmiObject Win32_ComputerSystem).PartOfDomain")
    if stdout.strip().lower() == "true":
        domain_out, _ = _ps(session, "(Get-WmiObject Win32_ComputerSystem).Domain")
        emit(out, "HO-24", "realized", 1, "winrm_command", f"winrm://{host}/domain", 0.95,
             apid, rid, wid, "Host is domain-joined.",
             {"domain": domain_out.strip()[:100]})
    else:
        emit(out, "HO-24", "blocked", 1, "winrm_command", f"winrm://{host}/domain", 0.85,
             apid, rid, wid, "Host is not domain-joined (workgroup).")


def eval_ho08_writable_tasks(session, host: str, out: Path, apid: str, rid: str, wid: str):
    stdout, _ = _ps(session,
        "Get-ScheduledTask | Where-Object {$_.TaskPath -ne '\\'} | "
        "Select-Object TaskName,TaskPath -First 30 | ConvertTo-Json -Compress 2>&1")
    # Check for writable service executables
    svc_out, _ = _ps(session,
        "Get-WmiObject win32_service | Select-Object Name,PathName | "
        "Where-Object {$_.PathName -ne $null} | "
        "Select-Object -First 20 | ConvertTo-Json -Compress 2>&1")

    if stdout or svc_out:
        emit(out, "HO-08", "unknown", 3, "winrm_command", f"winrm://{host}/tasks", 0.4,
             apid, rid, wid,
             "Scheduled tasks and services enumerated; writability check requires deeper analysis.",
             {"task_count": len(stdout.splitlines()), "service_sample": svc_out[:200]})
    else:
        emit(out, "HO-08", "unknown", 3, "winrm_command", f"winrm://{host}/tasks", 0.3,
             apid, rid, wid, "Could not enumerate scheduled tasks or services.")


def main():
    ap = argparse.ArgumentParser(description="SKG WinRM host collection adapter")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=5985)
    ap.add_argument("--ssl", action="store_true", default=False)
    ap.add_argument("--out", required=True)
    ap.add_argument("--attack-path-id", default="host_winrm_initial_access_v1")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--workload-id", default=None)
    args = ap.parse_args()

    try:
        import winrm
    except ImportError:
        print("ERROR: pywinrm is required — pip install pywinrm")
        return 1

    rid = args.run_id or str(uuid.uuid4())
    wid = args.workload_id or args.host
    out_path = Path(args.out).expanduser().resolve()

    transport = "ssl" if args.ssl else "ntlm"
    try:
        session = winrm.Session(
            f"{'https' if args.ssl else 'http'}://{args.host}:{args.port}/wsman",
            auth=(args.user, args.password),
            transport=transport,
        )
        # Quick connectivity test
        test = session.run_ps("$true")
        if test.status_code != 0:
            raise RuntimeError(f"WinRM test command failed: {test.std_err}")
    except Exception as e:
        emit(out_path, "HO-04", "unknown", 4, "winrm_connect_attempt",
             f"winrm://{args.host}:{args.port}", 0.5,
             args.attack_path_id, rid, wid, f"WinRM connection failed: {e}")
        emit(out_path, "HO-05", "blocked", 1, "winrm_connect_attempt",
             f"winrm://{args.host}:{args.port}", 0.8,
             args.attack_path_id, rid, wid, f"WinRM authentication failed: {e}")
        print(f"[WARN] WinRM connection failed: {e}", flush=True)
        return 1

    print(f"[*] Connected to {args.host}:{args.port} via WinRM as {args.user}", flush=True)

    eval_ho04_winrm(args.host, args.port, out_path, args.attack_path_id, rid, wid)
    eval_ho05_credential(args.host, args.user, out_path, args.attack_path_id, rid, wid)
    eval_ho10_admin(session, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho09_cred_in_env(session, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho11_vuln_packages(session, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho19_smb(session, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho20_rdp(session, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho23_av_edr(session, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho24_domain_joined(session, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho08_writable_tasks(session, args.host, out_path, args.attack_path_id, rid, wid)

    print(f"[OK] Collection complete → {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

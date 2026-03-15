"""
adapters/firmware_probe/__init__.py
=====================================
IoT firmware probe adapter — collects IF-* wicket evidence from live
devices (SSH) or static firmware images.

Evidence ranks:
  rank 1  live SSH query to running device
  rank 2  static analysis of extracted firmware / string scan
  rank 3  firmware metadata / version string from image header
  rank 5  CVE database cross-reference (NVD)
  rank 6  heuristic / behavioural probe

Tri-state semantics:
  REALIZED  — vulnerable condition confirmed
  BLOCKED   — constraint prevents (patched, feature disabled, absent)
  UNKNOWN   — condition not yet measurable

Usage:
  python -m adapters.firmware_probe --host 192.168.1.1 --user root --out events.ndjson
  python -m adapters.firmware_probe --image firmware.bin --out events.ndjson
"""
from __future__ import annotations
import argparse, json, re, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN  = "skg-iot_firmware-toolchain"
SOURCE_ID  = "adapter.firmware_probe"

# Known-vulnerable version thresholds (from NVD)
KNOWN_VULNERABLE = {
    "busybox": [
        {"below": "1.34.0", "cve": "CVE-2022-48174",  "desc": "stack overflow in ash/hush"},
        {"below": "1.32.1", "cve": "CVE-2021-42373",  "desc": "NULL deref in man applet"},
        {"below": "1.30.0", "cve": "CVE-2019-5747",   "desc": "out-of-bounds read"},
    ],
    "dropbear": [
        {"below": "2020.80", "cve": "CVE-2020-36254", "desc": "use-after-free in svr-auth"},
        {"below": "2019.78", "cve": "CVE-2018-15599", "desc": "user enum side channel"},
    ],
    "openssl": [
        {"below": "1.1.1t",  "cve": "CVE-2023-0286",  "desc": "type confusion in X.400"},
        {"below": "1.0.2u",  "cve": "CVE-2022-0778",  "desc": "BN_mod_sqrt infinite loop"},
    ],
    "dnsmasq": [
        {"below": "2.83",    "cve": "CVE-2020-25681",  "desc": "DNSpooq stack overflow"},
    ],
}

HARDCODED_CRED_PATTERNS = [
    r"root:(\$1\$|\$5\$|\$6\$)[^:]+:",
    r"admin:\$",
    r"password\s*=\s*['\"]?[a-z0-9]{4,}",
    r"(admin|root|user):(admin|root|1234|password|12345|changeme)",
]

def iso_now(): return datetime.now(timezone.utc).isoformat()

def _ev(wid, status, rank, conf, detail, workload_id, run_id, apid, sk="firmware_probe"):
    now = iso_now()
    return {
        "id": str(uuid.uuid4()), "ts": now, "type": "obs.attack.precondition",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN, "version": "0.1.0"},
        "payload": {"wicket_id": wid, "status": status, "workload_id": workload_id,
                    "detail": str(detail)[:400], "attack_path_id": apid,
                    "run_id": run_id, "observed_at": now},
        "provenance": {"evidence_rank": rank,
                       "evidence": {"source_kind": sk, "pointer": workload_id,
                                    "collected_at": now, "confidence": conf}},
    }

def _parse_version(v):
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums) if nums else (0,)

def _version_below(installed, below):
    try: return _parse_version(installed) < _parse_version(below)
    except: return False

def _run_ssh(client, cmd, timeout=15):
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        rc  = stdout.channel.recv_exit_status()
        return out, rc
    except Exception as exc:
        return "", 1

def _check_versions(events, raw_str, workload_id, run_id, apid, rank):
    """Check all known-vulnerable packages in a string corpus."""
    checks = [
        ("busybox",  r"BusyBox v?(\d+\.\d+[\d.]*)",       "IF-03", "IF-04"),
        ("dropbear", r"[Dd]ropbear(?:SSH)? v?(\d{4}\.\d+)", "IF-05", "IF-05"),
        ("openssl",  r"OpenSSL (\d+\.\d+[\d.\w]*)",       "IF-08", "IF-08"),
        ("dnsmasq",  r"[Dd]nsmasq v?(\d+\.\d+)",            "IF-09", "IF-09"),
    ]
    for pkg, pattern, wid_vuln, wid_cve in checks:
        m = re.search(pattern, raw_str)
        if not m:
            continue
        ver = m.group(1)
        hit = False
        for vuln in KNOWN_VULNERABLE.get(pkg, []):
            if _version_below(ver, vuln["below"]):
                events.append(_ev(wid_vuln, "realized", rank, 0.88,
                                  f"{pkg} {ver} < {vuln['below']}: {vuln['desc']}",
                                  workload_id, run_id, apid))
                if wid_cve != wid_vuln:
                    events.append(_ev(wid_cve, "realized", 5, 0.75,
                                      f"{vuln['cve']} confirmed for {pkg} {ver}",
                                      workload_id, run_id, apid))
                hit = True
                break
        if not hit:
            events.append(_ev(wid_vuln, "blocked", rank, 0.75,
                              f"{pkg} {ver} — no CVE match in catalog",
                              workload_id, run_id, apid))

def collect_live(host, user, key, password, port, workload_id, run_id, apid):
    try:
        import paramiko
    except ImportError:
        return [_ev("IF-01", "unknown", 4, 0.3, "paramiko not installed",
                    workload_id, run_id, apid)]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    events = []

    try:
        if key:
            client.connect(host, port=port, username=user,
                           key_filename=str(Path(key).expanduser()), timeout=15)
        elif password:
            client.connect(host, port=port, username=user, password=password, timeout=15)
        else:
            client.connect(host, port=port, username=user, timeout=15)
    except Exception as exc:
        return [_ev("IF-01", "blocked", 4, 0.9, f"SSH failed: {exc}",
                    workload_id, run_id, apid)]

    events.append(_ev("IF-01", "realized", 1, 0.99,
                      f"SSH connected to {host}:{port} as {user}",
                      workload_id, run_id, apid))

    # IF-02: management service exposed
    out, _ = _run_ssh(client, "ss -tnlp 2>/dev/null || netstat -tnlp 2>/dev/null | head -20")
    mgmt = [p for p in ["23","80","443","8080","8443"] if f":{p}" in out]
    status = "realized" if mgmt else "unknown"
    events.append(_ev("IF-02", status, 1, 0.88 if mgmt else 0.50,
                      f"Management ports: {mgmt}" if mgmt else "No management ports",
                      workload_id, run_id, apid))

    # IF-03/IF-04: busybox, IF-08: openssl
    for cmd in ["busybox --version 2>/dev/null", "openssl version 2>/dev/null"]:
        out, _ = _run_ssh(client, cmd)
        if out:
            _check_versions(events, out, workload_id, run_id, apid, rank=1)

    # IF-05: hardcoded credentials
    shadow, _ = _run_ssh(client, "cat /etc/shadow 2>/dev/null | head -5")
    hc = [p for p in HARDCODED_CRED_PATTERNS if re.search(p, shadow, re.IGNORECASE)]
    if hc:
        events.append(_ev("IF-05", "realized", 2, 0.85,
                          f"Hardcoded cred pattern in /etc/shadow: {hc[0][:60]}",
                          workload_id, run_id, apid))

    # IF-06: telnet
    teln, _ = _run_ssh(client, "pgrep -x telnetd 2>/dev/null; which telnetd 2>/dev/null")
    events.append(_ev("IF-06", "realized" if teln.strip() else "blocked", 1,
                      0.95 if teln.strip() else 0.85,
                      "telnetd running" if teln.strip() else "telnetd not running",
                      workload_id, run_id, apid))

    # IF-10: debug interfaces
    dbg, _ = _run_ssh(client, "ls /dev/ttyS* /dev/ttyUSB* 2>/dev/null | head -5")
    if dbg.strip():
        events.append(_ev("IF-10", "realized", 2, 0.70,
                          f"Debug serial interfaces: {dbg[:80]}", workload_id, run_id, apid))

    client.close()
    return events

def collect_from_image(image_path, workload_id, run_id, apid):
    events = []
    img = Path(image_path)
    if not img.exists():
        return [_ev("IF-01","blocked",3,0.99,f"Image not found: {image_path}",
                    workload_id, run_id, apid)]

    events.append(_ev("IF-01","realized",3,0.80,
                      f"Firmware image: {img.name} ({img.stat().st_size} bytes)",
                      workload_id, run_id, apid))

    raw_str = img.read_bytes()[:2_000_000].decode("utf-8", errors="replace")
    _check_versions(events, raw_str, workload_id, run_id, apid, rank=2)

    # Hardcoded creds in image
    hc = [p for p in HARDCODED_CRED_PATTERNS if re.search(p, raw_str, re.IGNORECASE)]
    if hc:
        events.append(_ev("IF-05","realized",2,0.85,
                          f"Hardcoded cred in image: {hc[0][:60]}",
                          workload_id, run_id, apid))

    # Telnet
    if "telnetd" in raw_str:
        events.append(_ev("IF-06","realized",2,0.75,"telnetd in firmware image",
                          workload_id, run_id, apid))
    else:
        events.append(_ev("IF-06","blocked",2,0.70,"telnetd not found in image",
                          workload_id, run_id, apid))

    # Debug strings
    dbg = re.findall(r"(?:JTAG|uart|ttyS\d|/dev/console|DEBUG_PORT)", raw_str, re.IGNORECASE)
    if dbg:
        events.append(_ev("IF-10","realized",2,0.65,
                          f"Debug strings: {list(set(dbg[:5]))}",
                          workload_id, run_id, apid))

    return events

def run_firmware_probe(host=None, image_path=None, user="root",
                       key=None, password=None, port=22,
                       workload_id=None, attack_path_id="firmware_rce_via_busybox_v1",
                       run_id=None):
    run_id = run_id or str(uuid.uuid4())[:8]
    workload_id = workload_id or f"iot::{host or image_path or 'unknown'}"
    if host:
        return collect_live(host, user, key, password, port, workload_id, run_id, attack_path_id)
    elif image_path:
        return collect_from_image(image_path, workload_id, run_id, attack_path_id)
    return [_ev("IF-01","unknown",3,0.2,"No host or image provided",
                workload_id, run_id, attack_path_id)]

def main():
    p = argparse.ArgumentParser(description="SKG IoT firmware probe")
    p.add_argument("--host",     default=None)
    p.add_argument("--user",     default="root")
    p.add_argument("--key",      default=None)
    p.add_argument("--password", default=None)
    p.add_argument("--port",     type=int, default=22)
    p.add_argument("--image",    default=None)
    p.add_argument("--workload-id",    dest="workload_id",    default=None)
    p.add_argument("--attack-path-id", dest="attack_path_id",
                   default="firmware_rce_via_busybox_v1")
    p.add_argument("--run-id",   dest="run_id", default=None)
    p.add_argument("--out",      required=True)
    a = p.parse_args()
    events = run_firmware_probe(
        host=a.host, image_path=a.image,
        user=a.user, key=a.key, password=a.password, port=a.port,
        workload_id=a.workload_id, attack_path_id=a.attack_path_id, run_id=a.run_id)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out,"w") as f:
        for ev in events: f.write(json.dumps(ev)+"\n")
    r = sum(1 for e in events if e["payload"]["status"]=="realized")
    b = sum(1 for e in events if e["payload"]["status"]=="blocked")
    u = sum(1 for e in events if e["payload"]["status"]=="unknown")
    print(f"  {len(events)} events: {r}R {b}B {u}U → {a.out}")

if __name__ == "__main__":
    main()

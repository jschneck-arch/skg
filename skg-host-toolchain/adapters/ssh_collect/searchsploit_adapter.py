"""
searchsploit_adapter.py
=======================
Exploit-DB search via searchsploit for discovered service versions.
Emits high-confidence wickets when public exploits exist for detected versions.
"""
from __future__ import annotations
import json, re, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Service → primary wicket when exploit found
SERVICE_WICKET = {
    "apache":       ("WB-21", "web"),
    "nginx":        ("WB-21", "web"),
    "openssh":      ("HO-25", "host"),
    "samba":        ("HO-25", "host"),
    "vsftpd":       ("HO-25", "host"),
    "proftpd":      ("HO-25", "host"),
    "mysql":        ("DP-06", "data"),
    "tomcat":       ("WB-21", "web"),
}


def run_searchsploit(service_banners: list[dict], out_dir: Path) -> list[dict]:
    """
    Search exploit-db for each service banner.
    service_banners: [{"service": "ssh", "banner": "OpenSSH 7.4", "port": 22}]
    """
    try:
        subprocess.run(["searchsploit", "--help"], capture_output=True, timeout=5)
    except FileNotFoundError:
        return []

    events = []
    now = datetime.now(timezone.utc).isoformat()
    out_dir.mkdir(parents=True, exist_ok=True)

    for svc in service_banners:
        banner = svc.get("banner", "") or svc.get("service", "")
        if not banner:
            continue

        try:
            proc = subprocess.run(
                ["searchsploit", "--json", banner],
                capture_output=True, text=True, timeout=30
            )
            data = json.loads(proc.stdout)
            exploits = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
        except Exception:
            continue

        if not exploits:
            continue

        # Classify by service type
        banner_lower = banner.lower()
        wicket_id = "HO-25"  # default: confirmed exploitable
        domain = "host"
        for svc_key, (wid, dom) in SERVICE_WICKET.items():
            if svc_key in banner_lower:
                wicket_id = wid
                domain = dom
                break

        # Pick highest-confidence exploit
        rce_exploits = [e for e in exploits
                        if re.search(r"(remote|rce|code exec|command)",
                                     e.get("Title",""), re.IGNORECASE)]
        top_exploits = (rce_exploits or exploits)[:3]
        titles = [e.get("Title","")[:80] for e in top_exploits]

        events.append({
            "type": "obs.attack.precondition",
            "id": str(uuid.uuid4()),
            "ts": now,
            "payload": {
                "wicket_id": wicket_id,
                "target_ip": svc.get("target_ip", ""),
                "workload_id": f"{domain}::{svc.get('target_ip','')}",
                "domain": domain,
                "status": "realized",
                "confidence": 0.80 if rce_exploits else 0.65,
                "evidence": f"searchsploit: {len(exploits)} exploits for '{banner}'. Top: {titles[0] if titles else ''}",
                "decay_class": "structural",
                "source": "searchsploit",
                "exploit_titles": titles,
                "exploit_count": len(exploits),
            },
        })
        print(f"  [SEARCHSPLOIT] {banner}: {len(exploits)} exploits ({len(rce_exploits)} RCE)")

    return events

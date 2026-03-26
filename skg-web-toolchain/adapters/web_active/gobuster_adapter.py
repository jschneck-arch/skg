"""
gobuster_adapter.py
===================
Web directory and file enumeration via gobuster.
Emits obs.attack.precondition events for:
  WB-03: admin panel / hidden paths discovered
  WB-04: backup files / source exposure
  WB-15: directory traversal indicators
  WB-17: server info / debug exposure
  WB-20: webshell / backdoor path indicators
"""
from __future__ import annotations
import json, re, subprocess, sys, uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/SecLists/Discovery/Web-Content/common.txt",
]

# Paths that indicate admin panels, backup files, debug endpoints, webshells
INTERESTING_PATTERNS = {
    "WB-03": [r"admin", r"manager", r"console", r"login", r"dashboard", r"cpanel", r"phpmyadmin"],
    "WB-04": [r"\.bak$", r"\.old$", r"\.backup$", r"\.sql$", r"\.zip$", r"backup", r"db\."],
    "WB-15": [r"\.\./", r"\.\.%2f", r"etc/passwd", r"windows/win.ini"],
    "WB-17": [r"server-status", r"server-info", r"phpinfo", r"info\.php", r"test\.php", r"\.git/"],
    "WB-20": [r"shell", r"webshell", r"cmd\.php", r"exec\.php", r"c99", r"r57"],
}

def run_gobuster(target_url: str, out_file: Path, wordlist: str | None = None) -> list[dict]:
    """Run gobuster dir against target_url, parse results, return events."""
    # Find wordlist
    wl = wordlist
    if not wl:
        for candidate in WORDLIST_CANDIDATES:
            if Path(candidate).exists():
                wl = candidate
                break
    if not wl:
        # Fall back to a minimal built-in list
        wl = _write_minimal_wordlist()

    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wl,
        "-t", "20",
        "--no-error",
        "-q",
        "--timeout", "10s",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout
    except FileNotFoundError:
        # gobuster not installed — try ffuf as fallback
        return _run_ffuf(target_url, wl)
    except subprocess.TimeoutExpired:
        output = ""

    events = []
    found_paths = []
    for line in output.splitlines():
        # gobuster output: "/admin                 (Status: 200) [Size: 1234]"
        m = re.match(r"^(/[^\s]*)\s+\(Status:\s*(\d+)\)", line.strip())
        if not m:
            continue
        path = m.group(1)
        status = int(m.group(2))
        if status in (200, 301, 302, 403):
            found_paths.append((path, status))

    if not found_paths:
        return []

    now = datetime.now(timezone.utc).isoformat()
    # Classify found paths into wickets
    triggered: dict[str, list] = {}
    for path, status in found_paths:
        for wicket_id, patterns in INTERESTING_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, path, re.IGNORECASE):
                    triggered.setdefault(wicket_id, []).append(path)
                    break

    # WB-03 base: any 200 response means there's accessible content
    if any(s == 200 for _, s in found_paths):
        triggered.setdefault("WB-03", []).extend(
            p for p, s in found_paths if s == 200
        )

    for wicket_id, paths in triggered.items():
        confidence = min(0.75 + 0.05 * len(paths), 0.95)
        events.append({
            "type": "obs.attack.precondition",
            "id": str(uuid.uuid4()),
            "ts": now,
            "payload": {
                "wicket_id": wicket_id,
                "target_ip": target_url,
                "workload_id": f"web::{target_url}",
                "domain": "web",
                "status": "realized",
                "confidence": round(confidence, 2),
                "evidence": f"gobuster found {len(paths)} path(s): {', '.join(paths[:3])}",
                "decay_class": "operational",
                "source": "gobuster",
                "paths_found": paths[:10],
            },
        })

    # Write NDJSON
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with out_file.open("w") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    return events


def _write_minimal_wordlist() -> str:
    """Write a minimal built-in wordlist when no system wordlist is available."""
    minimal = [
        "admin", "administrator", "login", "wp-admin", "phpmyadmin", "manager",
        "dashboard", "backup", "db", "database", "api", "v1", "v2", "test",
        "config", "configuration", ".git", ".env", "server-status", "phpinfo.php",
        "info.php", "shell.php", "cmd.php", "upload", "uploads", "files",
        "tmp", "temp", "logs", "log", "debug", "console", "panel",
    ]
    import tempfile
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp.write("\n".join(minimal))
    tmp.close()
    return tmp.name


def _run_ffuf(target_url: str, wordlist: str) -> list[dict]:
    """Fallback to ffuf if gobuster not available."""
    try:
        cmd = ["ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist, "-t", "20", "-mc", "200,301,302,403", "-of", "json"]
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        cmd += ["-o", out_path]
        subprocess.run(cmd, capture_output=True, timeout=120)
        if Path(out_path).exists():
            data = json.loads(Path(out_path).read_text())
            # Parse ffuf output
            paths = [r.get("input", {}).get("FUZZ", "") for r in data.get("results", [])]
            os.unlink(out_path)
            return paths  # Simplified — caller handles
    except Exception:
        pass
    return []

"""
gobuster_adapter.py
===================
Web directory and file enumeration via gobuster.
Emits obs.attack.precondition events for:
  WB-05: admin panel / hidden paths discovered
  WB-08: .git directory exposure
  WB-09: .env / config file exposure
  WB-14: login / auth surface present (also via 401/403 responses)
  WB-17: sensitive files / backup / path traversal indicators
  WB-07: debug / server-info endpoints
  WB-21: webshell / backdoor path indicators
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
    "WB-05": [r"admin", r"manager", r"console", r"dashboard", r"cpanel", r"phpmyadmin"],  # admin_interface_exposed
    "WB-08": [r"\.git(?:/|$)"],                                                  # git_exposure
    "WB-09": [r"\.env(?:$|\.)", r"\.env\.", r"config\.php", r"config\.yml",     # env_file_exposed
              r"config\.yaml", r"settings\.py", r"wp-config", r"\.htpasswd",
              r"database\.yml", r"secrets\.", r"credentials"],
    "WB-14": [r"login", r"signin", r"auth", r"oauth", r"sso", r"saml",          # auth_surface_present
              r"account", r"user", r"password", r"forgot", r"reset"],
    "WB-17": [r"\.bak$", r"\.old$", r"\.backup$", r"\.sql$", r"\.zip$",        # sensitive_path_exposed
              r"backup", r"db\.", r"\.\./", r"\.\.%2f", r"etc/passwd",
              r"windows/win\.ini", r"phpinfo", r"info\.php", r"test\.php"],
    "WB-07": [r"server-status", r"server-info", r"actuator", r"debug"],         # debug_endpoint_exposed
    "WB-21": [r"shell", r"webshell", r"cmd\.php", r"exec\.php", r"c99", r"r57"], # webshell_present
}

def run_gobuster(target_url: str, out_file: Path, wordlist: str | None = None) -> list[dict]:
    """Run gobuster dir against target_url, parse results, return events."""
    # Strip any double-scheme (e.g. http://http://...) that can arise from upstream bugs
    if target_url.count("://") > 1:
        from urllib.parse import urlparse as _up
        _p = _up(target_url)
        target_url = f"{_p.scheme}://{_p.netloc}{_p.path or ''}"

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

    is_https = target_url.startswith("https://")
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wl,
        "-t", "20",
        "--no-error",
        "-q",
        "--timeout", "10s",
        # Always skip 404 to avoid false positives from custom error pages
        "-b", "404,429",
        # Follow redirects to catch admin panels behind 301/302
        "-r",
    ]
    if is_https:
        cmd.append("-k")  # skip TLS verification for internal/self-signed certs
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

    # Classify found paths into wickets
    triggered: dict[str, list] = {}
    for path, status in found_paths:
        for wicket_id, patterns in INTERESTING_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, path, re.IGNORECASE):
                    triggered.setdefault(wicket_id, []).append(path)
                    break
        # 401/403 responses signal an auth-gated surface even without path match
        if status in (401, 403):
            triggered.setdefault("WB-14", []).append(path)

    # WB-05 base: any unclassified 200 response is a potential admin/exposed path
    classified = set(p for paths in triggered.values() for p in paths)
    unclassified_200 = [p for p, s in found_paths if s == 200 and p not in classified]
    if unclassified_200:
        triggered.setdefault("WB-05", []).extend(unclassified_200)

    try:
        from skg.sensors.event_builder import make_precondition_event
        from skg.identity.workload import canonical_workload_id
        _use_builder = True
    except ImportError:
        _use_builder = False

    now = datetime.now(timezone.utc).isoformat()
    workload_id = canonical_workload_id(target_url, domain="web") if _use_builder else f"web::{target_url}"

    for wicket_id, paths in triggered.items():
        confidence = min(0.75 + 0.05 * len(paths), 0.95)
        detail = f"gobuster found {len(paths)} path(s): {', '.join(paths[:3])}"
        pointer = f"gobuster://{target_url}"
        if _use_builder:
            events.append(make_precondition_event(
                wicket_id=wicket_id,
                status="realized",
                workload_id=workload_id,
                source_id="gobuster_adapter",
                toolchain="skg-web-toolchain",
                target_ip=target_url,
                domain="web",
                label="web_path_discovered",
                detail=detail,
                evidence_rank=4,
                source_kind="gobuster",
                pointer=pointer,
                confidence=round(confidence, 2),
            ))
        else:
            events.append({
                "type": "obs.attack.precondition",
                "id": str(uuid.uuid4()),
                "ts": now,
                "source": {"source_id": "gobuster_adapter", "toolchain": "skg-web-toolchain"},
                "payload": {
                    "wicket_id": wicket_id,
                    "workload_id": workload_id,
                    "domain": "web",
                    "status": "realized",
                    "detail": detail,
                },
                "provenance": {
                    "evidence_rank": 4,
                    "evidence": {"source_kind": "gobuster", "pointer": pointer,
                                 "confidence": round(confidence, 2)},
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
    """Fallback to ffuf; if ffuf is also absent, use pure-Python requests enumeration."""
    try:
        import tempfile, os
        cmd = ["ffuf", "-u", f"{target_url}/FUZZ", "-w", wordlist,
               "-t", "20", "-mc", "200,301,302,403", "-of", "json"]
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = f.name
        cmd += ["-o", out_path]
        subprocess.run(cmd, capture_output=True, timeout=120)
        if Path(out_path).exists():
            data = json.loads(Path(out_path).read_text())
            paths = [(f"/{r.get('input', {}).get('FUZZ', '')}", r.get("status", 0))
                     for r in data.get("results", [])]
            os.unlink(out_path)
            if paths:
                return _paths_to_events(target_url, paths)
    except FileNotFoundError:
        pass  # ffuf not installed — fall through to Python
    except Exception:
        pass
    # Pure-Python fallback: threaded urllib enumeration (no external deps)
    return _run_python_enum(target_url, wordlist)


def _run_python_enum(target_url: str, wordlist: str) -> list[dict]:
    """
    Pure-Python directory enumeration using urllib with a thread pool.

    Uses only stdlib — no requests dependency needed.
    50 workers, 5 s per request timeout, stops after 500 words to stay polite.
    """
    import urllib.request
    import urllib.error
    from concurrent.futures import ThreadPoolExecutor, as_completed

    try:
        with open(wordlist) as f:
            words = [l.strip() for l in f
                     if l.strip() and not l.startswith("#")][:500]
    except Exception:
        words = []

    if not words:
        return []

    found: list[tuple[str, int]] = []

    def _probe(word: str) -> tuple[str, int] | None:
        url = f"{target_url}/{word}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "SKG-Scanner/1.0"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 301, 302, 403):
                    return f"/{word}", resp.status
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 403):
                return f"/{word}", e.code
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(_probe, w): w for w in words}
        for fut in as_completed(futures):
            hit = fut.result()
            if hit:
                found.append(hit)

    return _paths_to_events(target_url, found)


def _paths_to_events(target_url: str, paths: list[tuple[str, int]]) -> list[dict]:
    """Convert (path, status_code) pairs to obs.attack.precondition events."""
    ROOT_DIR = Path(__file__).resolve().parents[4]
    import sys
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))
    try:
        from skg.sensors import envelope, precondition_payload
    except ImportError:
        return []

    now = datetime.now(timezone.utc).isoformat()
    events = []
    for path, status in paths:
        wid = "WB-05"  # admin_interface_exposed — default for unclassified discovered paths
        for candidate_wid, patterns in INTERESTING_PATTERNS.items():
            if any(re.search(p, path, re.IGNORECASE) for p in patterns):
                wid = candidate_wid
                break
        events.append(envelope(
            event_type="obs.attack.precondition",
            source_id="gobuster_adapter.python_enum",
            toolchain="skg-web-toolchain",
            payload=precondition_payload(
                wicket_id=wid,
                label=f"directory found: {path} (HTTP {status})",
                domain="web",
                workload_id=f"web::{target_url}",
                realized=True,
                detail=f"{path} returned HTTP {status}",
                target_ip=target_url,
            ),
            evidence_rank=2,
            source_kind="web_enum",
            pointer=f"gobuster://{target_url}{path}",
            confidence=0.75,
        ))
    return events

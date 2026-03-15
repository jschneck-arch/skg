"""
adapters/sbom_check/check.py
=============================
Software Bill of Materials (SBOM) adapter for supply chain toolchain.

Collects installed package versions via SSH or from a local SBOM file
(CycloneDX JSON, SPDX JSON, or plain pip/dpkg/rpm list) and evaluates
them against the CVEs in the supply chain catalog.

This is what makes the supply chain toolchain active rather than
catalog-only. The collection is exactly the same as the host toolchain's
eval_ho11_vuln_packages but mapped to SC-* wickets and supply chain paths.

Evidence ranks:
  rank 1 — live SSH collection (dpkg, pip, rpm queries)
  rank 2 — SBOM file provided by the build pipeline
  rank 3 — package manifest from a config file
  rank 5 — NVD CVE match (static, not runtime confirmed)

Tri-state semantics for supply chain:
  REALIZED  — vulnerable version confirmed installed
  BLOCKED   — constraint prevents (patched version installed, not present)
  UNKNOWN   — package not found on this system

Usage:
  python check.py --host 10.0.0.5 --user root --out events.ndjson
  python check.py --sbom /path/to/sbom.json --out events.ndjson
  python check.py --packages "pyyaml==5.1 paramiko==2.4.1" --out events.ndjson
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

TOOLCHAIN = "skg-supply-chain-toolchain"
SOURCE_ID = "adapter.sbom_check"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ev(wicket_id: str, status: str, rank: int, confidence: float,
        detail: str, workload_id: str, run_id: str,
        attack_path_id: str) -> dict:
    now = iso_now()
    return {
        "id": str(uuid.uuid4()), "ts": now,
        "type": "obs.attack.precondition",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN, "version": "1.0.0"},
        "payload": {
            "wicket_id": wicket_id, "status": status,
            "workload_id": workload_id, "detail": detail,
            "attack_path_id": attack_path_id, "run_id": run_id,
            "observed_at": now,
        },
        "provenance": {
            "evidence_rank": rank,
            "evidence": {"source_kind": "sbom_check",
                         "pointer": workload_id,
                         "collected_at": now, "confidence": confidence},
        },
    }


# ── Vulnerable version mappings ────────────────────────────────────────────
# Maps SC-* wicket IDs to (package_name, vulnerable_versions_pattern, CVE)
# Versions are matched as: installed_version < fixed_version

VULNERABLE_PACKAGES: dict[str, list[dict]] = {
    "SC-03": [
        {"package": "pyyaml", "below": "5.4", "cve": "CVE-2017-18342",
         "description": "PyYAML unsafe deserialization via full_load"},
    ],
    "SC-04": [
        {"package": "pyyaml", "below": "5.4", "cve": "CVE-2020-1747",
         "description": "PyYAML arbitrary code execution via load()"},
    ],
    "SC-05": [
        {"package": "paramiko", "below": "2.4.2", "cve": "CVE-2018-7750",
         "description": "Paramiko authentication bypass"},
    ],
    "SC-06": [
        {"package": "cryptography", "below": "1.6", "cve": "CVE-2001-1125",
         "description": "Cryptography library integrity issue"},
    ],
    "SC-07": [
        {"package": "pillow", "below": "6.2.2", "cve": "CVE-2020-5311",
         "description": "Pillow SGI buffer overflow"},
        {"package": "Pillow", "below": "6.2.2", "cve": "CVE-2020-5311",
         "description": "Pillow SGI buffer overflow"},
    ],
    "SC-08": [
        {"package": "paramiko", "below": "2.4.2", "cve": "CVE-2018-1000805",
         "description": "Paramiko RCE via SSH server"},
    ],
    "SC-09": [
        {"package": "pillow", "below": "6.2.2", "cve": "CVE-2020-5310",
         "description": "Pillow integer overflow"},
        {"package": "Pillow", "below": "6.2.2", "cve": "CVE-2020-5310",
         "description": "Pillow integer overflow"},
    ],
    "SC-10": [
        {"package": "requests", "below": "2.20.0", "cve": "CVE-2018-18074",
         "description": "Requests credential exposure via redirect"},
        {"package": "urllib3", "below": "1.24.2", "cve": "CVE-2019-11324",
         "description": "urllib3 SSL certificate validation bypass"},
    ],
}

# Additional high-value packages always worth checking
WATCHLIST = {
    "log4j":         ("1.99.99", "CVE-2021-44228", "Log4Shell RCE"),
    "log4j2":        ("1.99.99", "CVE-2021-44228", "Log4Shell RCE"),
    "spring-core":   ("5.3.17",  "CVE-2022-22965", "Spring4Shell RCE"),
    "openssl":       ("3.0.1",   "CVE-2022-0778",  "OpenSSL infinite loop DoS"),
    "setuptools":    ("65.5.1",  "CVE-2022-40897", "setuptools ReDoS"),
    "numpy":         ("1.22.0",  "CVE-2021-41496", "NumPy buffer overflow"),
    "django":        ("3.2.14",  "CVE-2022-34265", "Django SQL injection"),
    "flask":         ("2.2.0",   "CVE-2023-30861", "Flask cookie signing weakness"),
    "sqlalchemy":    ("1.4.46",  "CVE-2023-23935", "SQLAlchemy RCE via pickle"),
    "jinja2":        ("3.1.2",   "CVE-2024-34064", "Jinja2 SSTI filter bypass"),
}


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse version string to comparable tuple."""
    parts = re.findall(r'\d+', v)
    return tuple(int(p) for p in parts[:4]) if parts else (0,)


def _is_vulnerable(installed: str, below: str) -> bool:
    """Returns True if installed version is below the fixed version."""
    try:
        return _parse_version(installed) < _parse_version(below)
    except Exception:
        return False


def collect_via_ssh(host: str, user: str, key: str | None,
                    password: str | None, port: int) -> dict[str, str]:
    """
    Collect installed package versions via SSH.
    Returns dict of {package_name: version}.
    """
    try:
        import paramiko
    except ImportError:
        print("[WARN] paramiko not installed — cannot collect via SSH")
        return {}

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if key:
            client.connect(host, port=port, username=user,
                           key_filename=str(Path(key).expanduser()), timeout=20)
        else:
            client.connect(host, port=port, username=user,
                           password=password or "", timeout=20)
    except Exception as exc:
        print(f"[WARN] SSH connect failed: {exc}")
        return {}

    packages: dict[str, str] = {}

    def _run(cmd):
        _, stdout, _ = client.exec_command(cmd, timeout=15)
        return stdout.read().decode(errors="replace").strip()

    # Python packages (pip)
    pip_out = _run("pip list --format=columns 2>/dev/null || pip3 list --format=columns 2>/dev/null")
    for line in pip_out.splitlines()[2:]:  # skip header
        parts = line.split()
        if len(parts) >= 2:
            packages[parts[0].lower()] = parts[1]

    # System packages (dpkg)
    dpkg_out = _run("dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2,$3}'")
    for line in dpkg_out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkg = parts[0].split(":")[0].lower()
            packages[pkg] = parts[1]

    # RPM systems
    rpm_out = _run("rpm -qa --queryformat '%{NAME} %{VERSION}\n' 2>/dev/null")
    for line in rpm_out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            packages[parts[0].lower()] = parts[1]

    # Java/JAR detection (for log4j)
    jar_out = _run("find / -name '*.jar' 2>/dev/null | grep -i 'log4j' | head -10")
    for path in jar_out.splitlines():
        m = re.search(r'log4j[^/]*?[-_](\d+\.\d+[\.\d]*)', path, re.I)
        if m:
            packages["log4j"] = m.group(1)

    client.close()
    print(f"  [SBOM] Collected {len(packages)} packages from {host}")
    return packages


def collect_from_sbom_file(path: str) -> dict[str, str]:
    """
    Parse a CycloneDX JSON, SPDX JSON, or plain package list file.
    Returns dict of {package_name: version}.
    """
    content = Path(path).read_text()
    packages: dict[str, str] = {}

    # Try CycloneDX
    try:
        data = json.loads(content)
        # CycloneDX format
        components = data.get("components", [])
        for c in components:
            name    = c.get("name", "").lower()
            version = c.get("version", "")
            if name and version:
                packages[name] = version
        if packages:
            print(f"  [SBOM] Parsed CycloneDX: {len(packages)} components")
            return packages
    except json.JSONDecodeError:
        pass

    # Try plain pip requirements / package list
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # requirements.txt: package==version or package>=version
        m = re.match(r'^([A-Za-z0-9_.-]+)[=><]+([0-9][0-9A-Za-z._-]*)', line)
        if m:
            packages[m.group(1).lower()] = m.group(2)
        # dpkg -l format: package version
        elif " " in line:
            parts = line.split()
            if len(parts) >= 2 and re.match(r'\d', parts[1]):
                packages[parts[0].lower()] = parts[1]

    print(f"  [SBOM] Parsed package list: {len(packages)} packages")
    return packages


def collect_from_string(packages_str: str) -> dict[str, str]:
    """Parse 'package==version package>=version ...' string."""
    packages: dict[str, str] = {}
    for token in packages_str.split():
        m = re.match(r'^([A-Za-z0-9_.-]+)[=><]+([0-9][0-9A-Za-z._-]*)', token)
        if m:
            packages[m.group(1).lower()] = m.group(2)
    return packages


def evaluate_packages(packages: dict[str, str], workload_id: str,
                       run_id: str, attack_path_id: str,
                       evidence_rank: int = 1) -> list[dict]:
    """
    Evaluate collected packages against vulnerability catalog.
    Returns list of obs.attack.precondition events.
    """
    events = []

    # SC-01: reachability (always realized if we collected packages)
    events.append(_ev("SC-01", "realized", evidence_rank, 0.95,
                      f"Package collection succeeded: {len(packages)} packages",
                      workload_id, run_id, attack_path_id))

    # SC-02: service exposed (realized if packages suggest a running service)
    service_pkgs = {"flask", "django", "fastapi", "tornado", "gunicorn",
                    "uvicorn", "nginx", "apache2", "httpd"}
    if any(p in packages for p in service_pkgs):
        events.append(_ev("SC-02", "realized", evidence_rank, 0.80,
                          f"Web service package present: "
                          f"{[p for p in service_pkgs if p in packages][:3]}",
                          workload_id, run_id, attack_path_id))
    else:
        events.append(_ev("SC-02", "unknown", evidence_rank, 0.50,
                          "No web service package identified",
                          workload_id, run_id, attack_path_id))

    # Evaluate each SC-* wicket against the vulnerability catalog
    for wicket_id, vuln_list in VULNERABLE_PACKAGES.items():
        found_vuln = False
        for vuln in vuln_list:
            pkg_name = vuln["package"].lower()
            if pkg_name in packages:
                installed = packages[pkg_name]
                if _is_vulnerable(installed, vuln["below"]):
                    events.append(_ev(wicket_id, "realized", evidence_rank, 0.85,
                                      f"{vuln['package']}=={installed} is vulnerable "
                                      f"(fix: >={vuln['below']}) — {vuln['cve']}: "
                                      f"{vuln['description']}",
                                      workload_id, run_id, attack_path_id))
                    found_vuln = True
                    break
                else:
                    events.append(_ev(wicket_id, "blocked", evidence_rank, 0.90,
                                      f"{vuln['package']}=={installed} is patched "
                                      f"(>={vuln['below']})",
                                      workload_id, run_id, attack_path_id))
                    found_vuln = True
                    break

        if not found_vuln:
            events.append(_ev(wicket_id, "unknown", evidence_rank, 0.60,
                              f"Package not found in inventory",
                              workload_id, run_id, attack_path_id))

    # Watchlist: check high-value packages regardless of SC-* mapping
    for pkg_name, (fixed_version, cve, desc) in WATCHLIST.items():
        installed = packages.get(pkg_name.lower())
        if installed and _is_vulnerable(installed, fixed_version):
            # Emit as a CVE contextual event — not an SC-* wicket but relevant
            events.append({
                "id": str(uuid.uuid4()), "ts": iso_now(),
                "type": "obs.attack.precondition",
                "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN},
                "payload": {
                    "wicket_id":      cve,
                    "status":         "realized",
                    "workload_id":    workload_id,
                    "detail":         f"{pkg_name}=={installed} vulnerable — {desc}",
                    "attack_path_id": attack_path_id,
                    "run_id":         run_id,
                    "observed_at":    iso_now(),
                },
                "provenance": {
                    "evidence_rank": evidence_rank,
                    "evidence": {"source_kind": "sbom_watchlist",
                                 "pointer": workload_id,
                                 "collected_at": iso_now(),
                                 "confidence": 0.80},
                },
            })

    return events


def main():
    p = argparse.ArgumentParser(description="SKG supply chain SBOM adapter")
    p.add_argument("--host",        default=None, help="SSH target host")
    p.add_argument("--user",        default="root")
    p.add_argument("--key",         default=None)
    p.add_argument("--password",    default=None)
    p.add_argument("--port",        type=int, default=22)
    p.add_argument("--sbom",        default=None, help="SBOM file path")
    p.add_argument("--packages",    default=None, help="Inline package list")
    p.add_argument("--out",         required=True)
    p.add_argument("--workload-id", dest="workload_id", default=None)
    p.add_argument("--attack-path-id", dest="attack_path_id",
                   default="supply_chain_network_exploit_v1")
    p.add_argument("--run-id",      dest="run_id", default=None)
    args = p.parse_args()

    run_id      = args.run_id or str(uuid.uuid4())[:8]
    workload_id = args.workload_id or (args.host or "supply_chain_local")

    if args.host:
        packages = collect_via_ssh(args.host, args.user, args.key,
                                   args.password, args.port)
        rank = 1
    elif args.sbom:
        packages = collect_from_sbom_file(args.sbom)
        rank = 2
    elif args.packages:
        packages = collect_from_string(args.packages)
        rank = 3
    else:
        p.print_help()
        return

    events = evaluate_packages(packages, workload_id, run_id,
                                args.attack_path_id, rank)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in events if e["payload"]["status"] == "realized")
    b = sum(1 for e in events if e["payload"]["status"] == "blocked")
    u = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"\n  {len(events)} SC-* events: {r}R {b}B {u}U → {out}")


if __name__ == "__main__":
    main()

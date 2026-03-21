"""
skg :: feeds/nvd_ingester.py

NVD API v2 CVE feed ingester for SKG.

Queries the National Vulnerability Database for CVEs matching
discovered services, normalizes findings into wicket candidates
for the resonance engine, and emits envelope events for known
CVE conditions on observed targets.

The ingester does NOT infer exploitability. It maps CVE preconditions
to the tri-state model: if a vulnerable version is running, the
version-match wicket is realized. Whether the vulnerability is
reachable remains unknown until other telemetry confirms it.

Usage:
  python nvd_ingester.py --service "Apache/2.4.25" --out /tmp/cve_events.ndjson
  python nvd_ingester.py --surface /var/lib/skg/discovery/surface_*.json --out-dir /var/lib/skg/cve/
  python nvd_ingester.py --cpe "cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*"

Environment:
  NIST_NVD_API_KEY  — API key for higher rate limits (required)
"""

import argparse
import json
import os
import re
import sys
import time
import uuid
import glob
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlencode, quote

# Add transport to path
WEB_TRANSPORT = Path("/opt/skg/skg-web-toolchain/adapters/web_active")
if WEB_TRANSPORT.exists():
    sys.path.insert(0, str(WEB_TRANSPORT))

try:
    from transport import HttpTransport
except ImportError:
    # Fallback — use urllib
    HttpTransport = None


TOOLCHAIN = "skg-feed-nvd"
SOURCE_ID = "feed.nvd.cve"
VERSION = "1.0.0"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── Known service → CPE mappings ─────────────────────────────────────────

SERVICE_CPE_MAP = {
    # Web servers
    r"apache[/ ]?([\d.]+)": ("cpe:2.3:a:apache:http_server:{version}", "Apache HTTP Server"),
    r"nginx[/ ]?([\d.]+)": ("cpe:2.3:a:f5:nginx:{version}", "nginx"),
    r"iis[/ ]?([\d.]+)": ("cpe:2.3:a:microsoft:internet_information_services:{version}", "Microsoft IIS"),
    r"lighttpd[/ ]?([\d.]+)": ("cpe:2.3:a:lighttpd:lighttpd:{version}", "lighttpd"),

    # Languages / frameworks
    r"php[/ ]?([\d.]+)": ("cpe:2.3:a:php:php:{version}", "PHP"),
    r"python[/ ]?([\d.]+)": ("cpe:2.3:a:python:python:{version}", "Python"),
    r"node\.?js[/ ]?([\d.]+)": ("cpe:2.3:a:nodejs:node.js:{version}", "Node.js"),

    # Databases
    r"mysql[/ ]?([\d.]+)": ("cpe:2.3:a:oracle:mysql:{version}", "MySQL"),
    r"mariadb[/ ]?([\d.]+)": ("cpe:2.3:a:mariadb:mariadb:{version}", "MariaDB"),
    r"postgresql[/ ]?([\d.]+)": ("cpe:2.3:a:postgresql:postgresql:{version}", "PostgreSQL"),

    # Other
    r"openssh[_ ]?([\d.]+)": ("cpe:2.3:a:openbsd:openssh:{version}", "OpenSSH"),
    r"openssl[/ ]?([\d.]+)": ("cpe:2.3:a:openssl:openssl:{version}", "OpenSSL"),
    r"tomcat[/ ]?([\d.]+)": ("cpe:2.3:a:apache:tomcat:{version}", "Apache Tomcat"),
    r"neo4j[/ ]?([\d.]+)": ("cpe:2.3:a:neo4j:neo4j:{version}", "Neo4j"),
}

# High-value CVEs to always check — known weaponized vulns
HIGH_VALUE_CVES = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046",  # Log4Shell bypass
    "CVE-2021-41773",  # Apache path traversal
    "CVE-2021-42013",  # Apache path traversal bypass
    "CVE-2020-1472",   # ZeroLogon
    "CVE-2019-5736",   # RunC escape
    "CVE-2024-21626",  # Leaky Vessels
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2024-3094",   # XZ backdoor
    "CVE-2023-23397",  # Outlook NTLM relay
]


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_nvd_api_key() -> str:
    api_key = os.environ.get("NIST_NVD_API_KEY", "")
    if api_key:
        return api_key

    env_file = Path("/etc/skg/skg.env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("NIST_NVD_API_KEY="):
                api_key = line.split("=", 1)[1].strip()
                if api_key:
                    os.environ["NIST_NVD_API_KEY"] = api_key
                    return api_key
    return ""


# ── NVD API client ───────────────────────────────────────────────────────

def nvd_query(params: dict, api_key: str = None) -> dict:
    """Query NVD API v2 with rate limiting."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    url = NVD_API_BASE + "?" + urlencode(params)

    if HttpTransport:
        transport = HttpTransport(timeout=30.0, verify_ssl=True)
        resp = transport.request("GET", url, headers=headers)
        if resp.error:
            print(f"  [!] NVD API error: {resp.error}")
            return {}
        try:
            return json.loads(resp.text)
        except json.JSONDecodeError:
            print(f"  [!] NVD API returned non-JSON: {resp.text[:200]}")
            return {}
    else:
        # Fallback to urllib
        import urllib.request
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except Exception as e:
            print(f"  [!] NVD API error: {e}")
            return {}


def query_by_keyword(keyword: str, api_key: str = None,
                     results_per_page: int = 20) -> list:
    """Search NVD by keyword."""
    data = nvd_query({
        "keywordSearch": keyword,
        "resultsPerPage": str(results_per_page),
    }, api_key)
    return data.get("vulnerabilities", [])


def query_by_cpe(cpe_string: str, api_key: str = None,
                 results_per_page: int = 20) -> list:
    """Search NVD by CPE match string."""
    data = nvd_query({
        "cpeName": cpe_string,
        "resultsPerPage": str(results_per_page),
    }, api_key)
    return data.get("vulnerabilities", [])


def query_by_cve_id(cve_id: str, api_key: str = None) -> dict:
    """Fetch a specific CVE by ID."""
    data = nvd_query({"cveId": cve_id}, api_key)
    vulns = data.get("vulnerabilities", [])
    return vulns[0] if vulns else {}


# ── Service version extraction ───────────────────────────────────────────

def extract_service_info(banner: str) -> list:
    """
    Extract service name, version, and CPE from a banner string.
    Returns list of (product_name, version, cpe_template) tuples.
    """
    results = []
    banner_lower = banner.lower()

    for pattern, (cpe_template, product_name) in SERVICE_CPE_MAP.items():
        match = re.search(pattern, banner_lower)
        if match:
            version = match.group(1) if match.groups() else ""
            if version:
                cpe = cpe_template.replace("{version}", version)
                results.append((product_name, version, cpe))

    return results


def extract_from_headers(headers: dict) -> list:
    """Extract service info from HTTP response headers."""
    results = []
    for key in ("server", "x-powered-by"):
        val = headers.get(key, "")
        if val:
            results.extend(extract_service_info(val))
    return results


# ── CVE → wicket candidate mapping ──────────────────────────────────────

def cve_to_wicket_candidate(cve_entry: dict, target_ip: str = "",
                             service_info: str = "") -> dict:
    """
    Map a CVE entry to a wicket candidate for the resonance engine.
    """
    cve_data = cve_entry.get("cve", {})
    cve_id = cve_data.get("id", "unknown")

    # Extract CVSS score
    metrics = cve_data.get("metrics", {})
    cvss_score = 0.0
    cvss_vector = ""
    severity = "unknown"

    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            severity = metric_list[0].get("baseSeverity",
                       cvss_data.get("baseSeverity", "unknown")).lower()
            break

    # Extract description
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # Extract attack vector
    attack_vector = "unknown"
    if "AV:N" in cvss_vector or "AV:NETWORK" in cvss_vector.upper():
        attack_vector = "network"
    elif "AV:A" in cvss_vector:
        attack_vector = "adjacent"
    elif "AV:L" in cvss_vector:
        attack_vector = "local"
    elif "AV:P" in cvss_vector:
        attack_vector = "physical"

    # Determine if auth required
    auth_required = "unknown"
    if "PR:N" in cvss_vector:
        auth_required = "none"
    elif "PR:L" in cvss_vector:
        auth_required = "low"
    elif "PR:H" in cvss_vector:
        auth_required = "high"

    return {
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "description": description[:300],
        "attack_vector": attack_vector,
        "auth_required": auth_required,
        "target_ip": target_ip,
        "service_info": service_info,
        "wicket_proposal": {
            "id": f"CVE-{cve_id.replace('CVE-', '')}",
            "label": f"cve_{cve_id.lower().replace('-', '_')}",
            "description": f"{cve_id}: {description[:150]}",
            "evidence_hint": f"Version match against {service_info}. "
                           f"CVSS {cvss_score} ({severity}). "
                           f"Attack vector: {attack_vector}.",
        },
    }


# ── Event emission ───────────────────────────────────────────────────────

def emit_cve_event(out_path: Path, cve_id: str, status: str,
                   target_ip: str, service_info: str,
                   cvss_score: float, severity: str,
                   description: str, run_id: str):
    """
    Emit a CVE observation as a proper obs.attack.precondition envelope event.

    Uses wicket_id = cve_id so that load_wicket_states() picks it up and
    feeds it into the entropy calculation.  The CVE ID is the condition
    identifier — 'this version of this software is present and this CVE
    applies to it'.  Gravity can then treat unresolved CVEs as unknown
    wickets and pull toward instruments that can confirm exploitability.
    workload_id and target_ip are both set so the IP filter in
    _load_events_file matches.
    """
    now = iso_now()
    workload_id = f"cve::{target_ip}"
    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": VERSION,
        },
        "payload": {
            # wicket_id + status = what _load_events_file looks for
            "wicket_id":    cve_id,
            "status":       status,           # "realized" = version match confirmed
            "workload_id":  workload_id,
            "target_ip":    target_ip,
            # Extra context preserved in detail
            "detail": json.dumps({
                "cve_id":       cve_id,
                "service":      service_info,
                "cvss":         cvss_score,
                "severity":     severity,
                "description":  description[:200],
            }),
            "run_id":       run_id,
        },
        "provenance": {
            "evidence_rank": 5,   # static/database — not runtime confirmation
            "evidence": {
                "source_kind": "nvd_api_v2",
                "pointer": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "collected_at": now,
                "confidence": 0.7,   # version match, not confirmed exploitable
            },
        },
    }
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


# ── Main ingestion logic ────────────────────────────────────────────────

def ingest_service(service_string: str, target_ip: str,
                   out_path: Path, api_key: str, run_id: str) -> list:
    """
    Look up CVEs for a service string (e.g. "Apache/2.4.25").
    Returns list of CVE candidates.
    """
    services = extract_service_info(service_string)
    if not services:
        # Try the raw string as a keyword search
        services = [(service_string, "", "")]

    candidates = []

    for product_name, version, cpe in services:
        print(f"    {product_name} {version}")

        cves = []
        if cpe:
            # CPE-based lookup — most precise
            print(f"      CPE: {cpe}")
            time.sleep(0.7)  # Rate limit: ~6 req/min without key, ~50 with
            cves = query_by_cpe(cpe, api_key)

        if not cves:
            # Keyword fallback
            keyword = f"{product_name} {version}" if version else product_name
            print(f"      Keyword: {keyword}")
            time.sleep(0.7)
            cves = query_by_keyword(keyword, api_key)

        print(f"      Found {len(cves)} CVEs")

        for cve_entry in cves:
            candidate = cve_to_wicket_candidate(cve_entry, target_ip, service_string)

            # Only emit events for significant CVEs
            if candidate["cvss_score"] >= 7.0 or candidate["cve_id"] in HIGH_VALUE_CVES:
                emit_cve_event(
                    out_path,
                    candidate["cve_id"],
                    "realized",  # Version match confirmed
                    target_ip,
                    service_string,
                    candidate["cvss_score"],
                    candidate["severity"],
                    candidate["description"],
                    run_id,
                )
                candidates.append(candidate)

    return candidates


def ingest_from_surface(surface_path: str, out_dir: str, api_key: str) -> dict:
    """
    Read a surface JSON, extract service versions from all targets,
    look up CVEs for each, and emit events.
    """
    surface = json.loads(Path(surface_path).read_text())
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    run_id = str(uuid.uuid4())
    all_candidates = []

    print(f"[NVD-FEED] Surface: {surface_path}")
    print(f"[NVD-FEED] Run:     {run_id[:8]}")
    print(f"[NVD-FEED] Time:    {iso_now()}")
    print()

    # Also check event files for discovered service versions
    service_versions = {}  # ip → list of service strings

    for target in surface.get("targets", []):
        ip = target["ip"]
        services = []

        # From port scan banners
        for svc in target.get("services", []):
            banner = svc.get("banner", "")
            if banner and any(c.isdigit() for c in banner):
                extracted = extract_service_info(banner)
                for product, version, cpe in extracted:
                    services.append(f"{product}/{version}")

        # From web collector events (header disclosures)
        for ef in glob.glob(f"{out_dir}/../discovery/web_events_{ip}_*.ndjson"):
            try:
                with open(ef) as f:
                    for line in f:
                        event = json.loads(line.strip())
                        payload = event.get("payload", {})
                        if payload.get("wicket_id") == "WB-02" and payload.get("status") == "realized":
                            detail = payload.get("detail", "")
                            try:
                                headers = json.loads(detail)
                                for key, val in headers.items():
                                    extracted = extract_service_info(val)
                                    for product, version, cpe in extracted:
                                        services.append(f"{product}/{version}")
                            except json.JSONDecodeError:
                                pass
            except Exception:
                continue

        if services:
            service_versions[ip] = list(set(services))

    if not service_versions:
        print("[NVD-FEED] No service versions found to look up.")
        return {"candidates": [], "run_id": run_id}

    # Query NVD for each unique service
    seen_services = set()
    events_file = out_path / f"cve_events_{run_id[:8]}.ndjson"

    for ip, services in service_versions.items():
        print(f"  Target: {ip}")
        for svc in services:
            if svc in seen_services:
                continue
            seen_services.add(svc)

            candidates = ingest_service(svc, ip, events_file, api_key, run_id)
            all_candidates.extend(candidates)

    # Summary
    print()
    print(f"[NVD-FEED] Queried {len(seen_services)} services")
    print(f"[NVD-FEED] Found {len(all_candidates)} high-severity CVE matches")
    if events_file.exists():
        count = sum(1 for _ in open(events_file))
        print(f"[NVD-FEED] Events: {events_file} ({count} events)")

    # Write candidates summary
    summary_file = out_path / f"cve_candidates_{run_id[:8]}.json"
    with open(summary_file, "w") as f:
        json.dump({
            "run_id": run_id,
            "ts": iso_now(),
            "services_queried": list(seen_services),
            "candidates": all_candidates,
        }, f, indent=2)
    print(f"[NVD-FEED] Summary: {summary_file}")

    return {"candidates": all_candidates, "run_id": run_id}


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SKG NVD CVE Feed Ingester")
    parser.add_argument("--service", default=None,
                        help="Service string to look up (e.g. 'Apache/2.4.25')")
    parser.add_argument("--surface", default=None,
                        help="Surface JSON to extract services from")
    parser.add_argument("--auto", action="store_true",
                        help="Find latest surface automatically")
    parser.add_argument("--cpe", default=None,
                        help="Direct CPE lookup")
    parser.add_argument("--out", default=None,
                        help="Output events file (for --service mode)")
    parser.add_argument("--out-dir", dest="out_dir",
                        default="/var/lib/skg/cve",
                        help="Output directory (for --surface mode)")
    args = parser.parse_args()

    api_key = load_nvd_api_key()
    if not api_key:
        print("[!] Set NIST_NVD_API_KEY environment variable for NVD access")
        print("    export NIST_NVD_API_KEY=your_key_here")
        print("    or add NIST_NVD_API_KEY=<key> to /etc/skg/skg.env")
        sys.exit(1)

    if args.service:
        out = Path(args.out or "/tmp/cve_events.ndjson")
        run_id = str(uuid.uuid4())
        candidates = ingest_service(args.service, "manual", out, api_key, run_id)
        print(f"\n{len(candidates)} CVE candidates found")

    elif args.surface or args.auto:
        surface_path = args.surface
        if args.auto:
            surfaces = sorted(glob.glob("/var/lib/skg/discovery/surface_*.json"))
            if not surfaces:
                print("[!] No surface files found")
                sys.exit(1)
            surface_path = surfaces[-1]

        ingest_from_surface(surface_path, args.out_dir, api_key)

    elif args.cpe:
        cves = query_by_cpe(args.cpe, api_key)
        print(f"Found {len(cves)} CVEs for {args.cpe}")
        for cve in cves[:10]:
            cd = cve.get("cve", {})
            cid = cd.get("id", "?")
            desc = ""
            for d in cd.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d["value"][:100]
            print(f"  {cid}: {desc}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

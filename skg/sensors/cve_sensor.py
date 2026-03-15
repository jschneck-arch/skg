"""
skg.sensors.cve_sensor
======================
Cross-references package inventories collected from targets against
NVD CVE feeds and IAVA (IA Vulnerability Alert) databases.

Pipeline:
  1. Reads package inventory files from EVENTS_DIR or USB drops
  2. Queries NVD API v2 for CVEs matching package names/versions
  3. Maps CVE records to wickets via CVSS vectors and CPE strings
  4. Emits obs.attack.precondition events with evidence_rank=6 (scanner)

NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
  - Rate limited: 5 req/30s unauthenticated, 50 req/30s with API key
  - NIST_NVD_API_KEY env var enables higher rate limit

IAVA feed: CSV from https://www.iavm.cyber.mil/iavmnotices/
  - Cross-referenced against package names for known critical vulns

CVE → wicket mapping logic:
  - log4j CVEs (CVE-2021-44228, etc.)  → AP-L4..AP-L9 (APRS)
  - container escape CVEs               → CE-01..CE-14
  - Kerberos/AD CVEs                   → AD-01..AD-25
  - CVSS v3 exploitability ≥ 3.9       → mark wicket as realized
  - CVSS v3 exploitability < 3.9       → mark as indeterminate (None)

State: cached CVE lookups TTL 24h to avoid hammering NVD.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

from skg.sensors import BaseSensor, envelope, precondition_payload, register
from skg.core.paths import SKG_STATE_DIR

log = logging.getLogger("skg.sensors.cve")

CVE_STATE_FILE  = SKG_STATE_DIR / "cve_sensor.state.json"
CVE_CACHE_FILE  = SKG_STATE_DIR / "cve_cache.json"
CACHE_TTL_HOURS = 24

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── CVE → wicket mappings ─────────────────────────────────────────────────────

# Hard-coded high-value CVE → wicket mappings (supplement dynamic NVD lookup)
KNOWN_CVE_WICKETS: dict[str, list[tuple]] = {
    # Log4Shell family
    "CVE-2021-44228": [("aprs", "AP-L4", "log4j_loaded_at_runtime",     True, 6),
                       ("aprs", "AP-L9", "log4j_version_is_vulnerable",  True, 6)],
    "CVE-2021-45046": [("aprs", "AP-L4", "log4j_loaded_at_runtime",     True, 6),
                       ("aprs", "AP-L9", "log4j_version_is_vulnerable",  True, 6)],
    "CVE-2021-45105": [("aprs", "AP-L4", "log4j_loaded_at_runtime",     True, 6)],
    "CVE-2021-44832": [("aprs", "AP-L4", "log4j_loaded_at_runtime",     True, 6)],
    # Container escape
    "CVE-2022-0492":  [("container_escape", "CE-05", "sys_admin_capability_present", True, 6)],
    "CVE-2019-5736":  [("container_escape", "CE-08", "runc_version_vulnerable",      True, 6)],
    "CVE-2020-15257": [("container_escape", "CE-10", "containerd_socket_exposed",    True, 6)],
    # Supply chain / host packages
    "CVE-2020-14343": [("host", "HO-11", "vuln_packages_installed", True, 6)],  # pyyaml RCE
    "CVE-2020-1747":  [("host", "HO-11", "vuln_packages_installed", True, 6)],  # pyyaml RCE
    "CVE-2019-20477": [("host", "HO-11", "vuln_packages_installed", True, 6)],  # pyyaml RCE
    "CVE-2017-18342": [("host", "HO-11", "vuln_packages_installed", True, 6)],  # pyyaml RCE
    "CVE-2023-32681": [("host", "HO-11", "vuln_packages_installed", True, 6)],  # requests
    "CVE-2023-49083": [("host", "HO-11", "vuln_packages_installed", True, 6)],  # cryptography
    # Kerberos / AD
    "CVE-2020-1472":  [("ad_lateral", "AD-22", "zerologon_unpatched",   True, 6)],
    "CVE-2021-42287": [("ad_lateral", "AD-23", "sameaccountname_path",  True, 6)],
    "CVE-2021-42278": [("ad_lateral", "AD-23", "sameaccountname_path",  True, 6)],
    "CVE-2022-26923": [("ad_lateral", "AD-24", "certifried_vulnerable", True, 6)],
}

# CPE product substrings → domain hints
CPE_DOMAIN_HINTS = {
    "log4j":         "aprs",
    "log4j2":        "aprs",
    "docker":        "container_escape",
    "containerd":    "container_escape",
    "runc":          "container_escape",
    "kerberos":      "ad_lateral",
    "active_directory": "ad_lateral",
    "windows_server": "ad_lateral",
    # Supply chain / host packages
    "pyyaml":        "host",
    "yaml":          "host",
    "requests":      "host",
    "paramiko":      "host",
    "cryptography":  "host",
    "pillow":        "host",
    "openssl":       "host",
    "spring":        "aprs",
    "struts":        "aprs",
}


def _load_cache() -> dict:
    if CVE_CACHE_FILE.exists():
        try:
            return json.loads(CVE_CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_cache(cache: dict):
    CVE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CVE_CACHE_FILE.write_text(json.dumps(cache, indent=2))


def _cache_valid(entry: dict) -> bool:
    if "cached_at" not in entry:
        return False
    cached = datetime.fromisoformat(entry["cached_at"])
    return (datetime.now(timezone.utc) - cached) < timedelta(hours=CACHE_TTL_HOURS)


def _nvd_search(keyword: str, api_key: str | None, cache: dict) -> list[dict]:
    """Search NVD for CVEs matching keyword. Returns list of CVE dicts."""
    cache_key = f"kw:{keyword}"
    if cache_key in cache and _cache_valid(cache[cache_key]):
        return cache[cache_key]["cves"]

    try:
        import urllib.request, urllib.parse
        params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 20})
        url = f"{NVD_API_URL}?{params}"
        headers = {"User-Agent": "skg-cve-sensor/1.0"}
        if api_key:
            headers["apiKey"] = api_key
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        cves = [v["cve"] for v in data.get("vulnerabilities", [])]
        cache[cache_key] = {"cves": cves, "cached_at": datetime.now(timezone.utc).isoformat()}
        _save_cache(cache)
        time.sleep(0.7)  # NVD rate limit courtesy
        return cves
    except Exception as exc:
        log.debug(f"NVD lookup failed for '{keyword}': {exc}")
        return []


def _extract_packages(inventory_text: str) -> list[str]:
    """Parse dpkg/rpm/pip package list for product names."""
    packages = []
    for line in inventory_text.splitlines():
        # dpkg: "ii  packagename  version  arch  description"
        dpkg = re.match(r'^ii\s+(\S+)', line)
        if dpkg:
            packages.append(dpkg.group(1).lower().split(":")[0])
            continue
        # rpm: "name-version-release.arch"
        rpm = re.match(r'^(\S+)-\d', line)
        if rpm:
            packages.append(rpm.group(1).lower())
            continue
        # pip: "Package==version" or "Package (version)"
        pip = re.match(r'^(\S+)[=\s(]', line.strip())
        if pip:
            packages.append(pip.group(1).lower())
    return list(set(packages))


def _cve_to_events(cve: dict, workload_id: str, package: str) -> list[dict]:
    """Map a NVD CVE record to envelope events."""
    events = []
    cve_id = cve.get("id", "")

    # Check known CVE table first
    if cve_id in KNOWN_CVE_WICKETS:
        for (domain, wicket_id, label, realized, rank) in KNOWN_CVE_WICKETS[cve_id]:
            events.append(envelope(
                event_type="obs.attack.precondition",
                source_id=f"cve_sensor/{cve_id}",
                toolchain=domain,
                payload=precondition_payload(
                    wicket_id=wicket_id, label=label, domain=domain,
                    workload_id=workload_id, realized=realized,
                    detail=f"{cve_id} matched via package '{package}'",
                    attack_path_id="",
                ),
                evidence_rank=rank,
                source_kind="nvd_cve",
                pointer=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                confidence=0.80,
            ))
        return events

    # Dynamic: infer domain from CPE
    domain = None
    descriptions = cve.get("descriptions", [])
    desc_text = " ".join(d.get("value", "") for d in descriptions if d.get("lang") == "en").lower()
    for (cpe_hint, dom) in CPE_DOMAIN_HINTS.items():
        if cpe_hint in desc_text or cpe_hint in package:
            domain = dom
            break
    if not domain:
        return events

    # CVSS exploitability → realized
    metrics = cve.get("metrics", {})
    cvss3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
    exp_score = cvss3.get("cvssData", {}).get("exploitabilityScore", 0)
    realized = exp_score >= 3.9 if exp_score else None

    events.append(envelope(
        event_type="obs.attack.precondition",
        source_id=f"cve_sensor/{cve_id}",
        toolchain=domain,
        payload={
            "cve_id": cve_id,
            "domain": domain,
            "workload_id": workload_id,
            "realized": realized,
            "exploitability_score": exp_score,
            "detail": f"{cve_id} via '{package}': {desc_text[:120]}",
            "label": "cve_vulnerable_package",
            "wicket_id": "DYNAMIC",
        },
        evidence_rank=6,
        source_kind="nvd_cve",
        pointer=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        confidence=0.65,
    ))
    return events


@register("cve")
class CveSensor(BaseSensor):
    """
    Cross-references collected package inventories against NVD CVE feeds.
    Emits both known CVE → wicket mappings and dynamic CVSS-scored events.
    """

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.api_key  = cfg.get("nvd_api_key", os.environ.get("NIST_NVD_API_KEY"))
        self.packages_to_check = cfg.get("packages", [
            "log4j", "log4j2", "docker", "containerd", "runc", "openssl"
        ])
        self.inv_dirs = [
            SKG_STATE_DIR / "usb_drops",
            SKG_STATE_DIR / "ssh_collection",
        ]
        self._state = self._load_state()
        self._cache = _load_cache()

    def _load_state(self) -> dict:
        if CVE_STATE_FILE.exists():
            try:
                return json.loads(CVE_STATE_FILE.read_text())
            except Exception:
                pass
        return {"checked_files": [], "last_run": ""}

    def _save_state(self):
        CVE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CVE_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def run(self) -> list[str]:
        events: list[dict] = []
        checked = set(self._state.get("checked_files", []))

        # Scan inventory files from drop dirs
        inv_texts: list[tuple[str, str]] = []  # (workload_id, text)
        for inv_dir in self.inv_dirs:
            if not inv_dir.exists():
                continue
            for drop in inv_dir.iterdir():
                if not drop.is_dir():
                    continue
                pkg_file = drop / "packages.txt"
                if pkg_file.exists() and str(pkg_file) not in checked:
                    try:
                        text = pkg_file.read_text(errors="replace")
                        inv_texts.append((f"usb::{drop.name}", text))
                        checked.add(str(pkg_file))
                    except Exception:
                        pass

        # Also check known CVEs with configured packages (no inventory needed)
        workload_id = "cve_sensor::global"
        for pkg in self.packages_to_check:
            cves = _nvd_search(pkg, self.api_key, self._cache)
            for cve in cves:
                events.extend(_cve_to_events(cve, workload_id, pkg))

        # Process inventories
        for (wid, inv_text) in inv_texts:
            packages = _extract_packages(inv_text)
            vuln_pkgs = [p for p in packages
                         if any(kp in p for kp in self.packages_to_check)]
            for pkg in vuln_pkgs:
                cves = _nvd_search(pkg, self.api_key, self._cache)
                for cve in cves:
                    cve_events = _cve_to_events(cve, wid, pkg)
                    # Calibrate and record each CVE event
                    for ev in cve_events:
                        payload = ev.get("payload", {})
                        wicket_id = payload.get("wicket_id", "DYNAMIC")
                        domain    = payload.get("domain", "unknown")
                        cve_id    = payload.get("cve_id", "")
                        if self._ctx and wicket_id != "DYNAMIC":
                            evidence_text = f"{cve_id} in {pkg}"
                            base = ev["provenance"]["evidence"]["confidence"]
                            calibrated = self._ctx.calibrate(
                                base, evidence_text, wicket_id, domain, wid
                            )
                            ev["provenance"]["evidence"]["confidence"] = calibrated
                            self._ctx.record(
                                evidence_text=evidence_text,
                                wicket_id=wicket_id, domain=domain,
                                source_kind="nvd_cve",
                                evidence_rank=6,
                                sensor_realized=payload.get("realized"),
                                confidence=calibrated,
                                workload_id=wid,
                            )
                    events.extend(cve_events)

        self._state["checked_files"] = list(checked)
        self._state["last_run"] = datetime.now(timezone.utc).isoformat()
        self._save_state()
        _save_cache(self._cache)
        return self.emit(events)

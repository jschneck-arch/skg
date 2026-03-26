"""
skg.sensors.zero_day_detector
=============================
Version-specific CVE discovery and automatic catalog generation.

When nmap (or any adapter) finds a service version not covered by any
existing catalog wicket, this module:
  1. Queries NVD API for CVEs affecting that product+version
  2. Generates new wickets for each CVE above CVSS threshold
  3. Writes a new catalog JSON into the matching toolchain
  4. Returns the list of new wicket IDs so the caller can hot-reload

This is the "zero-day" detection mechanism: not discovering novel CVEs,
but discovering applicable CVEs for specific software versions that the
default catalog does not yet cover.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger("skg.sensors.zero_day_detector")

SKG_HOME = Path(__file__).resolve().parents[3]

# CVSS threshold — only generate wickets for CVEs above this score
CVSS_MIN = 6.0

# NVD API base URL (public, no key required for low rate)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Domain → toolchain directory mapping
DOMAIN_TOOLCHAIN = {
    "web":              "skg-web-toolchain",
    "host":             "skg-host-toolchain",
    "data":             "skg-data-toolchain",
    "nginx":            "skg-nginx-toolchain",
    "container_escape": "skg-container-escape-toolchain",
    "ad_lateral":       "skg-ad-lateral-toolchain",
    "binary_analysis":  "skg-binary-toolchain",
}

# Product → domain mapping for auto-classification
PRODUCT_DOMAIN = {
    "apache":       "web",
    "nginx":        "web",
    "iis":          "web",
    "tomcat":       "web",
    "lighttpd":     "web",
    "php":          "web",
    "wordpress":    "web",
    "drupal":       "web",
    "joomla":       "web",
    "openssh":      "host",
    "openssl":      "host",
    "bash":         "host",
    "linux":        "host",
    "windows":      "host",
    "samba":        "host",
    "vsftpd":       "host",
    "proftpd":      "host",
    "mysql":        "data",
    "postgresql":   "data",
    "mariadb":      "data",
    "mongodb":      "data",
    "redis":        "data",
    "elasticsearch":"data",
    "docker":       "container_escape",
    "containerd":   "container_escape",
    "kubernetes":   "container_escape",
    "k8s":          "container_escape",
    "active directory": "ad_lateral",
    "ldap":         "ad_lateral",
    "kerberos":     "ad_lateral",
}

# Rate limit: NVD allows 5 req/30s without key
_last_nvd_request: float = 0.0
NVD_RATE_LIMIT_S = 7.0  # conservative


@dataclass
class VersionGap:
    """A detected service version with no catalog coverage."""
    product: str
    version: str
    target_ip: str
    port: int
    domain: str
    banner: str = ""


@dataclass
class GeneratedWicket:
    wicket_id: str
    cve_id: str
    cvss: float
    description: str
    domain: str
    product: str
    version: str
    evidence_hint: str


def detect_version_gaps(
    service_list: list[dict],
    domain_wickets: dict[str, set],
    target_ip: str,
) -> list[VersionGap]:
    """
    Given a list of services from nmap (each with 'service', 'banner', 'port',
    optionally 'product', 'version'), return VersionGaps for any service whose
    product+version has no wicket in the catalog.

    service_list: [{"port": 80, "service": "http", "banner": "Apache/2.4.49", ...}]
    domain_wickets: output of load_all_wicket_ids()
    """
    gaps = []
    all_wicket_descriptions: set[str] = set()
    for wickets in domain_wickets.values():
        all_wicket_descriptions.update(w.lower() for w in wickets)

    for svc in service_list:
        banner = svc.get("banner", "") or ""
        product, version = _parse_banner(banner, svc.get("service", ""))
        if not product or not version:
            continue

        domain = _classify_domain(product)
        if not domain:
            continue

        # Check if any existing wicket description mentions this product+version
        pv_key = f"{product.lower()} {version.lower()}"
        pv_key2 = f"{product.lower()}/{version.lower()}"
        # Quick check: is this version mentioned in any catalog?
        covered = any(
            pv_key in w or pv_key2 in w
            for w in all_wicket_descriptions
        )
        if not covered:
            gaps.append(VersionGap(
                product=product,
                version=version,
                target_ip=target_ip,
                port=int(svc.get("port", 0)),
                domain=domain,
                banner=banner,
            ))
            log.info(f"[zero_day] version gap: {product} {version} on {target_ip}:{svc.get('port')}")

    return gaps


def query_nvd_for_version(product: str, version: str) -> list[dict]:
    """
    Query NVD API for CVEs affecting product+version.
    Returns list of CVE dicts: {id, cvss, description, published}.
    Rate-limited to respect NVD's 5req/30s limit.
    """
    global _last_nvd_request
    elapsed = time.time() - _last_nvd_request
    if elapsed < NVD_RATE_LIMIT_S:
        time.sleep(NVD_RATE_LIMIT_S - elapsed)

    # CPE keyword search: product version
    keyword = f"{product} {version}"
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": 20,
    })
    url = f"{NVD_API_BASE}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "skg-zero-day-detector/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        _last_nvd_request = time.time()
    except Exception as exc:
        log.warning(f"[zero_day] NVD query failed for {product} {version}: {exc}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # Extract CVSS score (try v3.1 first, then v3.0, then v2)
        cvss = 0.0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in metrics.get(key, []):
                score = m.get("cvssData", {}).get("baseScore", 0.0)
                if score > cvss:
                    cvss = score
        if cvss < CVSS_MIN:
            continue

        # Get English description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:300]
                break

        results.append({
            "id": cve_id,
            "cvss": cvss,
            "description": desc,
            "published": cve.get("published", ""),
        })

    log.info(f"[zero_day] NVD: {product} {version} → {len(results)} CVEs above CVSS {CVSS_MIN}")
    return results


def generate_wickets_for_version(
    gap: VersionGap,
    cves: list[dict],
) -> list[GeneratedWicket]:
    """
    Generate wicket objects for each CVE applicable to a version gap.
    """
    wickets = []
    for cve in sorted(cves, key=lambda c: -c["cvss"]):
        # Stable wicket ID: hash of (domain, product, cve_id) → 4 hex chars
        h = hashlib.sha1(f"{gap.domain}:{gap.product}:{cve['id']}".encode()).hexdigest()[:4].upper()
        # Find next available ID in this domain
        prefix = _domain_prefix(gap.domain)
        wicket_id = f"{prefix}Z{h}"  # Z-prefix marks auto-generated zero-day wickets

        wickets.append(GeneratedWicket(
            wicket_id=wicket_id,
            cve_id=cve["id"],
            cvss=cve["cvss"],
            description=cve["description"],
            domain=gap.domain,
            product=gap.product,
            version=gap.version,
            evidence_hint=(
                f"Detected {gap.product}/{gap.version} on port {gap.port}. "
                f"Verify {cve['id']} (CVSS {cve['cvss']:.1f}) with targeted scan or MSF module."
            ),
        ))
    return wickets


def write_catalog_for_gap(
    gap: VersionGap,
    wickets: list[GeneratedWicket],
) -> Optional[Path]:
    """
    Write a new catalog JSON file for the generated wickets into the appropriate toolchain.
    Returns the path of the written catalog, or None if nothing was written.
    """
    if not wickets:
        return None

    toolchain_name = DOMAIN_TOOLCHAIN.get(gap.domain)
    if not toolchain_name:
        log.warning(f"[zero_day] no toolchain for domain {gap.domain}")
        return None

    toolchain_dir = SKG_HOME / toolchain_name / "contracts" / "catalogs"
    toolchain_dir.mkdir(parents=True, exist_ok=True)

    safe_product = re.sub(r"[^a-z0-9]", "_", gap.product.lower())
    safe_version = re.sub(r"[^a-z0-9]", "_", gap.version.lower())
    catalog_name = f"attack_preconditions_catalog.{gap.domain}.{safe_product}_{safe_version}.auto.json"
    catalog_path = toolchain_dir / catalog_name

    # Don't overwrite if already exists with same content
    wicket_dict = {}
    for w in wickets:
        wicket_dict[w.wicket_id] = {
            "label": f"{w.cve_id.lower().replace('-','_')}_vulnerability",
            "description": f"{w.product} {w.version}: {w.description} ({w.cve_id}, CVSS {w.cvss:.1f})",
            "evidence_hint": w.evidence_hint,
            "cve_id": w.cve_id,
            "cvss": w.cvss,
            "auto_generated": True,
            "decay_class": "structural",
        }

    catalog = {
        "domain": gap.domain,
        "version": "1.0.0-auto",
        "description": f"Auto-generated: {gap.product} {gap.version} version-specific CVEs",
        "generated_by": "skg.sensors.zero_day_detector",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_product": gap.product,
        "source_version": gap.version,
        "wickets": wicket_dict,
    }

    catalog_path.write_text(json.dumps(catalog, indent=2))
    log.info(f"[zero_day] wrote catalog: {catalog_path.name} ({len(wickets)} wickets)")
    return catalog_path


def run_zero_day_detection(
    service_list: list[dict],
    domain_wickets: dict[str, set],
    target_ip: str,
) -> dict:
    """
    Full pipeline: detect gaps → query NVD → generate wickets → write catalogs.
    Returns summary dict with new_wickets, new_catalogs.
    """
    gaps = detect_version_gaps(service_list, domain_wickets, target_ip)
    if not gaps:
        return {"new_wickets": [], "new_catalogs": []}

    all_new_wickets = []
    new_catalogs = []

    # Deduplicate gaps by (product, version) — multiple targets may run same software
    seen = set()
    for gap in gaps:
        key = (gap.product, gap.version)
        if key in seen:
            continue
        seen.add(key)

        cves = query_nvd_for_version(gap.product, gap.version)
        if not cves:
            continue

        wickets = generate_wickets_for_version(gap, cves)
        catalog_path = write_catalog_for_gap(gap, wickets)
        if catalog_path:
            all_new_wickets.extend(w.wicket_id for w in wickets)
            new_catalogs.append(str(catalog_path))
            print(f"  [ZERO-DAY] {gap.product} {gap.version}: {len(wickets)} new wickets from NVD")
            for w in wickets[:3]:
                print(f"    + {w.wicket_id}: {w.cve_id} (CVSS {w.cvss:.1f})")
            if len(wickets) > 3:
                print(f"    ... and {len(wickets)-3} more")

    return {"new_wickets": all_new_wickets, "new_catalogs": new_catalogs}


# ── Internal helpers ─────────────────────────────────────────────────────────

def _parse_banner(banner: str, service: str) -> tuple[str, str]:
    """Extract (product, version) from nmap banner string."""
    if not banner:
        return "", ""
    banner = banner.strip()
    # Common patterns: Apache/2.4.49, nginx/1.18.0, OpenSSH_8.2p1, vsftpd 3.0.3
    patterns = [
        r"^([\w-]+)[/_ ]([\d]+\.[\d]+\.?[\d]*)",
        r"^([\w]+)\s+([\d]+\.[\d]+\.?[\d]*)",
    ]
    for pat in patterns:
        m = re.match(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1).lower(), m.group(2)
    return "", ""


def _classify_domain(product: str) -> str:
    """Map product name to SKG domain."""
    product_lower = product.lower()
    for key, domain in PRODUCT_DOMAIN.items():
        if key in product_lower:
            return domain
    return ""


def _domain_prefix(domain: str) -> str:
    mapping = {
        "web": "WB-",
        "host": "HO-",
        "data": "DP-",
        "nginx": "NX-",
        "container_escape": "CE-",
        "ad_lateral": "AD-",
        "binary_analysis": "BA-",
    }
    return mapping.get(domain, "GN-")

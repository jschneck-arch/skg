#!/usr/bin/env python3
"""
skg/forge/compiler.py
─────────────────────
Data-driven catalog compiler for SKG.

Derives wicket catalogs from:
  1. NVD CVE feed (primary — CVSS vectors, affected packages, CWE)
  2. Existing catalog corpus (similarity matching to avoid duplication)
  3. IAVA notices (when available — severity + remediation deadline)

AI is NOT the engine here. AI is optional enrichment for wickets that have
no CVE coverage and no corpus analog. The compiler runs first. If it can
fully resolve the domain from data, AI is never invoked.

Usage:
  python3 -m skg.forge.compiler --domain supply_chain --description "..." --out catalog.json
  python3 -m skg.forge.compiler --domain iot --nvd-packages "busybox,dropbear,uboot"

Schema produced:
  {
    "domain": "supply_chain",
    "version": "1.0.0",
    "description": "...",
    "generated_by": "skg.forge.compiler",
    "wickets": {
      "SC-01": {
        "id": "SC-01",
        "label": "vulnerable_dependency_present",
        "description": "...",
        "evidence_hint": "..."
      }
    },
    "attack_paths": {
      "supply_chain_weaponized_dep_v1": {
        "id": "...",
        "description": "...",
        "required_wickets": [...],
        "references": [...]
      }
    }
  }
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import re
import sys
import urllib.request
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("skg.forge.compiler")

# ── paths ────────────────────────────────────────────────────────────────────
SKG_ROOT     = Path(__file__).resolve().parents[2]
CATALOG_GLOB = "skg-*-toolchain/contracts/catalogs/*.json"
NVD_API      = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ── CVSS attack vector → evidence hint template ──────────────────────────────
AV_HINTS = {
    "NETWORK":   "Network-accessible service probe; confirm reachability via TCP connect or banner grab",
    "ADJACENT":  "Adjacent network scan (ARP/mDNS broadcast range); confirm via subnet sweep",
    "LOCAL":     "Local execution required; confirm via SSH command or agent collection",
    "PHYSICAL":  "Physical access required; confirm via USB drop or console access",
}

# ── CVSS privilege required → wicket dependency hint ─────────────────────────
PR_DEPS = {
    "NONE":  "no_authentication_required",
    "LOW":   "low_privilege_user_present",
    "HIGH":  "privileged_account_present",
}

# ── CWE → plain-language description seed ────────────────────────────────────
CWE_DESC = {
    "CWE-78":  "OS command injection via unsanitized input",
    "CWE-79":  "Cross-site scripting via unsanitized output",
    "CWE-89":  "SQL injection via unsanitized query parameter",
    "CWE-94":  "Code injection via unsafe deserialization or eval",
    "CWE-119": "Buffer overflow via unchecked memory operation",
    "CWE-125": "Out-of-bounds read via malformed input",
    "CWE-190": "Integer overflow leading to memory corruption",
    "CWE-200": "Sensitive information exposure via error message or response",
    "CWE-269": "Improper privilege management allowing escalation",
    "CWE-276": "Incorrect default permissions on file or directory",
    "CWE-287": "Authentication bypass via improper credential validation",
    "CWE-306": "Missing authentication for critical function",
    "CWE-400": "Resource exhaustion via uncontrolled input",
    "CWE-416": "Use-after-free via improper memory lifecycle",
    "CWE-434": "Unrestricted file upload allowing remote execution",
    "CWE-502": "Deserialization of untrusted data enabling code execution",
    "CWE-611": "XML external entity injection via parser misconfiguration",
    "CWE-787": "Out-of-bounds write via malformed input",
    "CWE-798": "Hardcoded credential present in software",
    "CWE-862": "Missing authorization check on sensitive operation",
}


# ─────────────────────────────────────────────────────────────────────────────
# Corpus loader — reads all existing catalogs into a flat wicket list
# ─────────────────────────────────────────────────────────────────────────────

def load_corpus(skg_root: Path) -> list[dict]:
    """Load all existing wickets from all toolchain catalogs."""
    corpus = []
    for cat_file in sorted(skg_root.glob(CATALOG_GLOB)):
        try:
            d = json.loads(cat_file.read_text())
            domain = d.get("domain", cat_file.stem)
            for wid, w in d.get("wickets", {}).items():
                corpus.append({
                    "id":           wid,
                    "domain":       domain,
                    "label":        w.get("label", ""),
                    "description":  w.get("description", ""),
                    "evidence_hint": w.get("evidence_hint", ""),
                    "_source":      str(cat_file),
                })
        except Exception as e:
            log.debug(f"corpus load skip {cat_file}: {e}")
    log.info(f"Corpus: {len(corpus)} wickets from {skg_root.glob(CATALOG_GLOB)}")
    return corpus


# ─────────────────────────────────────────────────────────────────────────────
# TF-IDF similarity — no embeddings, no AI, pure token overlap
# ─────────────────────────────────────────────────────────────────────────────

def _tokenize(text: str) -> list[str]:
    return re.findall(r'[a-z0-9]+', text.lower())

def _tfidf_vectors(docs: list[str]) -> list[dict[str, float]]:
    """Compute TF-IDF vectors for a list of documents."""
    tokenized = [_tokenize(d) for d in docs]
    # IDF
    N = len(docs)
    df: dict[str, int] = defaultdict(int)
    for tokens in tokenized:
        for t in set(tokens):
            df[t] += 1
    idf = {t: math.log((N + 1) / (df[t] + 1)) + 1 for t in df}
    # TF-IDF
    vectors = []
    for tokens in tokenized:
        tf: dict[str, float] = defaultdict(float)
        for t in tokens:
            tf[t] += 1
        n = len(tokens) or 1
        vec = {t: (c / n) * idf.get(t, 1.0) for t, c in tf.items()}
        vectors.append(vec)
    return vectors

def _cosine(a: dict, b: dict) -> float:
    keys = set(a) & set(b)
    if not keys:
        return 0.0
    dot = sum(a[k] * b[k] for k in keys)
    na  = math.sqrt(sum(v*v for v in a.values()))
    nb  = math.sqrt(sum(v*v for v in b.values()))
    return dot / (na * nb) if na * nb > 0 else 0.0

def find_similar(query: str, corpus: list[dict], top_k: int = 3,
                 threshold: float = 0.35) -> list[tuple[float, dict]]:
    """Find corpus wickets most similar to query text."""
    if not corpus:
        return []
    docs  = [f"{w['label']} {w['description']} {w['evidence_hint']}" for w in corpus]
    docs.append(query)
    vecs  = _tfidf_vectors(docs)
    q_vec = vecs[-1]
    scored = [(i, _cosine(q_vec, vecs[i])) for i in range(len(corpus))]
    scored.sort(key=lambda x: -x[1])
    return [(score, corpus[i]) for i, score in scored[:top_k] if score >= threshold]


# ─────────────────────────────────────────────────────────────────────────────
# NVD fetcher
# ─────────────────────────────────────────────────────────────────────────────

def fetch_nvd(keyword: str, api_key: str | None = None,
              max_results: int = 20) -> list[dict]:
    """Fetch CVEs from NVD API v2 for a keyword."""
    params = {"keywordSearch": keyword, "resultsPerPage": min(max_results, 2000)}
    url = NVD_API + "?" + urllib.parse.urlencode(params)
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        vulns = data.get("vulnerabilities", [])
        log.info(f"NVD: {len(vulns)} CVEs for '{keyword}'")
        return vulns
    except Exception as e:
        log.warning(f"NVD fetch failed for '{keyword}': {e}")
        return []


def parse_cve(vuln: dict) -> dict | None:
    """Extract structured fields from a NVD vulnerability record."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # Description
    descs = cve.get("descriptions", [])
    desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

    # Match the live NVD feed path: prefer CVSS v3, then fall back to v2.
    metrics = cve.get("metrics", {})
    metric = {}
    cvss_data = {}
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            metric = metric_list[0] or {}
            cvss_data = metric.get("cvssData", {}) or {}
            break

    av  = cvss_data.get("attackVector", cvss_data.get("accessVector", "NETWORK"))
    pr  = cvss_data.get("privilegesRequired", "NONE")
    ui  = cvss_data.get("userInteraction", "NONE")
    sco = cvss_data.get("baseScore", 0.0)
    sev = metric.get("baseSeverity", cvss_data.get("baseSeverity", ""))

    # CWE
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])

    # Affected CPEs
    configs = cve.get("configurations", [])
    cpes = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpes.append(match.get("criteria", ""))

    # References
    refs = [r["url"] for r in cve.get("references", [])
            if "url" in r][:3]

    return {
        "id":          cve_id,
        "description": desc,
        "av":          av,
        "pr":          pr,
        "ui":          ui,
        "score":       sco,
        "severity":    sev,
        "cwes":        cwes,
        "cpes":        cpes,
        "references":  refs,
        "published":   cve.get("published", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Wicket derivation — CVE record → catalog wicket
# ─────────────────────────────────────────────────────────────────────────────

def cve_to_wicket(cve: dict, prefix: str, index: int,
                  corpus: list[dict],
                  package_hint: str = "") -> dict | None:
    """
    Derive a catalog wicket from a parsed CVE record.
    Returns None if a sufficiently similar wicket already exists in corpus.
    """
    # Build query text for similarity check
    cwe_desc = " ".join(CWE_DESC.get(c, c) for c in cve["cwes"])
    query = f"{cve['description']} {cwe_desc}"

    # Check corpus similarity — if strong match exists, skip (avoid duplication)
    similar = find_similar(query, corpus, top_k=1, threshold=0.60)
    if similar:
        score, match = similar[0]
        log.debug(f"  {cve['id']} similar to {match['id']} ({score:.2f}) — skipping")
        return None

    # Derive label from CVE description
    label = _derive_label(cve, package_hint=package_hint)

    # Derive description
    if cve["cwes"] and cve["cwes"][0] in CWE_DESC:
        desc = f"{CWE_DESC[cve['cwes'][0]]} ({cve['id']}, CVSS {cve['score']} {cve['severity']})"
    else:
        # Truncate NVD description to one sentence
        sentences = re.split(r'(?<=[.!?])\s+', cve["description"])
        desc = sentences[0][:200] if sentences else cve["description"][:200]
        desc += f" ({cve['id']}, CVSS {cve['score']})"

    # Derive evidence hint from CVSS vectors
    av_hint = AV_HINTS.get(cve["av"], AV_HINTS["NETWORK"])
    pr_hint = PR_DEPS.get(cve["pr"], "")
    ev_hint = av_hint
    if pr_hint and pr_hint != "no_authentication_required":
        ev_hint += f"; requires {pr_hint.replace('_', ' ')}"
    if cve["ui"] == "REQUIRED":
        ev_hint += "; user interaction required (social engineering or phishing vector)"

    wid = f"{prefix}-{index:02d}"
    return {
        "id":            wid,
        "label":         label,
        "description":   desc,
        "evidence_hint": ev_hint,
        "_cve_id":       cve["id"],
        "_cvss_score":   cve["score"],
        "_references":   cve["references"],
    }


def _derive_label(cve: dict, package_hint: str = "") -> str:
    """Derive a snake_case label from CVE data."""
    # CWE-based labels take priority
    cwe_labels = {
        "CWE-502": "unsafe_deserialization_exploitable",
        "CWE-78":  "command_injection_exploitable",
        "CWE-89":  "sql_injection_exploitable",
        "CWE-287": "authentication_bypass_possible",
        "CWE-306": "unauthenticated_access_to_critical_function",
        "CWE-798": "hardcoded_credential_present",
        "CWE-434": "unrestricted_file_upload_exploitable",
        "CWE-611": "xxe_injection_exploitable",
        "CWE-94":  "code_injection_exploitable",
        "CWE-269": "privilege_escalation_path_exists",
        "CWE-276": "insecure_default_permissions",
        "CWE-200": "sensitive_data_exposure",
        "CWE-400": "resource_exhaustion_possible",
        "CWE-119": "memory_corruption_exploitable",
        "CWE-125": "out_of_bounds_read_exploitable",
        "CWE-787": "out_of_bounds_write_exploitable",
        "CWE-416": "use_after_free_exploitable",
        "CWE-190": "integer_overflow_exploitable",
    }
    for cwe in cve.get("cwes", []):
        if cwe in cwe_labels:
            base = cwe_labels[cwe]
            # Qualify with package name to avoid collisions across packages
            if package_hint:
                pkg = re.sub(r'[^a-z0-9]', '_', package_hint.lower())
                return f"{pkg}_{base}"
            return base

    # Fall back to keyword extraction from description
    desc_lower = cve["description"].lower()
    keyword_labels = [
        (["remote code execution", "rce"],         "remote_code_execution_possible"),
        (["arbitrary code"],                        "arbitrary_code_execution_possible"),
        (["privilege escalat", "privesc"],          "privilege_escalation_path_exists"),
        (["authentication bypass", "bypass auth"],  "authentication_bypass_possible"),
        (["denial of service", " dos "],            "denial_of_service_possible"),
        (["information disclosure", "info leak"],   "sensitive_data_exposure"),
        (["path traversal", "directory traversal"], "path_traversal_exploitable"),
        (["open redirect"],                         "open_redirect_present"),
        (["csrf", "cross-site request"],            "csrf_exploitable"),
        (["ssrf"],                                  "ssrf_exploitable"),
        (["heap overflow", "heap-based"],           "heap_overflow_exploitable"),
        (["stack overflow", "stack-based"],         "stack_overflow_exploitable"),
        (["null pointer", "null dereference"],      "null_dereference_exploitable"),
        (["integer overflow"],                      "integer_overflow_exploitable"),
        (["use after free", "use-after-free"],      "use_after_free_exploitable"),
        (["out-of-bounds", "out of bounds"],        "out_of_bounds_exploitable"),
        (["format string"],                         "format_string_exploitable"),
        (["race condition", "time-of-check"],       "race_condition_exploitable"),
    ]
    for keywords, label in keyword_labels:
        if any(k in desc_lower for k in keywords):
            if package_hint:
                pkg = re.sub(r'[^a-z0-9]', '_', package_hint.lower())
                return f"{pkg}_{label}"
            return label

    # Last resort: package + severity
    if package_hint:
        pkg = re.sub(r'[^a-z0-9]', '_', package_hint.lower())
        sev = cve.get("severity", "").lower() or "medium"
        return f"{pkg}_{sev}_vuln_present"

    return "vulnerability_condition_present"


# ─────────────────────────────────────────────────────────────────────────────
# Attack path derivation — group wickets into logical paths
# ─────────────────────────────────────────────────────────────────────────────

def derive_attack_paths(wickets: dict[str, dict], domain: str,
                        description: str) -> dict[str, dict]:
    """
    Derive attack paths from compiled wickets.

    Logic:
      - Group wickets by attack vector (network vs local)
      - Add standard precondition wickets (reachability, auth) as path heads
      - Each CVE-derived wicket becomes a terminal node in its path
    """
    paths: dict[str, dict] = {}
    domain_slug = domain.replace("-", "_").replace(" ", "_")

    # Separate by attack vector
    network_wickets = [wid for wid, w in wickets.items()
                       if "network" in w.get("evidence_hint", "").lower()
                       or "reachab" in w.get("evidence_hint", "").lower()]
    local_wickets   = [wid for wid, w in wickets.items()
                       if wid not in network_wickets]

    # Reachability precondition (always first)
    reach_id = next((wid for wid, w in wickets.items()
                     if "reachab" in w.get("label", "")), None)

    if network_wickets:
        path_id = f"{domain_slug}_network_exploit_v1"
        required = []
        if reach_id:
            required.append(reach_id)
        required.extend(w for w in network_wickets if w != reach_id)
        paths[path_id] = {
            "id":               path_id,
            "description":      f"Remote exploitation via network-accessible vulnerability in {domain} environment.",
            "required_wickets": required[:6],  # cap at 6 for tractability
            "references":       _collect_refs(wickets, required),
        }

    if local_wickets:
        path_id = f"{domain_slug}_local_exploit_v1"
        required = []
        if reach_id:
            required.append(reach_id)
        required.extend(w for w in local_wickets if w != reach_id)
        paths[path_id] = {
            "id":               path_id,
            "description":      f"Local exploitation of {domain} environment requiring initial access.",
            "required_wickets": required[:6],
            "references":       _collect_refs(wickets, required),
        }

    # Full chain path if both exist
    if network_wickets and local_wickets:
        path_id = f"{domain_slug}_full_chain_v1"
        required = []
        if reach_id:
            required.append(reach_id)
        required.extend(w for w in network_wickets if w != reach_id)
        required.extend(w for w in local_wickets   if w != reach_id)
        paths[path_id] = {
            "id":               path_id,
            "description":      f"Full exploitation chain: remote access through local privilege escalation in {domain}.",
            "required_wickets": required[:8],
            "references":       _collect_refs(wickets, required),
        }

    return paths


def _collect_refs(wickets: dict, wids: list[str]) -> list[str]:
    refs = []
    for wid in wids:
        refs.extend(wickets.get(wid, {}).get("_references", []))
    return list(dict.fromkeys(refs))[:5]  # deduplicated, max 5


# ─────────────────────────────────────────────────────────────────────────────
# Standard precondition wickets — every domain needs these
# ─────────────────────────────────────────────────────────────────────────────

STANDARD_PRECONDITIONS = {
    "reachability": {
        "label":         "target_reachable_and_responsive",
        "description":   "Target system or service responds to network probes; collection or exploitation is feasible.",
        "evidence_hint": "TCP connect or ICMP probe confirms reachability; confirm via port scan or HTTP HEAD request",
    },
    "service_exposed": {
        "label":         "target_service_exposed",
        "description":   "Target service is listening on a reachable port and accepting connections.",
        "evidence_hint": "Service banner grab or HTTP 200/401 response confirms service is listening",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Main compiler
# ─────────────────────────────────────────────────────────────────────────────

def compile_catalog(
    domain:      str,
    description: str,
    packages:    list[str] | None = None,
    keywords:    list[str] | None = None,
    prefix:      str | None = None,
    api_key:     str | None = None,
    skg_root:    Path = SKG_ROOT,
    min_cvss:    float = 4.0,
    max_wickets: int = 20,
) -> dict:
    """
    Compile a catalog for a domain from CVE/NVD data and corpus similarity.

    Args:
        domain:      Domain name (e.g. "supply_chain", "iot", "cloud_infra")
        description: One sentence describing the attack surface
        packages:    Package names to query NVD for (e.g. ["log4j", "spring"])
        keywords:    Additional NVD search keywords
        prefix:      Wicket ID prefix (e.g. "SC"). Auto-derived if not given.
        api_key:     NVD API key (optional, increases rate limit)
        min_cvss:    Minimum CVSS score to include (default 4.0)
        max_wickets: Maximum wickets to emit (default 20)

    Returns:
        Catalog dict matching SKG schema.
    """
    if prefix is None:
        # Derive prefix from domain: supply_chain → SC, iot → IO, cloud_infra → CI
        words = re.split(r'[_\-\s]+', domain.upper())
        prefix = "".join(w[0] for w in words if w)[:3]

    log.info(f"Compiling catalog: domain={domain} prefix={prefix}")

    # Load corpus for similarity checking
    corpus = load_corpus(skg_root)

    # Build NVD search terms
    search_terms = list(packages or []) + list(keywords or [])
    if not search_terms:
        # Fall back to domain keywords
        search_terms = re.split(r'[_\-\s]+', domain.lower())

    # Fetch and parse CVEs — track which package each CVE came from
    all_cves: list[dict] = []
    seen_ids: set[str] = set()
    cve_package: dict[str, str] = {}  # cve_id -> search term that found it
    for term in search_terms:
        vulns = fetch_nvd(term, api_key=api_key)
        for v in vulns:
            parsed = parse_cve(v)
            if parsed and parsed["id"] not in seen_ids:
                if parsed["score"] >= min_cvss:
                    parsed["_package_hint"] = term
                    all_cves.append(parsed)
                    seen_ids.add(parsed["id"])
                    cve_package[parsed["id"]] = term

    # Sort by CVSS score descending
    all_cves.sort(key=lambda c: -c["score"])
    log.info(f"CVEs after filter (CVSS>={min_cvss}): {len(all_cves)}")

    # Build wickets
    wickets: dict[str, dict] = {}
    index = 1

    # Standard preconditions first
    for key, w in STANDARD_PRECONDITIONS.items():
        wid = f"{prefix}-{index:02d}"
        wickets[wid] = {"id": wid, **w}
        index += 1

    # CVE-derived wickets — deduplicate by label, keep highest CVSS
    seen_labels: dict[str, str] = {}  # label -> wid
    for cve in all_cves:
        if len(wickets) >= max_wickets:
            break
        pkg_hint = cve.get("_package_hint", "")
        w = cve_to_wicket(cve, prefix, index, corpus, package_hint=pkg_hint)
        if not w:
            continue
        label = w["label"]
        if label in seen_labels:
            # Keep higher CVSS — replace if this one scores better
            existing_wid = seen_labels[label]
            if cve["score"] > wickets[existing_wid].get("_cvss_score", 0):
                # Update description to reflect better CVE
                wickets[existing_wid]["description"] = w["description"]
                wickets[existing_wid]["_references"]  = w.get("_references", [])
                wickets[existing_wid]["_cvss_score"]  = cve["score"]
            continue
        wid = w["id"]
        clean = {k: v for k, v in w.items() if not k.startswith("_")}
        clean["id"] = wid
        clean["_cvss_score"]  = cve["score"]
        clean["_references"]  = w.get("_references", [])
        wickets[wid] = clean
        seen_labels[label] = wid
        index += 1

    if len(wickets) <= 2:
        log.warning(f"Only {len(wickets)} wickets derived — CVE coverage may be sparse for '{domain}'")

    # Derive attack paths
    attack_paths = derive_attack_paths(wickets, domain, description)

    # Strip internal fields from final wickets
    final_wickets = {}
    for wid, w in wickets.items():
        final_wickets[wid] = {k: v for k, v in w.items() if not k.startswith("_")}

    catalog = {
        "domain":       domain,
        "version":      "1.0.0",
        "description":  description,
        "generated_by": "skg.forge.compiler",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_cves":  list(seen_ids),
        "wickets":      final_wickets,
        "attack_paths": attack_paths,
    }

    log.info(f"Compiled: {len(final_wickets)} wickets, {len(attack_paths)} paths")
    return catalog


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s  %(message)s")

    p = argparse.ArgumentParser(
        prog="skg-compiler",
        description="SKG catalog compiler — derives wickets from CVE/NVD data"
    )
    p.add_argument("--domain",      required=True,
                   help="Domain name (e.g. supply_chain, iot, cloud_infra)")
    p.add_argument("--description", required=True,
                   help="One sentence describing the attack surface")
    p.add_argument("--packages",    default="",
                   help="Comma-separated package/product names to query NVD")
    p.add_argument("--keywords",    default="",
                   help="Comma-separated additional NVD search keywords")
    p.add_argument("--prefix",      default=None,
                   help="Wicket ID prefix (auto-derived if not set)")
    p.add_argument("--api-key",     default=None,
                   help="NVD API key (optional)")
    p.add_argument("--min-cvss",    type=float, default=4.0,
                   help="Minimum CVSS score (default 4.0)")
    p.add_argument("--max-wickets", type=int,   default=20,
                   help="Maximum wickets to emit (default 20)")
    p.add_argument("--out",         default=None,
                   help="Output file (default: stdout)")
    p.add_argument("--dry-run",     action="store_true",
                   help="Show what would be compiled without writing")
    a = p.parse_args()

    packages = [x.strip() for x in a.packages.split(",") if x.strip()]
    keywords = [x.strip() for x in a.keywords.split(",") if x.strip()]

    catalog = compile_catalog(
        domain      = a.domain,
        description = a.description,
        packages    = packages,
        keywords    = keywords,
        prefix      = a.prefix,
        api_key     = a.api_key,
        min_cvss    = a.min_cvss,
        max_wickets = a.max_wickets,
    )

    output = json.dumps(catalog, indent=2)

    if a.dry_run:
        print(output)
        return

    if a.out:
        Path(a.out).write_text(output)
        print(f"Written: {a.out}")
        print(f"  {len(catalog['wickets'])} wickets")
        print(f"  {len(catalog['attack_paths'])} attack paths")
        print(f"  {len(catalog.get('source_cves', []))} source CVEs")
    else:
        print(output)


if __name__ == "__main__":
    main()
# PATCH — applied by fixup script, ignore

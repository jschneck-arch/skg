"""
skg.intel.gap_detector
=======================
Scans raw collection output for services, conditions, and artifacts
that have no current toolchain coverage.

A gap is: something observed during collection that SKG cannot evaluate
because no toolchain covers it.

Detection sources:
  1. Process list  — running services not covered by any toolchain
  2. Port scan     — open ports with no toolchain mapping
  3. Package list  — installed software with known attack patterns
  4. SSH collection results — services/configs with no wicket mapping
  5. Agent callbacks — platform-specific conditions with no toolchain

Each gap record:
  {
    service:       str,           # canonical service name
    category:      str,           # "network_service"|"process"|"package"|"config"
    hosts:         [str],         # workload_ids where observed
    evidence:      str,           # what was seen
    detail:        str,           # why this is a gap
    attack_surface: str,          # rough description of attack surface
    collection_hints: [str],      # what to collect to evaluate this
    forge_ready:   bool,          # enough context to auto-generate toolchain
  }

Known gaps are stored in state to avoid re-surfacing on every sweep.
New gaps trigger forge candidates.
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from skg.core.paths import EVENTS_DIR, SKG_STATE_DIR

log = logging.getLogger("skg.intel.gaps")

GAP_STATE_FILE = SKG_STATE_DIR / "gap_detector.state.json"

# Services with known attack patterns but no current SKG toolchain
# Format: {process_pattern: (service_name, attack_surface_description, forge_ready)}
KNOWN_SERVICES = {
    r"redis-server":      ("redis",       "Unauthenticated access, SSRF via RESP protocol, RCE via config rewrite", True),
    r"redis":             ("redis",       "Unauthenticated access, SSRF via RESP protocol, RCE via config rewrite", True),
    r"mongod\b":          ("mongodb",     "Unauthenticated access, data exfil, JS injection via mapReduce", True),
    r"postgres":          ("postgresql",  "Credential brute force, pg_read_file, COPY TO/FROM PROGRAM RCE", True),
    r"mysqld":            ("mysql",       "Credential attacks, SELECT INTO OUTFILE, UDF injection", True),
    r"nginx":             ("nginx",       "Path traversal, SSRF via proxy_pass, header injection", True),
    r"httpd|apache2":     ("apache",      "Path traversal, mod_status exposure, CVE-based RCE", True),
    r"jenkins":           ("jenkins",     "Groovy script console RCE, credential exposure, agent hijack", True),
    r"jboss|wildfly":     ("jboss",       "Deserialization RCE, admin console exposure, JMX abuse", True),
    r"tomcat":            ("tomcat",      "Manager app RCE, AJP Ghostcat, deserialization", True),
    r"elastic|elasticsearch": ("elasticsearch", "Unauthenticated access, script injection, CVE-based RCE", True),
    r"kibana":            ("kibana",      "Timelion RCE, SSRF, credential exposure", True),
    r"rabbitmq":          ("rabbitmq",    "Default creds, management API exposure, message injection", True),
    r"consul\b":          ("consul",      "Unauthenticated API, RCE via script checks, ACL bypass", True),
    r"vault\b":           ("vault",       "Token exposure, secret engine abuse, PKI misconfig", True),
    r"etcd\b":            ("etcd",        "Unauthenticated API, k8s secret exposure, raft manipulation", True),
    r"kubelet":           ("kubernetes",  "Kubelet API RCE, pod escape, RBAC abuse", True),
    r"k3s|k8s|kube-api":  ("kubernetes",  "API server exposure, RBAC abuse, etcd access", True),
    r"grafana":           ("grafana",     "CVE-2021-43798 path traversal, datasource SSRF, default creds", True),
    r"splunk":            ("splunk",      "Search head RCE, forwarder credential exposure, token abuse", True),
    r"gitlab":            ("gitlab",      "CVE-based RCE, SSRF, secret variable exposure", True),
    r"gitea|gogs":        ("gitea",       "Default creds, repo secret exposure, webhook SSRF", True),
    r"samba|smbd":        ("smb",         "CVE-based RCE (EternalBlue), share credential exposure", True),
    r"nfs":               ("nfs",         "World-readable shares, no_root_squash, mount relay", True),
    r"rsync\b":           ("rsync",       "Unauthenticated module access, path traversal", True),
    r"memcache":          ("memcached",   "Unauthenticated access, UDP amplification, data injection", True),
    r"zookeeper":         ("zookeeper",   "Unauthenticated access, config/credential exposure", True),
    r"kafka\b":           ("kafka",       "Unauthenticated producer/consumer, JMX RCE", True),
    r"solr\b":            ("solr",        "RCE via VelocityResponseWriter, SSRF, XXE", True),
    r"influxd":           ("influxdb",    "Unauthenticated API v1, flux injection, data exfil", True),
    r"prometheus":        ("prometheus",  "Metrics exposure, targets SSRF, alertmanager webhook", True),
    r"minio":             ("minio",       "Default creds, bucket enumeration, path traversal", True),
}

# Port → service mapping for port-based gap detection
PORT_SERVICES = {
    6379:  "redis",
    27017: "mongodb",
    5432:  "postgresql",
    3306:  "mysql",
    8080:  "tomcat_or_webapp",
    8443:  "tomcat_or_webapp",
    9200:  "elasticsearch",
    5601:  "kibana",
    5672:  "rabbitmq",
    15672: "rabbitmq",
    8500:  "consul",
    8200:  "vault",
    2379:  "etcd",
    2380:  "etcd",
    10250: "kubernetes_kubelet",
    6443:  "kubernetes_api",
    3000:  "grafana",
    8888:  "jupyter",
    8888:  "jupyter",
    11211: "memcached",
    2181:  "zookeeper",
    9092:  "kafka",
    8983:  "solr",
    8086:  "influxdb",
    9090:  "prometheus",
    9000:  "minio",
    445:   None,   # SMB — covered by host toolchain
    139:   None,   # SMB
    2049:  None,   # NFS — covered by host toolchain
}

# Known toolchains — services already covered
COVERED_SERVICES = {
    "log4j", "log4j2", "log4shell",     # APRS toolchain
    "docker", "container",               # Container escape toolchain
    "activedirectory", "ad", "kerberos", # AD lateral toolchain
    "ssh", "winrm", "rdp",              # Host toolchain
    # Data pipeline toolchain covers these as data sources (not attack surfaces)
    # They remain in KNOWN_SERVICES for the security angle but the data
    # toolchain profiles their integrity separately
    "postgresql", "mysql", "sqlite",
}

# Packages that indicate a gap service is installed
PACKAGE_PATTERNS = {
    r"redis":           "redis",
    r"mongodb|mongod":  "mongodb",
    r"postgresql|psql": "postgresql",
    r"mysql":           "mysql",
    r"elasticsearch":   "elasticsearch",
    r"kibana":          "kibana",
    r"rabbitmq":        "rabbitmq",
    r"consul":          "consul",
    r"vault":           "vault",
    r"etcd":            "etcd",
    r"grafana":         "grafana",
    r"jenkins":         "jenkins",
    r"tomcat":          "tomcat",
    r"memcached":       "memcached",
    r"zookeeper":       "zookeeper",
    r"kafka":           "kafka",
    r"solr":            "solr",
    r"influxdb":        "influxdb",
    r"prometheus":      "prometheus",
    r"minio":           "minio",
    r"gitlab":          "gitlab",
}


def detect_from_web_fingerprints() -> list[dict]:
    """
    Scan web_fingerprints directory for gap signals written by WebSensor.
    Returns gap records for services detected via web fingerprinting.
    """
    fp_dir = SKG_STATE_DIR / "web_fingerprints"
    if not fp_dir.exists():
        return []

    gaps: dict[str, dict] = {}

    for f in sorted(fp_dir.glob("*.json"))[-20:]:
        try:
            data = json.loads(f.read_text())
        except Exception:
            continue

        for sig in data.get("gap_signals", []):
            svc = sig.get("service", "")
            if not svc or svc in COVERED_SERVICES:
                continue
            if svc not in gaps:
                gaps[svc] = {
                    "service":        svc,
                    "category":       sig.get("category", "web_fingerprint"),
                    "hosts":          list(sig.get("hosts", [])),
                    "evidence":       sig.get("evidence", ""),
                    "detail":         sig.get("detail", ""),
                    "attack_surface": sig.get("attack_surface", ""),
                    "collection_hints": sig.get("collection_hints", _collection_hints(svc)),
                    "forge_ready":    sig.get("forge_ready", True),
                    "source_url":     sig.get("source_url", ""),
                }
            else:
                for h in sig.get("hosts", []):
                    if h not in gaps[svc]["hosts"]:
                        gaps[svc]["hosts"].append(h)

    return list(gaps.values())


def detect_from_events(events_dir: Path | None = None) -> list[dict]:
    """
    Scan EVENTS_DIR for raw collection events and extract gap signals.
    Returns list of gap records.
    """
    events_dir = events_dir or EVENTS_DIR
    if not events_dir.exists():
        return []

    # Aggregate by workload
    workload_data: dict[str, dict] = defaultdict(lambda: {
        "processes": "", "packages": "", "network": "", "workload_id": ""
    })

    for f in sorted(events_dir.glob("*.ndjson"))[-50:]:  # recent 50 files
        for line in f.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            payload = ev.get("payload", {})
            wid = payload.get("workload_id", "unknown")
            workload_data[wid]["workload_id"] = wid

            # Collect process/package/network evidence from payloads
            detail = str(payload.get("detail", ""))
            source = ev.get("provenance", {}).get("evidence", {}).get("pointer", "")

            if "ps" in source or "process" in source.lower():
                workload_data[wid]["processes"] += " " + detail
            elif "package" in source.lower() or "dpkg" in source.lower():
                workload_data[wid]["packages"] += " " + detail
            elif "port" in source.lower() or "network" in source.lower():
                workload_data[wid]["network"] += " " + detail
            elif "web_fingerprint" in source or ev.get("payload",{}).get("collection_type") == "web_fingerprint":
                # Web sensor technology findings — treat as process signal
                workload_data[wid]["processes"] += " " + detail

    gaps: dict[str, dict] = {}  # service → gap record

    for wid, data in workload_data.items():
        processes = data["processes"].lower()
        packages  = data["packages"].lower()
        network   = data["network"]

        # Process-based detection
        for pattern, (service, surface, forge_ready) in KNOWN_SERVICES.items():
            if service in COVERED_SERVICES:
                continue
            if re.search(pattern, processes, re.IGNORECASE):
                if service not in gaps:
                    gaps[service] = {
                        "service": service, "category": "process",
                        "hosts": [], "evidence": f"{service} process observed",
                        "detail": f"Running service with no toolchain coverage",
                        "attack_surface": surface,
                        "collection_hints": _collection_hints(service),
                        "forge_ready": forge_ready,
                    }
                if wid not in gaps[service]["hosts"]:
                    gaps[service]["hosts"].append(wid)

        # Package-based detection
        for pattern, service in PACKAGE_PATTERNS.items():
            if service in COVERED_SERVICES:
                continue
            if re.search(pattern, packages, re.IGNORECASE):
                if service not in gaps:
                    svc_info = next(
                        (v for k,v in KNOWN_SERVICES.items() if v[0] == service),
                        (service, f"{service} package installed", True)
                    )
                    gaps[service] = {
                        "service": service, "category": "package",
                        "hosts": [], "evidence": f"{service} package installed",
                        "detail": "Package present, no toolchain to evaluate exploit conditions",
                        "attack_surface": svc_info[1],
                        "collection_hints": _collection_hints(service),
                        "forge_ready": svc_info[2],
                    }
                if wid not in gaps[service]["hosts"]:
                    gaps[service]["hosts"].append(wid)

        # Port-based detection
        for port, service in PORT_SERVICES.items():
            if service is None or service in COVERED_SERVICES:
                continue
            if f":{port}" in network or f" {port} " in network:
                if service not in gaps:
                    svc_info = next(
                        (v for k,v in KNOWN_SERVICES.items() if v[0] == service),
                        (service, f"Port {port} open — {service}", True)
                    )
                    gaps[service] = {
                        "service": service, "category": "network_port",
                        "hosts": [], "evidence": f"Port {port} open",
                        "detail": f"Listening service on {port} with no toolchain coverage",
                        "attack_surface": svc_info[1],
                        "collection_hints": _collection_hints(service),
                        "forge_ready": svc_info[2],
                    }
                if wid not in gaps[service]["hosts"]:
                    gaps[service]["hosts"].append(wid)

    # Web gap signals — from web_sensor obs.gap.signal events
    for f in sorted(events_dir.glob("web_*.ndjson"))[-20:]:
        for line in f.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get("type") != "obs.gap.signal":
                continue
            payload = ev.get("payload", {})
            service = payload.get("service", "")
            wid     = payload.get("workload_id", "unknown")
            url     = payload.get("url", "")
            if not service or service in COVERED_SERVICES:
                continue
            svc_info = next(
                (v for k, v in KNOWN_SERVICES.items() if v[0] == service),
                (service, f"{service} detected on web target {url}", True)
            )
            if service not in gaps:
                gaps[service] = {
                    "service": service, "category": "web_fingerprint",
                    "hosts": [], "evidence": f"{service} detected at {url}",
                    "detail": f"Web surface: {service} with no toolchain coverage",
                    "attack_surface": svc_info[1],
                    "collection_hints": _collection_hints(service),
                    "forge_ready": svc_info[2],
                    "url": url,
                }
            if wid not in gaps[service]["hosts"]:
                gaps[service]["hosts"].append(wid)

    return [g for g in gaps.values() if g["hosts"]]


def _collection_hints(service: str) -> list[str]:
    """What SSH commands to run to collect evidence for this service."""
    hints = {
        "redis": [
            "redis-cli -h {host} ping",
            "redis-cli -h {host} config get requirepass",
            "redis-cli -h {host} info server",
            "cat /etc/redis/redis.conf 2>/dev/null | grep -E 'requirepass|bind|protected'",
        ],
        "mongodb": [
            "mongo --host {host} --eval 'db.adminCommand({listDatabases:1})' 2>/dev/null",
            "cat /etc/mongod.conf 2>/dev/null | grep -E 'auth|bindIp'",
            "ss -tnlp | grep 27017",
        ],
        "elasticsearch": [
            "curl -s http://{host}:9200/_cluster/health 2>/dev/null",
            "curl -s http://{host}:9200/_cat/indices 2>/dev/null",
            "cat /etc/elasticsearch/elasticsearch.yml 2>/dev/null | grep -E 'network|security|xpack'",
        ],
        "postgresql": [
            "psql -h {host} -U postgres -c '\\\\l' 2>/dev/null",
            "cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null",
            "ss -tnlp | grep 5432",
        ],
        "jenkins": [
            "curl -s http://{host}:8080/api/json 2>/dev/null | head -c 200",
            "cat /var/lib/jenkins/config.xml 2>/dev/null | grep -E 'useSecurity|authorizationStrategy'",
        ],
        "kubernetes": [
            "curl -sk https://{host}:10250/pods 2>/dev/null | head -c 200",
            "curl -sk https://{host}:6443/api 2>/dev/null | head -c 200",
            "kubectl get pods --all-namespaces 2>/dev/null | head -20",
        ],
        "consul": [
            "curl -s http://{host}:8500/v1/catalog/services 2>/dev/null",
            "curl -s http://{host}:8500/v1/acl/tokens 2>/dev/null",
        ],
        "vault": [
            "curl -s http://{host}:8200/v1/sys/health 2>/dev/null",
            "curl -s http://{host}:8200/v1/sys/mounts 2>/dev/null",
        ],
    }
    defaults = [
        f"ss -tnlp | grep {service}",
        f"ps aux | grep {service}",
        f"find /etc -name '*{service}*' -type f 2>/dev/null | head -5",
    ]
    return hints.get(service, defaults)


def load_known_gaps() -> dict:
    if GAP_STATE_FILE.exists():
        try:
            return json.loads(GAP_STATE_FILE.read_text())
        except Exception:
            pass
    return {}


def save_known_gaps(gaps: dict):
    GAP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    GAP_STATE_FILE.write_text(json.dumps(gaps, indent=2))


def detect_new_gaps(events_dir: Path | None = None) -> list[dict]:
    """
    Detect gaps not yet seen before.
    Returns only new gaps (not in known state).
    """
    known = load_known_gaps()
    # Combine event-based and web fingerprint-based gap detection
    all_gaps = detect_from_events(events_dir)
    web_gaps = detect_from_web_fingerprints()
    # Merge — web gaps take precedence for their services
    seen = {g["service"] for g in all_gaps}
    for g in web_gaps:
        if g["service"] not in seen:
            all_gaps.append(g)
            seen.add(g["service"])
    new_gaps = []
    for gap in all_gaps:
        svc = gap["service"]
        if svc not in known:
            new_gaps.append(gap)
            known[svc] = {
                "first_seen": __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc).isoformat(),
                "hosts": gap["hosts"],
            }
        else:
            # Update host list
            known[svc]["hosts"] = list(set(known[svc].get("hosts",[]) + gap["hosts"]))
    save_known_gaps(known)
    return new_gaps

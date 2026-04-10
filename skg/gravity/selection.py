from __future__ import annotations

import glob
import json
import math
from pathlib import Path
from typing import Any, Callable


BOOTSTRAP_NAMES = {
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
    "gobuster",
    "nikto",
    "searchsploit",
}

SPHERE_PREFIXES = {
    "WB-": "web",
    "HO-": "host",
    "DP-": "data",
    "DE-": "data",
    "CE-": "container_escape",
    "AD-": "ad_lateral",
    "BA-": "binary",
    "AI-": "ai_target",
    "SC-": "supply_chain",
    "IF-": "iot_firmware",
    "AP-": "aprs",
    "MC-": "metacognition",
    # Legacy aliases
    "DA-": "data",
    "LA-": "ad_lateral",
    "BI-": "binary",
    "IO-": "iot_firmware",
}

GRAVITY_DOMAIN_ALIASES = {
    "binary": "binary_analysis",
    "data": "data_pipeline",
}

INSTRUMENT_HINT_ALIASES = {
    "credential_reuse": "cred_reuse",
}


def _instrument_spheres(wavelength: list[str]) -> set[str]:
    spheres: set[str] = set()
    for wid in wavelength or []:
        for prefix, sphere in SPHERE_PREFIXES.items():
            if str(wid).startswith(prefix):
                spheres.add(sphere)
    return spheres


def _gravity_domain(domain: str) -> str:
    raw = str(domain or "").strip()
    return GRAVITY_DOMAIN_ALIASES.get(raw, raw)


def _instrument_hint_name(name: str) -> str:
    raw = str(name or "").strip()
    return INSTRUMENT_HINT_ALIASES.get(raw, raw)


def _observed_tooling_boost(inst_name: str, target_row: dict[str, Any], inst: Any) -> float:
    view_state = dict(target_row.get("view_state") or {})
    tool_overlay = dict(view_state.get("observed_tools") or {})
    if not tool_overlay:
        return 0.0

    instrument_hints = {
        _instrument_hint_name(item)
        for item in (tool_overlay.get("instrument_hints") or [])
        if str(item or "").strip()
    }
    domain_hints = {
        _gravity_domain(item)
        for item in (tool_overlay.get("domain_hints") or [])
        if str(item or "").strip()
    }
    tool_names = {
        str(item or "").strip().lower()
        for item in (tool_overlay.get("tool_names") or [])
        if str(item or "").strip()
    }
    observed_entries = {
        str(item.get("name") or "").strip().lower(): dict(item)
        for item in (tool_overlay.get("observed_tools") or [])
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    }

    boost = 0.0
    if inst_name in instrument_hints:
        boost += 0.30

    inst_spheres = {
        _gravity_domain(sphere)
        for sphere in _instrument_spheres(getattr(inst, "wavelength", []) or [])
    }
    if inst_spheres & domain_hints:
        boost += 0.15

    if inst_name == "binary_analysis" and tool_names & {"checksec", "rabin2", "r2", "ropgadget", "ltrace"}:
        boost += 0.10
    if inst_name == "capa_analysis" and "capa" in tool_names:
        boost += 0.12
    if inst_name == "angr_symbolic" and "py:angr" in tool_names:
        boost += 0.08
    if inst_name == "frida_trace" and "py:frida" in tool_names:
        boost += 0.10
    if inst_name == "nikto" and "nikto" in tool_names:
        boost += 0.10
    if inst_name == "searchsploit" and "searchsploit" in tool_names:
        boost += 0.10
    if inst_name == "enum4linux" and tool_names & {"enum4linux", "enum4linux-ng", "rpcclient"}:
        boost += 0.10
    if inst_name == "nmap":
        nmap_info = observed_entries.get("nmap", {})
        if nmap_info:
            boost += 0.05
            if bool(nmap_info.get("nse_available")) or bool(tool_overlay.get("nse_available")):
                boost += 0.10
        boost = min(boost, 0.15)

    return min(boost, 0.45)


def _load_h1_wickets(ip: str, interp_dir: Path | str) -> set[str]:
    wickets: set[str] = set()
    wid_safe = ip.replace(".", "_")
    for interp_file in sorted(Path(interp_dir).glob(f"*{wid_safe}*.json"))[-4:]:
        try:
            payload = json.loads(interp_file.read_text())
        except Exception:
            continue
        body = payload.get("payload", payload)
        if body.get("classification") != "indeterminate_h1":
            continue
        for wicket_id in body.get("sheaf", {}).get("affected_wickets", []):
            wickets.add(wicket_id)
    return wickets


def _fresh_unknown_mass(target_row: dict[str, Any]) -> float:
    view_state = dict(target_row.get("view_state") or {})
    measured_unknowns = float(view_state.get("measured_unknowns", 0.0) or 0.0)
    unresolved = float(target_row.get("unknowns", 0.0) or 0.0)
    return max(unresolved, measured_unknowns)


# Service ports that gate instrument execution.
# None = instrument is not service-gated (applies to all targets regardless of open ports).
# When service map is not yet established (open_ports empty), service-gated instruments
# are NOT blocked — the bootstrap sweep will discover the service map.
_SERVICE_INSTRUMENT_PORTS: dict[str, list[int] | None] = {
    "ssh_sensor":        [22, 2222, 2022],
    "sysaudit":          [22, 2222, 2022],
    "http_collector":    [80, 443, 8080, 8443, 8000, 8008, 8009, 8888],
    "auth_scanner":      [80, 443, 8080, 8443],
    "nikto":             [80, 443, 8080, 8443, 8000, 8008],
    "gobuster":          [80, 443, 8080, 8443, 8000, 8008],
    "sqlmap":            [80, 443, 8080, 8443],
    "enum4linux":        [139, 445],
    "bloodhound":        [88, 389, 636, 3268, 3269],
    "data_profiler":     [1433, 1521, 3306, 5432, 5433, 6379, 9200, 27017],
    "db_discovery":      [1433, 1521, 3306, 5432, 5433, 6379, 9200, 27017, 5601],
    "container_inspect": [2375, 2376, 5000, 6443, 10250],
}


def _is_service_accessible(instrument_name: str, target: dict[str, Any]) -> bool:
    """Gate check: can this instrument reach its required service on the target?

    Returns True when:
      - The instrument is not service-gated (applies universally), OR
      - The service map is not yet established (bootstrap must run first), OR
      - At least one required port is confirmed open.
    Returns False only when the service map IS established and none of the
    required ports appear in it — the instrument literally cannot reach its service.

    Wickets are the post-hoc knowledge ledger.  Service accessibility is the
    pre-hoc observation gate.  These are orthogonal — wicket state must never
    be used as a permission gate for instrument execution.
    """
    ports = _SERVICE_INSTRUMENT_PORTS.get(instrument_name)
    if ports is None:
        return True  # Not service-gated; applicable to all targets

    services = (
        target.get("services")
        or target.get("target", {}).get("services")
        or []
    )
    open_ports = {int(svc.get("port", 0)) for svc in services if svc.get("port")}
    if not open_ports:
        return True  # Service map not yet established; do not gate

    return any(p in open_ports for p in ports)


def _first_contact_entropy(inst: Any) -> float:
    """Information-theoretic potential at first contact (all wickets unknown).

    When no observations exist for a target, every wavelength wicket is in
    maximum-entropy (unknown) state: phi_u = 1.0 per wicket.
    Potential = |wavelength| / cost  (entropy gain per unit cost).
    """
    wavelength = getattr(inst, "wavelength", []) or []
    cost = max(float(getattr(inst, "cost", 1.0) or 1.0), 0.1)
    return len(wavelength) / cost


def _residual_entropy(inst: Any, node_key: str) -> float:
    """Residual entropy for an instrument that has run but may retain potential.

    Even after all cataloged wickets are settled, real attack surfaces have
    uncataloged observations (new CVEs, configuration drift, lateral paths).
    This term gives accessible instruments diminishing but non-zero potential.

    Computed as: log(1 + |wavelength|) / (1 + consecutive_no_change_runs)

    Consecutive runs with zero entropy reduction reduce this toward zero but
    never exactly reach it — instruments on accessible services always retain
    some observation drive.
    """
    wavelength = getattr(inst, "wavelength", []) or []
    history = list(getattr(inst, "entropy_history", {}).get(node_key, []) or [])
    consecutive = 0
    for delta in reversed(history):
        if (delta or 0) <= 0:
            consecutive += 1
        else:
            break
    return math.log1p(len(wavelength)) / (1.0 + consecutive)


def rank_instruments_for_node(
    *,
    target_row: dict[str, Any],
    instruments: dict[str, Any],
    focus_target: str | None,
    entropy_reduction_potential: Callable[[Any, str, dict[str, Any], set[str]], float],
    coherence_fn: Callable[[str, dict[str, Any]], float],
    reinforcement_fn: Callable[[str, Any], float],
    has_recent_artifact: Callable[[str, float], bool],
    discovery_dir: Path | str,
    cve_dir: Path | str,
    interp_dir: Path | str,
    print_fn: Callable[[str], None] = print,
) -> tuple[list[tuple[float, str, Any]], bool]:
    # node_key is the stable identity for this node — the identity_key resolved
    # by canonical_observation_subject().  For IP-only hosts it equals the IP;
    # for workload-identified nodes it is the host portion of the workload_id.
    node_key: str = str(target_row.get("identity_key") or target_row["ip"]).strip()
    # ip is the routable address used only for network instrument execution and
    # file-pattern matching — NOT as a scheduling identity.
    ip: str = str(target_row["ip"]).strip()

    candidates: list[tuple[float, str, Any]] = []
    h1_wickets = _load_h1_wickets(node_key, interp_dir)
    view_state = dict(target_row.get("view_state") or {})
    has_measured_view = bool(int(view_state.get("view_count", 0) or 0))
    fresh_unknowns = _fresh_unknown_mass(target_row)

    # File-pattern matching uses the routable IP (storage convention).
    has_nmap_history = bool(glob.glob(str(Path(discovery_dir) / f"gravity_nmap_{ip}_*.ndjson")))
    has_cve_history = bool(glob.glob(str(Path(cve_dir) / f"cve_events_{ip}_*.ndjson")))
    has_recent_web = has_recent_artifact(str(Path(discovery_dir) / f"gravity_http_{ip}_*.ndjson"))
    has_recent_auth = has_recent_artifact(str(Path(discovery_dir) / f"gravity_auth_{ip}_*.ndjson"))
    has_web_service = any(
        svc.get("service", "") in ("http", "https", "http-alt", "https-alt")
        for svc in target_row["target"].get("services", [])
    )
    has_versioned_service = any(
        (svc.get("banner") or "").strip()
        for svc in target_row["target"].get("services", [])
    )
    # focus_target may be either a node_key or an operator label; check both.
    focus_match = (focus_target in (node_key, ip))
    cold_start_target = (
        (not has_nmap_history and not has_measured_view)
        or target_row["target"].get("_no_nmap_history")
        or (focus_match and not has_measured_view)
        or (fresh_unknowns >= 15 and (has_web_service or has_versioned_service) and not has_measured_view)
    )

    for name, inst in instruments.items():
        if not getattr(inst, "available", False):
            continue

        # Accessibility gate: skip instruments whose required service is
        # confirmed absent.  If the service map is not yet built, do not gate.
        if not _is_service_accessible(name, target_row.get("target") or {}):
            continue

        potential = entropy_reduction_potential(
            inst,
            node_key,
            target_row["states"],
            target_row["applicable_wickets"],
        )
        # Residual entropy: instruments on accessible services always retain
        # observation drive even after all cataloged wickets settle.
        # This replaces magic floor constants with physics-derived diminishing potential.
        potential += _residual_entropy(inst, node_key)

        coherence = coherence_fn(name, target_row)
        if coherence <= 0.0:
            continue
        potential *= coherence

        tooling_boost = _observed_tooling_boost(name, target_row, inst)
        if tooling_boost > 0.0:
            potential *= (1.0 + tooling_boost)

        pearl_boost = reinforcement_fn(node_key, inst)
        if pearl_boost >= 1.0:
            potential *= (1.0 + pearl_boost / 10.0)
        else:
            potential += pearl_boost

        r_per_sphere = target_row.get("R_per_sphere", {})
        if r_per_sphere:
            inst_spheres = _instrument_spheres(getattr(inst, "wavelength", []) or [])
            if inst_spheres:
                r_vals = [r_per_sphere.get(sphere, 0.5) for sphere in inst_spheres]
                r_mean = sum(r_vals) / len(r_vals)
                potential *= (1.0 + 0.25 * (1.0 - r_mean))

        if h1_wickets:
            wave = set(getattr(inst, "wavelength", []) or [])
            overlap = wave & h1_wickets
            if overlap:
                penalty_frac = len(overlap) / max(len(wave), 1)
                potential *= max(0.2, 1.0 - 0.8 * penalty_frac)

        wg_inst_boost = target_row.get("wgraph_inst_boosts", {}).get(name, 0.0)
        if wg_inst_boost > 0:
            potential += 0.20 * math.log1p(wg_inst_boost)

        if cold_start_target:
            # First-contact entropy: all wavelength wickets are unknown → phi_u = 1.0
            # Potential = |wavelength| / cost — principled, no magic constants.
            # Gating by context (nmap history, web service, etc.) applies here to
            # avoid scheduling instruments that require preconditions not yet met.
            fc = _first_contact_entropy(inst)
            fc_floor: float | None = None
            if name == "nmap" and not has_nmap_history:
                fc_floor = fc
            elif name == "pcap" and not has_nmap_history:
                fc_floor = fc * 0.55
            elif name == "nvd_feed" and has_versioned_service and not has_cve_history:
                fc_floor = fc
            elif name == "http_collector" and (has_web_service or not has_nmap_history) and not has_recent_web:
                fc_floor = fc
            elif name == "auth_scanner" and has_web_service and not has_recent_auth:
                fc_floor = fc * 0.5
            elif name == "metasploit" and (has_web_service or not has_nmap_history):
                fc_floor = fc
            elif name == "gobuster" and has_web_service:
                fc_floor = fc * 0.7
            # Apply floor only if it exceeds current potential (which is already
            # coherence-scaled).  When floor kicks in, apply coherence once.
            if fc_floor is not None:
                fc_floor_scaled = fc_floor * coherence
                if fc_floor_scaled > potential:
                    potential = fc_floor_scaled

        if inst.failed_to_reduce(node_key):
            print_fn(f"    {name:20s} potential={potential:.1f} (penalized — no entropy reduction last time)")
        elif potential > 0:
            print_fn(f"    {name:20s} potential={potential:.1f}")

        if potential > 0:
            candidates.append((potential, name, inst))

    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates, cold_start_target


def choose_instruments_for_target(
    *,
    candidates: list[tuple[float, str, Any]],
    instruments: dict[str, Any],
    target_row: dict[str, Any],
    cold_start_target: bool,
    coherence_fn: Callable[[str, dict[str, Any]], float],
    interactive: bool,
    print_fn: Callable[[str], None] = print,
) -> tuple[list[tuple[float, str, Any]], tuple[float, str, Any] | None, list[tuple[float, str, Any]]]:
    if not candidates:
        return [], None, []

    if cold_start_target or _fresh_unknown_mass(target_row) >= 20:
        chosen: list[tuple[float, str, Any]] = []
        seen: set[str] = set()
        for potential, name, inst in candidates:
            if name in BOOTSTRAP_NAMES:
                chosen.append((potential, name, inst))
                seen.add(name)
        for name, inst in instruments.items():
            coherence = coherence_fn(name, target_row)
            if (
                name in BOOTSTRAP_NAMES
                and name not in seen
                and getattr(inst, "available", False)
                and name != "iot_firmware"
                and coherence > 0
            ):
                chosen.append((max(0.1 * coherence, 0.05), name, inst))
        to_run = chosen[:max(4, len(chosen))]
        print_fn(f"    [GRAVITY] Bootstrap sweep ({len(to_run)} instruments, E={target_row['entropy']:.1f})")
    else:
        to_run = candidates[:6]
        print_fn(f"    [GRAVITY] Top-{len(to_run)} by entropy potential (E={target_row['entropy']:.1f})")

    serial_item = None
    if interactive:
        for item in list(to_run):
            if item[1] == "metasploit":
                serial_item = item
                to_run = [row for row in to_run if row[1] != "metasploit"]
                break
        if serial_item is None:
            for item in candidates:
                if item[1] == "metasploit":
                    serial_item = item
                    break

    selected_items = list(to_run)
    if serial_item:
        selected_items.append(serial_item)
    return to_run, serial_item, selected_items


# Backward-compatibility alias — callers importing the old name continue to work.
rank_instruments_for_target = rank_instruments_for_node

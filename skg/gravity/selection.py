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
    "DA-": "data",
    "CE-": "container",
    "LA-": "lateral",
    "BI-": "binary",
    "AI-": "ai_target",
    "AD-": "ad_lateral",
}


def _instrument_spheres(wavelength: list[str]) -> set[str]:
    spheres: set[str] = set()
    for wid in wavelength or []:
        for prefix, sphere in SPHERE_PREFIXES.items():
            if str(wid).startswith(prefix):
                spheres.add(sphere)
    return spheres


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


def rank_instruments_for_target(
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
    ip = target_row["ip"]
    candidates: list[tuple[float, str, Any]] = []
    h1_wickets = _load_h1_wickets(ip, interp_dir)

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
    cold_start_target = (
        not has_nmap_history
        or target_row["target"].get("_no_nmap_history")
        or focus_target == ip
        or (target_row["unknowns"] >= 15 and (has_web_service or has_versioned_service))
    )

    for name, inst in instruments.items():
        if not getattr(inst, "available", False):
            continue

        potential = entropy_reduction_potential(
            inst,
            ip,
            target_row["states"],
            target_row["applicable_wickets"],
        )
        coherence = coherence_fn(name, target_row["target"])
        if coherence <= 0.0:
            continue
        potential *= coherence

        pearl_boost = reinforcement_fn(ip, inst)
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
            if name == "nmap" and not has_nmap_history:
                potential = max(potential, 30.0)
            if name == "pcap" and not has_nmap_history:
                potential = max(potential, 10.0)
            if name == "nvd_feed" and has_versioned_service and not has_cve_history:
                potential = max(potential, 18.0)
            if name == "http_collector" and (has_web_service or not has_nmap_history) and not has_recent_web:
                potential = max(potential, 12.0)
            if name == "auth_scanner" and has_web_service and not has_recent_auth:
                potential = max(potential, 6.0)
            if name == "metasploit" and (has_web_service or not has_nmap_history):
                potential = max(potential, 20.0)
            if name == "gobuster" and has_web_service:
                potential = max(potential, 8.0)
            potential *= coherence

        if inst.failed_to_reduce(ip):
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

    if cold_start_target or target_row["unknowns"] >= 20:
        chosen: list[tuple[float, str, Any]] = []
        seen: set[str] = set()
        for potential, name, inst in candidates:
            if name in BOOTSTRAP_NAMES:
                chosen.append((potential, name, inst))
                seen.add(name)
        for name, inst in instruments.items():
            coherence = coherence_fn(name, target_row["target"])
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

"""
skg.intel.surface
==================
Synthesizes all available SKG state into a ranked operator picture.

Reads from:
  INTERP_DIR     — latest projection results per workload+path
  DELTA_DIR      — transition history (expansions, regressions, remediations)
  EVENTS_DIR     — raw observations (for coverage gap detection)
  WorkloadGraph  — cross-workload relationships and priors
  ObservMemory   — sensor confirmation rates

Produces:
  surface()      — current attack surface across all workloads, ranked
  delta_report() — what changed since last N sweeps
  next_actions() — ranked list of what to pursue next
  full_report()  — complete engagement picture

All output is plain dicts — CLI and daemon endpoint both use this.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.core.paths import INTERP_DIR, EVENTS_DIR, SKG_STATE_DIR, SKG_HOME
from skg.identity import parse_workload_ref

# Score key by domain
SCORE_KEY = {
    "aprs":             "aprs",
    "container_escape": "escape_score",
    "ad_lateral":       "lateral_score",
    "host":             "host_score",
    "web":              "web_score",
    "ai_target":        "ai_score",
    "data":             "data_score",
    "supply_chain":     "supply_chain_score",
    "iot_firmware":     "iot_score",
    "binary":           "binary_score",
}

DOMAIN_LABEL = {
    "aprs":             "Log4Shell / JNDI RCE",
    "container_escape": "Container Escape",
    "ad_lateral":       "AD Lateral Movement",
    "host":             "Host Compromise",
    "web":              "Web Surface",
    "ai_target":        "AI/ML Target",
    "data":             "Data Exposure",
    "supply_chain":     "Supply Chain",
    "iot_firmware":     "IoT Firmware",
    "binary":           "Binary Exploitation",
}

CLASSIFICATION_RANK = {
    "realized":       0,
    "indeterminate":  1,
    "not_realized":   2,
    "unknown":        3,
}


def _normalize_classification(classification: str) -> str:
    if classification in {"realized", "not_realized", "indeterminate", "unknown"}:
        return classification
    if classification == "fully_realized":
        return "realized"
    if classification == "blocked":
        return "not_realized"
    if classification in {"partial", "indeterminate_h1"}:
        return "indeterminate"
    return classification or "unknown"


def _read_interp_dir(interp_dir: Path) -> list[dict]:
    """Read all projection results from INTERP_DIR. Returns latest per workload+path."""
    results: dict[str, dict] = {}
    if not interp_dir.exists():
        return []
    files = list(interp_dir.glob("*.json")) + list(interp_dir.glob("*_interp.ndjson"))
    for f in files:
        try:
            text = f.read_text()
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                if f.suffix != ".ndjson":
                    raise
                data = None
                for line in reversed(text.splitlines()):
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    break
                if data is None:
                    continue
            # Handle both direct payload and wrapped event
            if "payload" in data:
                payload = data["payload"]
            else:
                payload = data
            wid    = payload.get("workload_id", f.stem)
            path_id = payload.get("attack_path_id", "unknown")
            key    = f"{wid}::{path_id}"
            mtime = f.stat().st_mtime
            existing = results.get(key)
            if existing is not None and mtime <= existing.get("_mtime", 0.0):
                continue
            payload = dict(payload)
            payload["_source_file"] = f.name
            payload["_mtime"] = mtime
            payload["classification"] = _normalize_classification(payload.get("classification", "unknown"))
            results[key] = payload
        except Exception:
            pass
    rows = []
    for payload in results.values():
        payload.pop("_mtime", None)
        rows.append(payload)
    return rows


def _infer_domain(payload: dict, filename: str) -> str:
    for key, domain in [("aprs","aprs"), ("lateral_score","ad_lateral"),
                        ("escape_score","container_escape"), ("host_score","host"),
                        ("web_score","web"), ("ai_score","ai_target"),
                        ("data_score","data"), ("supply_chain_score","supply_chain"),
                        ("iot_score","iot_firmware"), ("binary_score","binary")]:
        if key in payload:
            return domain
    fname = filename.lower()
    for kw, domain in [("supply_chain","supply_chain"), ("iot_firmware","iot_firmware"),
                       ("binary","binary"), ("data_","data"),
                       ("lateral","ad_lateral"), ("ad_","ad_lateral"),
                       ("escape","container_escape"), ("container","container_escape"),
                       ("aprs","aprs"), ("log4j","aprs"), ("host","host"),
                       ("web","web"), ("ai","ai_target")]:
        if kw in fname:
            return domain
    return "unknown"


def _get_score(payload: dict, domain: str) -> float:
    key = SCORE_KEY.get(domain)
    if key and key in payload:
        return float(payload[key])
    # Fallback: compute from realized/required
    realized = payload.get("realized", [])
    required = payload.get("required_wickets", [])
    if required:
        return len(realized) / len(required)
    return 0.0


def surface(interp_dir: Path | None = None,
            delta_store=None,
            graph=None,
            min_score: float = 0.0) -> dict:
    """
    Current attack surface across all workloads.

    Returns:
      {
        workloads: [
          {
            workload_id, domain, domain_label, attack_path_id,
            classification, score,
            realized: [...wicket_ids],
            blocked:  [...wicket_ids],
            unknown:  [...wicket_ids],
            neighbors: [...workload_ids with relationships],
            computed_at,
          }
        ],
        summary: {
          total_workloads, realized_paths, indeterminate_paths,
          not_realized_paths, top_realized: [...]
        }
      }
    """
    interp_dir = interp_dir or INTERP_DIR
    projections = _read_interp_dir(interp_dir)

    workloads = []
    for proj in projections:
        domain = _infer_domain(proj, proj.get("_source_file",""))
        score  = _get_score(proj, domain)
        if score < min_score:
            continue
        ident = parse_workload_ref(proj.get("workload_id","unknown"))

        classification = _normalize_classification(proj.get("classification", "unknown"))
        neighbors = []
        if graph:
            try:
                wid = proj.get("workload_id","")
                neighbors = [neighbor_id for neighbor_id, _, _ in graph.neighbors(wid, min_weight=0.1)]
            except Exception:
                pass

        workloads.append({
            "workload_id":    proj.get("workload_id","unknown"),
            "identity_key":   ident["identity_key"],
            "manifestation_key": ident["manifestation_key"],
            "domain":         domain,
            "domain_label":   DOMAIN_LABEL.get(domain, domain),
            "attack_path_id": proj.get("attack_path_id",""),
            "classification": classification,
            "score":          round(score, 3),
            "realized":       proj.get("realized", []),
            "blocked":        proj.get("blocked", []),
            "unknown":        proj.get("unknown", []),
            "unresolved_detail": proj.get("unresolved_detail", {}),
            "local_energy": round(
                float(proj.get("total_energy", 0.0) or 0.0)
                or sum(float((proj.get("unresolved_detail", {}) or {}).get(nid, {}).get("local_energy", 0.0) or 0.0)
                       for nid in proj.get("unknown", [])),
                3,
            ),
            "compatibility_score": round(float(proj.get("compatibility_score", 0.0) or 0.0), 3),
            "compatibility_span": int(proj.get("compatibility_span", 0) or 0),
            "decoherence": round(float(proj.get("decoherence", 0.0) or 0.0), 3),
            "unresolved_reason": proj.get("unresolved_reason", ""),
            "neighbors":      neighbors,
            "computed_at":    proj.get("computed_at",""),
        })

    # Sort: realized first, then by score desc
    workloads.sort(key=lambda w: (
        CLASSIFICATION_RANK.get(w["classification"], 9),
        -float(w.get("local_energy", 0.0) or 0.0),
        -w["score"]
    ))

    realized_paths = [w for w in workloads if w["classification"] == "realized"]
    indet_paths    = [w for w in workloads if w["classification"] == "indeterminate"]
    not_real_paths = [w for w in workloads if w["classification"] == "not_realized"]

    return {
        "workloads": workloads,
        "summary": {
            "total_workloads":    len(workloads),
            "realized_paths":     len(realized_paths),
            "indeterminate_paths": len(indet_paths),
            "not_realized_paths": len(not_real_paths),
            "top_realized": [
                {"workload_id": w["workload_id"], "domain": w["domain_label"],
                 "score": w["score"], "attack_path_id": w["attack_path_id"]}
                for w in realized_paths[:5]
            ],
        },
    }


def delta_report(delta_store=None, hours: int = 24) -> dict:
    """
    What changed in the last N hours across all workloads.
    """
    if delta_store is None:
        try:
            from skg.temporal import DeltaStore
            from skg.core.paths import DELTA_DIR
            delta_store = DeltaStore(DELTA_DIR)
        except Exception:
            return {"error": "DeltaStore unavailable", "transitions": []}

    cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
    expansions   = []
    regressions  = []
    remediations = []
    other        = []

    try:
        from skg.temporal import WicketTransition
        trans_dir = delta_store.trans_dir
        for f in trans_dir.glob("*.jsonl"):
            for line in f.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    t = WicketTransition.from_dict(json.loads(line))
                    # Filter by time
                    try:
                        ts = datetime.fromisoformat(t.ts).timestamp()
                        if ts < cutoff:
                            continue
                    except Exception:
                        pass
                    entry = {
                        "workload_id": t.workload_id,
                        "wicket_id":   t.wicket_id,
                        "from_state":  t.from_state,
                        "to_state":    t.to_state,
                        "meaning":     t.meaning,
                        "weight":      t.signal_weight,
                        "ts":          t.ts,
                    }
                    if t.meaning == "surface_expansion":
                        expansions.append(entry)
                    elif t.meaning == "regression":
                        regressions.append(entry)
                    elif t.meaning == "remediation":
                        remediations.append(entry)
                    else:
                        other.append(entry)
                except Exception:
                    pass
    except Exception as e:
        return {"error": str(e), "transitions": []}

    return {
        "period_hours":  hours,
        "surface_expansions": sorted(expansions,  key=lambda x: x["ts"], reverse=True),
        "regressions":        sorted(regressions,  key=lambda x: x["ts"], reverse=True),
        "remediations":       sorted(remediations, key=lambda x: x["ts"], reverse=True),
        "other":              sorted(other,        key=lambda x: x["ts"], reverse=True),
        "counts": {
            "expansions":  len(expansions),
            "regressions": len(regressions),
            "remediations":len(remediations),
        },
    }


def next_actions(surface_data: dict, gaps: list[dict] | None = None) -> list[dict]:
    """
    Ranked list of what to pursue next.

    Priority:
      1. Realized paths — exploit or escalate
      2. Indeterminate paths with high score — fill unknown wickets
      3. Coverage gaps — generate toolchain and collect
      4. Not-realized paths with single blocking wicket — investigate control
    """
    actions = []

    for w in surface_data.get("workloads", []):
        if w["classification"] == "realized":
            actions.append({
                "priority":    1,
                "action":      "exploit",
                "workload_id": w["workload_id"],
                "domain":      w["domain_label"],
                "attack_path": w["attack_path_id"],
                "score":       w["score"],
                "detail":      f"All required wickets realized. Path is actionable.",
                "realized_wickets": w["realized"],
            })

        elif w["classification"] == "indeterminate" and w["score"] >= 0.5:
            unknown_count = len(w["unknown"])
            actions.append({
                "priority":    2,
                "action":      "collect",
                "workload_id": w["workload_id"],
                "domain":      w["domain_label"],
                "attack_path": w["attack_path_id"],
                "score":       w["score"],
                "detail":      f"{unknown_count} unknown wicket(s) — additional collection may realize path.",
                "unknown_wickets": w["unknown"],
            })

        elif w["classification"] == "not_realized" and len(w["blocked"]) == 1:
            actions.append({
                "priority":    4,
                "action":      "investigate_control",
                "workload_id": w["workload_id"],
                "domain":      w["domain_label"],
                "attack_path": w["attack_path_id"],
                "score":       w["score"],
                "detail":      f"Single blocking wicket: {w['blocked'][0]}. Verify control or find bypass.",
                "blocked_wicket": w["blocked"][0],
            })

    if gaps:
        for gap in gaps[:5]:
            actions.append({
                "priority":  3,
                "action":    "generate_toolchain",
                "service":   gap.get("service",""),
                "hosts":     gap.get("hosts", []),
                "detail":    gap.get("detail",""),
                "forge_cmd": f"skg forge generate {gap.get('service','')}",
            })

    actions.sort(key=lambda a: (a["priority"], -a.get("score", 0)))
    return actions


def full_report(interp_dir: Path | None = None,
                delta_store=None,
                graph=None,
                gaps: list[dict] | None = None,
                hours: int = 24) -> dict:
    """Complete engagement picture — surface + delta + gaps + next actions."""
    surf  = surface(interp_dir, delta_store, graph)
    delta = delta_report(delta_store, hours)
    acts  = next_actions(surf, gaps)
    now   = datetime.now(timezone.utc).isoformat()

    return {
        "generated_at":  now,
        "surface":        surf,
        "delta":          delta,
        "coverage_gaps":  gaps or [],
        "next_actions":   acts,
    }

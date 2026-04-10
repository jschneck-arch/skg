from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_web.mappings import load_path_signatures
from skg_domain_web.ontology import load_wickets
from skg_domain_web.policies import load_adapter_policy


@dataclass(frozen=True, slots=True)
class PathFinding:
    path: str
    status_code: int
    source: str = "web.path.inventory"
    pointer: str = ""
    detail: str = ""


def normalize_findings(rows: Iterable[PathFinding | Mapping[str, Any]]) -> list[PathFinding]:
    findings: list[PathFinding] = []
    for row in rows:
        if isinstance(row, PathFinding):
            findings.append(row)
            continue
        if not isinstance(row, Mapping):
            continue
        findings.append(
            PathFinding(
                path=str(row.get("path") or "/"),
                status_code=int(row.get("status_code") or 0),
                source=str(row.get("source") or "web.path.inventory"),
                pointer=str(row.get("pointer") or ""),
                detail=str(row.get("detail") or ""),
            )
        )
    return findings


def _confidence(value: float) -> float:
    return max(0.0, min(0.99, float(value)))


def _signature_matches(path: str, signatures: dict[str, Any]) -> list[str]:
    winners: list[str] = []
    wickets = signatures.get("wickets") if isinstance(signatures, dict) else {}
    if not isinstance(wickets, dict):
        return winners

    for wicket_id, rule in wickets.items():
        if not isinstance(rule, Mapping):
            continue
        patterns = rule.get("patterns")
        if not isinstance(patterns, list):
            continue
        for pattern in patterns:
            try:
                if re.search(str(pattern), path, re.IGNORECASE):
                    winners.append(str(wicket_id))
                    break
            except re.error:
                continue
    return winners


def map_findings_to_events(
    findings: Iterable[PathFinding | Mapping[str, Any]],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "adapter.web_path_inventory",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    """Map domain observations to canonical `obs.attack.precondition` events."""

    normalized = normalize_findings(findings)
    policy = load_adapter_policy()
    signatures = load_path_signatures()
    wicket_meta = load_wickets()

    realized_codes = {int(code) for code in policy.get("realized_status_codes", [200, 301, 302, 403])}
    reachable_wicket = str(policy.get("reachable_wicket") or "WB-01")
    fallback_admin_wicket = str(policy.get("fallback_admin_wicket") or "WB-05")
    fallback_admin_on_http_200 = bool(policy.get("fallback_admin_on_http_200", True))
    reachable_confidence = _confidence(float(policy.get("reachable_confidence", 0.9)))
    minimum_confidence = _confidence(float(policy.get("minimum_confidence", 0.65)))

    hits: dict[str, list[PathFinding]] = {}
    reachable_signals: list[PathFinding] = []

    for finding in normalized:
        if finding.status_code not in realized_codes:
            continue

        reachable_signals.append(finding)
        path = str(finding.path or "/")

        matched = _signature_matches(path, signatures)
        if not matched and fallback_admin_on_http_200 and finding.status_code == 200 and path not in {"", "/"}:
            matched = [fallback_admin_wicket]

        for wicket_id in matched:
            hits.setdefault(wicket_id, []).append(finding)

    if reachable_signals:
        hits.setdefault(reachable_wicket, []).append(reachable_signals[0])

    events: list[dict[str, Any]] = []
    wickets = signatures.get("wickets") if isinstance(signatures, dict) else {}

    for wicket_id in sorted(hits):
        finding_rows = hits[wicket_id]
        first = finding_rows[0]

        path_preview = ", ".join(
            f"{row.path} ({row.status_code})" for row in finding_rows[:3]
        )
        detail = f"{len(finding_rows)} path signal(s): {path_preview}"
        if first.detail:
            detail = f"{first.detail}; {detail}"

        rule = wickets.get(wicket_id, {}) if isinstance(wickets, dict) else {}
        base_conf = float(rule.get("confidence", minimum_confidence)) if isinstance(rule, Mapping) else minimum_confidence
        if wicket_id == reachable_wicket:
            confidence = reachable_confidence
        else:
            confidence = _confidence(max(minimum_confidence, base_conf + min(0.1, 0.03 * (len(finding_rows) - 1))))

        pointer = first.pointer or f"web-path://{first.path}"
        label = str((wicket_meta.get(wicket_id) or {}).get("label") or wicket_id)

        payload = build_precondition_payload(
            wicket_id=wicket_id,
            label=label,
            domain="web",
            workload_id=workload_id,
            realized=True,
            status="realized",
            detail=detail,
            attack_path_id=attack_path_id,
        )

        events.append(
            build_event_envelope(
                event_type="obs.attack.precondition",
                source_id=source_id,
                toolchain=toolchain,
                payload=payload,
                evidence_rank=2,
                source_kind=first.source,
                pointer=pointer,
                confidence=confidence,
            )
        )

    return events


def write_events_ndjson(events: Iterable[Mapping[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(dict(event), sort_keys=True) + "\n")

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_web.mappings import load_nikto_patterns
from skg_domain_web.ontology import load_wickets
from skg_domain_web.policies import load_nikto_adapter_policy


@dataclass(frozen=True, slots=True)
class NiktoFinding:
    msg: str
    url: str = ""


def _conf(value: float) -> float:
    return max(0.0, min(0.99, float(value)))


def _wicket_label(wicket_id: str) -> str:
    wickets = load_wickets()
    row = wickets.get(wicket_id) if isinstance(wickets, dict) else None
    if isinstance(row, Mapping):
        return str(row.get("label") or wicket_id)
    return wicket_id


def _normalize_findings(rows: Iterable[NiktoFinding | Mapping[str, Any] | str]) -> list[NiktoFinding]:
    findings: list[NiktoFinding] = []
    for row in rows:
        if isinstance(row, NiktoFinding):
            findings.append(row)
            continue
        if isinstance(row, str):
            findings.append(NiktoFinding(msg=row, url=""))
            continue
        if isinstance(row, Mapping):
            findings.append(
                NiktoFinding(
                    msg=str(row.get("msg") or row.get("message") or ""),
                    url=str(row.get("url") or ""),
                )
            )
    return [row for row in findings if row.msg.strip()]


def map_nikto_findings_to_events(
    findings: Iterable[NiktoFinding | Mapping[str, Any] | str],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "adapter.web_nikto_findings",
    toolchain: str = "web",
) -> list[dict[str, Any]]:
    """Map nikto finding text into canonical domain events."""

    rows = _normalize_findings(findings)
    patterns_payload = load_nikto_patterns()
    policy = load_nikto_adapter_policy()

    pattern_rows = patterns_payload.get("patterns") if isinstance(patterns_payload, Mapping) else []
    if not isinstance(pattern_rows, list):
        pattern_rows = []

    source_kind = str(policy.get("source_kind") or "nikto")
    evidence_rank = int(policy.get("evidence_rank") or 5)
    default_conf = _conf(float(policy.get("default_confidence") or 0.65))
    pointer_prefix = str(policy.get("pointer_prefix") or "nikto://")

    hits: dict[str, dict[str, Any]] = {}

    for finding in rows:
        text = finding.msg.lower()
        for entry in pattern_rows:
            if not isinstance(entry, Mapping):
                continue
            pattern = str(entry.get("pattern") or "")
            wicket_id = str(entry.get("wicket_id") or "").strip()
            if not pattern or not wicket_id:
                continue
            try:
                matched = re.search(pattern, text, re.IGNORECASE)
            except re.error:
                continue
            if not matched:
                continue

            conf = _conf(float(entry.get("confidence") or default_conf))
            row = hits.setdefault(
                wicket_id,
                {
                    "confidence": conf,
                    "messages": [],
                    "url": finding.url,
                },
            )
            row["confidence"] = max(float(row["confidence"]), conf)
            row["messages"].append(finding.msg)
            if finding.url and not row.get("url"):
                row["url"] = finding.url

    events: list[dict[str, Any]] = []
    for wicket_id in sorted(hits):
        row = hits[wicket_id]
        messages = list(row.get("messages") or [])
        preview = "; ".join(messages[:2])
        detail = f"nikto matched {len(messages)} finding(s): {preview}"
        pointer = str(row.get("url") or f"{pointer_prefix}{workload_id}")

        payload = build_precondition_payload(
            wicket_id=wicket_id,
            label=_wicket_label(wicket_id),
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
                evidence_rank=evidence_rank,
                source_kind=source_kind,
                pointer=pointer,
                confidence=_conf(float(row.get("confidence") or default_conf)),
            )
        )

    return events

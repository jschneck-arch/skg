from __future__ import annotations

import hashlib
import json
import re
from typing import Any


def _domain_from_attack_path(attack_path_id: str) -> str:
    text = str(attack_path_id or "").strip().lower()
    if not text:
        return "unknown"
    for prefix, domain in (
        ("host_", "host"),
        ("web_", "web"),
        ("container_escape_", "container_escape"),
        ("data_", "data"),
        ("ad_", "ad_lateral"),
        ("ai_", "ai_target"),
        ("iot_", "iot_firmware"),
        ("supply_chain_", "supply_chain"),
    ):
        if text.startswith(prefix):
            return domain
    return text.split("_", 1)[0]


def _service_tokens(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for token in ((bundle.get("surface") or {}).get("services") or []):
        text = str(token or "").strip()
        if not text:
            continue
        if "/" in text:
            port_text, service = text.split("/", 1)
        else:
            port_text, service = "", text
        try:
            port = int(port_text)
        except Exception:
            port = None
        rows.append({
            "token": text,
            "port": port,
            "service": service.strip().lower(),
        })
    return rows


def _top_field_row(bundle: dict[str, Any]) -> dict[str, Any]:
    paths = ((bundle.get("field_state") or {}).get("paths") or [])
    if not paths:
        return {}
    return max(paths, key=lambda row: float(row.get("E") or 0.0))


def _candidate_modules(service_rows: list[dict[str, Any]], domain: str) -> list[str]:
    services = {row.get("service") for row in service_rows if row.get("service")}
    ports = {row.get("port") for row in service_rows if row.get("port") is not None}
    if "https" in services or 443 in ports:
        return ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/dir_scanner"]
    if "http" in services or 80 in ports:
        return ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/dir_scanner"]
    if "ssh" in services or 22 in ports or domain == "host":
        return ["auxiliary/scanner/ssh/ssh_version", "auxiliary/scanner/ssh/ssh_login"]
    if "mysql" in services or 3306 in ports:
        return ["auxiliary/admin/mysql/mysql_version"]
    if "postgres" in services or "postgresql" in services or 5432 in ports:
        return ["auxiliary/scanner/postgres/postgres_version"]
    return []


def _suggested_port(service_rows: list[dict[str, Any]], domain: str) -> int | None:
    for preferred in (443, 80, 22, 3306, 5432):
        if any(row.get("port") == preferred for row in service_rows):
            return preferred
    if service_rows and service_rows[0].get("port") is not None:
        return int(service_rows[0]["port"])
    if domain == "host":
        return 22
    if domain == "web":
        return 80
    return None


def _slug(text: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")
    return cleaned or "artifact"


def _demand_id(payload: dict[str, Any]) -> str:
    digest = hashlib.sha1(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8", errors="replace")
    ).hexdigest()[:12]
    return f"dmd_{digest}"


def _make_demand(
    *,
    demand_kind: str,
    contract: str,
    identity_key: str,
    source: dict[str, Any],
    title: str,
    rationale: str,
    priority: float,
    admissible_effects: list[str],
    forbidden_effects: list[str],
    inputs: dict[str, Any],
    selection: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "demand_kind": demand_kind,
        "identity_key": identity_key,
        "source": source,
        "title": title,
        "contract": contract,
        "inputs": inputs,
    }
    return {
        "id": _demand_id(payload),
        "demand_kind": demand_kind,
        "contract": contract,
        "identity_key": identity_key,
        "selection": selection,
        "source": source,
        "title": title,
        "rationale": rationale,
        "priority": round(float(priority or 0.0), 4),
        "admissible_effects": list(admissible_effects or []),
        "forbidden_effects": list(forbidden_effects or []),
        "inputs": inputs,
    }


def _observation_demand(bundle: dict[str, Any]) -> dict[str, Any] | None:
    selection = bundle.get("selection") or {}
    identity_key = selection.get("identity_key") or ""
    subject = bundle.get("subject") or {}
    proposals = ((bundle.get("proposals") or {}).get("items") or [])
    chosen = None
    if subject.get("kind") == "field_action":
        chosen = subject
    else:
        for proposal in proposals:
            if proposal.get("kind") == "field_action":
                chosen = proposal
                break
    if not chosen:
        return None

    top_path = _top_field_row(bundle)
    domain = str(chosen.get("domain") or top_path.get("attack_path_id") or "")
    domain = _domain_from_attack_path(domain)
    services = _service_tokens(bundle)
    suggested_port = _suggested_port(services, domain)
    inputs = {
        "target_ip": identity_key,
        "domain": domain,
        "proposal_id": chosen.get("id"),
        "description": chosen.get("description"),
        "command_hint": chosen.get("command_hint"),
        "attack_path_id": top_path.get("attack_path_id"),
        "classification": top_path.get("classification"),
        "E": top_path.get("E"),
        "unknown_nodes": list(top_path.get("unknown_nodes") or [])[:4],
        "resolution_required": dict(top_path.get("resolution_required") or {}),
        "services": services[:6],
        "suggested_port": suggested_port,
        "candidate_modules": _candidate_modules(services, domain),
        "filename_stub": f"observe_{_slug(identity_key)}",
    }
    rationale = (
        f"Current field pressure around {identity_key or 'the selected identity'} remains observational. "
        f"Draft an RC artifact without claiming state change."
    )
    return _make_demand(
        demand_kind="observation_rc",
        contract="observation_rc",
        identity_key=identity_key,
        source={
            "kind": "proposal" if chosen.get("id") else "field_state",
            "id": chosen.get("id") or top_path.get("attack_path_id") or "",
        },
        title=f"Draft observation RC for {identity_key or 'selection'}",
        rationale=rationale,
        priority=float(top_path.get("E") or chosen.get("confidence") or 0.0),
        admissible_effects=["reduce_E_base", "resolve_wickets", "collect_support"],
        forbidden_effects=["assign_state", "claim_execution", "claim_observation"],
        inputs=inputs,
        selection=selection,
    )


def _catalog_patch_demands(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    selection = bundle.get("selection") or {}
    identity_key = selection.get("identity_key") or ""
    demands = []
    seen: set[str] = set()
    folds = ((bundle.get("folds") or {}).get("items") or [])
    proposals = ((bundle.get("proposals") or {}).get("items") or [])
    subject = bundle.get("subject") or {}

    candidates: list[dict[str, Any]] = []
    if subject.get("kind") == "catalog_growth":
        candidates.append({
            "source_kind": "proposal",
            "source_id": subject.get("id") or "",
            "domain": subject.get("domain") or "",
            "description": subject.get("description") or "",
            "detail": subject.get("description") or "",
            "priority": float(subject.get("confidence") or 0.5),
            "family": _slug(subject.get("description") or subject.get("domain") or "catalog"),
            "fold_type": "structural",
        })

    for fold in folds:
        if fold.get("fold_type") != "structural":
            continue
        why = fold.get("why") or {}
        family = why.get("service") or fold.get("fold_type") or "catalog"
        candidates.append({
            "source_kind": "fold",
            "source_id": fold.get("fold_id") or "",
            "domain": _domain_from_attack_path(why.get("attack_path_id") or ""),
            "description": fold.get("detail") or "",
            "detail": fold.get("detail") or "",
            "priority": float(fold.get("gravity_weight") or 0.0),
            "family": _slug(family),
            "fold_type": fold.get("fold_type") or "structural",
            "attack_path_id": why.get("attack_path_id") or "",
            "service": why.get("service") or "",
        })

    for proposal in proposals:
        if proposal.get("kind") != "catalog_growth":
            continue
        candidates.append({
            "source_kind": "proposal",
            "source_id": proposal.get("id") or "",
            "domain": proposal.get("domain") or "",
            "description": proposal.get("description") or "",
            "detail": proposal.get("description") or "",
            "priority": float(proposal.get("confidence") or 0.5),
            "family": _slug(proposal.get("description") or proposal.get("domain") or "catalog"),
            "fold_type": "structural",
        })

    service_rows = _service_tokens(bundle)
    for row in candidates:
        key = f"{row['source_kind']}:{row['source_id']}:{row['family']}"
        if key in seen:
            continue
        seen.add(key)
        inputs = {
            "identity_key": identity_key,
            "domain": row.get("domain") or "unknown",
            "service_family": row.get("family") or "catalog",
            "detail": row.get("detail") or row.get("description") or "",
            "attack_path_id": row.get("attack_path_id") or "",
            "service": row.get("service") or "",
            "services": service_rows[:6],
            "filename_stub": f"catalog_patch_{_slug(identity_key)}_{row.get('family') or 'catalog'}",
        }
        demands.append(_make_demand(
            demand_kind="catalog_patch",
            contract="catalog_patch",
            identity_key=identity_key,
            source={"kind": row["source_kind"], "id": row["source_id"]},
            title=f"Draft catalog patch for {identity_key or 'selection'}",
            rationale="Physics indicates a coverage deficit. Draft catalog additions without assigning state.",
            priority=float(row.get("priority") or 0.0),
            admissible_effects=["add_coverage", "reduce_future_fold_pressure"],
            forbidden_effects=["assign_state", "claim_observation", "mark_resolved"],
            inputs=inputs,
            selection=selection,
        ))
    return demands


def _wicket_patch_demands(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    selection = bundle.get("selection") or {}
    identity_key = selection.get("identity_key") or ""
    demands = []
    seen: set[str] = set()
    folds = ((bundle.get("folds") or {}).get("items") or [])
    service_rows = _service_tokens(bundle)
    for fold in folds:
        fold_type = str(fold.get("fold_type") or "")
        if fold_type not in {"projection", "contextual"}:
            continue
        why = fold.get("why") or {}
        attack_path_id = str(why.get("attack_path_id") or "")
        if not attack_path_id:
            continue
        key = f"{fold.get('fold_id')}:{attack_path_id}"
        if key in seen:
            continue
        seen.add(key)
        domain = _domain_from_attack_path(attack_path_id)
        family = why.get("service") or domain
        inputs = {
            "identity_key": identity_key,
            "domain": domain,
            "attack_path_id": attack_path_id,
            "fold_id": fold.get("fold_id"),
            "fold_type": fold_type,
            "detail": fold.get("detail") or "",
            "service": why.get("service") or "",
            "mismatch": why.get("mismatch") or "",
            "services": service_rows[:6],
            "filename_stub": f"wicket_patch_{_slug(identity_key)}_{_slug(family)}",
        }
        demands.append(_make_demand(
            demand_kind="wicket_patch",
            contract="wicket_patch",
            identity_key=identity_key,
            source={"kind": "fold", "id": fold.get("fold_id") or ""},
            title=f"Draft wicket patch for {attack_path_id}",
            rationale="Physics indicates a projection/context gap. Draft wicket coverage tied to the measured fold.",
            priority=float(fold.get("gravity_weight") or 0.0),
            admissible_effects=["add_wicket_coverage", "reduce_projection_gap"],
            forbidden_effects=["assign_state", "mark_realized", "mark_blocked"],
            inputs=inputs,
            selection=selection,
        ))
    return demands


def derive_demands(bundle: dict[str, Any], limit: int = 6) -> list[dict[str, Any]]:
    """Derive deterministic artifact-writing demands from a canonical assistant bundle."""
    limit = max(1, min(int(limit or 6), 12))
    demands: list[dict[str, Any]] = []

    observation = _observation_demand(bundle)
    if observation:
        demands.append(observation)
    demands.extend(_wicket_patch_demands(bundle))
    demands.extend(_catalog_patch_demands(bundle))

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for demand in demands:
        source = demand.get("source") or {}
        key = (
            str(demand.get("demand_kind") or ""),
            str(source.get("kind") or ""),
            str(source.get("id") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(demand)

    deduped.sort(
        key=lambda row: (
            -float(row.get("priority") or 0.0),
            str(row.get("demand_kind") or ""),
            str((row.get("source") or {}).get("id") or ""),
        )
    )
    return deduped[:limit]


def select_demand(
    demands: list[dict[str, Any]],
    *,
    demand_id: str = "",
    demand_kind: str = "",
) -> dict[str, Any] | None:
    for demand in demands:
        if demand_id and demand.get("id") == demand_id:
            return demand
    for demand in demands:
        if demand_kind and demand.get("demand_kind") == demand_kind:
            return demand
    return demands[0] if demands else None

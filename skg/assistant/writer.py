from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.assistant.validators import get_contract, render_content, validate_draft
from skg.core.paths import SKG_STATE_DIR


def _draft_dir() -> Path:
    path = SKG_STATE_DIR / "assistant_drafts"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_name(text: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "_", str(text or "").lower()).strip("_") or "artifact"


def _artifact_name(demand: dict[str, Any], contract: dict[str, Any], filename_hint: str = "") -> str:
    if filename_hint:
        return _safe_name(Path(filename_hint).name)
    extension = str(contract.get("filename_extension") or "").strip() or ".txt"
    stub = str((demand.get("inputs") or {}).get("filename_stub") or demand.get("demand_kind") or "artifact")
    return f"{_safe_name(stub)}{extension}"


def _default_observation_rc(demand: dict[str, Any]) -> dict[str, Any]:
    inputs = demand.get("inputs") or {}
    target_ip = str(inputs.get("target_ip") or demand.get("identity_key") or "TARGET_IP")
    port = inputs.get("suggested_port")
    lines = [
        "# SKG Demand: observation_rc",
        f"# identity_key: {demand.get('identity_key') or target_ip}",
        f"# source: {(demand.get('source') or {}).get('kind', '')}:{(demand.get('source') or {}).get('id', '')}",
        f"# rationale: {demand.get('rationale') or ''}",
        f"setg RHOSTS {target_ip}",
    ]
    if port:
        lines.append(f"setg RPORT {int(port)}")
    for module in list(inputs.get("candidate_modules") or [])[:2]:
        lines.extend([
            "",
            f"# Candidate module: {module}",
            f"# use {module}",
            "# Review options before execution.",
        ])
    unknown_nodes = list(inputs.get("unknown_nodes") or [])
    hints = dict(inputs.get("resolution_required") or {})
    if unknown_nodes:
        lines.extend([
            "",
            "# Unknown wickets to reduce:",
        ])
        for wicket_id in unknown_nodes[:4]:
            hint = str(hints.get(wicket_id) or "measurement required")
            lines.append(f"# - {wicket_id}: {hint}")
    lines.extend([
        "",
        "# This draft does not claim execution or observation.",
        "exit",
        "",
    ])
    return {
        "filename_hint": _artifact_name(demand, get_contract("observation_rc")),
        "content": "\n".join(lines),
        "notes": [
            "Deterministic fallback RC scaffold.",
            "Review candidate modules before running the resource script.",
        ],
    }


def _default_wicket_patch(demand: dict[str, Any]) -> dict[str, Any]:
    inputs = demand.get("inputs") or {}
    domain = str(inputs.get("domain") or "unknown")
    attack_path_id = str(inputs.get("attack_path_id") or f"{domain}_draft_path_v1")
    service = str(inputs.get("service") or domain or "service")
    prefix = _safe_name(service)[:3].upper() or "WK"
    wicket_id = f"{prefix}-DRAFT-01"
    payload = {
        "patch_type": "wicket_patch_v1",
        "domain": domain,
        "reason": demand.get("rationale") or "",
        "source": demand.get("source") or {},
        "draft_status": "review_required",
        "wickets": {
            wicket_id: {
                "id": wicket_id,
                "label": f"{_safe_name(service)}_coverage_needed",
                "description": str(inputs.get("detail") or f"Draft wicket derived from {service} fold"),
                "evidence_hint": str(inputs.get("mismatch") or "Add a concrete evidence check for this fold before accepting."),
            }
        },
        "attack_paths": {
            attack_path_id: {
                "id": attack_path_id,
                "operation": "extend_required_wickets",
                "required_wickets": [wicket_id],
            }
        },
    }
    return {
        "filename_hint": _artifact_name(demand, get_contract("wicket_patch")),
        "content": payload,
        "notes": [
            "Deterministic fallback wicket patch scaffold.",
            "Replace draft IDs and evidence hints during review.",
        ],
    }


def _default_catalog_patch(demand: dict[str, Any]) -> dict[str, Any]:
    inputs = demand.get("inputs") or {}
    domain = str(inputs.get("domain") or inputs.get("service_family") or "unknown")
    service_family = str(inputs.get("service_family") or domain or "coverage")
    attack_path_id = str(inputs.get("attack_path_id") or f"{domain}_draft_path_v1")
    prefix = _safe_name(service_family)[:3].upper() or "CT"
    wicket_id = f"{prefix}-DRAFT-01"
    payload = {
        "patch_type": "catalog_patch_v1",
        "domain": domain,
        "description": str(inputs.get("detail") or f"Draft catalog patch for {service_family} coverage"),
        "reason": demand.get("rationale") or "",
        "source": demand.get("source") or {},
        "draft_status": "review_required",
        "wickets": {
            wicket_id: {
                "id": wicket_id,
                "label": f"{_safe_name(service_family)}_surface_observed",
                "description": str(inputs.get("detail") or f"Observed {service_family} surface lacks explicit catalog coverage"),
                "evidence_hint": "Bind this wicket to a concrete observation source before acceptance.",
            }
        },
        "attack_paths": {
            attack_path_id: {
                "id": attack_path_id,
                "description": f"Draft attack path for {service_family} coverage",
                "required_wickets": [wicket_id],
                "references": [],
            }
        },
    }
    return {
        "filename_hint": _artifact_name(demand, get_contract("catalog_patch")),
        "content": payload,
        "notes": [
            "Deterministic fallback catalog patch scaffold.",
            "Expand wickets and references during review.",
        ],
    }


def _default_draft(demand: dict[str, Any]) -> dict[str, Any]:
    kind = str(demand.get("demand_kind") or "")
    if kind == "observation_rc":
        return _default_observation_rc(demand)
    if kind == "wicket_patch":
        return _default_wicket_patch(demand)
    return _default_catalog_patch(demand)


def _draft_prompt(demand: dict[str, Any], contract: dict[str, Any], fallback: dict[str, Any]) -> str:
    schema = (
        '{"filename_hint":"string","content":"string-or-object","notes":["string"]}'
    )
    notes = "\n".join(f"- {line}" for line in (contract.get("prompt_notes") or []))
    return (
        "You are the SKG artifact writer.\n"
        "SKG already decided the physics deficit and selected the artifact contract.\n"
        "You may only draft the requested artifact. Do not choose a different artifact.\n"
        "Do not claim execution, observation, or state change.\n"
        f"Artifact contract: {json.dumps(contract, ensure_ascii=True)}\n"
        f"Demand JSON: {json.dumps(demand, ensure_ascii=True)}\n"
        f"Deterministic fallback draft: {json.dumps(fallback, ensure_ascii=True, default=str)}\n"
        f"Output only valid JSON with schema {schema}\n"
        f"Contract notes:\n{notes}"
    )


def _parse_draft_json(raw: str) -> dict[str, Any] | None:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    start = text.find("{")
    if start < 0:
        return None
    decoder = json.JSONDecoder()
    try:
        parsed, _ = decoder.raw_decode(text[start:])
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None
    return None


def _try_llm_draft(demand: dict[str, Any], contract: dict[str, Any], fallback: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    try:
        from skg.resonance.llm_pool import get_pool
    except Exception:
        return None, None
    pool = get_pool()
    if not pool.any_available():
        return None, None
    model = pool.primary_model_name() or "llm"
    prompt = _draft_prompt(demand, contract, fallback)
    raw = pool.generate(prompt, num_predict=int(contract.get("num_predict") or 320))
    return _parse_draft_json(raw), model


def _save_draft(demand: dict[str, Any], draft: dict[str, Any], contract: dict[str, Any], mode: str, model: str | None) -> dict[str, Any]:
    out_dir = _draft_dir()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    filename = _artifact_name(demand, contract, draft.get("filename_hint") or "")
    path = out_dir / f"{timestamp}_{filename}"
    rendered = render_content(draft.get("content"), contract)
    path.write_text(rendered, encoding="utf-8")

    meta_path = path.with_suffix(path.suffix + ".meta.json")
    metadata = {
        "demand": demand,
        "mode": mode,
        "model": model,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "path": str(path),
        "filename": path.name,
        "notes": list(draft.get("notes") or []),
    }
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {
        "path": str(path),
        "meta_path": str(meta_path),
        "filename": path.name,
        "content": draft.get("content"),
        "notes": list(draft.get("notes") or []),
    }


def draft_demand(demand: dict[str, Any], use_llm: bool = True) -> dict[str, Any]:
    contract_name = str(demand.get("contract") or demand.get("demand_kind") or "")
    contract = get_contract(contract_name)
    if not contract:
        raise ValueError(f"Unknown assistant contract: {contract_name}")

    fallback = _default_draft(demand)
    chosen = fallback
    mode = "deterministic"
    model = None

    if use_llm:
        candidate, model = _try_llm_draft(demand, contract, fallback)
        if isinstance(candidate, dict):
            result = validate_draft(demand, candidate, contract)
            if result.get("ok"):
                chosen = result["normalized"]
                mode = "llm"

    validation = validate_draft(demand, chosen, contract)
    if not validation.get("ok"):
        raise ValueError(f"Assistant draft validation failed: {validation.get('errors')}")
    saved = _save_draft(demand, validation["normalized"], contract, mode=mode, model=model)
    return {
        "ok": True,
        "mode": mode,
        "model": model,
        "contract": contract_name,
        "demand": demand,
        "validation": validation,
        **saved,
    }

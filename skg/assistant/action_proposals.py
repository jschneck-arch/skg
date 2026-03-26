from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg.assistant.validators import get_contract, render_content, validate_draft
from skg.core.paths import SKG_STATE_DIR
from skg.forge.proposals import create_action


def _artifact_dir(out_dir: Path | str | None = None) -> Path:
    target = Path(out_dir) if out_dir is not None else (SKG_STATE_DIR / "assistant_drafts")
    target.mkdir(parents=True, exist_ok=True)
    return target


def write_contract_artifact(
    *,
    contract_name: str,
    content: Any,
    filename_hint: str,
    out_dir: Path | str | None = None,
    notes: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    contract = get_contract(contract_name)
    if not contract:
        raise ValueError(f"Unknown assistant contract: {contract_name}")

    filename = Path(str(filename_hint or "").strip() or "artifact.txt").name
    validation = validate_draft(
        {},
        {
            "filename_hint": filename,
            "content": content,
            "notes": list(notes or []),
        },
        contract,
    )
    if not validation.get("ok"):
        raise ValueError(f"Assistant artifact validation failed: {validation.get('errors')}")

    normalized = validation["normalized"]
    target_dir = _artifact_dir(out_dir)
    path = target_dir / normalized["filename_hint"]
    path.write_text(render_content(normalized["content"], contract), encoding="utf-8")

    meta_path = path.with_suffix(path.suffix + ".meta.json")
    meta_path.write_text(
        json.dumps(
            {
                "contract": contract_name,
                "filename": path.name,
                "path": str(path),
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "notes": list(normalized.get("notes") or []),
                **dict(metadata or {}),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return {
        "contract": contract_name,
        "path": str(path),
        "meta_path": str(meta_path),
        "filename": path.name,
        "notes": list(normalized.get("notes") or []),
        "content": normalized["content"],
    }


def create_msf_action_proposal(
    *,
    contract_name: str,
    rc_text: str,
    filename_hint: str,
    out_dir: Path | str | None,
    domain: str,
    description: str,
    action: dict[str, Any],
    attack_surface: str = "",
    hosts: list[str] | None = None,
    category: str = "runtime_observation",
    evidence: str = "",
    notes: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    command_prefix: str = "msfconsole -r",
) -> tuple[dict[str, Any], dict[str, Any]]:
    action_payload = dict(action or {})
    dispatch = dict(action_payload.get("dispatch") or {})
    dispatch.setdefault("kind", "msf_rc_script")
    action_payload["dispatch"] = dispatch
    proposal, artifact = create_action_proposal(
        contract_name=contract_name,
        artifact_content=rc_text,
        filename_hint=filename_hint,
        out_dir=out_dir,
        domain=domain,
        description=description,
        action=action_payload,
        attack_surface=attack_surface,
        hosts=hosts,
        category=category,
        evidence=evidence,
        notes=notes,
        metadata=metadata,
    )
    proposal["action"]["dispatch"]["command_hint"] = f"{command_prefix} {artifact['path']}"
    return proposal, artifact


def create_action_proposal(
    *,
    contract_name: str | None,
    artifact_content: Any | None,
    filename_hint: str,
    out_dir: Path | str | None,
    domain: str,
    description: str,
    action: dict[str, Any],
    attack_surface: str = "",
    hosts: list[str] | None = None,
    category: str = "runtime_observation",
    evidence: str = "",
    notes: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    action_payload = dict(action or {})
    artifact = None
    if contract_name:
        artifact = write_contract_artifact(
            contract_name=contract_name,
            content=artifact_content,
            filename_hint=filename_hint,
            out_dir=out_dir,
            notes=notes,
            metadata=metadata,
        )
        action_payload["artifact_path"] = artifact["path"]
        action_payload["artifact_contract"] = contract_name
        action_payload["artifact_meta_path"] = artifact["meta_path"]
        if str(artifact["path"]).endswith(".rc"):
            action_payload["rc_file"] = artifact["path"]

    proposal = create_action(
        domain=domain,
        description=description,
        action=action_payload,
        attack_surface=attack_surface,
        hosts=hosts or [],
        category=category,
        evidence=evidence,
    )
    return proposal, artifact

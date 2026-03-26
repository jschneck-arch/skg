from __future__ import annotations

import json
from typing import Any

from skg.core.paths import SKG_CONFIG_DIR, SKG_HOME


def load_contracts() -> dict[str, dict[str, Any]]:
    try:
        import yaml
    except Exception:
        return {}

    candidates = [
        SKG_CONFIG_DIR / "assistant_contracts.yaml",
        SKG_HOME / "config" / "assistant_contracts.yaml",
    ]
    for path in candidates:
        if not path.exists():
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        contracts = data.get("contracts") or {}
        if isinstance(contracts, dict):
            return contracts
    return {}


def get_contract(contract_name: str) -> dict[str, Any]:
    contracts = load_contracts()
    return dict(contracts.get(contract_name) or {})


def _normalize_json_content(content: Any) -> tuple[dict[str, Any] | None, list[str]]:
    if isinstance(content, dict):
        return content, []
    if isinstance(content, str):
        text = content.strip()
        if not text:
            return None, ["content is empty"]
        try:
            return json.loads(text), []
        except Exception as exc:
            return None, [f"content is not valid JSON: {exc}"]
    return None, [f"unexpected content type for JSON artifact: {type(content).__name__}"]


def _validate_string_keys(content: dict[str, Any], keys: list[str], errors: list[str]) -> None:
    for key in keys:
        value = content.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"JSON key {key} must be a non-empty string")


def _validate_mapping_keys(
    content: dict[str, Any],
    keys: list[str],
    errors: list[str],
    *,
    non_empty: bool = False,
) -> None:
    for key in keys:
        value = content.get(key)
        if not isinstance(value, dict):
            errors.append(f"JSON key {key} must be an object")
            continue
        if non_empty and not value:
            errors.append(f"JSON object {key} must not be empty")


def _validate_nested_string_keys(
    content: dict[str, Any],
    mapping: dict[str, list[str]],
    errors: list[str],
) -> None:
    for key, nested_keys in mapping.items():
        value = content.get(key)
        if not isinstance(value, dict):
            continue
        for entry_key, entry_value in value.items():
            if not isinstance(entry_value, dict):
                errors.append(f"Entries under {key} must be objects ({entry_key})")
                continue
            for nested_key in nested_keys:
                nested_value = entry_value.get(nested_key)
                if not isinstance(nested_value, str) or not nested_value.strip():
                    errors.append(
                        f"Entry {key}.{entry_key}.{nested_key} must be a non-empty string"
                    )


def _validate_nested_list_keys(
    content: dict[str, Any],
    mapping: dict[str, list[str]],
    errors: list[str],
) -> None:
    for key, nested_keys in mapping.items():
        value = content.get(key)
        if not isinstance(value, dict):
            continue
        for entry_key, entry_value in value.items():
            if not isinstance(entry_value, dict):
                errors.append(f"Entries under {key} must be objects ({entry_key})")
                continue
            for nested_key in nested_keys:
                nested_value = entry_value.get(nested_key)
                if not isinstance(nested_value, list) or not nested_value:
                    errors.append(
                        f"Entry {key}.{entry_key}.{nested_key} must be a non-empty list"
                    )
                    continue
                if not all(isinstance(item, str) and item.strip() for item in nested_value):
                    errors.append(
                        f"Entry {key}.{entry_key}.{nested_key} must contain only non-empty strings"
                    )


def _validate_expected_values(
    content: dict[str, Any],
    expected: dict[str, Any],
    errors: list[str],
) -> None:
    for key, expected_value in expected.items():
        if content.get(key) != expected_value:
            errors.append(f"JSON key {key} must equal {expected_value!r}")


def validate_draft(demand: dict[str, Any], draft: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    filename_hint = str(draft.get("filename_hint") or "").strip()
    extension = str(contract.get("filename_extension") or "").strip()
    output_format = str(contract.get("output_format") or "text").strip().lower()
    content = draft.get("content")

    if not filename_hint:
        errors.append("filename_hint is required")
    elif extension and not filename_hint.endswith(extension):
        errors.append(f"filename_hint must end with {extension}")

    normalized_content: Any = content
    if output_format == "text":
        normalized_content = str(content or "")
        if not normalized_content.strip():
            errors.append("text content is empty")
        if "```" in normalized_content:
            errors.append("text content must not include markdown fences")
        for marker in (contract.get("required_markers") or []):
            if marker not in normalized_content:
                errors.append(f"text content missing required marker: {marker}")
    elif output_format == "json":
        normalized_content, json_errors = _normalize_json_content(content)
        errors.extend(json_errors)
        if isinstance(normalized_content, dict):
            for key in (contract.get("required_keys") or []):
                if key not in normalized_content:
                    errors.append(f"JSON content missing required key: {key}")
            _validate_string_keys(
                normalized_content,
                list(contract.get("required_string_keys") or []),
                errors,
            )
            _validate_mapping_keys(
                normalized_content,
                list(contract.get("required_mapping_keys") or []),
                errors,
            )
            _validate_mapping_keys(
                normalized_content,
                list(contract.get("non_empty_mapping_keys") or []),
                errors,
                non_empty=True,
            )
            _validate_nested_string_keys(
                normalized_content,
                dict(contract.get("mapping_value_string_keys") or {}),
                errors,
            )
            _validate_nested_list_keys(
                normalized_content,
                dict(contract.get("mapping_value_list_keys") or {}),
                errors,
            )
            _validate_expected_values(
                normalized_content,
                dict(contract.get("expected_values") or {}),
                errors,
            )
    else:
        errors.append(f"unsupported contract output_format: {output_format}")

    notes = list(draft.get("notes") or [])
    if not all(isinstance(item, str) and item.strip() for item in notes):
        errors.append("notes must contain only non-empty strings")

    return {
        "ok": not errors,
        "errors": errors,
        "normalized": {
            "filename_hint": filename_hint,
            "content": normalized_content,
            "notes": notes,
        },
    }


def render_content(content: Any, contract: dict[str, Any]) -> str:
    output_format = str(contract.get("output_format") or "text").strip().lower()
    if output_format == "json":
        return json.dumps(content, indent=2, sort_keys=True) + "\n"
    return str(content or "")

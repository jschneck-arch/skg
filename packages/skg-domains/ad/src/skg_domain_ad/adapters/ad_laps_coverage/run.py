from __future__ import annotations

from typing import Any, Mapping

from skg_protocol.events import build_event_envelope, build_precondition_payload

from skg_domain_ad.adapters.common import (
    is_non_dc_computer_candidate,
    resolve_laps_presence,
)
from skg_domain_ad.mappings import load_laps_semantics_mapping
from skg_domain_ad.ontology import load_wickets
from skg_domain_ad.policies import load_laps_coverage_policy


DEFAULT_LAPS_EXPLICIT_KEYS = (
    "haslaps",
    "has_laps",
)

DEFAULT_IS_DC_KEYS = (
    "isdc",
    "isDomainController",
    "is_domain_controller",
)

DEFAULT_LAPS_ATTRIBUTE_KEYS = (
    "ms-Mcs-AdmPwd",
    "ms-mcs-admpwd",
    "msLAPS-Password",
)

ENABLED_KEYS = (
    "enabled",
    "Enabled",
)


def _conf(value: float) -> float:
    return max(0.0, min(0.99, float(value)))


def _status_realized(status: str) -> bool | None:
    if status == "realized":
        return True
    if status == "blocked":
        return False
    return None


def _wicket_label(wicket_id: str) -> str:
    wickets = load_wickets()
    row = wickets.get(wicket_id) if isinstance(wickets, dict) else None
    if isinstance(row, Mapping):
        return str(row.get("label") or wicket_id)
    return wicket_id


def _extract_properties(row: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("Properties", "properties", "attributes"):
        value = row.get(key)
        if isinstance(value, Mapping):
            return value
    return row


def _as_text(value: Any) -> str:
    if isinstance(value, list):
        if not value:
            return ""
        value = value[0]
    if value is None:
        return ""
    return str(value).strip()


def _extract_name(props: Mapping[str, Any], row: Mapping[str, Any]) -> str:
    keys = (
        "dNSHostName",
        "dnshostname",
        "name",
        "samaccountname",
        "sAMAccountName",
        "cn",
    )
    for key in keys:
        text = _as_text(props.get(key))
        if text:
            return text
    for key in keys:
        text = _as_text(row.get(key))
        if text:
            return text
    return "unknown-computer"


def _mapping_tuple(
    payload: Mapping[str, Any],
    key: str,
    fallback: tuple[str, ...],
) -> tuple[str, ...]:
    values = payload.get(key)
    if isinstance(values, list):
        parsed = tuple(str(value).strip() for value in values if str(value).strip())
        if parsed:
            return parsed
    return fallback


def _first_value(props: Mapping[str, Any], row: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in props:
            return props.get(key)
    for key in keys:
        if key in row:
            return row.get(key)
    return None


def _extract_enabled(props: Mapping[str, Any], row: Mapping[str, Any]) -> Any:
    return _first_value(props, row, ENABLED_KEYS)


def _extract_is_domain_controller(
    props: Mapping[str, Any],
    row: Mapping[str, Any],
    keys: tuple[str, ...],
) -> Any:
    return _first_value(props, row, keys)


def _extract_explicit_has_laps(
    props: Mapping[str, Any],
    row: Mapping[str, Any],
    keys: tuple[str, ...],
) -> Any:
    return _first_value(props, row, keys)


def _extract_computers(inventory: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = inventory.get("computers")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, Mapping)]


def _merged_attribute_view(props: Mapping[str, Any], row: Mapping[str, Any]) -> Mapping[str, Any]:
    merged: dict[str, Any] = {}
    merged.update(row)
    merged.update(props)
    return merged


def _emit(
    *,
    wicket_id: str,
    status: str,
    detail: str,
    run_id: str,
    workload_id: str,
    attack_path_id: str,
    source_id: str,
    toolchain: str,
    source_kind: str,
    pointer_prefix: str,
    evidence_rank: int,
    confidence: float,
    attributes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    payload = build_precondition_payload(
        wicket_id=wicket_id,
        label=_wicket_label(wicket_id),
        domain="ad",
        workload_id=workload_id,
        realized=_status_realized(status),
        status=status,
        detail=detail,
        attack_path_id=attack_path_id,
    )
    payload["run_id"] = run_id
    if attributes:
        payload["attributes"] = dict(attributes)

    return build_event_envelope(
        event_type="obs.attack.precondition",
        source_id=source_id,
        toolchain=toolchain,
        payload=payload,
        evidence_rank=evidence_rank,
        source_kind=source_kind,
        pointer=f"{pointer_prefix}{workload_id}/{wicket_id.lower()}",
        confidence=_conf(confidence),
    )


def map_laps_coverage_to_events(
    inventory: Mapping[str, Any],
    *,
    attack_path_id: str,
    run_id: str,
    workload_id: str,
    source_id: str = "",
    toolchain: str = "ad",
) -> list[dict[str, Any]]:
    """Map AD computer inventory into LAPS baseline coverage events (AD-25 core only)."""

    policy = load_laps_coverage_policy()
    source_kind = str(policy.get("source_kind") or "ad.inventory.snapshot")
    canonical_source_id = str(source_id or policy.get("source_id") or "adapter.ad_laps_coverage")
    pointer_prefix = str(policy.get("pointer_prefix") or "ad://")
    wickets_policy = policy.get("wickets") if isinstance(policy.get("wickets"), Mapping) else {}
    mappings_payload = load_laps_semantics_mapping()
    laps_semantics = mappings_payload.get("laps_semantics")
    if not isinstance(laps_semantics, Mapping):
        laps_semantics = {}
    explicit_laps_keys = _mapping_tuple(
        laps_semantics,
        "explicit_presence_keys",
        DEFAULT_LAPS_EXPLICIT_KEYS,
    )
    domain_controller_keys = _mapping_tuple(
        laps_semantics,
        "domain_controller_keys",
        DEFAULT_IS_DC_KEYS,
    )
    laps_attribute_keys = _mapping_tuple(
        laps_semantics,
        "password_attribute_keys",
        DEFAULT_LAPS_ATTRIBUTE_KEYS,
    )

    computers = _extract_computers(inventory if isinstance(inventory, Mapping) else {})

    observed_non_dc: list[dict[str, Any]] = []
    no_laps: list[dict[str, Any]] = []
    has_laps: list[dict[str, Any]] = []
    unknown_laps: list[dict[str, Any]] = []

    for row in computers:
        props = _extract_properties(row)
        name = _extract_name(props, row)

        enabled = _extract_enabled(props, row)
        is_domain_controller = _extract_is_domain_controller(
            props,
            row,
            domain_controller_keys,
        )
        explicit_has_laps = _extract_explicit_has_laps(
            props,
            row,
            explicit_laps_keys,
        )

        if not is_non_dc_computer_candidate(
            enabled=enabled,
            is_domain_controller=is_domain_controller,
        ):
            continue

        merged_attrs = _merged_attribute_view(props, row)
        laps_present = resolve_laps_presence(
            explicit_has_laps=explicit_has_laps,
            attributes=merged_attrs,
            attribute_keys=laps_attribute_keys,
        )

        if explicit_has_laps is not None:
            signal_source = "explicit_haslaps"
        elif laps_present is not None:
            signal_source = "laps_attribute"
        else:
            signal_source = "unknown"

        record = {
            "name": name,
            "laps_present": laps_present,
            "signal_source": signal_source,
        }
        observed_non_dc.append(record)

        if laps_present is False:
            no_laps.append(record)
        elif laps_present is True:
            has_laps.append(record)
        else:
            unknown_laps.append(record)

    has_observed = bool(observed_non_dc)
    has_no_laps = bool(no_laps)
    all_signals_known = has_observed and not unknown_laps

    statuses = {
        "AD-LP-01": "realized" if has_observed else "unknown",
        "AD-LP-02": (
            "realized"
            if has_no_laps
            else ("blocked" if all_signals_known else "unknown")
        ),
    }

    details = {
        "AD-LP-01": (
            f"Observed {len(observed_non_dc)} non-DC enabled computer account(s) for LAPS baseline assessment"
            if has_observed
            else "No enabled non-DC computer inventory observed for LAPS baseline assessment"
        ),
        "AD-LP-02": (
            f"Non-DC enabled computers without LAPS observed: {', '.join(row['name'] for row in no_laps[:5])}"
            if has_no_laps
            else (
                "Observed non-DC enabled computer inventory indicates LAPS coverage present"
                if all_signals_known
                else (
                    "LAPS signal is indeterminate for one or more observed non-DC computers"
                    if has_observed
                    else "Cannot assess LAPS coverage baseline without non-DC computer observation"
                )
            )
        ),
    }

    attributes = {
        "AD-LP-01": {
            "observed_non_dc_count": len(observed_non_dc),
            "observed_non_dc_sample": observed_non_dc[:20],
        },
        "AD-LP-02": {
            "no_laps_count": len(no_laps),
            "no_laps_sample": no_laps[:20],
            "with_laps_count": len(has_laps),
            "with_laps_sample": has_laps[:20],
            "unknown_laps_count": len(unknown_laps),
            "unknown_laps_sample": unknown_laps[:20],
        },
    }

    events: list[dict[str, Any]] = []
    for wicket_id in ("AD-LP-01", "AD-LP-02"):
        wicket_cfg = wickets_policy.get(wicket_id) if isinstance(wickets_policy, Mapping) else {}
        if not isinstance(wicket_cfg, Mapping):
            wicket_cfg = {}

        events.append(
            _emit(
                wicket_id=wicket_id,
                status=statuses[wicket_id],
                detail=details[wicket_id],
                run_id=run_id,
                workload_id=workload_id,
                attack_path_id=attack_path_id,
                source_id=canonical_source_id,
                toolchain=toolchain,
                source_kind=source_kind,
                pointer_prefix=pointer_prefix,
                evidence_rank=int(wicket_cfg.get("evidence_rank") or 3),
                confidence=float(wicket_cfg.get("confidence") or 0.9),
                attributes=attributes[wicket_id],
            )
        )

    return events

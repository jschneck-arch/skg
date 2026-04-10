from __future__ import annotations

from skg_domain_ad.adapters.common import (
    build_computer_tier_index,
    normalize_privileged_session_rows,
    summarize_privileged_tiering_exposure,
)


def test_normalize_privileged_session_rows_handles_mixed_shapes() -> None:
    rows = [
        {"computer": "WS01.CONTOSO.LOCAL", "user": "ALICE@CONTOSO.LOCAL", "user_id": "U-1", "computer_id": "C-1"},
        {"attributes": {"computer_name": "APP01.CONTOSO.LOCAL", "username": "BOB", "userid": "U-2", "computerid": "C-2"}},
        {"name": "ignored-row"},
        "not-a-row",
    ]

    normalized = normalize_privileged_session_rows(rows)
    assert len(normalized) == 2
    assert normalized[0]["computer"] == "WS01.CONTOSO.LOCAL"
    assert normalized[1]["computer"] == "APP01.CONTOSO.LOCAL"


def test_build_computer_tier_index_handles_properties_and_ids() -> None:
    computers = [
        {
            "Properties": {
                "name": "DC01.CONTOSO.LOCAL",
                "isdc": True,
            },
            "ObjectIdentifier": "S-1-5-21-DC01",
        },
        {
            "attributes": {
                "dNSHostName": "WS01.CONTOSO.LOCAL",
                "isdc": False,
            },
            "objectid": "S-1-5-21-WS01",
        },
    ]

    index = build_computer_tier_index(computers)
    assert index["dc01.contoso.local"] == "tier0"
    assert index["s-1-5-21-dc01"] == "tier0"
    assert index["ws01.contoso.local"] == "non_tier0"
    assert index["s-1-5-21-ws01"] == "non_tier0"


def test_summarize_privileged_tiering_exposure_reports_realized_for_non_tier0_sessions() -> None:
    sessions = [
        {"computer": "WS01.CONTOSO.LOCAL", "user": "ADMINISTRATOR@CONTOSO.LOCAL", "computer_id": "C-WS01"},
        {"computer": "DC01.CONTOSO.LOCAL", "user": "DA2@CONTOSO.LOCAL", "computer_id": "C-DC01"},
    ]
    computers = [
        {"Properties": {"name": "WS01.CONTOSO.LOCAL", "isdc": False}, "ObjectIdentifier": "C-WS01"},
        {"Properties": {"name": "DC01.CONTOSO.LOCAL", "isdc": True}, "ObjectIdentifier": "C-DC01"},
    ]

    summary = summarize_privileged_tiering_exposure(sessions, computers)
    assert summary["status"] == "realized"
    assert summary["non_tier0_session_count"] == 1
    assert summary["tier0_session_count"] == 1


def test_summarize_privileged_tiering_exposure_unknown_when_tier_is_unresolved() -> None:
    sessions = [{"computer": "WS01.CONTOSO.LOCAL", "user": "DA@CONTOSO.LOCAL", "computer_id": "C-WS01"}]

    summary = summarize_privileged_tiering_exposure(sessions, computers=[])
    assert summary["status"] == "unknown"
    assert summary["unknown_tier_session_count"] == 1

from __future__ import annotations

from skg_services.gravity.delegation_context import classify_ad07_unconstrained_activity


def test_classify_ad07_unconstrained_activity_matches_legacy_freshness_semantics() -> None:
    now_ts = 2_000_000_000.0
    stale_days = 90
    recent_epoch = now_ts - (30 * 86400)
    stale_epoch = now_ts - (120 * 86400)

    result = classify_ad07_unconstrained_activity(
        [
            {
                "Properties": {
                    "name": "WS01.CONTOSO.LOCAL",
                    "enabled": True,
                    "isdc": False,
                    "unconstraineddelegation": True,
                    "lastlogontimestamp": recent_epoch,
                }
            },
            {
                "Properties": {
                    "name": "WS02.CONTOSO.LOCAL",
                    "enabled": True,
                    "isdc": False,
                    "unconstraineddelegation": True,
                    "lastlogontimestamp": stale_epoch,
                }
            },
            {
                "Properties": {
                    "name": "WS03.CONTOSO.LOCAL",
                    "enabled": True,
                    "isdc": False,
                    "unconstraineddelegation": True,
                }
            },
        ],
        stale_days=stale_days,
        now_ts=now_ts,
        unknown_last_logon_is_active=True,
    )

    active_names = {row["name"] for row in result["active_unconstrained"]}
    stale_names = {row["name"] for row in result["stale_unconstrained"]}
    unknown_names = {row["name"] for row in result["unknown_last_logon"]}

    assert result["total_unconstrained_non_dc"] == 3
    assert active_names == {"WS01.CONTOSO.LOCAL", "WS03.CONTOSO.LOCAL"}
    assert stale_names == {"WS02.CONTOSO.LOCAL"}
    assert unknown_names == {"WS03.CONTOSO.LOCAL"}


def test_classify_ad07_unconstrained_activity_can_disable_unknown_as_active_assumption() -> None:
    now_ts = 2_000_000_000.0
    result = classify_ad07_unconstrained_activity(
        [
            {
                "name": "WS04.CONTOSO.LOCAL",
                "enabled": True,
                "isdc": False,
                "unconstraineddelegation": True,
            }
        ],
        stale_days=90,
        now_ts=now_ts,
        unknown_last_logon_is_active=False,
    )

    assert result["total_unconstrained_non_dc"] == 1
    assert result["active_unconstrained"] == []
    assert result["unknown_last_logon"][0]["name"] == "WS04.CONTOSO.LOCAL"


def test_classify_ad07_unconstrained_activity_filters_dc_disabled_and_non_unconstrained() -> None:
    result = classify_ad07_unconstrained_activity(
        [
            {
                "attributes": {
                    "name": "DC01.CONTOSO.LOCAL",
                    "enabled": True,
                    "isdc": True,
                    "unconstraineddelegation": True,
                    "lastlogontimestamp": 1_900_000_000,
                }
            },
            {
                "attributes": {
                    "name": "WS05.CONTOSO.LOCAL",
                    "enabled": False,
                    "isdc": False,
                    "unconstraineddelegation": True,
                    "lastlogontimestamp": 1_900_000_000,
                }
            },
            {
                "attributes": {
                    "name": "WS06.CONTOSO.LOCAL",
                    "enabled": True,
                    "isdc": False,
                    "unconstraineddelegation": False,
                    "lastlogontimestamp": 1_900_000_000,
                }
            },
        ],
        stale_days=90,
        unknown_last_logon_is_active=True,
    )

    assert result["total_unconstrained_non_dc"] == 0
    assert result["active_unconstrained"] == []
    assert result["stale_unconstrained"] == []

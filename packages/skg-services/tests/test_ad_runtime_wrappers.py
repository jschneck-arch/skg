from __future__ import annotations

import json
from pathlib import Path

from skg.sensors.adapter_runner import run_bloodhound
from skg_protocol.contracts import (
    AD_DELEGATION_CONTEXT_FILENAME,
    AD_DELEGATION_CONTEXT_SCHEMA,
    AD_DELEGATION_INPUT_FILENAME,
    AD_DELEGATION_INPUT_SCHEMA,
)
from skg_services.gravity.ad_runtime import (
    route_bloodhound_ad07_context,
    map_ad0608_sidecar_to_events,
    route_bloodhound_delegation_evidence,
    map_ad22_sidecar_to_events,
    route_bloodhound_ad22_evidence,
)


def _write_bh_v4_file(path: Path, key: str, rows: list[dict]) -> None:
    path.write_text(json.dumps({key: rows, "count": len(rows)}, indent=2), encoding="utf-8")


def test_route_bloodhound_ad22_evidence_writes_canonical_input(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)
    (bh_dir / "sessions.json").write_text(
        json.dumps(
            {
                "sessions": [
                    {
                        "computer": "WS01.CONTOSO.LOCAL",
                        "user": "ADMINISTRATOR@CONTOSO.LOCAL",
                        "computer_id": "C-WS01",
                        "user_id": "U-DA-1",
                    }
                ],
                "count": 1,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    payload = route_bloodhound_ad22_evidence(
        bh_dir=bh_dir,
        computers=[
            {
                "Properties": {"name": "WS01.CONTOSO.LOCAL", "isdc": False},
                "ObjectIdentifier": "C-WS01",
            }
        ],
        workload_id="ad::contoso.local",
        run_id="run-ad22-seam-test-1",
    )

    canonical_path = bh_dir / "ad22_tiering_input.json"
    assert canonical_path.exists()
    on_disk = json.loads(canonical_path.read_text(encoding="utf-8"))

    assert on_disk["schema"] == "skg.ad.tiering_input.v1"
    assert on_disk["wicket_id"] == "AD-22"
    assert on_disk["workload_id"] == "ad::contoso.local"
    assert on_disk["run_id"] == "run-ad22-seam-test-1"
    assert on_disk["summary"]["status"] == "realized"
    assert on_disk["summary"]["non_tier0_session_count"] == 1
    assert payload["session_rows"][0]["computer"] == "WS01.CONTOSO.LOCAL"


def test_route_bloodhound_delegation_evidence_writes_canonical_input(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    payload = route_bloodhound_delegation_evidence(
        bh_dir=bh_dir,
        computers=[
            {
                "Properties": {
                    "name": "WS01.CONTOSO.LOCAL",
                    "enabled": True,
                    "isdc": False,
                    "unconstraineddelegation": True,
                },
                "ObjectIdentifier": "C-WS01",
            }
        ],
        users=[
            {
                "Properties": {
                    "name": "APP01$",
                    "enabled": True,
                    "trustedtoauthfordelegation": True,
                    "allowedtodelegate": ["ldap/DC01.CONTOSO.LOCAL"],
                },
                "ObjectIdentifier": "U-APP01",
            }
        ],
        workload_id="ad::contoso.local",
        run_id="run-ad-delegation-seam-test-1",
    )

    canonical_path = bh_dir / AD_DELEGATION_INPUT_FILENAME
    assert canonical_path.exists()
    on_disk = json.loads(canonical_path.read_text(encoding="utf-8"))

    assert on_disk["schema"] == AD_DELEGATION_INPUT_SCHEMA
    assert on_disk["wicket_ids"] == ["AD-06", "AD-08"]
    assert on_disk["summary"]["status"] == "realized"
    assert on_disk["summary"]["unconstrained_non_dc_count"] == 1
    assert on_disk["summary"]["protocol_transition_count"] == 1
    assert on_disk["deferred_coupling"]["ad07_context_deferred"] is True
    assert on_disk["deferred_coupling"]["ad09_sensitive_target_deferred"] is True
    assert payload["delegation_spn_edges"][0]["service"] == "ldap"


def test_route_bloodhound_ad07_context_writes_canonical_context_input(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    payload = route_bloodhound_ad07_context(
        bh_dir=bh_dir,
        computers=[
            {
                "Properties": {
                    "name": "WS01.CONTOSO.LOCAL",
                    "enabled": True,
                    "isdc": False,
                    "unconstraineddelegation": True,
                    "lastlogontimestamp": 1_999_900_000,
                }
            }
        ],
        workload_id="ad::contoso.local",
        run_id="run-ad07-context-test-1",
        stale_days=90,
        unknown_last_logon_is_active=True,
    )

    canonical_path = bh_dir / AD_DELEGATION_CONTEXT_FILENAME
    assert canonical_path.exists()
    on_disk = json.loads(canonical_path.read_text(encoding="utf-8"))

    assert on_disk["schema"] == AD_DELEGATION_CONTEXT_SCHEMA
    assert on_disk["wicket_id"] == "AD-07"
    assert on_disk["recency_policy"]["stale_days"] == 90
    assert on_disk["unknown_handling_policy"]["unknown_last_logon_is_active"] is True
    assert "active_unconstrained" in on_disk["activity_classification"]
    assert payload["summary"]["status"] in {"realized", "blocked", "unknown"}


def test_run_bloodhound_routes_sessions_to_canonical_ad22_input_and_quarantines_legacy_ad22(
    tmp_path: Path,
) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    _write_bh_v4_file(
        bh_dir / "users.json",
        "users",
        [
            {
                "Properties": {"name": "ALICE", "enabled": True, "lastlogontimestamp": 0},
                "ObjectIdentifier": "U-1",
            }
        ],
    )
    _write_bh_v4_file(
        bh_dir / "groups.json",
        "groups",
        [
            {
                "Properties": {"name": "DOMAIN ADMINS"},
                "Members": [{"ObjectIdentifier": "U-1"}],
            }
        ],
    )
    _write_bh_v4_file(
        bh_dir / "computers.json",
        "computers",
        [
            {
                "Properties": {"name": "WS01.CONTOSO.LOCAL", "isdc": False, "enabled": True},
                "ObjectIdentifier": "C-WS01",
            }
        ],
    )
    _write_bh_v4_file(bh_dir / "acls.json", "acls", [])
    _write_bh_v4_file(
        bh_dir / "domains.json",
        "domains",
        [{"Properties": {"name": "contoso.local", "minpwdlength": 8}, "ObjectIdentifier": "D-1"}],
    )
    (bh_dir / "sessions.json").write_text(
        json.dumps(
            {
                "sessions": [
                    {
                        "computer": "WS01.CONTOSO.LOCAL",
                        "user": "ALICE@CONTOSO.LOCAL",
                        "computer_id": "C-WS01",
                        "user_id": "U-1",
                    }
                ],
                "count": 1,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    events = run_bloodhound(
        bh_dir=bh_dir,
        workload_id="ad::contoso.local",
        attack_path_id="ad_kerberoast_v1",
        run_id="run-ad22-seam-test-2",
    )

    # AD-21 still comes from legacy check_stale_privileged, but AD-22 legacy
    # static-unknown output is quarantined.
    wicket_ids = {event.get("payload", {}).get("wicket_id") for event in events}
    assert "AD-21" in wicket_ids
    assert "AD-22" not in wicket_ids

    canonical_input = json.loads((bh_dir / "ad22_tiering_input.json").read_text(encoding="utf-8"))
    assert canonical_input["summary"]["observed_session_count"] == 1
    assert canonical_input["summary"]["non_tier0_session_count"] == 1
    assert canonical_input["summary"]["status"] == "realized"
    delegation_input = json.loads((bh_dir / AD_DELEGATION_INPUT_FILENAME).read_text(encoding="utf-8"))
    assert delegation_input["schema"] == AD_DELEGATION_INPUT_SCHEMA
    assert delegation_input["wicket_ids"] == ["AD-06", "AD-08"]
    assert delegation_input["deferred_coupling"]["path_value_reasoning_deferred"] is True
    ad07_context = json.loads((bh_dir / AD_DELEGATION_CONTEXT_FILENAME).read_text(encoding="utf-8"))
    assert ad07_context["schema"] == AD_DELEGATION_CONTEXT_SCHEMA
    assert ad07_context["wicket_id"] == "AD-07"


def test_run_bloodhound_emits_canonical_ad22_events_when_ad22_path_requested(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    _write_bh_v4_file(
        bh_dir / "users.json",
        "users",
        [
            {
                "Properties": {"name": "ALICE", "enabled": True, "lastlogontimestamp": 0},
                "ObjectIdentifier": "U-1",
            }
        ],
    )
    _write_bh_v4_file(
        bh_dir / "groups.json",
        "groups",
        [
            {
                "Properties": {"name": "DOMAIN ADMINS"},
                "Members": [{"ObjectIdentifier": "U-1"}],
            }
        ],
    )
    _write_bh_v4_file(
        bh_dir / "computers.json",
        "computers",
        [
            {
                "Properties": {"name": "WS01.CONTOSO.LOCAL", "isdc": False, "enabled": True},
                "ObjectIdentifier": "C-WS01",
            }
        ],
    )
    _write_bh_v4_file(bh_dir / "acls.json", "acls", [])
    _write_bh_v4_file(bh_dir / "domains.json", "domains", [])
    (bh_dir / "sessions.json").write_text(
        json.dumps(
            {
                "sessions": [
                    {
                        "computer": "WS01.CONTOSO.LOCAL",
                        "user": "ALICE@CONTOSO.LOCAL",
                        "computer_id": "C-WS01",
                        "user_id": "U-1",
                    }
                ],
                "count": 1,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    events = run_bloodhound(
        bh_dir=bh_dir,
        workload_id="ad::contoso.local",
        attack_path_id="ad_privileged_session_tiering_baseline_v1",
        run_id="run-ad22-seam-test-3",
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert "AD-TI-01" in by_wicket
    assert "AD-22" in by_wicket
    assert by_wicket["AD-TI-01"]["payload"]["status"] == "realized"
    assert by_wicket["AD-22"]["payload"]["status"] == "realized"


def test_map_ad0608_sidecar_to_events_emits_only_delegation_posture_core(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    route_bloodhound_delegation_evidence(
        bh_dir=bh_dir,
        computers=[
            {
                "Properties": {
                    "name": "WS01.CONTOSO.LOCAL",
                    "enabled": True,
                    "isdc": False,
                    "unconstraineddelegation": True,
                },
                "ObjectIdentifier": "C-WS01",
            }
        ],
        users=[
            {
                "Properties": {
                    "name": "APP01$",
                    "enabled": True,
                    "trustedtoauthfordelegation": True,
                    "allowedtodelegate": ["ldap/DC01.CONTOSO.LOCAL"],
                },
                "ObjectIdentifier": "U-APP01",
            }
        ],
        workload_id="ad::contoso.local",
        run_id="run-ad0608-map-test",
    )

    events = map_ad0608_sidecar_to_events(
        sidecar_path=bh_dir / AD_DELEGATION_INPUT_FILENAME,
        attack_path_id="ad_delegation_posture_baseline_v1",
        run_id="run-ad0608-map-test",
        workload_id="ad::contoso.local",
    )

    wicket_ids = {event.get("payload", {}).get("wicket_id") for event in events}
    assert wicket_ids == {"AD-06", "AD-08"}


def test_run_bloodhound_emits_canonical_ad0608_events_when_delegation_path_requested(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    _write_bh_v4_file(
        bh_dir / "users.json",
        "users",
        [
            {
                "Properties": {
                    "name": "APP01$",
                    "enabled": True,
                    "trustedtoauthfordelegation": True,
                    "allowedtodelegate": ["ldap/DC01.CONTOSO.LOCAL"],
                },
                "ObjectIdentifier": "U-APP01",
            }
        ],
    )
    _write_bh_v4_file(
        bh_dir / "groups.json",
        "groups",
        [],
    )
    _write_bh_v4_file(
        bh_dir / "computers.json",
        "computers",
        [
            {
                "Properties": {
                    "name": "WS01.CONTOSO.LOCAL",
                    "isdc": False,
                    "enabled": True,
                    "unconstraineddelegation": True,
                },
                "ObjectIdentifier": "C-WS01",
            }
        ],
    )
    _write_bh_v4_file(bh_dir / "acls.json", "acls", [])
    _write_bh_v4_file(bh_dir / "domains.json", "domains", [])

    events = run_bloodhound(
        bh_dir=bh_dir,
        workload_id="ad::contoso.local",
        attack_path_id="ad_delegation_posture_baseline_v1",
        run_id="run-ad0608-runtime-test",
    )

    by_wicket = {}
    for event in events:
        payload = event.get("payload", {})
        wicket_id = payload.get("wicket_id")
        if wicket_id:
            by_wicket[wicket_id] = payload

    assert by_wicket["AD-06"]["status"] == "realized"
    assert by_wicket["AD-08"]["status"] == "realized"
    assert "AD-07" not in by_wicket
    assert "AD-09" not in by_wicket


def test_run_bloodhound_drops_legacy_ad07_emission_and_uses_context_sidecar(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    _write_bh_v4_file(
        bh_dir / "users.json",
        "users",
        [],
    )
    _write_bh_v4_file(
        bh_dir / "groups.json",
        "groups",
        [],
    )
    _write_bh_v4_file(
        bh_dir / "computers.json",
        "computers",
        [
            {
                "Properties": {
                    "name": "WS01.CONTOSO.LOCAL",
                    "isdc": False,
                    "enabled": True,
                    "unconstraineddelegation": True,
                    "lastlogontimestamp": 2_000_000_000,
                },
                "ObjectIdentifier": "C-WS01",
            }
        ],
    )
    _write_bh_v4_file(bh_dir / "acls.json", "acls", [])
    _write_bh_v4_file(bh_dir / "domains.json", "domains", [])

    events = run_bloodhound(
        bh_dir=bh_dir,
        workload_id="ad::contoso.local",
        attack_path_id="ad_kerberoast_v1",
        run_id="run-ad07-routing-test",
    )

    wicket_ids = {event.get("payload", {}).get("wicket_id") for event in events}
    assert "AD-07" not in wicket_ids

    context_sidecar = json.loads((bh_dir / AD_DELEGATION_CONTEXT_FILENAME).read_text(encoding="utf-8"))
    assert context_sidecar["schema"] == AD_DELEGATION_CONTEXT_SCHEMA
    assert context_sidecar["wicket_id"] == "AD-07"


def test_run_bloodhound_disables_legacy_delegation_for_non_legacy_paths(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    _write_bh_v4_file(
        bh_dir / "users.json",
        "users",
        [
            {
                "Properties": {
                    "name": "APP01$",
                    "enabled": True,
                    "trustedtoauthfordelegation": True,
                    "allowedtodelegate": ["ldap/DC01.CONTOSO.LOCAL"],
                },
                "ObjectIdentifier": "U-APP01",
            }
        ],
    )
    _write_bh_v4_file(bh_dir / "groups.json", "groups", [])
    _write_bh_v4_file(
        bh_dir / "computers.json",
        "computers",
        [
            {
                "Properties": {
                    "name": "WS01.CONTOSO.LOCAL",
                    "isdc": False,
                    "enabled": True,
                    "unconstraineddelegation": True,
                },
                "ObjectIdentifier": "C-WS01",
            }
        ],
    )
    _write_bh_v4_file(bh_dir / "acls.json", "acls", [])
    _write_bh_v4_file(bh_dir / "domains.json", "domains", [])

    events = run_bloodhound(
        bh_dir=bh_dir,
        workload_id="ad::contoso.local",
        attack_path_id="ad_kerberoast_v1",
        run_id="run-ad07-ad09-nonlegacy-gate-test",
    )

    wicket_ids = {event.get("payload", {}).get("wicket_id") for event in events}
    assert "AD-06" not in wicket_ids
    assert "AD-07" not in wicket_ids
    assert "AD-08" not in wicket_ids
    assert "AD-09" not in wicket_ids


def test_run_bloodhound_keeps_legacy_delegation_dormant_without_compat_flag(tmp_path: Path) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)

    _write_bh_v4_file(
        bh_dir / "users.json",
        "users",
        [
            {
                "Properties": {
                    "name": "APP01$",
                    "enabled": True,
                    "trustedtoauthfordelegation": True,
                    "allowedtodelegate": ["ldap/DC01.CONTOSO.LOCAL"],
                },
                "ObjectIdentifier": "U-APP01",
            }
        ],
    )
    _write_bh_v4_file(bh_dir / "groups.json", "groups", [])
    _write_bh_v4_file(bh_dir / "computers.json", "computers", [])
    _write_bh_v4_file(bh_dir / "acls.json", "acls", [])
    _write_bh_v4_file(bh_dir / "domains.json", "domains", [])

    events = run_bloodhound(
        bh_dir=bh_dir,
        workload_id="ad::contoso.local",
        attack_path_id="ad_constrained_delegation_s4u_v1",
        run_id="run-ad09-legacy-gate-test",
    )

    wicket_ids = {event.get("payload", {}).get("wicket_id") for event in events}
    assert "AD-08" not in wicket_ids
    assert "AD-09" not in wicket_ids
    assert "AD-07" not in wicket_ids


def test_run_bloodhound_allows_legacy_delegation_for_legacy_path_with_compat_flag(
    tmp_path: Path,
    monkeypatch,
) -> None:
    bh_dir = tmp_path / "bh"
    bh_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("SKG_ENABLE_LEGACY_DELEGATION_COMPAT", "1")

    _write_bh_v4_file(
        bh_dir / "users.json",
        "users",
        [
            {
                "Properties": {
                    "name": "APP01$",
                    "enabled": True,
                    "trustedtoauthfordelegation": True,
                    "allowedtodelegate": ["ldap/DC01.CONTOSO.LOCAL"],
                },
                "ObjectIdentifier": "U-APP01",
            }
        ],
    )
    _write_bh_v4_file(bh_dir / "groups.json", "groups", [])
    _write_bh_v4_file(bh_dir / "computers.json", "computers", [])
    _write_bh_v4_file(bh_dir / "acls.json", "acls", [])
    _write_bh_v4_file(bh_dir / "domains.json", "domains", [])

    events = run_bloodhound(
        bh_dir=bh_dir,
        workload_id="ad::contoso.local",
        attack_path_id="ad_constrained_delegation_s4u_v1",
        run_id="run-ad09-legacy-gate-with-compat-test",
    )

    wicket_ids = {event.get("payload", {}).get("wicket_id") for event in events}
    assert "AD-08" in wicket_ids
    assert "AD-09" in wicket_ids
    assert "AD-07" not in wicket_ids


def test_map_ad22_sidecar_to_events_fails_fast_on_invalid_sidecar(tmp_path: Path) -> None:
    sidecar = tmp_path / "ad22_tiering_input.json"
    sidecar.write_text(
        json.dumps(
            {
                "schema": "skg.ad.tiering_input.v0",
                "wicket_id": "AD-22",
                "summary": {"status": "unknown"},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    try:
        map_ad22_sidecar_to_events(
            sidecar_path=sidecar,
            attack_path_id="ad_privileged_session_tiering_baseline_v1",
            run_id="run-ad22-invalid-sidecar",
            workload_id="ad::invalid.local",
        )
        assert False, "expected RuntimeError for invalid sidecar contract"
    except RuntimeError as exc:
        assert "Invalid AD tiering sidecar payload" in str(exc)

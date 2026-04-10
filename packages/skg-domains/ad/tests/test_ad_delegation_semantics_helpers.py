from __future__ import annotations

from skg_domain_ad.adapters.common import (
    extract_delegation_spn_edges,
    extract_protocol_transition_principals,
    extract_unconstrained_non_dc_hosts,
    normalize_delegation_principals,
)


def test_normalize_delegation_principals_handles_mixed_shapes() -> None:
    rows = [
        {
            "Properties": {
                "name": "WS01.CONTOSO.LOCAL",
                "enabled": True,
                "isdc": False,
                "unconstraineddelegation": True,
                "allowedtodelegate": ["ldap/DC01.CONTOSO.LOCAL"],
                "trustedtoauthfordelegation": True,
            },
            "ObjectIdentifier": "C-WS01",
        },
        {
            "attributes": {
                "samaccountname": "APP01$",
                "enabled": "true",
                "isdc": "false",
                "allowed_to_delegate": ["cifs/FILE01.CONTOSO.LOCAL"],
                "trusted_to_auth_for_delegation": "false",
            },
            "objectid": "C-APP01",
        },
        "ignored",
    ]

    normalized = normalize_delegation_principals(rows)
    assert len(normalized) == 2
    assert normalized[0]["name"] == "WS01.CONTOSO.LOCAL"
    assert normalized[0]["unconstrained_delegation"] is True
    assert normalized[1]["name"] == "APP01$"
    assert normalized[1]["enabled"] is True


def test_extract_unconstrained_non_dc_hosts_filters_dc_and_disabled() -> None:
    rows = [
        {"Properties": {"name": "WS01.CONTOSO.LOCAL", "enabled": True, "isdc": False, "unconstraineddelegation": True}},
        {"Properties": {"name": "DC01.CONTOSO.LOCAL", "enabled": True, "isdc": True, "unconstraineddelegation": True}},
        {"Properties": {"name": "WS02.CONTOSO.LOCAL", "enabled": False, "isdc": False, "unconstraineddelegation": True}},
    ]

    hosts = extract_unconstrained_non_dc_hosts(rows)
    assert hosts == [{"name": "WS01.CONTOSO.LOCAL", "object_id": ""}]


def test_extract_protocol_transition_and_spn_edges_are_structural_only() -> None:
    rows = [
        {
            "Properties": {
                "name": "APP01$",
                "enabled": True,
                "trustedtoauthfordelegation": True,
                "allowedtodelegate": [
                    "ldap/DC01.CONTOSO.LOCAL",
                    "cifs/FS01.CONTOSO.LOCAL",
                ],
            },
            "ObjectIdentifier": "C-APP01",
        },
        {
            "Properties": {
                "name": "APP02$",
                "enabled": True,
                "trustedtoauthfordelegation": False,
                "allowedtodelegate": ["http/WEB01.CONTOSO.LOCAL"],
            },
            "ObjectIdentifier": "C-APP02",
        },
    ]

    protocol_transition = extract_protocol_transition_principals(rows)
    assert protocol_transition == [
        {
            "name": "APP01$",
            "object_id": "C-APP01",
            "allowed_to_delegate": [
                "ldap/DC01.CONTOSO.LOCAL",
                "cifs/FS01.CONTOSO.LOCAL",
            ],
        }
    ]

    edges = extract_delegation_spn_edges(rows)
    assert len(edges) == 3
    assert edges[0]["service"] == "ldap"
    assert edges[0]["target"] == "dc01.contoso.local"
    assert edges[1]["service"] == "cifs"
    assert edges[2]["service"] == "http"

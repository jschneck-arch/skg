from skg_protocol.contracts.compatibility import is_protocol_compatible
from skg_protocol.contracts.manifest import normalize_manifest


def test_normalize_manifest_domain_pack_payload() -> None:
    payload = {
        "name": "web",
        "runtime": "domain-pack",
        "components": {
            "adapters": "adapters",
            "projectors": "projectors",
            "policies": "policies",
        },
        "contracts": {"catalogs": "contracts/catalogs"},
        "compatibility": {"protocol": "1.2"},
    }

    manifest = normalize_manifest(payload)

    assert manifest.name == "web"
    assert manifest.protocol_version == "1.2"


def test_protocol_compatibility_uses_major_version() -> None:
    assert is_protocol_compatible("1.9", "1.0") is True
    assert is_protocol_compatible("2.0", "1.0") is False

from __future__ import annotations

import json
from pathlib import Path

from skg_domain_ad.adapters.ad_privileged_membership.run import (
    map_privileged_memberships_to_events,
)
from skg_domain_ad.projectors.ad.run import compute_ad, project_events_to_artifact
from skg_registry import DomainRegistry


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_ad" / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[4]


def test_ad_adapter_to_projector_e2e_writes_projection_artifact(tmp_path: Path) -> None:
    inventory = json.loads((FIXTURES / "ad_privileged_membership_inventory.json").read_text(encoding="utf-8"))

    events = map_privileged_memberships_to_events(
        inventory,
        attack_path_id="ad_privilege_relationship_mapping_v1",
        run_id="run-ad-e2e",
        workload_id="ad::contoso.local",
    )

    out_path = tmp_path / "interp" / "ad_privilege_relationship_mapping.json"
    result = project_events_to_artifact(
        events,
        attack_path_id="ad_privilege_relationship_mapping_v1",
        out_path=out_path,
        run_id="run-ad-e2e",
        workload_id="ad::contoso.local",
    )

    assert out_path.exists()
    payload = result.get("payload", {})
    assert payload.get("classification") == "realized"
    assert payload.get("ad_score") == 1.0

    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written.get("payload", {}).get("classification") == "realized"


def test_ad_projector_human_assignment_path_indeterminate_when_human_membership_missing() -> None:
    inventory = {
        "users": [
            {
                "Properties": {"name": "WS01$@CONTOSO.LOCAL", "enabled": True},
                "ObjectIdentifier": "S-1-5-21-1234-5678-9012-2101"
            }
        ],
        "groups": [
            {
                "Properties": {"name": "DOMAIN ADMINS@CONTOSO.LOCAL"},
                "ObjectIdentifier": "S-1-5-21-1234-5678-9012-512",
                "Members": [{"ObjectIdentifier": "S-1-5-21-1234-5678-9012-2101"}]
            }
        ],
    }

    events = map_privileged_memberships_to_events(
        inventory,
        attack_path_id="ad_human_admin_assignment_v1",
        run_id="run-ad-indeterminate",
        workload_id="ad::contoso.local",
    )

    result = compute_ad(
        events,
        {},
        "ad_human_admin_assignment_v1",
        run_id="run-ad-indeterminate",
        workload_id="ad::contoso.local",
    )

    assert result.get("payload", {}).get("classification") == "not_realized"


def test_registry_discovers_ad_pack_src_layout() -> None:
    registry = DomainRegistry.discover(
        search_roots=[REPO_ROOT / "packages" / "skg-domains", REPO_ROOT]
    )

    ad = registry.get("ad")
    assert ad is not None
    assert ad.manifest_kind == "domain-pack"
    assert ad.manifest_path == REPO_ROOT / "packages" / "skg-domains" / "ad" / "src" / "skg_domain_ad" / "manifest.yaml"
    assert ad.adapters_dir == REPO_ROOT / "packages" / "skg-domains" / "ad" / "src" / "skg_domain_ad" / "adapters"
    assert ad.projectors_dir == REPO_ROOT / "packages" / "skg-domains" / "ad" / "src" / "skg_domain_ad" / "projectors"
    assert ad.policies_dir == REPO_ROOT / "packages" / "skg-domains" / "ad" / "src" / "skg_domain_ad" / "policies"

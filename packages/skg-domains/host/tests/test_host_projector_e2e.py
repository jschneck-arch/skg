from __future__ import annotations

import json
from pathlib import Path

from skg_domain_host.adapters.host_nmap_profile.run import map_nmap_profiles_to_events
from skg_domain_host.projectors.host.run import compute_host, project_events_to_artifact
from skg_registry import DomainRegistry


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_host" / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[4]


def test_host_adapter_to_projector_e2e_writes_projection_artifact(tmp_path: Path) -> None:
    profiles = json.loads((FIXTURES / "host_nmap_profiles.json").read_text(encoding="utf-8"))

    events = map_nmap_profiles_to_events(
        profiles,
        attack_path_id="host_network_exploit_v1",
        run_id="run-host-e2e",
        workload_id="host::192.168.56.10",
    )

    out_path = tmp_path / "interp" / "host_network_exploit.json"
    result = project_events_to_artifact(
        events,
        attack_path_id="host_network_exploit_v1",
        out_path=out_path,
        run_id="run-host-e2e",
        workload_id="host::192.168.56.10",
    )

    assert out_path.exists()
    payload = result.get("payload", {})
    assert payload.get("classification") == "realized"
    assert payload.get("host_score") == 1.0

    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written.get("payload", {}).get("classification") == "realized"


def test_host_projector_sudo_path_is_indeterminate_for_network_only_events() -> None:
    profiles = json.loads((FIXTURES / "host_nmap_profiles.json").read_text(encoding="utf-8"))

    events = map_nmap_profiles_to_events(
        profiles,
        attack_path_id="host_linux_privesc_sudo_v1",
        run_id="run-host-indeterminate",
        workload_id="host::192.168.56.10",
    )

    result = compute_host(
        events,
        {},
        "host_linux_privesc_sudo_v1",
        run_id="run-host-indeterminate",
        workload_id="host::192.168.56.10",
    )

    payload = result.get("payload", {})
    assert payload.get("classification") == "indeterminate"


def test_registry_discovers_host_pack_src_layout() -> None:
    registry = DomainRegistry.discover(
        search_roots=[REPO_ROOT / "packages" / "skg-domains", REPO_ROOT]
    )

    host = registry.get("host")
    assert host is not None
    assert host.manifest_kind == "domain-pack"
    assert host.manifest_path == REPO_ROOT / "packages" / "skg-domains" / "host" / "src" / "skg_domain_host" / "manifest.yaml"
    assert host.adapters_dir == REPO_ROOT / "packages" / "skg-domains" / "host" / "src" / "skg_domain_host" / "adapters"
    assert host.projectors_dir == REPO_ROOT / "packages" / "skg-domains" / "host" / "src" / "skg_domain_host" / "projectors"
    assert host.policies_dir == REPO_ROOT / "packages" / "skg-domains" / "host" / "src" / "skg_domain_host" / "policies"

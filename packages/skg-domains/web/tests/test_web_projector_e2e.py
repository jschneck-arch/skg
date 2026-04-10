from __future__ import annotations

import json
from pathlib import Path

from skg_domain_web.adapters.web_path_inventory.run import map_findings_to_events
from skg_domain_web.projectors.web.run import compute_web, project_events_to_artifact
from skg_registry import DomainRegistry


FIXTURES = Path(__file__).resolve().parents[1] / "src" / "skg_domain_web" / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[4]


def test_adapter_to_projector_e2e_writes_projection_artifact(tmp_path: Path) -> None:
    findings = json.loads((FIXTURES / "web_path_findings.json").read_text(encoding="utf-8"))

    events = map_findings_to_events(
        findings,
        attack_path_id="web_initial_access_v1",
        run_id="run-web-e2e",
        workload_id="web::demo.local",
    )

    out_path = tmp_path / "interp" / "web_initial_access.json"
    result = project_events_to_artifact(
        events,
        attack_path_id="web_initial_access_v1",
        out_path=out_path,
        run_id="run-web-e2e",
        workload_id="web::demo.local",
    )

    assert out_path.exists()
    payload = result.get("payload", {})
    assert payload.get("classification") == "realized"
    assert payload.get("web_score") == 1.0

    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written.get("payload", {}).get("classification") == "realized"


def test_projector_alias_path_behaves_as_full_chain() -> None:
    findings = json.loads((FIXTURES / "web_path_findings.json").read_text(encoding="utf-8"))
    events = map_findings_to_events(
        findings,
        attack_path_id="web_sqli_to_shell_v1",
        run_id="run-web-alias",
        workload_id="web::demo.local",
    )

    result = compute_web(
        events,
        {},
        "web_sqli_to_shell_v1",
        run_id="run-web-alias",
        workload_id="web::demo.local",
    )

    payload = result.get("payload", {})
    assert payload.get("canonical_attack_path_id") == "web_full_chain_v1"
    assert payload.get("classification") == "indeterminate"


def test_registry_discovers_web_pack_src_layout() -> None:
    registry = DomainRegistry.discover(
        search_roots=[REPO_ROOT / "packages" / "skg-domains", REPO_ROOT]
    )

    web = registry.get("web")
    assert web is not None
    assert web.manifest_kind == "domain-pack"
    assert web.manifest_path == REPO_ROOT / "packages" / "skg-domains" / "web" / "src" / "skg_domain_web" / "manifest.yaml"
    assert web.adapters_dir == REPO_ROOT / "packages" / "skg-domains" / "web" / "src" / "skg_domain_web" / "adapters"
    assert web.projectors_dir == REPO_ROOT / "packages" / "skg-domains" / "web" / "src" / "skg_domain_web" / "projectors"
    assert web.policies_dir == REPO_ROOT / "packages" / "skg-domains" / "web" / "src" / "skg_domain_web" / "policies"

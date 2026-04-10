"""Canonical web domain pack (pilot extraction)."""

from skg_domain_web.adapters.web_auth_assessment.run import map_auth_assessment_to_events
from skg_domain_web.adapters.web_path_inventory.run import map_findings_to_events
from skg_domain_web.adapters.web_nikto_findings.run import map_nikto_findings_to_events
from skg_domain_web.adapters.web_surface_fingerprint.run import map_surface_profile_to_events
from skg_domain_web.projectors.web.run import compute_web, project_events_to_artifact

__all__ = [
    "compute_web",
    "map_auth_assessment_to_events",
    "map_findings_to_events",
    "map_nikto_findings_to_events",
    "map_surface_profile_to_events",
    "project_events_to_artifact",
]

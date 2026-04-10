"""Canonical host domain pack (Phase 6A extraction)."""

from skg_domain_host.adapters.host_nmap_profile.run import map_nmap_profiles_to_events
from skg_domain_host.adapters.host_ssh_assessment.run import map_ssh_assessments_to_events
from skg_domain_host.adapters.host_winrm_assessment.run import map_winrm_assessments_to_events
from skg_domain_host.projectors.host.run import compute_host, project_events_to_artifact

__all__ = [
    "compute_host",
    "map_nmap_profiles_to_events",
    "map_ssh_assessments_to_events",
    "map_winrm_assessments_to_events",
    "project_events_to_artifact",
]

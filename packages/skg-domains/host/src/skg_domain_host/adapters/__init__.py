"""Host domain adapters."""

from skg_domain_host.adapters.host_nmap_profile.run import map_nmap_profiles_to_events
from skg_domain_host.adapters.host_ssh_assessment.run import map_ssh_assessments_to_events
from skg_domain_host.adapters.host_winrm_assessment.run import map_winrm_assessments_to_events

__all__ = [
    "map_nmap_profiles_to_events",
    "map_ssh_assessments_to_events",
    "map_winrm_assessments_to_events",
]

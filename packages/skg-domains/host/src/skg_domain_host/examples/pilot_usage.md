# Host Domain Pack Pilot Usage

```python
from skg_domain_host.adapters.host_nmap_profile.run import map_nmap_profiles_to_events
from skg_domain_host.projectors.host.run import compute_host

profiles = [
    {
        "host": "192.168.56.10",
        "host_up": True,
        "open_ports": [
            {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.1"},
            {"port": 445, "service": "microsoft-ds", "product": "Samba", "version": "4.10.16"},
        ],
    }
]

events = map_nmap_profiles_to_events(
    profiles,
    attack_path_id="host_network_exploit_v1",
    run_id="run-host-pilot",
    workload_id="host::192.168.56.10",
)

result = compute_host(
    events,
    {},
    "host_network_exploit_v1",
    run_id="run-host-pilot",
    workload_id="host::192.168.56.10",
)
```

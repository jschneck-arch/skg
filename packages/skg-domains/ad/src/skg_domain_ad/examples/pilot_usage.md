# AD Pilot Usage

This pilot slice maps AD privileged-group memberships from a normalized
inventory snapshot into canonical `obs.attack.precondition` events, then
projects them onto AD attack-path realizability artifacts.

Adapter entrypoint:
- `skg_domain_ad.adapters.ad_privileged_membership.run.map_privileged_memberships_to_events`

Projector entrypoint:
- `skg_domain_ad.projectors.ad.run.project_events_to_artifact`

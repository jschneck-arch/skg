This slice normalizes canonical delegation posture-core input into AD
precondition events for AD-06 and AD-08 only.

Canonical entrypoints:
- `skg_domain_ad.adapters.ad_delegation_posture.map_delegation_posture_to_events`
- `skg_domain_ad.adapters.ad_delegation_posture.map_delegation_posture_file_to_events`

Attack path:
- `ad_delegation_posture_baseline_v1`

Wickets emitted:
- `AD-06` unconstrained delegation on non-DC principals present
- `AD-08` protocol-transition constrained delegation principals present

Explicitly deferred in this slice:
- `AD-07` reachability/recency context
- `AD-09` sensitive-target/value/path reasoning

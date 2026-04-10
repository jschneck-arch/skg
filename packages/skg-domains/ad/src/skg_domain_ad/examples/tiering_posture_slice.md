# AD-22 Tiering Posture Core Slice (Phase 7L)

This slice maps canonical AD-22 runtime sidecar input into AD domain
precondition events for privileged-session tiering posture baseline.

Adapter:
- `skg_domain_ad.adapters.ad_tiering_posture.map_tiering_posture_to_events`
- `skg_domain_ad.adapters.ad_tiering_posture.map_tiering_posture_file_to_events`

Attack path:
- `ad_privileged_session_tiering_baseline_v1`

Wickets:
- `AD-TI-01` privileged session tiering observation present
- `AD-22` no privileged account tiering (core posture signal)

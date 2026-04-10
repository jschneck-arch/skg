# AD LAPS Baseline Coverage Slice (Phase 7I)

This slice normalizes LAPS baseline coverage posture for enabled non-DC
computer inventory into canonical AD precondition events.

Adapter:
- `skg_domain_ad.adapters.ad_laps_coverage.map_laps_coverage_to_events`

Attack path:
- `ad_laps_coverage_baseline_v1`

Wickets:
- `AD-LP-01` LAPS baseline candidate hosts observed
- `AD-LP-02` non-DC hosts without LAPS present

# AD AS-REP Baseline Exposure Slice (Phase 7F)

This slice normalizes AD user pre-authentication exposure into canonical
AS-REP baseline events without privilege/value/path coupling.

Adapter:
- `skg_domain_ad.adapters.ad_asrep_exposure.map_asrep_exposure_to_events`

Attack path:
- `ad_asrep_exposure_baseline_v1`

Wickets:
- `AD-AS-01` user pre-auth state observed
- `AD-AS-02` AS-REP roastable accounts present

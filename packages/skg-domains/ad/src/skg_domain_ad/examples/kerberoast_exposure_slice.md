# AD Kerberoast Baseline Exposure Slice (Phase 7G)

This slice normalizes Kerberoast baseline exposure semantics for:
- enabled SPN-linked accounts
- RC4-permitted Kerberoastable accounts

The slice intentionally excludes:
- AD-03 detection/absence reasoning
- AD-23 privilege/value coupling

Adapter:
- `skg_domain_ad.adapters.ad_kerberoast_exposure.map_kerberoast_exposure_to_events`

Attack path:
- `ad_kerberoast_exposure_baseline_v1`

Wickets:
- `AD-KR-01` kerberoastable accounts present
- `AD-KR-02` kerberoastable RC4-permitted accounts present

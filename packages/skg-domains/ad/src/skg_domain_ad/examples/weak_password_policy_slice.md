# AD Weak Password Policy Slice (Phase 7D)

This slice normalizes AD domain password policy snapshots into canonical
precondition events for weak minimum password length assessment.

Adapter:
- `skg_domain_ad.adapters.ad_weak_password_policy.map_weak_password_policy_to_events`

Attack path:
- `ad_weak_password_policy_v1`

Wickets:
- `AD-WP-01` password policy snapshot observed
- `AD-WP-02` weak minimum password length present

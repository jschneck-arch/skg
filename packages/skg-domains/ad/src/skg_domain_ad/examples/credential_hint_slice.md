# AD Credential-Hint Slice (Phase 7C)

This slice normalizes description-field credential hints from AD inventory
snapshots into canonical AD precondition events.

Inputs:
- `users` rows from BloodHound-style or LDAP dump-style snapshots
- `computers` rows from BloodHound-style or LDAP dump-style snapshots

Adapter:
- `skg_domain_ad.adapters.ad_credential_hints.map_credential_hints_to_events`

Attack path:
- `ad_password_hint_exposure_v1`

Wickets:
- `AD-CH-01` credential hints in descriptions present
- `AD-CH-02` enabled non-machine credential hints present

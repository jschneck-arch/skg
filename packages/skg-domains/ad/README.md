# skg-domain-ad

Canonical AD domain pack (Phases 7A, 7C, 7D, 7F, 7G, 7I, and 7L).

Implemented semantic slices:
- Privileged group membership and privilege-assignment mapping from AD inventory snapshots.
- Password-description / credential-hint normalization from AD account inventory snapshots.
- Weak password policy normalization from AD domain policy snapshots.
- AS-REP baseline exposure normalization from AD user inventory snapshots.
- Kerberoast baseline exposure normalization from AD user/SPN inventory snapshots.
- LAPS baseline coverage normalization from AD computer inventory snapshots.
- AD-22 core privileged-session tiering posture normalization from canonical runtime sidecar input.

Not migrated:
- ACL abuse and DCSync semantics
- Delegation abuse semantics
- Runtime LDAP/BloodHound transport execution
- Redteam/ad-lateral orchestration flows

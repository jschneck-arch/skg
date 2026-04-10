# Archive

This directory stores non-canonical repository material.

## Allowed Content

- deploy mirrors (`skg_deploy` lineage)
- backup trees (`*.backup` lineage)
- generated artifacts (embedded virtualenvs, dependency mirrors, cache snapshots)
- stale worktrees and staging trees (`forge_staging` lineage)
- migration snapshots by phase

## Rules

- Nothing in `archive/` is runtime authority.
- No production import path may point into `archive/`.
- Every archived subtree should include provenance metadata (`origin path`, `archive date`, `reason`).

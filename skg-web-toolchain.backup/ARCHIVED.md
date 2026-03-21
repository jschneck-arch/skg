# ARCHIVED — skg-web-toolchain.backup/

This directory is a **point-in-time backup** of the web toolchain prior to the refactor that split it into:

- `/opt/skg/skg-web-toolchain/` — HTTP/web collection and projection (canonical)
- `/opt/skg/skg-nginx-toolchain/` — Nginx-specific catalog and collection

## Status

**Non-canonical. Preserved for reference only.**

Do not import from this directory. The canonical web toolchain is `/opt/skg/skg-web-toolchain/`.

## What Changed

The backup was taken before:
1. `web_fingerprint` adapter was split into nginx-specific toolchain
2. Auth scanner was updated to handle CSRF-protected forms
3. Projection loop was integrated with the kernel state engine
4. The `forge_staging/skg-web-toolchain/` replaced this as the active web toolchain staging area

## Deletion

This directory may be removed once the refactor has been validated in production. It exists only as a rollback reference.

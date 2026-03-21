# ARCHIVED — skg_deploy/

This directory is a **deployment mirror** of the canonical SKG substrate at `/opt/skg/`.

## Status

**Non-canonical.** The canonical codebase is `/opt/skg/`.

Do not modify files here directly. Changes made here will be overwritten when the deployment mirror is synchronized from the canonical tree.

## Purpose

`skg_deploy/` exists to hold a synchronized copy of the deployed configuration for production deployment scenarios (e.g., packaging, container images, remote installs).

## Synchronization

To synchronize from canonical:
```bash
rsync -av --exclude='__pycache__' --exclude='*.pyc' \
    /opt/skg/skg/ /opt/skg/skg_deploy/skg/
rsync -av --exclude='__pycache__' --exclude='*.pyc' \
    /opt/skg/skg-gravity/ /opt/skg/skg_deploy/skg-gravity/
```

## Risk

Files in this directory may be stale relative to the canonical tree. Before referencing any code here, verify the canonical version at `/opt/skg/`.

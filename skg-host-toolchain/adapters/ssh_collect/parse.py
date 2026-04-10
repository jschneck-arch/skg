#!/usr/bin/env python3
"""Legacy compatibility wrapper for canonical host SSH runtime collection.

This module is intentionally reduced. Active in-repo runtime callsites now
use `skg_services.gravity.host_runtime` directly. This file remains only as a
compatibility entrypoint for external scripts that still execute
`skg-host-toolchain/adapters/ssh_collect/parse.py`.
"""

from __future__ import annotations

import argparse
import uuid
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Legacy host SSH compatibility wrapper (canonical runtime-backed)"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default="")
    parser.add_argument("--key", default="")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--out", required=True)
    parser.add_argument("--attack-path-id", default="host_ssh_initial_access_v1")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--workload-id", default="")
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser


def main() -> int:
    args = _build_parser().parse_args()

    run_id = str(args.run_id or str(uuid.uuid4()))
    workload_id = str(args.workload_id or f"ssh::{args.host}")
    out_path = Path(args.out).expanduser().resolve()

    try:
        from skg_services.gravity.host_runtime import collect_ssh_assessment_to_file
    except Exception as exc:
        print(f"[ERROR] canonical host runtime unavailable: {exc}", flush=True)
        return 1

    try:
        events = collect_ssh_assessment_to_file(
            args.host,
            out_path=out_path,
            attack_path_id=args.attack_path_id,
            run_id=run_id,
            workload_id=workload_id,
            username=args.user,
            password=args.password,
            key=args.key,
            port=int(args.port),
            timeout=float(args.timeout),
        )
    except Exception as exc:
        print(f"[WARN] host ssh compatibility wrapper failed: {exc}", flush=True)
        return 1

    print(f"[OK] Canonical host SSH runtime wrote {len(events)} event(s) -> {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

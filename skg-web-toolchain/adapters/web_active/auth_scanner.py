"""
Legacy compatibility wrapper for authenticated web scanning.

Canonical runtime path:
- service runtime: `skg_services.gravity.web_runtime.collect_auth_surface_events_to_file`
- domain semantics: `skg_domain_web.adapters.web_surface_fingerprint` +
  `skg_domain_web.adapters.web_auth_assessment`
"""
from __future__ import annotations

import argparse
import uuid
from pathlib import Path
from urllib.parse import urlparse


def auth_scan(
    target: str,
    out_path: str,
    attack_path_id: str,
    username: str | None = None,
    password: str | None = None,
    try_defaults: bool = False,
    run_id: str | None = None,
    workload_id: str | None = None,
    timeout: float = 10.0,
):
    """Compatibility entrypoint retained for controlled migration."""
    try:
        from skg_services.gravity.web_runtime import collect_auth_surface_events_to_file
    except Exception as exc:
        raise RuntimeError(
            "auth_scanner compatibility wrapper requires canonical services/runtime packages"
        ) from exc

    rid = str(run_id or uuid.uuid4().hex[:8])
    host = urlparse(str(target or "")).hostname or str(target or "unknown")
    wid = str(workload_id or f"web::{host}")
    return collect_auth_surface_events_to_file(
        str(target),
        out_path=Path(out_path),
        attack_path_id=str(attack_path_id),
        run_id=rid,
        workload_id=wid,
        username=str(username or ""),
        password=str(password or ""),
        try_defaults=bool(try_defaults),
        timeout=float(timeout),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Legacy auth scanner compatibility wrapper")
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--attack-path-id", dest="attack_path_id", default="web_sqli_to_shell_v1")
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--try-defaults", action="store_true")
    parser.add_argument("--run-id", dest="run_id", default=None)
    parser.add_argument("--workload-id", dest="workload_id", default=None)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    events = auth_scan(
        target=args.target,
        out_path=args.out,
        attack_path_id=args.attack_path_id,
        username=args.username,
        password=args.password,
        try_defaults=args.try_defaults,
        run_id=args.run_id,
        workload_id=args.workload_id,
        timeout=args.timeout,
    )
    print(f"[SKG-WEB][auth-legacy-wrapper] Canonical runtime wrote {len(events)} events to {args.out}")


if __name__ == "__main__":
    main()

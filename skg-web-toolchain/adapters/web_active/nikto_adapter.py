"""
Legacy compatibility wrapper for nikto execution.

Canonical runtime path:
- service runtime: `skg_services.gravity.web_runtime`
- domain semantics: `skg_domain_web.adapters.web_nikto_findings`
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
import uuid


def run_nikto(target_url: str, out_dir: Path) -> list[dict]:
    """
    Compatibility entrypoint retained for controlled migration.

    Active runtime callers should invoke service wrappers directly.
    """
    try:
        from skg_services.gravity.web_runtime import collect_nikto_events_to_file
    except Exception as exc:
        raise RuntimeError(
            "nikto_adapter compatibility wrapper requires canonical services/runtime packages"
        ) from exc

    target = str(target_url or "").strip()
    host = urlparse(target).hostname or target or "unknown"
    run_id = uuid.uuid4().hex[:8]
    events_file = Path(out_dir) / f"nikto_events_{run_id}.ndjson"
    return collect_nikto_events_to_file(
        target,
        out_path=events_file,
        out_dir=Path(out_dir),
        attack_path_id="web_surface_v1",
        run_id=run_id,
        workload_id=f"web::{host}",
    )

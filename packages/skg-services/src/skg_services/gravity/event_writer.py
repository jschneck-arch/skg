from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def emit_events(
    events: list[dict],
    events_dir: Path | str | None,
    source_tag: str = "sensor",
    run_id: str | None = None,
) -> list[str]:
    """Service-owned event writer for measurement-plane outputs."""

    if events_dir is None:
        return []

    output_dir = Path(events_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    tag = source_tag.replace("/", "_").replace(":", "_")[:40]
    if run_id:
        out_path = output_dir / f"{timestamp}_{tag}_{run_id}.ndjson"
    else:
        out_path = output_dir / f"{timestamp}_{tag}.ndjson"

    ids: list[str] = []
    with out_path.open("a", encoding="utf-8") as handle:
        for event in events:
            if "id" not in event:
                event["id"] = str(uuid.uuid4())
            handle.write(json.dumps(event) + "\n")
            ids.append(event["id"])

    return ids

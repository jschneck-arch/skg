from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


def read_jsonl(path: Path) -> list[dict]:
    """Load newline-delimited JSON records; invalid lines are skipped."""

    records: list[dict] = []
    if not path.exists():
        return records

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def append_jsonl(path: Path, records: Iterable[dict]) -> int:
    """Append dictionary records to JSONL and return number written."""

    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            if not isinstance(record, dict):
                continue
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
            written += 1
    return written

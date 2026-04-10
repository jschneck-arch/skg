from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from skg_core.config.paths import SKG_STATE_DIR


class GravityFailureReporter:
    """Record non-fatal gravity cycle failures instead of silently swallowing them."""

    def __init__(
        self,
        *,
        run_id: str,
        cycle_num: int,
        state_dir: Path | str | None = None,
        logger: Any | None = None,
        printer: Any | None = print,
    ) -> None:
        root = Path(state_dir) if state_dir is not None else SKG_STATE_DIR
        self._path = root / "gravity" / "cycle_failures.ndjson"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = logger
        self._printer = printer
        self._run_id = str(run_id or "")
        self._cycle_num = int(cycle_num or 0)
        self.failures: list[dict[str, Any]] = []

    @property
    def path(self) -> Path:
        return self._path

    def emit(
        self,
        stage: str,
        message: str,
        *,
        target_ip: str = "",
        severity: str = "warning",
        exc: Exception | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": self._run_id,
            "cycle": self._cycle_num,
            "stage": str(stage or "").strip() or "unknown",
            "severity": str(severity or "warning"),
            "message": str(message or "").strip() or "gravity cycle issue",
            "target_ip": str(target_ip or ""),
            "exception": repr(exc) if exc is not None else "",
            "context": dict(context or {}),
        }
        self.failures.append(record)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

        target_label = f" target={target_ip}" if target_ip else ""
        printable = f"  [WARN] {record['stage']}{target_label}: {record['message']}"
        if self._printer is not None:
            self._printer(printable)
        if self._logger is not None:
            try:
                self._logger.warning(
                    "%s%s: %s",
                    record["stage"],
                    target_label,
                    record["message"],
                )
            except Exception:
                pass
        return record

    def count(self) -> int:
        return len(self.failures)

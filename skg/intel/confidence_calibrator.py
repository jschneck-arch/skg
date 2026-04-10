"""
skg.intel.confidence_calibrator
================================
Compatibility wrapper around the canonical runtime confidence calibrator.

This module previously maintained a separate evidence-rank calibration file,
which diverged from the sensor confidence model used by the runtime. The
canonical implementation now lives in `skg.sensors.confidence_calibrator`.

Supported paths:
- build calibration from an engagement database via `skg calibrate`
- build calibration from DeltaStore NDJSON via this wrapper
- load/save the same calibration file used by SensorContext at runtime
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from skg_core.config.paths import DELTA_DIR
from skg.sensors.confidence_calibrator import (
    CALIBRATION_PATH as CAL_STATE_FILE,
    ConfidenceCalibrator as _CanonicalConfidenceCalibrator,
)

log = logging.getLogger("skg.intel.calibrator")


class ConfidenceCalibrator(_CanonicalConfidenceCalibrator):
    """
    Backward-compatible facade.

    The persisted output and reporting now match the runtime sensor
    calibration model exactly. No second calibration file is written.
    """

    def __init__(self, events_dir: Path | None = None, delta_dir: Path | None = None):
        super().__init__()
        self.events_dir = events_dir
        self.delta_dir = delta_dir or DELTA_DIR

    def calibrate_from_delta_store(self) -> dict:
        for candidate in [
            self.delta_dir / "delta_store.ndjson",
            self.delta_dir.parent / "delta_store.ndjson",
        ]:
            if candidate.exists():
                return self.fit_from_ndjson(candidate)
        log.warning(f"[calibrator] Delta file not found under {self.delta_dir}")
        return {}

    def calibrate_and_save(self) -> dict:
        report = self.calibrate_from_delta_store()
        self.save()
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description="SKG calibration compatibility wrapper")
    parser.add_argument("--delta-file", default=None, help="explicit DeltaStore NDJSON file")
    parser.add_argument("--report", action="store_true", help="print calibration report")
    parser.add_argument("--update", action="store_true", help="recompute and save calibration")
    args = parser.parse_args()

    calibrator = ConfidenceCalibrator(
        delta_dir=Path(args.delta_file).parent if args.delta_file else None,
    )

    if args.delta_file:
        calibrator.fit_from_ndjson(Path(args.delta_file))
    elif args.update:
        calibrator.calibrate_and_save()
    else:
        calibrator.calibrate_from_delta_store()

    if args.update:
        print(f"\n  Saved → {CAL_STATE_FILE}")

    print(f"\n{calibrator.report()}")


if __name__ == "__main__":
    main()

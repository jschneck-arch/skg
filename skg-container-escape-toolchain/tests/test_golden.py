#!/usr/bin/env python3
"""
Golden test: container escape projection determinism.

Runs the projection engine against a fixed docker inspect fixture
and validates the output matches expected_payload.json exactly.
Same pattern as skg-aprs-toolchain/tests/test_golden.py.
"""
import json, subprocess, sys
from pathlib import Path

ROOT     = Path(__file__).resolve().parents[1]
INSPECT  = ROOT / "tests/golden/events/sample_inspect.json"
SAMPLE   = ROOT / "tests/golden/events/sample.ndjson"
OUT      = ROOT / "tests/golden/expected/_out_interp.ndjson"
EXPECTED = json.loads((ROOT / "tests/golden/expected/expected_payload.json").read_text(encoding="utf-8"))

ATTACK_PATH = "container_escape_privileged_v1"
RUN_ID      = "golden-run-001"
WORKLOAD    = "test-container"


def read_last_interp(path: Path) -> dict | None:
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("type") == "interp.container_escape.realizability":
            last = obj
    return last


def main() -> int:
    # Step 1: regenerate events from fixture (ensures adapter is deterministic)
    if SAMPLE.exists():
        SAMPLE.unlink()
    rc = subprocess.call([
        sys.executable,
        str(ROOT / "adapters/container_inspect/parse.py"),
        "--inspect",     str(INSPECT),
        "--out",         str(SAMPLE),
        "--attack-path-id", ATTACK_PATH,
        "--run-id",      RUN_ID,
        "--workload-id", WORKLOAD,
    ])
    if rc != 0:
        print("[ERR] adapter failed", file=sys.stderr)
        return 2

    # Step 2: run projection
    if OUT.exists():
        OUT.unlink()
    rc = subprocess.call([
        sys.executable,
        str(ROOT / "projections/escape/run.py"),
        "--in",              str(SAMPLE),
        "--out",             str(OUT),
        "--attack-path-id",  ATTACK_PATH,
        "--run-id",          RUN_ID,
        "--workload-id",     WORKLOAD,
    ])
    if rc != 0:
        print("[ERR] projection failed", file=sys.stderr)
        return 2

    # Step 3: validate
    interp = read_last_interp(OUT)
    if not interp:
        print("[ERR] no interp event emitted", file=sys.stderr)
        return 2

    payload = interp.get("payload", {})
    failed = False
    for k, v in EXPECTED.items():
        got = payload.get(k)
        # Sort lists for comparison (order may vary)
        if isinstance(v, list):
            v_s, got_s = sorted(v), sorted(got or [])
            if v_s != got_s:
                print(f"[ERR] mismatch for {k}\n  expected: {v_s}\n  got:      {got_s}",
                      file=sys.stderr)
                failed = True
        else:
            if got != v:
                print(f"[ERR] mismatch for {k}\n  expected: {v}\n  got:      {got}",
                      file=sys.stderr)
                failed = True

    if failed:
        return 2

    print("[OK] golden test passed — container_escape_privileged_v1 score=1.0 classification=realized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

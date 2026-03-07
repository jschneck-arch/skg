#!/usr/bin/env python3
"""
Golden test: AD lateral movement projection determinism.
Runs the full pipeline against a fixed BloodHound fixture
and validates the output matches expected_payload.json exactly.
"""
import json, subprocess, sys
from pathlib import Path

ROOT     = Path(__file__).resolve().parents[1]
BH_DIR   = ROOT / "tests/golden/events/bloodhound"
EVENTS   = ROOT / "tests/golden/events/sample.ndjson"
OUT      = ROOT / "tests/golden/expected/_out_interp.ndjson"
EXPECTED = json.loads((ROOT / "tests/golden/expected/expected_payload.json").read_text(encoding="utf-8"))

ATTACK_PATH = "ad_kerberoast_v1"
RUN_ID      = "golden-run-001"
WORKLOAD    = "CONTOSO.LOCAL"


def read_last_interp(path: Path) -> dict | None:
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("type") == "interp.ad_lateral.realizability":
            last = obj
    return last


def main() -> int:
    # Step 1: ingest from BloodHound fixture
    if EVENTS.exists():
        EVENTS.unlink()
    rc = subprocess.call([
        sys.executable,
        str(ROOT / "adapters/bloodhound/parse.py"),
        "--bh-dir",        str(BH_DIR),
        "--out",           str(EVENTS),
        "--attack-path-id", ATTACK_PATH,
        "--run-id",        RUN_ID,
        "--workload-id",   WORKLOAD,
    ])
    if rc != 0:
        print("[ERR] bloodhound adapter failed", file=sys.stderr)
        return 2

    # Step 2: project
    if OUT.exists():
        OUT.unlink()
    rc = subprocess.call([
        sys.executable,
        str(ROOT / "projections/lateral/run.py"),
        "--in",             str(EVENTS),
        "--out",            str(OUT),
        "--attack-path-id", ATTACK_PATH,
        "--run-id",         RUN_ID,
        "--workload-id",    WORKLOAD,
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
    failed  = False
    for k, v in EXPECTED.items():
        got = payload.get(k)
        if isinstance(v, list):
            if sorted(v) != sorted(got or []):
                print(f"[ERR] {k}\n  expected: {sorted(v)}\n  got:      {sorted(got or [])}",
                      file=sys.stderr)
                failed = True
        else:
            if got != v:
                print(f"[ERR] {k}\n  expected: {v}\n  got:      {got}", file=sys.stderr)
                failed = True

    if failed:
        return 2

    print("[OK] golden test passed — ad_kerberoast_v1 score=1.0 classification=realized")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

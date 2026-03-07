#!/usr/bin/env python3
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "tests/golden/events/sample.ndjson"
OUT = ROOT / "tests/golden/expected/_out_interp.ndjson"
EXPECTED = json.loads((ROOT / "tests/golden/expected/expected_payload.json").read_text(encoding="utf-8"))

def read_last_interp(path: Path):
    last = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("type") == "interp.host.realizability":
            last = obj
    return last

def main():
    if OUT.exists():
        OUT.unlink()
    cmd = [sys.executable, str(ROOT / "projections/host/run.py"),
           "--in", str(SAMPLE), "--out", str(OUT),
           "--attack-path-id", "host_linux_privesc_sudo_v1"]
    rc = subprocess.call(cmd)
    if rc != 0:
        print("[ERR] projection failed", file=sys.stderr)
        return 2
    interp = read_last_interp(OUT)
    if not interp:
        print("[ERR] no interp event emitted", file=sys.stderr)
        return 2
    payload = interp.get("payload", {})
    for k, v in EXPECTED.items():
        if payload.get(k) != v:
            print(f"[ERR] mismatch for {k}\n  expected: {v}\n  got:      {payload.get(k)}", file=sys.stderr)
            return 2
    print("[OK] golden test passed")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

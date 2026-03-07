#!/usr/bin/env python3
"""
adapter: manual
================
Accepts a structured JSON file of directly observed wicket states.
For use when BloodHound or ldapdomaindump cannot be run — manual enumeration,
partial tooling output, or operator-provided observations.

Input format:
{
  "workload_id": "CONTOSO",
  "observations": [
    {
      "wicket_id": "AD-01",
      "status": "realized",
      "confidence": 0.9,
      "note": "Found 3 SPNs on svc-sql, svc-web, svc-backup"
    },
    {
      "wicket_id": "AD-15",
      "status": "blocked",
      "confidence": 1.0,
      "note": "Only Domain Admins have GetChanges rights confirmed"
    }
  ]
}

Usage:
  python parse.py --input /tmp/manual_obs.json \\
                  --out /tmp/events.ndjson \\
                  --attack-path-id ad_dcsync_v1 \\
                  [--run-id <uuid>] [--workload-id <domain>]
"""

import argparse, json, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN    = "skg-ad-lateral-toolchain"
SOURCE_ID    = "adapter.manual"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

VALID_STATUSES = {"realized", "blocked", "unknown"}


def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main():
    p = argparse.ArgumentParser(
        description="Manual observation adapter for SKG AD lateral movement toolchain")
    p.add_argument("--input", required=True,
                   help="Path to structured manual observations JSON")
    p.add_argument("--out", required=True,
                   help="Output NDJSON events file (append)")
    p.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    p.add_argument("--run-id", default=None)
    p.add_argument("--workload-id", default=None)
    args = p.parse_args()

    input_path = Path(args.input)
    out_path   = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    run_id      = args.run_id or str(uuid.uuid4())
    attack_path_id = args.attack_path_id

    data = json.loads(input_path.read_text(encoding="utf-8"))
    workload_id = args.workload_id or data.get("workload_id") or "unknown"
    observations = data.get("observations", [])

    emitted = 0
    for obs in observations:
        wicket_id  = obs.get("wicket_id")
        status     = obs.get("status", "unknown")
        confidence = float(obs.get("confidence", 0.7))
        note       = obs.get("note", "")

        if not wicket_id:
            print(f"[WARN] skipping observation missing wicket_id: {obs}")
            continue
        if status not in VALID_STATUSES:
            print(f"[WARN] invalid status '{status}' for {wicket_id}, defaulting to unknown")
            status = "unknown"

        now = iso_now()
        event = {
            "id":  str(uuid.uuid4()),
            "ts":  now,
            "type": "obs.attack.precondition",
            "source": {
                "source_id": SOURCE_ID,
                "toolchain": TOOLCHAIN,
                "version":   get_version(),
            },
            "payload": {
                "wicket_id":      wicket_id,
                "status":         status,
                "attack_path_id": attack_path_id,
                "run_id":         run_id,
                "workload_id":    workload_id,
                "note":           note,
            },
            "provenance": {
                "evidence_rank": 5,  # manual = lowest automated rank
                "evidence": {
                    "source_kind":  "manual",
                    "pointer":      f"{input_path.name}[].{wicket_id}",
                    "collected_at": now,
                    "confidence":   confidence,
                },
            },
        }
        with open(out_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        emitted += 1

    print(f"[OK] emitted {emitted} manual observations → {out_path}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
projection: container_escape
============================
Deterministic tri-state projection engine for container escape attack paths.
Same logic as skg-aprs-toolchain/projections/aprs/run.py — different catalog.

Reads obs.attack.precondition events from an NDJSON file.
For each wicket in the required set:
  realized  — at least one realized observation, no blocked
  blocked   — at least one blocked observation
  unknown   — no observations

Score: ESCAPE = |realized| / |required|
Classification:
  realized      — all wickets realized, none blocked
  not_realized  — any wicket blocked
  indeterminate — unknowns present, or mix of blocked + unknown
"""

import argparse, json, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN = "skg-container-escape-toolchain"
SOURCE_ID = "projection.escape"


def get_version() -> str:
    v = Path(__file__).resolve().parents[2] / "VERSION"
    return v.read_text(encoding="utf-8").strip() if v.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_catalog(catalog_path: Path) -> dict:
    return json.loads(catalog_path.read_text(encoding="utf-8"))


def load_events(events_path: Path, attack_path_id: str,
                run_id: str | None, workload_id: str | None) -> list[dict]:
    """Load obs.attack.precondition events matching filters."""
    events = []
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("type") != "obs.attack.precondition":
            continue
        payload = obj.get("payload", {})
        if payload.get("attack_path_id") != attack_path_id:
            continue
        if run_id and payload.get("run_id") != run_id:
            continue
        if workload_id and payload.get("workload_id") != workload_id:
            continue
        events.append(obj)
    return events


def compute_escape(events: list[dict], catalog: dict,
                   attack_path_id: str,
                   run_id: str | None = None,
                   workload_id: str | None = None) -> dict:
    """
    Compute escape realizability for one attack path.
    Returns the payload dict (not the full envelope event).
    """
    paths = catalog.get("attack_paths", {})
    if attack_path_id not in paths:
        raise ValueError(f"Attack path '{attack_path_id}' not in catalog")

    required = paths[attack_path_id]["required_wickets"]

    # Aggregate per-wicket status from events
    # Priority: blocked > realized > unknown
    wicket_status: dict[str, str] = {}
    for event in events:
        payload = event.get("payload", {})
        wid = payload.get("wicket_id")
        status = payload.get("status")
        if wid not in required:
            continue
        if wid not in wicket_status:
            wicket_status[wid] = status
        else:
            # blocked wins over realized, realized wins over unknown
            current = wicket_status[wid]
            if status == "blocked":
                wicket_status[wid] = "blocked"
            elif status == "realized" and current == "unknown":
                wicket_status[wid] = "realized"

    # Classify each required wicket
    realized = [w for w in required if wicket_status.get(w) == "realized"]
    blocked  = [w for w in required if wicket_status.get(w) == "blocked"]
    unknown  = [w for w in required if wicket_status.get(w, "unknown") == "unknown"]

    score = round(len(realized) / len(required), 6) if required else 0.0

    if not blocked and not unknown:
        classification = "realized"
    elif blocked:
        classification = "not_realized"
    else:
        classification = "indeterminate"

    # Latest per-wicket status snapshot
    latest_status = {w: wicket_status.get(w, "unknown") for w in required}

    return {
        "attack_path_id": attack_path_id,
        "required_wickets": required,
        "latest_status": latest_status,
        "realized": realized,
        "blocked": blocked,
        "unknown": unknown,
        "escape_score": score,
        "classification": classification,
        "workload_id": workload_id,
        "run_id": run_id,
        "computed_at": iso_now(),
        "derivation": {
            "rule": "escape_score=|realized|/|required|; classification uses blocked/unknown sets",
            "engine": f"{TOOLCHAIN}/projections/escape/run.py",
            "version": get_version(),
        },
    }


def emit_interp(out_path: Path, payload: dict):
    """Append one interp.container_escape.realizability event."""
    now = iso_now()
    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "interp.container_escape.realizability",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": get_version(),
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": 1,
            "evidence": {
                "source_kind": "projection",
                "pointer": "projections/escape/run.py",
                "collected_at": payload["computed_at"],
                "confidence": 1.0,
            },
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def main():
    p = argparse.ArgumentParser(description="Container escape projection engine")
    p.add_argument("--in", dest="events_in", required=True,
                   help="Input NDJSON events file")
    p.add_argument("--out", required=True,
                   help="Output NDJSON interpretations file (append)")
    p.add_argument("--attack-path-id", required=True,
                   help="Attack path ID to project (e.g. container_escape_privileged_v1)")
    p.add_argument("--run-id", default=None)
    p.add_argument("--workload-id", default=None)
    p.add_argument("--catalog", default=None,
                   help="Path to catalog JSON (default: contracts/catalogs/attack_preconditions_catalog.container_escape.v1.json)")
    args = p.parse_args()

    root = Path(__file__).resolve().parents[2]
    catalog_path = Path(args.catalog) if args.catalog else (
        root / "contracts" / "catalogs" / "attack_preconditions_catalog.container_escape.v1.json"
    )

    catalog = load_catalog(catalog_path)
    events = load_events(Path(args.events_in), args.attack_path_id,
                         args.run_id, args.workload_id)

    payload = compute_escape(events, catalog, args.attack_path_id,
                             run_id=args.run_id, workload_id=args.workload_id)
    emit_interp(Path(args.out), payload)

    print(f"[OK] {args.attack_path_id}: score={payload['escape_score']} "
          f"classification={payload['classification']} → {args.out}")


if __name__ == "__main__":
    main()

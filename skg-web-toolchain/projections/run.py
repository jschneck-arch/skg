"""
skg-web-toolchain :: projections/run.py

Deterministic projection engine for the web domain.
Same logic as the APRS projection engine — reads NDJSON events,
evaluates wicket states against attack path requirements,
produces scored interpretation.

Usage:
  python run.py --in /tmp/events.ndjson \\
                --out /tmp/interp.ndjson \\
                --attack-path-id web_sqli_to_shell_v1
"""

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone


CATALOG_PATH = Path(__file__).resolve().parents[1] / "contracts" / "catalogs" / "attack_preconditions_catalog.web.v1.json"


def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def project(events_path: str, out_path: str, attack_path_id: str):
    """
    Read observation events, derive wicket states, score attack path.
    """
    catalog = load_catalog()
    attack_paths = catalog["attack_paths"]
    wickets = catalog["wickets"]

    if attack_path_id not in attack_paths:
        raise ValueError(f"Unknown attack path: {attack_path_id}. "
                         f"Available: {list(attack_paths.keys())}")

    ap = attack_paths[attack_path_id]
    required = ap["required_wickets"]

    # Read events and build wicket state map
    # Last-write-wins per wicket (most recent observation).
    # TODO(N3): refactor to accept events list and route through
    #   skg.substrate.projection.load_states_from_events + project_path,
    #   matching the pattern used by escape/run.py and lateral/run.py.
    wicket_states = {}
    wicket_evidence = {}

    events_file = Path(events_path)
    if not events_file.exists():
        raise FileNotFoundError(f"Events file not found: {events_path}")

    with open(events_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("type") != "obs.attack.precondition":
                continue

            payload = event.get("payload", {})
            wid = payload.get("wicket_id")
            status = payload.get("status")
            ts = event.get("ts", "")

            if wid and status:
                # Keep the most recent observation per wicket
                prev_ts = wicket_evidence.get(wid, {}).get("ts", "")
                if ts >= prev_ts:
                    wicket_states[wid] = status
                    wicket_evidence[wid] = {
                        "ts": ts,
                        "status": status,
                        "provenance": event.get("provenance", {}),
                        "detail": payload.get("detail", ""),
                    }

    # Classify wickets
    realized = [w for w in required if wicket_states.get(w) == "realized"]
    blocked = [w for w in required if wicket_states.get(w) == "blocked"]
    unknown = [w for w in required if wicket_states.get(w, "unknown") == "unknown"]

    # Score
    total = len(required)
    score = len(realized) / total if total > 0 else 0.0

    if len(realized) == total:
        classification = "realized"
    elif blocked:
        classification = "not_realized"
    else:
        classification = "indeterminate"

    # Build interpretation
    interp = {
        "attack_path_id": attack_path_id,
        "description": ap["description"],
        "realized": realized,
        "blocked": blocked,
        "unknown": unknown,
        "aprs": round(score, 6),
        "classification": classification,
        "wicket_count": total,
        "derivation": {
            "rule": f"|realized|/|required| = {len(realized)}/{total}",
            "classification_rule": (
                "realized if all required wickets realized; "
                "not_realized if any required wicket blocked; "
                "indeterminate otherwise"
            ),
        },
        "evidence_summary": {
            wid: {
                "status": wicket_states.get(wid, "unknown"),
                "label": wickets.get(wid, {}).get("label", ""),
                "detail": wicket_evidence.get(wid, {}).get("detail", ""),
            }
            for wid in required
        },
        "ts": iso_now(),
    }

    # Write interpretation
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "a", encoding="utf-8") as f:
        f.write(json.dumps(interp) + "\n")

    # Print summary
    print(f"Attack Path: {attack_path_id}")
    print(f"Score:       {score:.2%} ({len(realized)}/{total})")
    print(f"Class:       {classification}")
    print(f"Realized:    {realized}")
    print(f"Blocked:     {blocked}")
    print(f"Unknown:     {unknown}")
    print(f"Written to:  {out}")

    return interp


def latest(interp_path: str, attack_path_id: str, workload_id: str = None):
    """Read the most recent interpretation for an attack path."""
    interp_file = Path(interp_path)
    if not interp_file.exists():
        print(f"No interpretation file: {interp_path}")
        return None

    latest_interp = None
    with open(interp_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("attack_path_id") == attack_path_id:
                if workload_id and rec.get("workload_id") != workload_id:
                    continue
                latest_interp = rec

    if latest_interp:
        print(json.dumps(latest_interp, indent=2))
    else:
        print(f"No interpretation found for {attack_path_id}")

    return latest_interp


def main():
    parser = argparse.ArgumentParser(description="SKG Web Projection Engine")
    sub = parser.add_subparsers(dest="cmd")

    p_proj = sub.add_parser("project")
    p_proj.add_argument("--in", dest="events", required=True)
    p_proj.add_argument("--out", required=True)
    p_proj.add_argument("--attack-path-id", dest="attack_path_id", required=True)

    p_lat = sub.add_parser("latest")
    p_lat.add_argument("--interp", required=True)
    p_lat.add_argument("--attack-path-id", dest="attack_path_id", required=True)
    p_lat.add_argument("--workload-id", dest="workload_id", default=None)

    args = parser.parse_args()

    if args.cmd == "project":
        project(args.events, args.out, args.attack_path_id)
    elif args.cmd == "latest":
        latest(args.interp, args.attack_path_id, getattr(args, "workload_id", None))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

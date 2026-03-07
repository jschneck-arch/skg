#!/usr/bin/env python3
"""
skg-escape -- CLI for the SKG container escape toolchain.

Usage:
  skg-escape ingest container_inspect --inspect <path> --out <path> [options]
  skg-escape project --in <path> --out <path> --attack-path-id <id> [options]
  skg-escape latest --interp <path> --attack-path-id <id> [--workload-id <id>]
  skg-escape paths
"""
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def cmd_paths(args):
    catalog_path = ROOT / "contracts/catalogs/attack_preconditions_catalog.container_escape.v1.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    print(f"Container escape attack paths (catalog v{catalog['version']}):\n")
    for path_id, path_def in catalog["attack_paths"].items():
        wickets = ", ".join(path_def["required_wickets"])
        print(f"  {path_id}")
        print(f"    {path_def['description']}")
        print(f"    wickets: {wickets}")
        print()


def main():
    p = argparse.ArgumentParser(description="SKG container escape toolchain CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("ingest")
    pi_sub = pi.add_subparsers(dest="adapter", required=True)
    pic = pi_sub.add_parser("container_inspect")
    pic.add_argument("--inspect", required=True)
    pic.add_argument("--out", required=True)
    pic.add_argument("--attack-path-id", default="container_escape_privileged_v1")
    pic.add_argument("--run-id", default=None)
    pic.add_argument("--workload-id", default=None)

    pp = sub.add_parser("project")
    pp.add_argument("--in", dest="events_in", required=True)
    pp.add_argument("--out", required=True)
    pp.add_argument("--attack-path-id", required=True)
    pp.add_argument("--run-id", default=None)
    pp.add_argument("--workload-id", default=None)

    pl = sub.add_parser("latest")
    pl.add_argument("--interp", required=True)
    pl.add_argument("--attack-path-id", required=True)
    pl.add_argument("--workload-id", default=None)

    sub.add_parser("paths")

    args = p.parse_args()

    if args.cmd == "paths":
        cmd_paths(args)
        return

    if args.cmd == "ingest":
        sys.argv = [
            "parse.py",
            "--inspect", args.inspect,
            "--out", args.out,
            "--attack-path-id", args.attack_path_id,
        ]
        if args.run_id:    sys.argv += ["--run-id", args.run_id]
        if args.workload_id: sys.argv += ["--workload-id", args.workload_id]
        from adapters.container_inspect.parse import main as m
        m()
        return

    if args.cmd == "project":
        sys.argv = [
            "run.py",
            "--in", args.events_in,
            "--out", args.out,
            "--attack-path-id", args.attack_path_id,
        ]
        if args.run_id:    sys.argv += ["--run-id", args.run_id]
        if args.workload_id: sys.argv += ["--workload-id", args.workload_id]
        from projections.escape.run import main as m
        m()
        return

    if args.cmd == "latest":
        interp_path = Path(args.interp)
        if not interp_path.exists():
            print(f"[ERR] {interp_path} not found", file=sys.stderr)
            sys.exit(1)
        latest, latest_ts = None, None
        for line in interp_path.read_text(encoding="utf-8").splitlines():
            if not line.strip(): continue
            obj = json.loads(line)
            if obj.get("type") != "interp.container_escape.realizability": continue
            payload = obj.get("payload", {})
            if payload.get("attack_path_id") != args.attack_path_id: continue
            if args.workload_id and payload.get("workload_id") != args.workload_id: continue
            ts = obj.get("ts", "")
            if latest_ts is None or ts > latest_ts:
                latest, latest_ts = payload, ts
        if latest:
            print(json.dumps(latest, indent=2))
        else:
            print("[ERR] no matching interpretation found", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
skg-lateral — CLI for the SKG AD lateral movement toolchain.

Usage:
  skg-lateral ingest bloodhound --bh-dir <path> --out <path> [options]
  skg-lateral ingest ldapdomaindump --dump-dir <path> --out <path> [options]
  skg-lateral ingest manual --input <path> --out <path> [options]
  skg-lateral project --in <path> --out <path> --attack-path-id <id> [options]
  skg-lateral latest --interp <path> --attack-path-id <id> [--workload-id <id>]
  skg-lateral paths
"""
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def cmd_paths(args):
    catalog_path = ROOT / "contracts/catalogs/attack_preconditions_catalog.ad_lateral.v1.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    print(f"AD lateral movement attack paths (catalog v{catalog['version']}):\n")
    for path_id, path_def in catalog["attack_paths"].items():
        wickets = ", ".join(path_def["required_wickets"])
        print(f"  {path_id}")
        print(f"    {path_def['description']}")
        print(f"    wickets: {wickets}")
        print()


def main():
    p = argparse.ArgumentParser(description="SKG AD lateral movement toolchain CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ingest
    pi = sub.add_parser("ingest")
    pi_sub = pi.add_subparsers(dest="adapter", required=True)

    # ingest bloodhound
    pbh = pi_sub.add_parser("bloodhound")
    pbh.add_argument("--bh-dir", required=True)
    pbh.add_argument("--out", required=True)
    pbh.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    pbh.add_argument("--run-id", default=None)
    pbh.add_argument("--workload-id", default=None)

    # ingest ldapdomaindump
    pld = pi_sub.add_parser("ldapdomaindump")
    pld.add_argument("--dump-dir", required=True)
    pld.add_argument("--out", required=True)
    pld.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    pld.add_argument("--run-id", default=None)
    pld.add_argument("--workload-id", default=None)

    # ingest manual
    pm = pi_sub.add_parser("manual")
    pm.add_argument("--input", required=True)
    pm.add_argument("--out", required=True)
    pm.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    pm.add_argument("--run-id", default=None)
    pm.add_argument("--workload-id", default=None)

    # project
    pp = sub.add_parser("project")
    pp.add_argument("--in", dest="events_in", required=True)
    pp.add_argument("--out", required=True)
    pp.add_argument("--attack-path-id", required=True)
    pp.add_argument("--run-id", default=None)
    pp.add_argument("--workload-id", default=None)

    # latest
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
        if args.adapter == "bloodhound":
            sys.argv = ["parse.py",
                        "--bh-dir", args.bh_dir,
                        "--out", args.out,
                        "--attack-path-id", args.attack_path_id]
            if args.run_id: sys.argv += ["--run-id", args.run_id]
            if args.workload_id: sys.argv += ["--workload-id", args.workload_id]
            from adapters.bloodhound.parse import main as m
            m()

        elif args.adapter == "ldapdomaindump":
            sys.argv = ["parse.py",
                        "--dump-dir", args.dump_dir,
                        "--out", args.out,
                        "--attack-path-id", args.attack_path_id]
            if args.run_id: sys.argv += ["--run-id", args.run_id]
            if args.workload_id: sys.argv += ["--workload-id", args.workload_id]
            from adapters.ldapdomaindump.parse import main as m
            m()

        elif args.adapter == "manual":
            sys.argv = ["parse.py",
                        "--input", args.input,
                        "--out", args.out,
                        "--attack-path-id", args.attack_path_id]
            if args.run_id: sys.argv += ["--run-id", args.run_id]
            if args.workload_id: sys.argv += ["--workload-id", args.workload_id]
            from adapters.manual.parse import main as m
            m()
        return

    if args.cmd == "project":
        sys.argv = ["run.py",
                    "--in", args.events_in,
                    "--out", args.out,
                    "--attack-path-id", args.attack_path_id]
        if args.run_id: sys.argv += ["--run-id", args.run_id]
        if args.workload_id: sys.argv += ["--workload-id", args.workload_id]
        from projections.lateral.run import main as m
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
            if obj.get("type") != "interp.ad_lateral.realizability": continue
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

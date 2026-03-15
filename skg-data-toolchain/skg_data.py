#!/usr/bin/env python3
"""
skg_data.py — SKG data pipeline toolchain CLI

USAGE:
  skg_data.py ingest db --url <sqlalchemy_url> --table <table>
                         --out <file> [--workload-id <id>]
                         [--contract <json>] [--attack-path-id <id>]

  skg_data.py ingest config --config <data_sources.yaml>
                              --out-dir <dir>

  skg_data.py project --in <events.ndjson> --out <interp.json>
                       --attack-path-id <id> [--workload-id <id>]

  skg_data.py latest --interp <file> --attack-path-id <id>
                      [--workload-id <id>]

  skg_data.py paths
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

TC_DIR = Path(__file__).resolve().parent


def _py():
    venv = TC_DIR / ".venv" / "bin" / "python"
    return str(venv) if venv.exists() else sys.executable


def _sub(*args):
    return subprocess.call([_py()] + list(args), cwd=str(TC_DIR))


def _catalog() -> dict:
    catalog_dir = TC_DIR / "contracts" / "catalogs"
    catalogs    = list(catalog_dir.glob("*.json"))
    if not catalogs:
        raise SystemExit("No catalog found in contracts/catalogs/")
    return json.loads(catalogs[0].read_text())


def main():
    p   = argparse.ArgumentParser(prog="skg_data")
    sub = p.add_subparsers(dest="cmd", required=True)

    # paths
    sub.add_parser("paths", help="List available failure paths")

    # latest
    pl = sub.add_parser("latest")
    pl.add_argument("--interp",         required=True)
    pl.add_argument("--attack-path-id", required=True)
    pl.add_argument("--workload-id",    default=None)

    # project
    pp = sub.add_parser("project")
    pp.add_argument("--in",  dest="infile",  required=True)
    pp.add_argument("--out", dest="outfile", required=True)
    pp.add_argument("--attack-path-id", required=True)
    pp.add_argument("--workload-id",    default=None)
    pp.add_argument("--run-id",         default=None)
    pp.add_argument("--catalog",        default=None)

    # ingest
    pi     = sub.add_parser("ingest")
    pi_sub = pi.add_subparsers(dest="adapter", required=True)

    # ingest db — single table
    pdb = pi_sub.add_parser("db")
    pdb.add_argument("--url",           required=True)
    pdb.add_argument("--table",         required=True)
    pdb.add_argument("--out",           required=True)
    pdb.add_argument("--workload-id",   dest="workload_id",   default=None)
    pdb.add_argument("--contract",      default=None)
    pdb.add_argument("--attack-path-id",dest="attack_path_id",
                     default="data_completeness_failure_v1")
    pdb.add_argument("--batch-id",      dest="batch_id",      default=None)
    pdb.add_argument("--run-id",        dest="run_id",        default=None)

    # ingest config — multiple sources from YAML
    pcfg = pi_sub.add_parser("config")
    pcfg.add_argument("--config",   required=True)
    pcfg.add_argument("--out-dir",  dest="out_dir",
                      default="/var/lib/skg/events")

    a = p.parse_args()

    # ── paths ──────────────────────────────────────────────────────────────
    if a.cmd == "paths":
        catalog = _catalog()
        print(f"\nData pipeline failure paths ({TC_DIR.name}):\n")
        for pid, path in catalog.get("attack_paths", {}).items():
            required = path.get("required_wickets", [])
            desc     = path.get("description", "")
            domains  = ", ".join(path.get("domains", []))
            print(f"  {pid}")
            print(f"    {desc}")
            print(f"    required: {required}")
            print(f"    domains:  {domains}")
            print()
        return

    # ── ingest ─────────────────────────────────────────────────────────────
    if a.cmd == "ingest":
        adapter_script = TC_DIR / "adapters" / "db_profiler" / "profile.py"

        if a.adapter == "db":
            args = [
                str(adapter_script),
                "--url",   a.url,
                "--table", a.table,
                "--out",   a.out,
                "--attack-path-id", a.attack_path_id,
            ]
            if a.workload_id: args += ["--workload-id", a.workload_id]
            if a.contract:    args += ["--contract",    a.contract]
            if a.batch_id:    args += ["--batch-id",    a.batch_id]
            if a.run_id:      args += ["--run-id",      a.run_id]
            sys.exit(_sub(*args))

        elif a.adapter == "config":
            args = [
                str(adapter_script),
                "--config",  a.config,
                "--out-dir", a.out_dir,
            ]
            sys.exit(_sub(*args))

    # ── project ────────────────────────────────────────────────────────────
    if a.cmd == "project":
        proj_script = TC_DIR / "projections" / "data" / "run.py"
        catalog_dir = TC_DIR / "contracts" / "catalogs"
        catalog     = a.catalog or str(list(catalog_dir.glob("*.json"))[0])
        args = [
            str(proj_script),
            "--in",             a.infile,
            "--out",            a.outfile,
            "--attack-path-id", a.attack_path_id,
            "--catalog",        catalog,
        ]
        if a.workload_id: args += ["--workload-id", a.workload_id]
        if a.run_id:      args += ["--run-id",      a.run_id]
        sys.exit(_sub(*args))

    # ── latest ─────────────────────────────────────────────────────────────
    if a.cmd == "latest":
        if not Path(a.interp).exists():
            print(f"Interp file not found: {a.interp}", file=sys.stderr)
            sys.exit(1)
        try:
            data = json.loads(Path(a.interp).read_text())
        except Exception as e:
            print(f"Failed to read interp: {e}", file=sys.stderr)
            sys.exit(1)

        payload = data.get("payload", data)
        apid    = payload.get("attack_path_id", "")
        if apid != a.attack_path_id:
            print(f"attack_path_id mismatch: {apid} != {a.attack_path_id}",
                  file=sys.stderr)
            sys.exit(1)

        if a.workload_id and payload.get("workload_id") != a.workload_id:
            sys.exit(1)

        print(json.dumps(payload, indent=2))
        sys.exit(0)


if __name__ == "__main__":
    main()

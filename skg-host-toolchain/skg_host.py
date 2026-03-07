#!/usr/bin/env python3
"""
skg_host.py — SKG host toolchain CLI

USAGE:
  skg host ingest ssh --host <ip> --user <user> [--key <path>|--password <pw>]
                      --out <file> [--attack-path-id <id>] [--workload-id <id>]

  skg host ingest winrm --host <ip> --user <user> --password <pw>
                         --out <file> [--attack-path-id <id>] [--workload-id <id>]

  skg host ingest nmap [--xml <file>|--target <cidr>]
                        --out <file> [--attack-path-id <id>] [--workload-id <id>]

  skg host ingest msf_session [--rpc-host <ip>|--json-dump <file>]
                               --out <file> [--attack-path-id <id>]

  skg host project --in <events> --out <interp> --attack-path-id <id>

  skg host latest --interp <file> --attack-path-id <id> [--workload-id <id>]

  skg host paths
"""

import argparse, json, subprocess, sys
from pathlib import Path

TC_DIR = Path(__file__).resolve().parent


def _py():
    venv = TC_DIR / ".venv" / "bin" / "python"
    return str(venv) if venv.exists() else sys.executable


def _sub(*args):
    return subprocess.call([_py()] + list(args), cwd=str(TC_DIR))


def main():
    p = argparse.ArgumentParser(prog="skg_host")
    sub = p.add_subparsers(dest="cmd", required=True)

    # paths
    sub.add_parser("paths", help="List available attack paths")

    # latest
    pl = sub.add_parser("latest")
    pl.add_argument("--interp", required=True)
    pl.add_argument("--attack-path-id", required=True)
    pl.add_argument("--workload-id", default=None)

    # project
    pp = sub.add_parser("project")
    pp.add_argument("--in",  dest="infile",  required=True)
    pp.add_argument("--out", dest="outfile", required=True)
    pp.add_argument("--attack-path-id", default="host_ssh_initial_access_v1")
    pp.add_argument("--run-id",         default=None)
    pp.add_argument("--workload-id",    default=None)
    pp.add_argument("--catalog", default=str(
        TC_DIR / "contracts/catalogs/attack_preconditions_catalog.host.v1.json"))

    # ingest
    pi = sub.add_parser("ingest")
    pi_sub = pi.add_subparsers(dest="adapter", required=True)

    # ingest ssh
    ssh = pi_sub.add_parser("ssh")
    ssh.add_argument("--host",      required=True)
    ssh.add_argument("--user",      required=True)
    ssh.add_argument("--key",       default=None)
    ssh.add_argument("--password",  default=None)
    ssh.add_argument("--port",      type=int, default=22)
    ssh.add_argument("--timeout",   type=int, default=15)
    ssh.add_argument("--out",       required=True)
    ssh.add_argument("--attack-path-id", default="host_ssh_initial_access_v1")
    ssh.add_argument("--run-id",    default=None)
    ssh.add_argument("--workload-id", default=None)

    # ingest winrm
    win = pi_sub.add_parser("winrm")
    win.add_argument("--host",     required=True)
    win.add_argument("--user",     required=True)
    win.add_argument("--password", required=True)
    win.add_argument("--port",     type=int, default=5985)
    win.add_argument("--ssl",      action="store_true", default=False)
    win.add_argument("--out",      required=True)
    win.add_argument("--attack-path-id", default="host_winrm_initial_access_v1")
    win.add_argument("--run-id",   default=None)
    win.add_argument("--workload-id", default=None)

    # ingest nmap
    nm = pi_sub.add_parser("nmap")
    nm_grp = nm.add_mutually_exclusive_group(required=True)
    nm_grp.add_argument("--xml",    help="Existing nmap XML (-oX)")
    nm_grp.add_argument("--target", help="Target to scan")
    nm.add_argument("--ports",        default=None)
    nm.add_argument("--nmap-flags",   default=None)
    nm.add_argument("--out",          required=True)
    nm.add_argument("--attack-path-id", default="host_network_exploit_v1")
    nm.add_argument("--run-id",       default=None)
    nm.add_argument("--workload-id",  default=None)

    # ingest msf_session
    msf = pi_sub.add_parser("msf_session")
    msf_grp = msf.add_mutually_exclusive_group(required=True)
    msf_grp.add_argument("--rpc-host",  help="MSF RPC host")
    msf_grp.add_argument("--json-dump", help="MSF JSON dump file")
    msf.add_argument("--rpc-port",    type=int, default=55553)
    msf.add_argument("--rpc-password", default="msf")
    msf.add_argument("--rpc-ssl",     action="store_true", default=False)
    msf.add_argument("--out",         required=True)
    msf.add_argument("--attack-path-id", default="host_msf_post_exploitation_v1")
    msf.add_argument("--run-id",      default=None)
    msf.add_argument("--workload-id", default="msf_workspace")

    args = p.parse_args()

    # ---------- paths ----------
    if args.cmd == "paths":
        cat = TC_DIR / "contracts/catalogs/attack_preconditions_catalog.host.v1.json"
        import json as _j
        data = _j.loads(cat.read_text())
        print(f"\nHost toolchain attack paths ({len(data['attack_paths'])}):\n")
        for pid, pdef in data["attack_paths"].items():
            wcount = len(pdef["required_wickets"])
            print(f"  {pid}")
            print(f"    {pdef['description']}")
            print(f"    required wickets ({wcount}): {', '.join(pdef['required_wickets'])}")
        return 0

    # ---------- latest ----------
    if args.cmd == "latest":
        from pathlib import Path as P
        interp_path = P(args.interp)
        latest = None
        latest_ts = None
        for line in interp_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("type") != "interp.host.realizability":
                continue
            payload = obj.get("payload", {})
            if payload.get("attack_path_id") != args.attack_path_id:
                continue
            if args.workload_id and payload.get("workload_id") != args.workload_id:
                continue
            ts = obj.get("ts") or payload.get("computed_at")
            if latest_ts is None or (ts and ts > latest_ts):
                latest_ts = ts
                latest = payload
        if latest is None:
            print("{}", end="")
            return 0
        print(json.dumps(latest, indent=2, sort_keys=True))
        return 0

    # ---------- project ----------
    if args.cmd == "project":
        cmd = [_py(),
               str(TC_DIR / "projections/host/run.py"),
               "--in", args.infile,
               "--out", args.outfile,
               "--attack-path-id", args.attack_path_id,
               "--catalog", args.catalog]
        if args.run_id:
            cmd += ["--run-id", args.run_id]
        if args.workload_id:
            cmd += ["--workload-id", args.workload_id]
        return subprocess.call(cmd, cwd=str(TC_DIR))

    # ---------- ingest ----------
    if args.cmd == "ingest":
        adapter_scripts = {
            "ssh":        "adapters/ssh_collect/parse.py",
            "winrm":      "adapters/winrm_collect/parse.py",
            "nmap":       "adapters/nmap_scan/parse.py",
            "msf_session": "adapters/msf_session/parse.py",
        }
        script = adapter_scripts.get(args.adapter)
        if not script:
            print(f"Unknown adapter: {args.adapter}", file=sys.stderr)
            return 1

        cmd = [_py(), str(TC_DIR / script)]

        if args.adapter == "ssh":
            cmd += ["--host", args.host, "--user", args.user,
                    "--port", str(args.port), "--timeout", str(args.timeout),
                    "--out", args.out, "--attack-path-id", args.attack_path_id]
            if args.key:      cmd += ["--key",      args.key]
            if args.password: cmd += ["--password", args.password]
            if args.run_id:   cmd += ["--run-id",   args.run_id]
            if args.workload_id: cmd += ["--workload-id", args.workload_id]

        elif args.adapter == "winrm":
            cmd += ["--host", args.host, "--user", args.user,
                    "--password", args.password, "--port", str(args.port),
                    "--out", args.out, "--attack-path-id", args.attack_path_id]
            if args.ssl: cmd += ["--ssl"]
            if args.run_id: cmd += ["--run-id", args.run_id]
            if args.workload_id: cmd += ["--workload-id", args.workload_id]

        elif args.adapter == "nmap":
            cmd += ["--out", args.out, "--attack-path-id", args.attack_path_id]
            if args.xml:      cmd += ["--xml",    args.xml]
            if args.target:   cmd += ["--target", args.target]
            if args.ports:    cmd += ["--ports",  args.ports]
            if args.nmap_flags: cmd += ["--nmap-flags", args.nmap_flags]
            if args.run_id:   cmd += ["--run-id", args.run_id]
            if args.workload_id: cmd += ["--workload-id", args.workload_id]

        elif args.adapter == "msf_session":
            cmd += ["--out", args.out, "--attack-path-id", args.attack_path_id,
                    "--workload-id", args.workload_id or "msf_workspace",
                    "--rpc-port", str(args.rpc_port),
                    "--rpc-password", args.rpc_password]
            if args.rpc_host:  cmd += ["--rpc-host",  args.rpc_host]
            if args.json_dump: cmd += ["--json-dump", args.json_dump]
            if args.rpc_ssl:   cmd += ["--rpc-ssl"]
            if args.run_id:    cmd += ["--run-id", args.run_id]

        return subprocess.call(cmd, cwd=str(TC_DIR))

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

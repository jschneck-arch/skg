#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
# lazy import for validate command

def load_schema(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def validate_ndjson(events_path: Path, envelope_schema_path: Path):
    from jsonschema import Draft202012Validator
    schema = load_schema(envelope_schema_path)
    v = Draft202012Validator(schema)
    ok = True
    with events_path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line=line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception as e:
                print(f"[ERR] line {i}: invalid json: {e}", file=sys.stderr)
                ok = False
                continue
            errs = sorted(v.iter_errors(obj), key=lambda e: e.path)
            for e in errs:
                print(f"[ERR] line {i}: {e.message}", file=sys.stderr)
                ok = False
    return 0 if ok else 2

def main():
    p = argparse.ArgumentParser(prog="skg")
    sub = p.add_subparsers(dest="cmd", required=True)

    pv = sub.add_parser("validate")
    pv.add_argument("events")

    pl = sub.add_parser("latest")
    pl.add_argument("--interp", required=True, help="Interpretation NDJSON file")
    pl.add_argument("--attack-path-id", required=True)
    pl.add_argument("--workload-id", default=None)
    pl.add_argument("--out", default=None, help="Optional output file (JSON) for the latest matching interp payload")

    pp = sub.add_parser("project")
    pp_sub = pp.add_subparsers(dest="proj", required=True)
    pa = pp_sub.add_parser("aprs")
    pa.add_argument("--in", dest="infile", required=True)
    pa.add_argument("--out", dest="outfile", required=True)
    pa.add_argument("--attack-path-id", default="log4j_jndi_rce_v1")
    pa.add_argument("--catalog", default="contracts/catalogs/attack_preconditions_catalog.aprs.v1.json")
    pa.add_argument("--run-id", default=None)
    pa.add_argument("--workload-id", default=None)
    pi = sub.add_parser("ingest")
    pi_sub = pi.add_subparsers(dest="adapter", required=True)

    pic = pi_sub.add_parser("config_effective")
    pic.add_argument("--root", required=True, help="Root directory to scan for log4j jars/configs")
    pic.add_argument("--out", required=True, help="Output NDJSON events file (append)")
    pic.add_argument("--attack-path-id", default="log4j_jndi_rce_v1")
    pic.add_argument("--run-id", default=None)
    pic.add_argument("--workload-id", default=None)

    pin = pi_sub.add_parser("net_sandbox")
    pin.add_argument("--docker-inspect", required=True, help="Path to docker inspect JSON")
    pin.add_argument("--root", default=None, help="Optional rootfs snapshot for reading /etc/resolv.conf")
    pin.add_argument("--resolv-conf", default=None, help="Optional path to captured /etc/resolv.conf")
    pin.add_argument("--iptables", default=None, help="Optional path to host iptables rules output (e.g., iptables -S)")
    pin.add_argument("--ps", default=None, help="Optional path to captured ps output (e.g., docker exec ... ps -ef)")
    pin.add_argument("--out", required=True)
    pin.add_argument("--attack-path-id", default="log4j_jndi_rce_v1")
    pin.add_argument("--run-id", default=None)
    pin.add_argument("--workload-id", default=None)


    args = p.parse_args()

    if args.cmd == "latest":
        import json
        from pathlib import Path
        interp_path = Path(args.interp)
        latest = None
        latest_ts = None
        for line in interp_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if obj.get("type") != "interp.attack_path.realizability":
                continue
            payload = obj.get("payload", {})
            if payload.get("attack_path_id") != args.attack_path_id:
                continue
            if args.workload_id is not None and payload.get("workload_id") != args.workload_id:
                continue
            ts = obj.get("ts") or payload.get("computed_at")
            if latest_ts is None or (ts and ts > latest_ts):
                latest_ts = ts
                latest = payload
        if latest is None:
            print("{}", end="")
            return 0
        out_json = json.dumps(latest, indent=2, sort_keys=True)
        if args.out:
            Path(args.out).write_text(out_json + "\n", encoding="utf-8")
        else:
            print(out_json)
        return 0

    if args.cmd == "validate":
        env = Path("contracts/envelope/skg.event.envelope.v1.json")
        return validate_ndjson(Path(args.events), env)

    if args.cmd == "project" and args.proj == "aprs":
        # defer import to keep minimal deps at validate-time
        import subprocess, sys as _sys
        cmd = [_sys.executable, "projections/aprs/run.py",
               "--in", args.infile,
               "--out", args.outfile,
               "--attack-path-id", args.attack_path_id,
               "--catalog", args.catalog,
               "--run-id", args.run_id or "",
               "--workload-id", args.workload_id or ""]
        cmd = [c for c in cmd if c != ""]
        return subprocess.call(cmd)

    if args.cmd == "ingest" and args.adapter == "config_effective":
        import subprocess, sys as _sys
        cmd = [_sys.executable, "adapters/config_effective/parse.py",
               "--root", args.root,
               "--out", args.out,
               "--attack-path-id", args.attack_path_id,
               "--run-id", args.run_id or "",
               "--workload-id", args.workload_id or ""]
        # strip empty args
        cmd = [c for c in cmd if c != ""]
        return subprocess.call(cmd)


    if args.cmd == "ingest" and args.adapter == "net_sandbox":
        import subprocess, sys as _sys
        cmd = [_sys.executable, "adapters/net_sandbox/parse.py",
               "--docker-inspect", args.docker_inspect,
               "--out", args.out,
               "--attack-path-id", args.attack_path_id,
               "--run-id", args.run_id or "",
               "--workload-id", args.workload_id or ""]
        if args.root:
            cmd += ["--root", args.root]
        if getattr(args, "resolv_conf", None):
            cmd += ["--resolv-conf", args.resolv_conf]
        if getattr(args, "iptables", None):
            cmd += ["--iptables", args.iptables]
        if getattr(args, "ps", None):
            cmd += ["--ps", args.ps]
        cmd = [c for c in cmd if c != ""]
        return subprocess.call(cmd)

    return 1

if __name__ == "__main__":
    raise SystemExit(main())

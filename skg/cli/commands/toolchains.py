from __future__ import annotations
import json, sys
from pathlib import Path
from skg.cli.utils import (
    _api, _aprs, _escape, _lateral, _load_module_from_file,
    DISCOVERY_DIR, SKG_HOME, SKG_STATE_DIR,
)
import os, subprocess


def cmd_aprs(a):
    subcmd = a.aprs_cmd
    if subcmd == "paths":
        sys.exit(_aprs("paths"))
    elif subcmd == "ingest":
        args = ["ingest", a.adapter, "--out", a.out,
                "--attack-path-id", a.attack_path_id]
        if getattr(a, "run_id", None): args += ["--run-id", a.run_id]
        if getattr(a, "workload_id", None): args += ["--workload-id", a.workload_id]
        if getattr(a, "root", None): args += ["--root", a.root]
        if getattr(a, "docker_inspect", None): args += ["--docker-inspect", a.docker_inspect]
        if getattr(a, "resolv_conf", None): args += ["--resolv-conf", a.resolv_conf]
        if getattr(a, "iptables", None): args += ["--iptables", a.iptables]
        if getattr(a, "ps", None): args += ["--ps", a.ps]
        sys.exit(_aprs(*args))
    elif subcmd == "project":
        sys.exit(_aprs("project", "aprs",
                        "--in", a.infile, "--out", a.outfile,
                        "--attack-path-id", a.attack_path_id))
    elif subcmd == "latest":
        args = ["latest", "--interp", a.interp, "--attack-path-id", a.attack_path_id]
        if a.workload_id: args += ["--workload-id", a.workload_id]
        sys.exit(_aprs(*args))


def cmd_escape(a):
    subcmd = a.escape_cmd
    if subcmd == "paths":
        sys.exit(_escape("paths"))
    elif subcmd == "ingest":
        args = ["ingest", "container_inspect",
                "--inspect", a.inspect, "--out", a.out,
                "--attack-path-id", a.attack_path_id]
        if getattr(a, "run_id", None): args += ["--run-id", a.run_id]
        if getattr(a, "workload_id", None): args += ["--workload-id", a.workload_id]
        sys.exit(_escape(*args))
    elif subcmd == "project":
        sys.exit(_escape("project",
                          "--in", a.infile, "--out", a.outfile,
                          "--attack-path-id", a.attack_path_id))
    elif subcmd == "latest":
        args = ["latest", "--interp", a.interp, "--attack-path-id", a.attack_path_id]
        if a.workload_id: args += ["--workload-id", a.workload_id]
        sys.exit(_escape(*args))


def cmd_lateral(a):
    subcmd = a.lateral_cmd
    if subcmd == "paths":
        sys.exit(_lateral("paths"))
    elif subcmd == "ingest":
        adapter = a.lateral_adapter
        args = ["ingest", adapter, "--out", a.out,
                "--attack-path-id", a.attack_path_id]
        if getattr(a, "run_id", None): args += ["--run-id", a.run_id]
        if getattr(a, "workload_id", None): args += ["--workload-id", a.workload_id]
        if adapter == "bloodhound":
            args += ["--bh-dir", a.bh_dir]
        elif adapter == "ldapdomaindump":
            args += ["--dump-dir", a.dump_dir]
        elif adapter == "manual":
            args += ["--input", a.input]
        sys.exit(_lateral(*args))
    elif subcmd == "project":
        sys.exit(_lateral("project",
                           "--in", a.infile, "--out", a.outfile,
                           "--attack-path-id", a.attack_path_id))
    elif subcmd == "latest":
        args = ["latest", "--interp", a.interp, "--attack-path-id", a.attack_path_id]
        if a.workload_id: args += ["--workload-id", a.workload_id]
        sys.exit(_lateral(*args))


def cmd_catalog(a):
    subcmd = getattr(a, "catalog_cmd", None)
    if subcmd == "compile":
        cmd = [sys.executable, "-m", "skg.forge.compiler",
               "--domain", a.domain, "--description", a.description,
               "--min-cvss", str(a.min_cvss), "--max-wickets", str(a.max_wickets)]
        if a.packages: cmd += ["--packages", a.packages]
        if a.keywords: cmd += ["--keywords", a.keywords]
        if a.prefix: cmd += ["--prefix", a.prefix]
        if a.api_key: cmd += ["--api-key", a.api_key]
        if getattr(a, "dry_run", False):
            cmd += ["--dry-run"]
        if a.out:
            cmd += ["--out", a.out]
        elif not getattr(a, "dry_run", False):
            import re
            slug = re.sub(r"[^a-z0-9_]", "_", a.domain.lower())
            out_path = SKG_HOME / f"skg-{slug}-toolchain" / "contracts" / "catalogs" / f"attack_preconditions_catalog.{slug}.v1.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            cmd += ["--out", str(out_path)]
        env = dict(os.environ)
        repo_root = str(SKG_HOME)
        current_pythonpath = env.get("PYTHONPATH", "")
        if current_pythonpath:
            if repo_root not in current_pythonpath.split(os.pathsep):
                env["PYTHONPATH"] = os.pathsep.join([repo_root, current_pythonpath])
        else:
            env["PYTHONPATH"] = repo_root
        sys.exit(subprocess.call(cmd, env=env))
    else:
        print("usage: skg catalog compile --domain DOMAIN --description DESC [options]")

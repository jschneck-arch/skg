#!/usr/bin/env python3
"""
adapter: web_collect
=====================
Web surface collection adapter. The core logic lives in
skg.sensors.web_sensor — this is the standalone CLI entrypoint
for running web collection outside the daemon.

Usage:
  python parse.py --url https://target.example.com \
    --out /tmp/web_events.ndjson \
    --attack-path-id web_surface_v1 \
    --workload-id target-web-01
"""
import argparse, json, sys, uuid
from pathlib import Path

# Allow running standalone without skg package on sys.path
_here = Path(__file__).resolve()
for _p in [_here.parents[4], _here.parents[3]]:
    if (_p / "skg").exists():
        sys.path.insert(0, str(_p))
        break

TOOLCHAIN = "skg-web-toolchain"
SOURCE_ID  = "adapter.web_collect"


def evaluate_wickets(collection: dict, attack_path_id: str, run_id: str) -> list:
    """Delegate to web_sensor.evaluate_wickets."""
    from skg.sensors.web_sensor import evaluate_wickets as _eval
    return _eval(collection, attack_path_id, run_id)


def emit(out_path, wicket_id, status, evidence_rank,
         evidence_source_kind, pointer, confidence,
         attack_path_id, run_id, workload_id, extra_payload=None):
    """Delegate to web_sensor emit pattern."""
    from skg.sensors.web_sensor import _ev
    import json
    ev = _ev(workload_id, wicket_id, status, evidence_rank,
             evidence_source_kind, pointer, confidence,
             attack_path_id, run_id)
    with open(out_path, "a") as f:
        f.write(json.dumps(ev) + "\n")


def main():
    p = argparse.ArgumentParser(description="Web surface collection adapter")
    p.add_argument("--url",            required=True)
    p.add_argument("--out",            required=True)
    p.add_argument("--attack-path-id", default="web_surface_v1")
    p.add_argument("--workload-id",    default=None)
    p.add_argument("--run-id",         default=None)
    p.add_argument("--proxy",          default=None,
                   help="SOCKS/HTTP proxy e.g. socks5h://127.0.0.1:9050")
    p.add_argument("--timeout",        type=int, default=10)
    p.add_argument("--no-verify-tls",  action="store_true")
    a = p.parse_args()

    from skg.sensors.web_sensor import WebClient, collect_web_target, evaluate_wickets

    target = {
        "url":         a.url,
        "method":      "onion" if ".onion" in a.url else
                       ("https" if a.url.startswith("https") else "http"),
        "workload_id": a.workload_id or a.url,
        "proxy":       a.proxy,
        "probe_limit": 40,
    }

    client = WebClient(
        proxy=a.proxy,
        timeout=a.timeout,
        verify_tls=not a.no_verify_tls,
    )

    collection = collect_web_target(target, client)
    run_id     = a.run_id or str(uuid.uuid4())[:8]
    events     = evaluate_wickets(collection, a.attack_path_id, run_id)

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    print(f"[web] {a.url}: {len(events)} events → {a.out}")
    print(f"[web] technologies: {collection['technologies']}")
    print(f"[web] probe hits:   {[h['path'] for h in collection['probe_hits']]}")


if __name__ == "__main__":
    main()

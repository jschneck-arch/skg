#!/usr/bin/env python3
import argparse, json, sys, zipfile, os
from pathlib import Path
from datetime import datetime, timezone
import uuid

TOOLCHAIN = "skg-aprs-toolchain"

def get_version():
    try:
        return Path(__file__).resolve().parents[2].joinpath("VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "0.0.0"

def iso_now():
    return datetime.now(timezone.utc).isoformat()

def emit(out_path: Path, typ: str, source_id: str, payload: dict,
         evidence_rank: int, source_kind: str, pointer: str,
         confidence: float=0.7, run_id: str|None=None, workload_id: str|None=None):
    ts = iso_now()

    # Stamp run/workload identifiers into the payload (projection uses these for run slicing)
    if run_id is not None:
        payload.setdefault("run_id", run_id)
    if workload_id is not None:
        payload.setdefault("workload_id", workload_id)

    env = {
        "id": str(uuid.uuid4()),
        "ts": ts,
        "type": typ,
        "source": {"source_id": source_id, "toolchain": TOOLCHAIN, "version": get_version()},
        "payload": payload,
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": {
                "source_kind": source_kind,
                "pointer": pointer,
                "collected_at": ts,
                "confidence": confidence
            }
        }
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(env) + "\n")

def find_jars(root: Path):
    for p in root.rglob("*.jar"):
        yield p

def jar_has(path: Path, member_suffix: str) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as z:
            for n in z.namelist():
                if n.endswith(member_suffix):
                    return True
    except Exception:
        return False
    return False

def detect_log4j_and_jndi(root: Path):
    """
    Defensive heuristic:
    - Detect log4j-core jar presence (build/classpath evidence_rank=2)
    - Detect JndiLookup class presence inside jar (capability hint)
    This is not runtime proof; it is evidence of capability in the artifact set.
    """
    log4j_core = []
    jndi_lookup = []
    for jar in find_jars(root):
        name = jar.name.lower()
        if "log4j-core" in name:
            log4j_core.append(jar)
            if jar_has(jar, "org/apache/logging/log4j/core/lookup/JndiLookup.class"):
                jndi_lookup.append(jar)
    return log4j_core, jndi_lookup

def find_configs(root: Path):
    patterns = ["log4j2.xml", "log4j2.properties", "log4j2.json", "log4j2.yaml", "log4j2.yml"]
    for p in root.rglob("*"):
        if p.is_file() and p.name.lower() in patterns:
            yield p

def config_suggests_lookups_enabled(text: str) -> bool:
    """
    Conservative heuristic:
    - If config references '${' patterns or explicit 'lookups' usage in PatternLayout,
      treat as 'realized' for AP-L11. Otherwise unknown.
    This is not a guarantee; effective config resolution may differ.
    """
    t = text.lower()
    if "${" in t:
        return True
    if "patternlayout" in t and ("lookup" in t or "${" in t):
        return True
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="Root directory to scan")
    ap.add_argument("--out", required=True, help="Output NDJSON (append)")
    ap.add_argument("--attack-path-id", default="log4j_jndi_rce_v1")
    ap.add_argument("--run-id", default=None, help="Run id (UUID). Auto-generated if omitted.")
    ap.add_argument("--workload-id", default=None, help="Workload/system id.")
    args = ap.parse_args()

    import uuid as _uuid
    rid = args.run_id or str(_uuid.uuid4())
    wid = args.workload_id

    root = Path(args.root).expanduser().resolve()
    outp = Path(args.out).expanduser().resolve()

    # AP-L10 (capability present) from jar scan
    log4j_core, jndi_lookup = detect_log4j_and_jndi(root)

    # If no log4j-core jar found, we can mark capability as unknown (not blocked) unless you want a separate "absent" model.
    if log4j_core:
        if jndi_lookup:
            status = "realized"
            pointer = f"jar://{jndi_lookup[0]}"
            conf = 0.75
        else:
            status = "unknown"
            pointer = f"jar://{log4j_core[0]}"
            conf = 0.55
        emit(outp, "obs.attack.precondition", "adapter.config_effective",
             {"attack_path_id": args.attack_path_id, "wicket_id": "AP-L10", "status": status, "observed_at": iso_now(),
              "notes":"Heuristic from artifact jar scan (not runtime)."},
             evidence_rank=2, source_kind="jar_scan", pointer=pointer, confidence=conf, run_id=rid, workload_id=wid)
    else:
        emit(outp, "obs.attack.precondition", "adapter.config_effective",
             {"attack_path_id": args.attack_path_id, "wicket_id": "AP-L10", "status": "unknown", "observed_at": iso_now(),
              "notes":"No log4j-core jar observed under root; treat as unknown unless runtime evidence corroborates absence."},
             evidence_rank=2, source_kind="jar_scan", pointer=f"fs://{root}", confidence=0.4, run_id=rid, workload_id=wid)

    # AP-L11 (lookups enabled) from config files
    cfgs = list(find_configs(root))
    if not cfgs:
        emit(outp, "obs.attack.precondition", "adapter.config_effective",
             {"attack_path_id": args.attack_path_id, "wicket_id": "AP-L11", "status": "unknown", "observed_at": iso_now(),
              "notes":"No log4j2 config files found under root."},
             evidence_rank=3, source_kind="config_scan", pointer=f"fs://{root}", confidence=0.45, run_id=rid, workload_id=wid)
        return 0

    # If any config suggests lookup patterns, mark realized; otherwise unknown.
    realized = False
    used = None
    for c in cfgs:
        try:
            txt = c.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if config_suggests_lookups_enabled(txt):
            realized = True
            used = c
            break

    if realized and used:
        emit(outp, "obs.attack.precondition", "adapter.config_effective",
             {"attack_path_id": args.attack_path_id, "wicket_id": "AP-L11", "status": "realized", "observed_at": iso_now(),
              "notes":"Config contains lookup-style patterns; confirm with runtime effective config if available.",
              "attributes":{"config_file": str(used)}},
             evidence_rank=3, source_kind="config_file", pointer=f"file://{used}", confidence=0.7, run_id=rid, workload_id=wid)
    else:
        emit(outp, "obs.attack.precondition", "adapter.config_effective",
             {"attack_path_id": args.attack_path_id, "wicket_id": "AP-L11", "status": "unknown", "observed_at": iso_now(),
              "notes":"Config files found but no lookup indicators detected (heuristic).",
              "attributes":{"config_files":[str(x) for x in cfgs[:20]]}},
             evidence_rank=3, source_kind="config_scan", pointer=f"fs://{root}", confidence=0.55, run_id=rid, workload_id=wid)


    # AP-L18 / AP-L19 (MITM posture) - default unknown unless evidence indicates weak auth / no pinning.
    # This adapter is filesystem-focused; network/TLS posture is better asserted by net_sandbox adapter.
    emit(outp, "obs.attack.precondition", "adapter.config_effective",
         {"attack_path_id": args.attack_path_id, "wicket_id": "AP-L18", "status": "unknown", "observed_at": iso_now(),
          "notes":"MITM posture not assessed by filesystem scan; provide network/TLS evidence for AP-L18."},
         evidence_rank=4, source_kind="config_scan", pointer=f"fs://{root}", confidence=0.4, run_id=rid, workload_id=wid)

    emit(outp, "obs.attack.precondition", "adapter.config_effective",
         {"attack_path_id": args.attack_path_id, "wicket_id": "AP-L19", "status": "unknown", "observed_at": iso_now(),
          "notes":"Cert pinning / proxy interception not assessed; provide client/proxy config evidence for AP-L19."},
         evidence_rank=3, source_kind="config_scan", pointer=f"fs://{root}", confidence=0.4, run_id=rid, workload_id=wid)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

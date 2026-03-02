#!/usr/bin/env python3
import argparse, json, re
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

def load_inspect(path: Path):
    obj = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(obj, list) and obj:
        return obj[0]
    if isinstance(obj, dict):
        return obj
    raise ValueError("Unsupported docker inspect JSON shape")

def infer_egress_from_iptables(iptables_text: str):
    out_policy = None
    fwd_policy = None
    docker0_accept = False

    for line in iptables_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("-P OUTPUT"):
            parts = line.split()
            if len(parts) >= 3:
                out_policy = parts[2]
        if line.startswith("-P FORWARD"):
            parts = line.split()
            if len(parts) >= 3:
                fwd_policy = parts[2]
        if ("-i docker0" in line) and ("-j ACCEPT" in line) and (line.startswith("-A DOCKER-FORWARD") or line.startswith("-A FORWARD")):
            docker0_accept = True

    if out_policy in ("DROP", "REJECT") and not docker0_accept:
        return "blocked", {"output_policy": out_policy, "forward_policy": fwd_policy, "docker0_accept": docker0_accept,
                           "notes": "Host OUTPUT policy is restrictive and no docker0 allow rule found."}, 0.65
    if out_policy == "ACCEPT" and docker0_accept:
        return "realized", {"output_policy": out_policy, "forward_policy": fwd_policy, "docker0_accept": docker0_accept,
                            "notes": "Host OUTPUT ACCEPT and docker0 forwarding ACCEPT rule found; egress likely permitted for containers."}, 0.65
    return "unknown", {"output_policy": out_policy, "forward_policy": fwd_policy, "docker0_accept": docker0_accept,
                       "notes": "Cannot confidently infer egress from provided iptables rules."}, 0.4

def infer_runtime_load_from_ps(ps_text: str):
    has_jvm = False
    has_log4j_prop = False
    props = []
    for line in ps_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if ("openjdk" in line) or ("/bin/java" in line) or (" java " in (" " + line + " ")):
            has_jvm = True
        if "-Dlog4j." in line or "-Dlog4j2." in line:
            has_log4j_prop = True
            for m in re.findall(r"(-Dlog4j[^\s]+|-Dlog4j2[^\s]+)", line):
                props.append(m)
    props = sorted(set(props))
    if has_jvm and has_log4j_prop:
        return "realized", {"jvm": True, "log4j_props": props[:25], "notes":"Runtime JVM process includes log4j system properties; indicates active logging subsystem."}, 0.6
    if has_jvm:
        return "unknown", {"jvm": True, "log4j_props": props[:25], "notes":"JVM present but no log4j system properties observed in provided ps output."}, 0.45
    return "unknown", {"jvm": False, "log4j_props": [], "notes":"No JVM process line found in provided ps output."}, 0.35

def infer_exposure(inspect):
    ports = (inspect.get("NetworkSettings") or {}).get("Ports") or {}
    published = []
    for cport, bindings in ports.items():
        if bindings:
            for b in bindings:
                published.append({"container_port": cport, "host_ip": b.get("HostIp"), "host_port": b.get("HostPort")})
    if published:
        return "realized", {"published_ports": published}
    return "unknown", {"published_ports": []}

def infer_dns(inspect, root: Path|None, resolv_conf_path: Path|None):
    # AP-L12: DNS capability/configured. Prefer explicit resolv_conf_path (captured from container),
    # then rootfs /etc/resolv.conf, then fall back to inspect ResolvConfPath (weak).
    conf = None
    pointer = None

    if resolv_conf_path is not None and resolv_conf_path.exists():
        conf = resolv_conf_path.read_text(encoding="utf-8", errors="ignore")
        pointer = f"file://{resolv_conf_path}"

    if conf is None and root is not None:
        cand = root.joinpath("etc/resolv.conf")
        if cand.exists():
            conf = cand.read_text(encoding="utf-8", errors="ignore")
            pointer = f"file://{cand}"

    if conf is None:
        rcp = inspect.get("ResolvConfPath")
        if rcp:
            return "unknown", {"notes":"ResolvConfPath present but not read; provide --resolv-conf (captured) or rootfs /etc/resolv.conf for stronger evidence."}, f"hostfile://{rcp}", 0.4
        return "unknown", {"notes":"No resolv.conf evidence found."}, "inspect://ResolvConfPath", 0.3

    nameservers = []
    for line in conf.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                nameservers.append(parts[1])

    if nameservers:
        return "realized", {"nameservers": nameservers}, pointer, 0.7
    return "unknown", {"nameservers": [], "notes":"resolv.conf found but contained no nameserver lines."}, pointer, 0.55

def infer_egress(inspect, iptables_path: Path|None):
    # AP-L7: egress posture. Prefer host iptables evidence if provided; else conservative from NetworkMode.
    if iptables_path is not None and iptables_path.exists():
        rules = iptables_path.read_text(encoding="utf-8", errors="ignore")
        st, attrs, conf = infer_egress_from_iptables(rules)
        return st, attrs, f"file://{iptables_path}", conf

    hostcfg = inspect.get("HostConfig") or {}
    mode = hostcfg.get("NetworkMode")
    if mode == "none":
        return "blocked", {"network_mode":"none"}, "inspect://HostConfig.NetworkMode", 0.6
    return "unknown", {"network_mode": mode or "unknown", "notes":"Egress policy not derivable from inspect alone; pass --iptables for stronger evidence."}, "inspect://HostConfig.NetworkMode", 0.35

def infer_proxy_mitm(inspect):
    env = (inspect.get("Config") or {}).get("Env") or []
    envmap = {}
    for kv in env:
        if "=" in kv:
            k,v = kv.split("=",1)
            envmap[k]=v
    proxy_keys = [k for k in envmap.keys() if k.upper() in ("HTTP_PROXY","HTTPS_PROXY","NO_PROXY")]
    if proxy_keys:
        return "realized", {"proxy_env": {k: envmap.get(k) for k in proxy_keys}}, 0.6
    return "unknown", {"proxy_env": {}}, 0.4

def infer_endpoint_auth(_inspect):
    return "unknown", {"notes":"TLS validation/pinning not derivable from inspect; require app/client TLS config evidence."}, 0.4

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--docker-inspect", required=True, help="Path to docker inspect JSON (single container)")
    ap.add_argument("--out", required=True, help="Output NDJSON events file (append)")
    ap.add_argument("--attack-path-id", default="log4j_jndi_rce_v1")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--workload-id", default=None)
    ap.add_argument("--root", default=None, help="Optional rootfs snapshot for reading /etc/resolv.conf, etc.")
    ap.add_argument("--resolv-conf", default=None, help="Optional path to captured /etc/resolv.conf (preferred over rootfs)")
    ap.add_argument("--iptables", default=None, help="Optional path to host iptables rules output (e.g., `iptables -S`)")
    ap.add_argument("--ps", default=None, help="Optional path to captured process list/cmdline evidence for runtime load (e.g., `ps -ef` output)")
    args = ap.parse_args()

    rid = args.run_id or str(uuid.uuid4())
    wid = args.workload_id

    outp = Path(args.out).expanduser().resolve()
    insp_path = Path(args.docker_inspect).expanduser().resolve()
    inspect = load_inspect(insp_path)

    root = Path(args.root).expanduser().resolve() if args.root else None
    resolv_conf = Path(args.resolv_conf).expanduser().resolve() if args.resolv_conf else None
    iptables_path = Path(args.iptables).expanduser().resolve() if args.iptables else None
    ps_path = Path(args.ps).expanduser().resolve() if args.ps else None

    # AP-L9: exposure
    st9, attrs9 = infer_exposure(inspect)
    emit(outp, "obs.attack.precondition", "adapter.net_sandbox",
         {"attack_path_id": args.attack_path_id, "wicket_id":"AP-L9", "status": st9, "observed_at": iso_now(),
          "notes":"Exposure class inferred from published ports in docker inspect.", "attributes": attrs9},
         evidence_rank=2, source_kind="docker_inspect", pointer=f"file://{insp_path}",
         confidence=0.75 if st9=="realized" else 0.55, run_id=rid, workload_id=wid)

    # AP-L4: runtime load (optional)
    if ps_path is not None and ps_path.exists():
        ps_text = ps_path.read_text(encoding="utf-8", errors="ignore")
        st4, attrs4, conf4 = infer_runtime_load_from_ps(ps_text)
        emit(outp, "obs.attack.precondition", "adapter.net_sandbox",
             {"attack_path_id": args.attack_path_id, "wicket_id":"AP-L4", "status": st4, "observed_at": iso_now(),
              "notes":"Runtime load inferred from process list evidence.", "attributes": attrs4},
             evidence_rank=3, source_kind="process_list", pointer=f"file://{ps_path}",
             confidence=conf4, run_id=rid, workload_id=wid)

    # AP-L12: DNS capability
    st12, attrs12, ptr12, conf12 = infer_dns(inspect, root, resolv_conf)
    emit(outp, "obs.attack.precondition", "adapter.net_sandbox",
         {"attack_path_id": args.attack_path_id, "wicket_id":"AP-L12", "status": st12, "observed_at": iso_now(),
          "notes":"DNS capability inferred from resolv.conf evidence.", "attributes": attrs12},
         evidence_rank=3, source_kind="dns_config", pointer=ptr12,
         confidence=conf12, run_id=rid, workload_id=wid)

    # AP-L7: egress posture
    st7, attrs7, ptr7, conf7 = infer_egress(inspect, iptables_path)
    emit(outp, "obs.attack.precondition", "adapter.net_sandbox",
         {"attack_path_id": args.attack_path_id, "wicket_id":"AP-L7", "status": st7, "observed_at": iso_now(),
          "notes":"Egress posture inferred from firewall/policy evidence when provided.", "attributes": attrs7},
         evidence_rank=3, source_kind="egress_policy", pointer=ptr7,
         confidence=conf7, run_id=rid, workload_id=wid)

    # AP-L19: proxy-based MITM
    st19, attrs19, conf19 = infer_proxy_mitm(inspect)
    emit(outp, "obs.attack.precondition", "adapter.net_sandbox",
         {"attack_path_id": args.attack_path_id, "wicket_id":"AP-L19", "status": st19, "observed_at": iso_now(),
          "notes":"Proxy env vars imply interception path; absence does not prove no MITM.", "attributes": attrs19},
         evidence_rank=3, source_kind="docker_inspect_env", pointer=f"file://{insp_path}",
         confidence=conf19, run_id=rid, workload_id=wid)

    # AP-L18: endpoint auth strength (still unknown in this adapter)
    st18, attrs18, conf18 = infer_endpoint_auth(inspect)
    emit(outp, "obs.attack.precondition", "adapter.net_sandbox",
         {"attack_path_id": args.attack_path_id, "wicket_id":"AP-L18", "status": st18, "observed_at": iso_now(),
          "notes":"Endpoint auth strength not assessed; require app/client TLS config evidence.", "attributes": attrs18},
         evidence_rank=4, source_kind="insufficient_evidence", pointer=f"file://{insp_path}",
         confidence=conf18, run_id=rid, workload_id=wid)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

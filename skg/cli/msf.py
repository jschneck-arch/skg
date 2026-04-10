from __future__ import annotations

import json
import uuid
from pathlib import Path

from skg.assistant.action_proposals import create_msf_action_proposal
from skg.cli.utils import DISCOVERY_DIR, _latest_surface
from skg.forge.proposals import interactive_review


def find_web_port(target_ip: str) -> int:
    surface_path = _latest_surface()
    if not surface_path:
        return 80
    try:
        surface = json.loads(Path(surface_path).read_text())
    except Exception:
        return 80
    for target in surface.get("targets", []):
        if target.get("ip") != target_ip:
            continue
        for service in target.get("services", []):
            if service.get("service") in {"http", "https", "http-alt", "https-alt"}:
                try:
                    return int(service.get("port", 80))
                except Exception:
                    return 80
    return 80


def target_ports(target_ip: str) -> list[int]:
    surface_path = _latest_surface()
    if not surface_path:
        return []
    try:
        surface = json.loads(Path(surface_path).read_text())
    except Exception:
        return []
    for target in surface.get("targets", []):
        if target.get("ip") != target_ip:
            continue
        ports: list[int] = []
        for service in target.get("services", []):
            try:
                ports.append(int(service.get("port")))
            except Exception:
                continue
        return sorted(set(ports))
    return []


def queue_msf_observation_proposal(target_ip: str, *, source: str) -> None:
    out_dir = DISCOVERY_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    port = find_web_port(target_ip)
    if not port:
        print(f"  No web port found for {target_ip}")
        return

    run_id = str(uuid.uuid4())[:8]
    rc_lines = [
        f"setg RHOSTS {target_ip}",
        f"setg RPORT {port}",
        "setg THREADS 4",
        "",
        "# SQL injection scanner",
        "use auxiliary/scanner/http/sql_injection",
        f"set RHOSTS {target_ip}",
        f"set RPORT {port}",
        "set TARGETURI /",
        "run",
        "",
        "# Directory scanner",
        "use auxiliary/scanner/http/dir_scanner",
        f"set RHOSTS {target_ip}",
        f"set RPORT {port}",
        "run",
        "",
        "exit",
    ]

    proposal, artifact = create_msf_action_proposal(
        contract_name="msf_rc",
        rc_text="\n".join(rc_lines) + "\n",
        filename_hint=f"observe_msf_{target_ip}_{run_id}.rc",
        out_dir=out_dir,
        domain="web",
        description=f"Metasploit follow-on observation for {target_ip}:{port}",
        attack_surface=f"{target_ip}:{port}",
        hosts=[target_ip],
        category="runtime_observation",
        evidence=f"Operator requested MSF follow-on observation for {target_ip}:{port}",
        action={
            "instrument": "msf",
            "target_ip": target_ip,
            "port": port,
            "module_candidates": [
                {
                    "module": "auxiliary/scanner/http/sql_injection",
                    "confidence": 0.80,
                    "module_class": "auxiliary",
                },
                {
                    "module": "auxiliary/scanner/http/dir_scanner",
                    "confidence": 0.60,
                    "module_class": "auxiliary",
                },
            ],
        },
        notes=["Operator-requested follow-on observation RC."],
        metadata={"source": source},
    )

    print(f"  [MSF] Proposal queued: {proposal['id']}")
    print(f"  [MSF] RC script: {artifact['path']}")
    print(f"  [MSF] Trigger after approval: skg proposals trigger {proposal['id']}")

    review = interactive_review(proposal["id"])
    if review.get("decision") == "approved":
        print(f"  [MSF] Approved interactively: {proposal['id']}")
    elif review.get("decision") == "rejected":
        print(f"  [MSF] Rejected interactively: {proposal['id']}")
    elif review.get("decision") == "deferred":
        print(f"  [MSF] Deferred interactively: {proposal['id']}")

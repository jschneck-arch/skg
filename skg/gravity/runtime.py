from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from skg.assistant.action_proposals import create_msf_action_proposal
from skg_core.config.paths import EVENTS_DIR, SKG_STATE_DIR
from skg.identity import parse_workload_ref

from .failures import GravityFailureReporter


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _save_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2))


def _subject_aliases(*values: str) -> set[str]:
    aliases: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        aliases.add(text)
        parsed = parse_workload_ref(text)
        for candidate in (
            parsed.get("identity_key"),
            parsed.get("host"),
            parsed.get("locator"),
            parsed.get("manifestation_key"),
        ):
            candidate_text = str(candidate or "").strip()
            if candidate_text:
                aliases.add(candidate_text)
    return aliases


def _proposal_identity_key(proposal: dict[str, Any], action: dict[str, Any]) -> str:
    for candidate in (
        action.get("identity_key"),
        proposal.get("identity_key"),
        action.get("workload_id"),
        action.get("execution_target"),
        action.get("target_ip"),
        *(proposal.get("hosts") or []),
    ):
        identity_key = str(parse_workload_ref(str(candidate or "")).get("identity_key") or "").strip()
        if identity_key:
            return identity_key
    return ""


def _execution_target(proposal: dict[str, Any], action: dict[str, Any]) -> str:
    for candidate in (
        action.get("execution_target"),
        action.get("target_ip"),
        proposal.get("attack_surface"),
        _proposal_identity_key(proposal, action),
    ):
        parsed = parse_workload_ref(str(candidate or ""))
        target = str(parsed.get("host") or parsed.get("identity_key") or candidate or "").strip()
        if target:
            return target
    return ""


def _safe_subject_label(value: str) -> str:
    text = str(value or "").strip() or "subject"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text)


def emit_follow_on_proposals(
    *,
    concurrent_results: dict[str, dict[str, Any]],
    ip: str,
    node_key: str = "",
    out_path: Path,
    run_id: str,
    load_wicket_states: Callable[[str], dict[str, Any]],
    generate_exploit_proposals: Callable[..., list[dict[str, Any]]],
    get_lhost: Callable[[], str],
    interactive_review: Callable[[str], dict[str, Any]] | None = None,
    proposals_dir: Path | None = None,
    print_fn: Callable[[str], None] = print,
    reporter: GravityFailureReporter | None = None,
) -> list[dict[str, Any]]:
    proposals_dir = proposals_dir or (SKG_STATE_DIR / "proposals")
    # node_key is the stable identity anchor (identity_key). Falls back to ip for
    # hosts that have no workload-id differentiation.
    _node_key = node_key or ip
    generated: list[dict[str, Any]] = []

    for result in concurrent_results.values():
        for follow_on in result.get("follow_on_paths", []) or []:
            path_id = str(follow_on.get("path_id") or "").strip()
            if not path_id:
                continue
            try:
                refreshed_states = load_wicket_states(_node_key)
                realized = [
                    wid for wid, state in refreshed_states.items()
                    if isinstance(state, dict) and state.get("status") == "realized"
                ]
                already_pending = None
                if proposals_dir.exists():
                    for proposal_path in proposals_dir.glob("*.json"):
                        proposal = _load_json(proposal_path)
                        if not proposal:
                            continue
                        if (
                            proposal.get("status") == "pending"
                            and (
                                ip in json.dumps(proposal)
                                or ip in proposal.get("description", "")
                                or ip in json.dumps(proposal.get("hosts", []))
                            )
                            and path_id in json.dumps(proposal)
                        ):
                            already_pending = proposal
                            break
                if already_pending:
                    existing_id = already_pending.get("id", "")[:12]
                    print_fn(f"    [EXPLOIT] Pending proposal already exists for {path_id} on {ip}: {existing_id}")
                    existing_desc = already_pending.get("description", "")
                    if existing_desc:
                        print_fn(f"      {existing_desc[:100]}")
                    if interactive_review is not None and sys.stdin.isatty():
                        review = interactive_review(already_pending.get("id", ""))
                        decision = review.get("decision")
                        if decision and decision != "skipped":
                            print_fn(f"    [EXPLOIT] Reviewed existing proposal {existing_id}: {decision}")
                    continue

                props = generate_exploit_proposals(
                    path_id=path_id,
                    target_ip=ip,
                    identity_key=str(parse_workload_ref(ip).get("identity_key") or ip).strip(),
                    port=follow_on.get("port", 0),
                    realized_wickets=realized,
                    lhost=get_lhost(),
                    out_dir=out_path,
                    **(follow_on.get("kwargs", {})),
                )
                if props:
                    generated.extend(props)
                    print_fn(f"    [EXPLOIT] {len(props)} proposal(s) generated for {path_id}")
            except Exception as exc:
                if reporter is not None:
                    reporter.emit(
                        "follow_on_proposals",
                        f"follow-on proposal generation failed for {path_id}",
                        target_ip=ip,
                        exc=exc,
                        context={"path_id": path_id},
                    )
                else:
                    raise
    return generated


def emit_auxiliary_proposals(
    *,
    ip: str,
    node_key: str = "",
    target: dict[str, Any],
    run_id: str,
    out_path: Path,
    auxiliary_map: dict[str, list[dict[str, Any]]],
    lhost: str,
    load_wicket_states: Callable[[str], dict[str, Any]],
    proposals_dir: Path | None = None,
    print_fn: Callable[[str], None] = print,
    reporter: GravityFailureReporter | None = None,
) -> list[dict[str, Any]]:
    proposals_dir = proposals_dir or (SKG_STATE_DIR / "proposals")
    created: list[dict[str, Any]] = []
    _node_key = node_key or ip

    refreshed_states = load_wicket_states(_node_key)
    realized_set = {
        wid for wid, state in refreshed_states.items()
        if isinstance(state, dict) and state.get("status") == "realized"
    }

    for aux_path, candidates in auxiliary_map.items():
        for candidate in candidates:
            req = set(candidate.get("requires", []))
            if not req.issubset(realized_set):
                continue
            try:
                duplicate = False
                if proposals_dir.exists():
                    for proposal_path in proposals_dir.glob("*.json"):
                        proposal = _load_json(proposal_path)
                        if not proposal:
                            continue
                        if (
                            proposal.get("status") == "pending"
                            and ip in json.dumps(proposal)
                            and aux_path in json.dumps(proposal)
                        ):
                            duplicate = True
                            break
                if duplicate:
                    break

                identity_key = str(
                    target.get("identity_key")
                    or parse_workload_ref(ip).get("identity_key")
                    or ip
                ).strip()
                port_text = str(candidate.get("options", {}).get("RPORT", "0"))
                try:
                    port = int(port_text)
                except Exception:
                    port = 0
                options = {
                    key: value.replace("{target_ip}", ip).replace("{lhost}", lhost).replace("{port}", str(port))
                    for key, value in candidate.get("options", {}).items()
                }
                rc_lines = [
                    f"# SKG auxiliary — {aux_path}",
                    f"# Target: {ip}:{port}",
                    f"use {candidate['module']}",
                ]
                for key, value in options.items():
                    rc_lines.append(f"set {key} {value}")
                rc_lines += ["run", "", "exit"]

                proposal, _artifact = create_msf_action_proposal(
                    contract_name="msf_rc",
                    rc_text="\n".join(rc_lines) + "\n",
                    filename_hint=f"aux_{aux_path}_{ip.replace('.','_')}_{run_id[:8]}.rc",
                    out_dir=out_path,
                    domain=aux_path.split("_")[0],
                    description=f"{candidate['module']} against {ip}:{port} — {candidate.get('notes', '')}",
                    attack_surface=f"{ip}:{port}",
                    hosts=[ip],
                    category="runtime_observation",
                    evidence=f"Aux path {aux_path}: requires {sorted(req)} all realized.",
                    action={
                        "instrument": "msf",
                        "module": candidate["module"],
                        "module_class": candidate.get("class", "auxiliary"),
                        "identity_key": identity_key or ip,
                        "execution_target": ip,
                        "target_ip": ip,
                        "port": port,
                        "options": options,
                        "confidence": candidate.get("confidence", 0.70),
                    },
                    notes=["Validated auxiliary MSF RC generated from realized preconditions."],
                    metadata={"source": "skg.gravity.runtime.emit_auxiliary_proposals", "aux_path": aux_path},
                    command_prefix="msfconsole -q -r",
                )
                created.append(proposal)
                print_fn(f"    [AUX] Proposed {candidate['module']} for {ip} ({aux_path})")
                break
            except Exception as exc:
                if reporter is not None:
                    reporter.emit(
                        "auxiliary_proposals",
                        f"auxiliary proposal generation failed for {aux_path}",
                        target_ip=ip,
                        exc=exc,
                        context={"aux_path": aux_path, "module": candidate.get("module", "")},
                    )
                else:
                    raise
    return created


def execute_triggered_proposals(
    *,
    out_path: Path,
    run_id: str,
    focus_target: str | None = None,
    proposals_dir: Path | None = None,
    print_fn: Callable[[str], None] = print,
    reporter: GravityFailureReporter | None = None,
) -> list[dict[str, Any]]:
    proposals_dir = proposals_dir or (SKG_STATE_DIR / "proposals")
    executed: list[dict[str, Any]] = []
    if not proposals_dir.exists():
        return executed

    for proposal_path in sorted(proposals_dir.glob("*.json")):
        try:
            proposal = _load_json(proposal_path)
            if not proposal or proposal.get("status") != "triggered":
                continue
            action = proposal.get("action", {})
            rc_file = action.get("rc_file", "") or proposal.get("rc_file", "")
            identity_key = _proposal_identity_key(proposal, action)
            execution_target = _execution_target(proposal, action) or "?"
            target_ip = str(action.get("target_ip") or "").strip()
            proposal_id = proposal.get("id", "?")[:12]
            if focus_target and focus_target not in _subject_aliases(
                focus_target,
                identity_key,
                execution_target,
                target_ip,
            ):
                continue

            module_candidates = action.get("module_candidates", [])
            all_aux = bool(module_candidates) and all(
                candidate.get("module_class", "").lower() == "auxiliary"
                for candidate in module_candidates
            )
            module = action.get("module", "")
            is_exploit_module = module.startswith("exploit/") and module != "exploit/multi/handler"
            sync_exec = ((proposal.get("category") == "runtime_observation" or all_aux) and not is_exploit_module)

            print_fn(f"  [AUTO-EXEC] Triggered proposal {proposal_id} for {execution_target}")
            if not rc_file or not Path(rc_file).exists():
                if proposal.get("proposal_kind") == "field_action":
                    proposal["status"] = "error_missing_rc"
                    proposal["error"] = f"RC file missing: {rc_file}"
                    _save_json(proposal_path, proposal)
                    if reporter is not None:
                        reporter.emit(
                            "triggered_proposals",
                            "RC file missing for triggered field action",
                            target_ip=target_ip or execution_target,
                            context={"proposal_id": proposal.get("id", ""), "rc_file": rc_file},
                        )
                continue

            msf = subprocess.run(["which", "msfconsole"], capture_output=True)
            if msf.returncode != 0:
                if reporter is not None:
                    reporter.emit(
                        "triggered_proposals",
                        "msfconsole not found for triggered proposal execution",
                        target_ip=target_ip or execution_target,
                        context={"proposal_id": proposal.get("id", ""), "rc_file": rc_file},
                    )
                print_fn("    msfconsole not found — cannot auto-execute")
                continue

            log_path = out_path / f"msf_auto_{proposal_id}_{run_id[:8]}.log"
            if sync_exec:
                run = subprocess.run(
                    ["msfconsole", "-q", "-r", rc_file],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                log_path.write_text((run.stdout or "") + (run.stderr or ""))
                print_fn(f"    msfconsole completed log={log_path}")
                try:
                    from skg.sensors.msf_sensor import _parse_console_output, summarize_console_output

                    module_name = module_candidates[0].get("module") if module_candidates else "resource_script"
                    workload_anchor = identity_key or execution_target
                    workload_id = f"{proposal.get('domain', 'web')}::{workload_anchor}"
                    events = _parse_console_output(run.stdout or "", workload_id, module_name)
                    summary = summarize_console_output(run.stdout or "")
                    if events:
                        events_file = out_path / f"msf_events_{_safe_subject_label(workload_anchor)}_{run_id[:8]}.ndjson"
                        with events_file.open("w", encoding="utf-8") as fh:
                            for event in events:
                                payload = event.setdefault("payload", {})
                                if target_ip:
                                    payload["target_ip"] = target_ip
                                if identity_key:
                                    payload["identity_key"] = identity_key
                                fh.write(json.dumps(event) + "\n")
                        EVENTS_DIR.mkdir(parents=True, exist_ok=True)
                        (EVENTS_DIR / events_file.name).write_text(events_file.read_text())
                        print_fn(f"    ingested {len(events)} MSF events -> {events_file.name}")
                        proposal["events_file"] = str(events_file)
                        proposal["events_emitted"] = len(events)
                    if summary.get("findings"):
                        print_fn(f"    findings: {', '.join(summary['findings'][:5])}")
                    if summary.get("errors"):
                        print_fn(f"    parser notes: {', '.join(summary['errors'][:3])}")
                    proposal["msf_summary"] = summary
                except Exception as exc:
                    proposal["ingest_error"] = str(exc)
                    if reporter is not None:
                        reporter.emit(
                            "triggered_proposals_ingest",
                            "MSF output ingestion failed after triggered execution",
                            target_ip=target_ip or execution_target,
                            exc=exc,
                            context={"proposal_id": proposal.get("id", "")},
                        )
                proposal["status"] = "executed"
                proposal["log_file"] = str(log_path)
                proposal["returncode"] = run.returncode
                _save_json(proposal_path, proposal)
                executed.append(proposal)
                continue

            with log_path.open("w", encoding="utf-8") as log_fh:
                proc = subprocess.Popen(
                    ["msfconsole", "-q", "-r", rc_file],
                    stdin=subprocess.DEVNULL,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                    close_fds=True,
                )
            print_fn(f"    msfconsole PID={proc.pid} log={log_path}")
            proposal["status"] = "auto_executed"
            proposal["pid"] = proc.pid
            proposal["log_file"] = str(log_path)
            _save_json(proposal_path, proposal)
            executed.append(proposal)
        except Exception as exc:
            if reporter is not None:
                reporter.emit(
                    "triggered_proposals",
                    "unexpected error while executing triggered proposal",
                    exc=exc,
                    context={"proposal_path": str(proposal_path)},
                )
            else:
                raise
    return executed

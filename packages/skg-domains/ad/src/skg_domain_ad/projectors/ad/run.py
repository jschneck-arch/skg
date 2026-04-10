from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from skg_core.substrate.node import NodeState, TriState
from skg_core.substrate.path import Path as AttackPath
from skg_core.substrate.projection import project_path

from skg_domain_ad.ontology import load_attack_paths
from skg_domain_ad.policies import load_projection_policy


SOURCE_ID = "projection.ad.domain_pack"
TOOLCHAIN = "ad"
VERSION = "1.0.0"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _attack_path_definition(catalog: Mapping[str, Any] | None, attack_path_id: str) -> tuple[str, dict[str, Any]]:
    if isinstance(catalog, Mapping):
        attack_paths = catalog.get("attack_paths")
        if isinstance(attack_paths, Mapping):
            path = attack_paths.get(attack_path_id)
            if isinstance(path, Mapping):
                return attack_path_id, dict(path)

    attack_paths = load_attack_paths()
    path = attack_paths.get(attack_path_id)
    if isinstance(path, Mapping):
        return attack_path_id, dict(path)

    return attack_path_id, {}


def _status_from_payload(payload: Mapping[str, Any]) -> str:
    status = str(payload.get("status") or "").strip().lower()
    if status:
        if status == "not_realized":
            return "blocked"
        return status

    realized = payload.get("realized")
    if realized is True:
        return "realized"
    if realized is False:
        return "blocked"
    return "unknown"


def _tri_state(status: str) -> TriState:
    if status == "realized":
        return TriState.REALIZED
    if status in {"blocked", "not_realized"}:
        return TriState.BLOCKED
    return TriState.UNKNOWN


def _priority(status: str) -> int:
    policy = load_projection_policy()
    table = policy.get("status_priority") if isinstance(policy, Mapping) else {}
    if isinstance(table, Mapping):
        return int(table.get(status, 0) or 0)
    return 0


def _latest_wicket_states(events: Iterable[Mapping[str, Any]], required: list[str]) -> dict[str, NodeState]:
    latest: dict[str, tuple[str, int, Mapping[str, Any]]] = {}

    for event in events:
        if not isinstance(event, Mapping):
            continue
        if str(event.get("type") or "") != "obs.attack.precondition":
            continue

        payload = event.get("payload")
        if not isinstance(payload, Mapping):
            continue

        wicket_id = str(payload.get("wicket_id") or payload.get("node_id") or "").strip()
        if wicket_id not in required:
            continue

        ts = str(event.get("ts") or "")
        status = _status_from_payload(payload)
        prio = _priority(status)

        current = latest.get(wicket_id)
        if current is None or ts > current[0] or (ts == current[0] and prio > current[1]):
            latest[wicket_id] = (ts, prio, event)

    states: dict[str, NodeState] = {}
    for wicket_id in required:
        row = latest.get(wicket_id)
        if row is None:
            states[wicket_id] = NodeState.unknown(wicket_id)
            continue

        event = row[2]
        payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else {}
        provenance = event.get("provenance") if isinstance(event.get("provenance"), Mapping) else {}
        evidence = provenance.get("evidence") if isinstance(provenance.get("evidence"), Mapping) else {}

        status = _status_from_payload(payload)
        observed_at = str(event.get("ts") or _iso_now())

        states[wicket_id] = NodeState(
            node_id=wicket_id,
            state=_tri_state(status),
            confidence=float(evidence.get("confidence") or 0.5),
            observed_at=observed_at,
            source_kind=str(evidence.get("source_kind") or ""),
            pointer=str(evidence.get("pointer") or ""),
            notes=str(payload.get("detail") or ""),
            attributes={
                "status": status,
                "unresolved_reason": "not_observed" if status == "unknown" else "",
            },
        )

    return states


def compute_ad(
    events: list[dict[str, Any]],
    catalog: dict[str, Any],
    attack_path_id: str,
    run_id: str | None = None,
    workload_id: str | None = None,
) -> dict[str, Any]:
    canonical_attack_path_id, attack_path = _attack_path_definition(catalog, attack_path_id)
    required = list(attack_path.get("required_wickets") or [])
    if not required:
        return {}

    states = _latest_wicket_states(events, required)
    score = project_path(
        AttackPath(
            path_id=canonical_attack_path_id,
            required_nodes=required,
            domain="ad",
            description=str(attack_path.get("description") or ""),
        ),
        states,
        workload_id=workload_id or "unknown",
        run_id=run_id or str(uuid.uuid4()),
    )

    score_key = str((load_projection_policy().get("score_key") or "ad_score"))

    return {
        "id": str(uuid.uuid4()),
        "ts": _iso_now(),
        "type": "interp.attack.path",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": VERSION,
        },
        "payload": {
            "attack_path_id": attack_path_id,
            "canonical_attack_path_id": canonical_attack_path_id,
            "workload_id": workload_id or "unknown",
            "run_id": run_id or "unknown",
            "classification": score.classification,
            score_key: round(score.score, 4),
            "required_wickets": required,
            "realized": score.realized,
            "blocked": score.blocked,
            "unknown": score.unknown,
            "latest_status": score.latest_status,
            "unresolved_detail": score.unresolved_detail,
            "computed_at": score.computed_at,
        },
    }


def project_events_to_artifact(
    events: list[dict[str, Any]],
    *,
    attack_path_id: str,
    out_path: Path,
    run_id: str,
    workload_id: str,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = compute_ad(
        events,
        catalog or {},
        attack_path_id,
        run_id=run_id,
        workload_id=workload_id,
    )
    if not result:
        return {}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _read_events(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="AD domain projector")
    parser.add_argument("--in", dest="in_file", required=True)
    parser.add_argument("--out", dest="out_file", required=True)
    parser.add_argument("--attack-path-id", required=True)
    parser.add_argument("--run-id", default="")
    parser.add_argument("--workload-id", default="")

    args = parser.parse_args()
    in_file = Path(args.in_file)
    out_file = Path(args.out_file)

    result = project_events_to_artifact(
        _read_events(in_file),
        attack_path_id=args.attack_path_id,
        out_path=out_file,
        run_id=args.run_id or str(uuid.uuid4()),
        workload_id=args.workload_id or "unknown",
    )

    if not result:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import difflib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml

from skg_core.config.paths import DELTA_DIR, SKG_CONFIG_DIR, SKG_HOME
from skg_registry import DomainRegistry as _CanonicalDomainRegistry


DEFAULT_INTER_LOCAL: dict[tuple[str, str], float] = {
    ("host", "host"): 0.80,
    ("host", "smb"): 0.80,
    ("smb", "vuln"): 0.90,
    ("host", "vuln"): 0.85,
    ("credential", "host"): 0.95,
    ("credential", "ssh"): 0.95,
    ("credential", "web"): 0.80,
    ("web", "data"): 0.85,
    ("web", "data_pipeline"): 0.85,
    ("web", "cmdi"): 0.90,
    ("cmdi", "shell"): 0.90,
    ("host", "data"): 0.70,
    ("host", "data_pipeline"): 0.70,
    ("container", "host"): 0.85,
    ("container_escape", "host"): 0.85,
    ("host", "container"): 0.60,
    ("host", "container_escape"): 0.60,
    ("host", "lateral"): 0.80,
    ("host", "ad_lateral"): 0.80,
    ("lateral", "host"): 0.70,
    ("ad_lateral", "host"): 0.70,
    ("data", "lateral"): 0.65,
    ("data_pipeline", "ad_lateral"): 0.65,
    ("web", "lateral"): 0.55,
    ("web", "ad_lateral"): 0.55,
    ("host", "binary"): 0.60,
    ("host", "binary_analysis"): 0.60,
    ("binary", "host"): 0.60,
    ("binary_analysis", "host"): 0.60,
}

DEFAULT_CLUSTER: dict[tuple[str, str], float] = {
    ("host", "host"): 0.80,
    ("host", "web"): 0.75,
    ("web", "host"): 0.65,
    ("credential", "host"): 0.95,
    ("credential", "ssh"): 0.95,
    ("web", "data"): 0.85,
    ("host", "data"): 0.70,
    ("container", "host"): 0.85,
    ("host", "container"): 0.60,
    ("host", "lateral"): 0.80,
    ("lateral", "host"): 0.70,
    ("data", "lateral"): 0.65,
}

DEFAULT_INTRA_TARGET: dict[tuple[str, str], float] = {
    ("web", "data_pipeline"): 0.65,
    ("web", "host"): 0.60,
    ("web", "container_escape"): 0.50,
    ("host", "web"): 0.45,
    ("host", "container_escape"): 0.70,
    ("host", "ad_lateral"): 0.55,
    ("host", "data_pipeline"): 0.40,
    ("container_escape", "host"): 0.75,
    ("container_escape", "web"): 0.45,
    ("container_escape", "ad_lateral"): 0.65,
    ("ad_lateral", "host"): 0.60,
    ("aprs", "host"): 0.70,
    ("aprs", "container_escape"): 0.50,
    ("binary_analysis", "host"): 0.55,
    ("sysaudit", "host"): 0.50,
    ("data_pipeline", "host"): 0.30,
    ("data_pipeline", "web"): 0.55,
}

DEFAULT_DECAY_TTL_HOURS = {
    "ephemeral": 4.0,
    "operational": 24.0,
    "structural": 24.0 * 7.0,
}

_CONFIG_CACHE: dict[str, Any] = {
    "path": None,
    "mtime": None,
    "payload": None,
}


def _coupling_paths() -> list[Path]:
    return [
        SKG_CONFIG_DIR / "coupling.yaml",
        SKG_HOME / "config" / "coupling.yaml",
    ]


def _normalize_table(payload: Any) -> dict[tuple[str, str], float]:
    table: dict[tuple[str, str], float] = {}
    if not isinstance(payload, dict):
        return table
    for left, right_map in payload.items():
        left_key = str(left or "").strip()
        if not left_key or not isinstance(right_map, dict):
            continue
        for right, value in right_map.items():
            right_key = str(right or "").strip()
            if not right_key:
                continue
            try:
                weight = float(value)
            except Exception:
                continue
            table[(left_key, right_key)] = max(0.0, min(1.0, weight))
    return table


def _coerce_nested_table(payload: Any, *, clip: bool = False) -> dict[str, dict[str, float]]:
    table: dict[str, dict[str, float]] = {}
    if not isinstance(payload, dict):
        return table
    for left, right_map in payload.items():
        left_key = str(left or "").strip()
        if not left_key or not isinstance(right_map, dict):
            continue
        for right, value in right_map.items():
            right_key = str(right or "").strip()
            if not right_key:
                continue
            try:
                weight = float(value)
            except Exception:
                continue
            if clip:
                weight = max(0.0, min(1.0, weight))
            table.setdefault(left_key, {})[right_key] = round(weight, 4)
    return table


def _denormalize_table(table: dict[tuple[str, str], float]) -> dict[str, dict[str, float]]:
    payload: dict[str, dict[str, float]] = {}
    for (left, right), value in sorted(table.items()):
        payload.setdefault(left, {})[right] = round(float(value), 4)
    return payload


def _default_payload() -> dict[str, Any]:
    return {
        "inter_local": _denormalize_table(DEFAULT_INTER_LOCAL),
        "cluster": _denormalize_table(DEFAULT_CLUSTER),
        "intra_target": _denormalize_table(DEFAULT_INTRA_TARGET),
        "decay_ttl_hours": dict(DEFAULT_DECAY_TTL_HOURS),
        "reverse_discount": 0.8,
    }


def _merged_payload() -> dict[str, Any]:
    return {
        "inter_local": _denormalize_table(inter_local_table()),
        "cluster": _denormalize_table(cluster_table()),
        "intra_target": _denormalize_table(intra_target_table()),
        "decay_ttl_hours": {
            str(key): round(float(value), 4)
            for key, value in decay_ttl_hours().items()
        },
        "reverse_discount": round(float(reverse_discount()), 4),
    }


def active_config_path() -> Path:
    for path in _coupling_paths():
        if path.exists():
            return path
    return _coupling_paths()[0]


def backup_config_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.bak")


def render_payload(payload: dict[str, Any]) -> str:
    return yaml.safe_dump(payload, sort_keys=False)


def render_diff(current: dict[str, Any], proposed: dict[str, Any], target_path: Path) -> str:
    diff = difflib.unified_diff(
        render_payload(current).splitlines(),
        render_payload(proposed).splitlines(),
        fromfile=f"{target_path} (current)",
        tofile=f"{target_path} (proposed)",
        lineterm="",
    )
    return "\n".join(diff)


def _merge_nested_tables(
    base: dict[str, dict[str, float]] | None,
    overlay: dict[str, dict[str, float]] | None,
) -> dict[str, dict[str, float]]:
    merged: dict[str, dict[str, float]] = {}
    for source, target_map in (base or {}).items():
        merged[str(source)] = {
            str(target): float(value)
            for target, value in (target_map or {}).items()
        }
    for source, target_map in (overlay or {}).items():
        merged.setdefault(str(source), {})
        for target, value in (target_map or {}).items():
            merged[str(source)][str(target)] = float(value)
    return merged


def extract_learned_intra_target(payload: dict[str, Any]) -> dict[str, dict[str, float]]:
    if not isinstance(payload, dict):
        return {}
    if isinstance(payload.get("estimated"), dict):
        return _coerce_nested_table(payload.get("estimated"))
    if isinstance(payload.get("intra_target"), dict):
        return _coerce_nested_table(payload.get("intra_target"))
    return _coerce_nested_table(payload)


def load_learned_intra_target(path: Path) -> dict[str, dict[str, float]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: learned coupling payload must be a mapping")
    learned = extract_learned_intra_target(data)
    if not learned:
        raise ValueError(f"{path}: no learned intra_target table found")
    return learned


def _refresh_cache() -> None:
    _CONFIG_CACHE["path"] = None
    _CONFIG_CACHE["mtime"] = None
    _CONFIG_CACHE["payload"] = None
    _load_payload(force=True)


def _load_payload(force: bool = False) -> dict[str, Any]:
    if not force:
        for path in _coupling_paths():
            if not path.exists():
                continue
            try:
                mtime = path.stat().st_mtime
            except OSError:
                break
            if _CONFIG_CACHE["path"] == path and _CONFIG_CACHE["mtime"] == mtime and isinstance(_CONFIG_CACHE["payload"], dict):
                return dict(_CONFIG_CACHE["payload"])
            break
        else:
            if isinstance(_CONFIG_CACHE["payload"], dict) and _CONFIG_CACHE["path"] is None:
                return dict(_CONFIG_CACHE["payload"])

    payload = _default_payload()
    selected_path: Path | None = None
    selected_mtime = None

    for path in _coupling_paths():
        if not path.exists():
            continue
        selected_path = path
        try:
            selected_mtime = path.stat().st_mtime
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:
            data = {}
        if isinstance(data, dict):
            payload.update(data)
        break

    _CONFIG_CACHE["path"] = selected_path
    _CONFIG_CACHE["mtime"] = selected_mtime
    _CONFIG_CACHE["payload"] = dict(payload)
    return payload


def reverse_discount() -> float:
    payload = _load_payload()
    try:
        return float(payload.get("reverse_discount", 0.8))
    except Exception:
        return 0.8


def inter_local_table() -> dict[tuple[str, str], float]:
    payload = _load_payload()
    table = DEFAULT_INTER_LOCAL.copy()
    table.update(_normalize_table(payload.get("inter_local")))
    return table


def cluster_table() -> dict[tuple[str, str], float]:
    payload = _load_payload()
    table = DEFAULT_CLUSTER.copy()
    table.update(_normalize_table(payload.get("cluster")))
    return table


def intra_target_table() -> dict[tuple[str, str], float]:
    payload = _load_payload()
    table = DEFAULT_INTRA_TARGET.copy()
    table.update(_normalize_table(payload.get("intra_target")))
    return table


def decay_ttl_hours() -> dict[str, float]:
    payload = _load_payload()
    base = dict(DEFAULT_DECAY_TTL_HOURS)
    extra = payload.get("decay_ttl_hours") or {}
    if isinstance(extra, dict):
        for key, value in extra.items():
            try:
                hours = float(value)
            except Exception:
                continue
            base[str(key)] = max(0.0, hours)
    return base


def coupling_value(
    left: str,
    right: str,
    *,
    table: str = "inter_local",
    apply_reverse_discount: bool = True,
) -> float:
    if table == "cluster":
        mapping = cluster_table()
    elif table == "intra_target":
        mapping = intra_target_table()
    else:
        mapping = inter_local_table()

    key = (str(left or "").strip(), str(right or "").strip())
    if key in mapping:
        return mapping[key]

    reverse_key = (key[1], key[0])
    if reverse_key in mapping:
        reverse = mapping[reverse_key]
        if table == "intra_target" or not apply_reverse_discount:
            return reverse
        return max(0.0, min(1.0, reverse * reverse_discount()))

    return 0.10


def _known_domain_names() -> set[str]:
    return {
        domain.name
        for domain in _CanonicalDomainRegistry.discover().list_domains()
        if domain.name
    }


def validate_payload(payload: dict[str, Any] | None = None) -> list[str]:
    payload = dict(payload or _load_payload(force=True))
    errors: list[str] = []
    known_domains = _known_domain_names()
    known_domains.update({
        "host", "web", "data", "container", "container_escape", "ad", "ad_lateral",
        "aprs", "binary", "binary_analysis", "sysaudit", "data_pipeline",
        "ai_target", "iot_firmware", "supply_chain", "credential", "ssh",
        "smb", "vuln", "cmdi", "shell", "lateral",
    })

    for section in ("inter_local", "cluster", "intra_target"):
        table = payload.get(section)
        if table is None:
            continue
        if not isinstance(table, dict):
            errors.append(f"{section}: must be a mapping")
            continue
        for left, right_map in table.items():
            if not isinstance(right_map, dict):
                errors.append(f"{section}.{left}: must map to a nested mapping")
                continue
            if section == "intra_target" and str(left) not in known_domains:
                errors.append(f"{section}.{left}: unknown domain")
            for right, value in right_map.items():
                if section == "intra_target" and str(right) not in known_domains:
                    errors.append(f"{section}.{left}.{right}: unknown domain")
                try:
                    numeric = float(value)
                except Exception:
                    errors.append(f"{section}.{left}.{right}: non-numeric value")
                    continue
                if numeric < 0.0 or numeric > 1.0:
                    errors.append(f"{section}.{left}.{right}: value must be in [0, 1]")

    ttl_map = payload.get("decay_ttl_hours")
    if ttl_map is not None:
        if not isinstance(ttl_map, dict):
            errors.append("decay_ttl_hours: must be a mapping")
        else:
            for key, value in ttl_map.items():
                try:
                    hours = float(value)
                except Exception:
                    errors.append(f"decay_ttl_hours.{key}: non-numeric value")
                    continue
                if hours < 0.0:
                    errors.append(f"decay_ttl_hours.{key}: must be >= 0")

    return errors


def learn_intra_target_couplings(delta_dir: Path | None = None) -> dict[str, Any]:
    delta_dir = delta_dir or DELTA_DIR
    snapshots_dir = Path(delta_dir) / "snapshots"
    if not snapshots_dir.exists():
        return {"counts": {}, "estimated": {}}

    identities: dict[str, dict[str, bool]] = {}
    for snapshot_file in sorted(snapshots_dir.glob("*.jsonl")):
        latest: dict[str, Any] | None = None
        for line in snapshot_file.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                latest = json.loads(line)
            except Exception:
                continue
        if not isinstance(latest, dict):
            continue
        workload_id = str(latest.get("workload_id") or "")
        if not workload_id or "::" not in workload_id:
            continue
        domain, identity = workload_id.split("::", 1)
        realized = bool(latest.get("wicket_states")) and any(
            state == "realized" for state in (latest.get("wicket_states") or {}).values()
        )
        identities.setdefault(identity, {})[domain] = realized

    numerator: dict[tuple[str, str], int] = {}
    denominator: dict[str, int] = {}
    for realized_by_domain in identities.values():
        for source, source_realized in realized_by_domain.items():
            if not source_realized:
                continue
            denominator[source] = denominator.get(source, 0) + 1
            for target, target_realized in realized_by_domain.items():
                if source == target or not target_realized:
                    continue
                key = (source, target)
                numerator[key] = numerator.get(key, 0) + 1

    estimated: dict[str, dict[str, float]] = {}
    counts: dict[str, dict[str, dict[str, int]]] = {}
    for (source, target), hits in sorted(numerator.items()):
        total = max(denominator.get(source, 0), 1)
        prob = round(hits / total, 4)
        estimated.setdefault(source, {})[target] = prob
        counts.setdefault(source, {})[target] = {"hits": hits, "total": total}

    return {"counts": counts, "estimated": estimated}


def apply_learned_intra_target(
    *,
    delta_dir: Path | None = None,
    learned_file: Path | None = None,
    review: bool = False,
    backup: bool = False,
    assume_yes: bool = False,
) -> dict[str, Any]:
    target_path = active_config_path()
    current = _merged_payload()

    if learned_file is not None:
        learned_table = load_learned_intra_target(learned_file)
        learned_source = str(learned_file)
    else:
        learned_payload = learn_intra_target_couplings(delta_dir or DELTA_DIR)
        learned_table = extract_learned_intra_target(learned_payload)
        learned_source = str((delta_dir or DELTA_DIR) / "snapshots")

    proposed = dict(current)
    proposed["intra_target"] = _merge_nested_tables(
        _coerce_nested_table(current.get("intra_target"), clip=False),
        learned_table,
    )

    errors = validate_payload(proposed)
    if errors:
        return {
            "ok": False,
            "applied": False,
            "changed": False,
            "errors": errors,
            "path": str(target_path),
            "source": learned_source,
        }

    diff_text = render_diff(current, proposed, target_path)
    if not diff_text:
        return {
            "ok": True,
            "applied": False,
            "changed": False,
            "errors": [],
            "path": str(target_path),
            "source": learned_source,
            "updated_pairs": sum(len(v) for v in learned_table.values()),
            "backup_path": None,
            "diff": "",
        }

    if review and not assume_yes:
        if not sys.stdin.isatty():
            return {
                "ok": False,
                "applied": False,
                "changed": False,
                "errors": ["review requested outside an interactive TTY; rerun with --yes to apply"],
                "path": str(target_path),
                "source": learned_source,
                "updated_pairs": sum(len(v) for v in learned_table.values()),
                "backup_path": None,
                "diff": diff_text,
            }
        answer = input(f"Apply learned coupling values to {target_path}? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            return {
                "ok": False,
                "applied": False,
                "changed": False,
                "errors": ["operator declined apply"],
                "path": str(target_path),
                "source": learned_source,
                "updated_pairs": sum(len(v) for v in learned_table.values()),
                "backup_path": None,
                "diff": diff_text,
            }

    backup_path: Path | None = None
    if backup and target_path.exists():
        backup_path = backup_config_path(target_path)
        shutil.copy2(target_path, backup_path)

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(render_payload(proposed), encoding="utf-8")
    _refresh_cache()
    return {
        "ok": True,
        "applied": True,
        "changed": True,
        "errors": [],
        "path": str(target_path),
        "source": learned_source,
        "updated_pairs": sum(len(v) for v in learned_table.values()),
        "backup_path": str(backup_path) if backup_path else None,
        "diff": diff_text,
    }


def _write_learned_output(payload: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return
    path.write_text(render_payload(payload), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="SKG coupling configuration helper")
    action = ap.add_mutually_exclusive_group()
    action.add_argument("--validate", action="store_true", help="validate the active coupling config")
    action.add_argument("--show", action="store_true", help="print the active merged coupling config")
    action.add_argument("--learn", action="store_true", help="estimate intra-target couplings from delta snapshots")
    action.add_argument("--apply", action="store_true", help="apply learned intra-target couplings to the live config")
    ap.add_argument("--delta-dir", default=str(DELTA_DIR), help="delta directory for --learn/--apply")
    ap.add_argument("--out", default=None, help="write --learn output to a file instead of stdout")
    ap.add_argument("--learned-file", default=None, help="use a learned coupling file for --apply")
    ap.add_argument("--review", action="store_true", help="show a unified diff before --apply")
    ap.add_argument("--backup", action="store_true", help="back up the active coupling file before --apply")
    ap.add_argument("--yes", action="store_true", help="skip interactive confirmation during --apply")
    return ap


def run(args: argparse.Namespace) -> int:
    if getattr(args, "validate", False):
        errors = validate_payload()
        if errors:
            print(json.dumps({"ok": False, "errors": errors}, indent=2))
            return 1
        print(json.dumps({"ok": True}, indent=2))
        return 0

    if getattr(args, "learn", False):
        learned = learn_intra_target_couplings(Path(getattr(args, "delta_dir", DELTA_DIR)))
        out = getattr(args, "out", None)
        if out:
            _write_learned_output(learned, Path(out))
            print(json.dumps({"ok": True, "out": str(Path(out))}, indent=2))
            return 0
        print(json.dumps(learned, indent=2, sort_keys=True))
        return 0

    if getattr(args, "apply", False):
        learned_file = getattr(args, "learned_file", None)
        try:
            result = apply_learned_intra_target(
                delta_dir=Path(getattr(args, "delta_dir", DELTA_DIR)),
                learned_file=Path(learned_file) if learned_file else None,
                review=bool(getattr(args, "review", False)),
                backup=bool(getattr(args, "backup", False)),
                assume_yes=bool(getattr(args, "yes", False)),
            )
        except (OSError, ValueError) as exc:
            print(json.dumps({"ok": False, "errors": [str(exc)]}, indent=2))
            return 1
        if getattr(args, "review", False) and result.get("diff"):
            print(result["diff"])
        printable = {key: value for key, value in result.items() if key != "diff"}
        print(json.dumps(printable, indent=2, sort_keys=True))
        return 0 if result.get("ok") else 1

    merged = _merged_payload()
    merged["source"] = str(_CONFIG_CACHE.get("path") or "defaults")
    print(json.dumps(merged, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = build_arg_parser()
    args = ap.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

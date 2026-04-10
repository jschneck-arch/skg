from __future__ import annotations
import json, shutil, sys
from datetime import datetime, timezone
from pathlib import Path
from skg.cli.utils import (
    DISCOVERY_DIR, SKG_HOME, SKG_STATE_DIR, EVENTS_DIR, INTERP_DIR,
    CVE_DIR, _latest_surface, _iso_now,
)


def _derived_runtime_paths() -> dict[str, Path]:
    return {
        "interp": SKG_STATE_DIR / "interp",
        "folds": SKG_STATE_DIR / "discovery" / "folds",
    }


def _archive_root(timestamp: str | None = None) -> Path:
    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return SKG_STATE_DIR / "archive" / f"derived_{stamp}"


def cmd_derived(a):
    if a.derived_cmd == "archive":
        return _cmd_derived_archive(a)
    if a.derived_cmd == "rebuild":
        return _cmd_derived_rebuild(a)
    print("  Unknown derived command")


def _cmd_derived_archive(a):
    archive_root = _archive_root()
    archive_root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "archived_at": _iso_now(),
        "archive_root": str(archive_root),
        "paths": {},
    }

    for name, path in _derived_runtime_paths().items():
        count = 0
        if path.exists():
            try:
                count = sum(1 for _ in path.iterdir())
            except Exception:
                count = 0
        if not path.exists() or count == 0:
            path.mkdir(parents=True, exist_ok=True)
            manifest["paths"][name] = {
                "source": str(path),
                "archived_to": None,
                "entries": 0,
            }
            continue

        dest = archive_root / name
        shutil.move(str(path), str(dest))
        path.mkdir(parents=True, exist_ok=True)
        manifest["paths"][name] = {
            "source": str(path),
            "archived_to": str(dest),
            "entries": count,
        }

    (archive_root / "manifest.json").write_text(json.dumps(manifest, indent=2))

    print("  Derived State Archived:")
    print(f"    root   : {archive_root}")
    for name, info in manifest["paths"].items():
        archived_to = info.get("archived_to") or "(nothing to archive)"
        print(f"    {name:6s}: {info['entries']} entries -> {archived_to}")


def _rebuild_interp_from_events() -> tuple[int, list[str]]:
    """
    Project all events into interp files.
    Source: canonical events directory (append-only substrate).
    """
    from skg_services.gravity.projector_runtime import project_events_dir

    source_dir = EVENTS_DIR
    if not source_dir.exists():
        return 0, []
    outputs = []
    for out in project_events_dir(source_dir, SKG_STATE_DIR / "interp"):
        outputs.append(str(out))
    return len(outputs), outputs


def _rebuild_fold_state() -> tuple[int, list[str]]:
    surface_path = _latest_surface()
    if not surface_path:
        return 0, []

    sys.path.insert(0, str(SKG_HOME))
    from skg.kernel.folds import FoldDetector, FoldManager

    try:
        surface = json.loads(Path(surface_path).read_text())
    except Exception:
        return 0, []

    fold_state_dir = SKG_STATE_DIR / "discovery" / "folds"
    fold_state_dir.mkdir(parents=True, exist_ok=True)

    refreshed_by_ip = {}
    for fold in FoldDetector().detect_all(
        events_dir=EVENTS_DIR,
        cve_dir=CVE_DIR,
        toolchain_dir=SKG_HOME,
    ):
        for target in surface.get("targets", []):
            tip = target.get("ip", "")
            if tip and (tip in fold.location or fold.location.endswith(tip)):
                refreshed_by_ip.setdefault(tip, FoldManager()).add(fold)
                break

    written = []
    for ip, fm in refreshed_by_ip.items():
        out = fold_state_dir / f"folds_{ip.replace('.', '_')}.json"
        fm.persist(out)
        written.append(str(out))

    return len(written), written


def _cmd_derived_rebuild(a):
    interp_dir = SKG_STATE_DIR / "interp"
    folds_dir = SKG_STATE_DIR / "discovery" / "folds"
    interp_dir.mkdir(parents=True, exist_ok=True)
    folds_dir.mkdir(parents=True, exist_ok=True)

    interp_count = sum(1 for _ in interp_dir.iterdir()) if interp_dir.exists() else 0
    folds_count = sum(1 for _ in folds_dir.iterdir()) if folds_dir.exists() else 0
    if (interp_count or folds_count) and not getattr(a, "append", False):
        print("  Refusing rebuild into non-empty derived directories.")
        print("  Archive first with: skg derived archive")
        print("  Or explicitly append with: skg derived rebuild --append")
        return

    rebuilt_interp_count, interp_outputs = _rebuild_interp_from_events()
    rebuilt_fold_count, fold_outputs = _rebuild_fold_state()

    print("  Derived State Rebuilt:")
    print(f"    interp : {rebuilt_interp_count} outputs")
    if interp_outputs[:5]:
        for out in interp_outputs[:5]:
            print(f"      {out}")
    print(f"    folds  : {rebuilt_fold_count} files")
    if fold_outputs[:5]:
        for out in fold_outputs[:5]:
            print(f"      {out}")

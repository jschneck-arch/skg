from __future__ import annotations
import sys, tempfile
from pathlib import Path
from urllib.parse import urlparse
from skg.cli.utils import (
    SKG_HOME, DISCOVERY_DIR, SKG_STATE_DIR,
    _latest_surface, _load_module_from_file, _register_web_observation_target,
)


def cmd_gravity(a):
    """Run the gravity field loop."""
    gravity_script = SKG_HOME / "skg-gravity" / "gravity_field.py"
    if not gravity_script.exists():
        print(f"  Error: {gravity_script} not found")
        return

    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(line_buffering=True, write_through=True)
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(line_buffering=True, write_through=True)
    except Exception:
        pass

    cycles = str(getattr(a, "cycles", 5) or 5)
    surface_path = _latest_surface()
    if not surface_path:
        print("  No surface data. Run: skg target add-subnet <cidr>")
        return

    focus_target = getattr(a, "target", None)
    if focus_target and "://" in str(focus_target):
        parsed = urlparse(str(focus_target))
        canonical_target = parsed.hostname or str(focus_target)
        try:
            surface_path = _register_web_observation_target(str(focus_target), None)
            print(f"  Registered external-web target: {canonical_target}")
        except Exception as exc:
            print(f"  External target registration failed: {exc}")
        focus_target = canonical_target

    tmp_surface_path = None
    try:
        tmp_surface = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="skg_surface_",
            dir="/tmp",
            delete=False,
        )
        tmp_surface.write(Path(surface_path).read_text())
        tmp_surface.flush()
        tmp_surface.close()
        tmp_surface_path = tmp_surface.name

        gravity_mod = _load_module_from_file("skg_gravity_field_runtime", gravity_script)
        gravity_mod.gravity_field_loop(
            tmp_surface_path or surface_path,
            str(DISCOVERY_DIR),
            max_cycles=int(cycles),
            authorized=bool(getattr(a, "authorized", False)),
            focus_target=focus_target,
        )
    except Exception as exc:
        print(f"  Gravity runtime error: {exc}")
        raise
    finally:
        if tmp_surface_path:
            try:
                Path(tmp_surface_path).unlink(missing_ok=True)
            except Exception:
                pass

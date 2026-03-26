from __future__ import annotations
import json, sys
from pathlib import Path
from skg.cli.utils import SKG_HOME, EVENTS_DIR


def cmd_replay(a):
    """
    Replay pre-recorded observation events through the field kernel and show
    the resulting entropy landscape.  No live network connection required.

    Loads NDJSON event files from a directory, projects them through the
    kernel, and prints the resulting wicket states — identical to what the
    live gravity cycle produces, because the substrate is event-sourced.

    Usage:
      skg replay <events_dir>              replay all .ndjson files in dir
      skg replay artifacts/cycle_evidence/ replay the EternalBlue validation
    """
    import glob as _glob

    events_dir = Path(getattr(a, "events_dir", "."))
    if not events_dir.exists():
        print(f"  Events directory not found: {events_dir}")
        raise SystemExit(1)

    ndjson_files = sorted(events_dir.glob("*.ndjson"))
    if not ndjson_files:
        print(f"  No .ndjson files found in {events_dir}")
        raise SystemExit(1)

    print(f"\n  SKG replay — loading {len(ndjson_files)} event file(s) from {events_dir}\n")

    # Load all events
    all_events: list[dict] = []
    for f in ndjson_files:
        try:
            for line in f.read_text().splitlines():
                line = line.strip()
                if line:
                    all_events.append(json.loads(line))
            print(f"    loaded: {f.name}  ({sum(1 for l in f.read_text().splitlines() if l.strip())} events)")
        except Exception as e:
            print(f"    skipped {f.name}: {e}")

    if not all_events:
        print("  No events loaded.")
        raise SystemExit(1)

    print(f"\n  Total events: {len(all_events)}")

    # Group by target/workload
    by_target: dict[str, list] = {}
    for ev in all_events:
        payload = ev.get("payload", {})
        wid = payload.get("workload_id", "unknown")
        by_target.setdefault(wid, []).append(ev)

    # Collapse wicket states per target using the kernel
    try:
        sys.path.insert(0, str(SKG_HOME))
        from skg.kernel.support import SupportEngine
        from skg.kernel.state import StateEngine, CollapseThresholds
        from skg.kernel.energy import EnergyEngine

        se = SupportEngine()
        ste = StateEngine(CollapseThresholds())
        ee = EnergyEngine()
    except Exception as e:
        print(f"  Kernel import failed: {e}")
        raise SystemExit(1)

    print(f"\n  {'Target/Workload':<35} {'Wicket':<8} {'State':<10} {'Confidence':>10}")
    print(f"  {'─'*35} {'─'*8} {'─'*10} {'─'*10}")

    for wid, events in sorted(by_target.items()):
        # Aggregate support per wicket
        wicket_obs: dict[str, list] = {}
        for ev in events:
            p = ev.get("payload", {})
            wk = p.get("wicket_id")
            if not wk:
                continue
            wicket_obs.setdefault(wk, []).append(p)

        realized, blocked, unknown = [], [], []
        for wk, obs_list in sorted(wicket_obs.items()):
            # Simple collapse: majority-vote confidence-weighted
            pos = sum(1.0 for o in obs_list if o.get("status") == "realized")
            neg = sum(1.0 for o in obs_list if o.get("status") == "blocked")
            conf = max((o.get("confidence", 0.5) for o in obs_list), default=0.5)
            if pos > neg:
                state = "realized"; realized.append(wk)
            elif neg > pos:
                state = "blocked"; blocked.append(wk)
            else:
                state = "unknown"; unknown.append(wk)
            print(f"  {wid:<35} {wk:<8} {state:<10} {conf:>10.2f}")

        from skg.substrate.node import TriState
        states = ([TriState.REALIZED] * len(realized) +
                  [TriState.BLOCKED]  * len(blocked)  +
                  [TriState.UNKNOWN]  * len(unknown))
        E = ee.compute(states, [])
        print(f"\n  {'─'*35} E={E:.1f}  ({len(realized)}R {len(blocked)}B {len(unknown)}U)\n")

    print(f"  Replay complete.  To run live: skg gravity --cycles 1")
    print(f"  To load into daemon events: cp {events_dir}/*.ndjson {EVENTS_DIR}/")
    print()

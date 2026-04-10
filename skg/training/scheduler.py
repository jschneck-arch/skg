"""
skg.training.scheduler
=======================
Daily fine-tune scheduler — runs once per day via systemd timer.

Designed for laptop use:
  - Runs at a fixed time (default 02:00 local) to avoid impacting
    active engagement sessions
  - Checks battery/AC state — skips if on battery below threshold
  - Checks if enough new corpus examples exist before running
  - Idempotent — safe to call multiple times, only runs once per day
  - Writes lock file to prevent concurrent runs

Invoked by: systemd timer skg-train.timer
Also callable manually: python -m skg.training.scheduler_main
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone, date
from pathlib import Path

from skg_core.config.paths import SKG_STATE_DIR
from skg.training.corpus import corpus_status, MIN_EXAMPLES_FOR_RUN

log = logging.getLogger("skg.training.scheduler")

SCHEDULER_STATE = SKG_STATE_DIR / "training" / "scheduler.json"
LOCK_FILE       = SKG_STATE_DIR / "training" / "train.lock"

# Minimum battery % to proceed (0 = always run, even on battery)
MIN_BATTERY_PCT  = 20
# Skip if on battery (True = only run on AC power)
REQUIRE_AC       = False


def _load_state() -> dict:
    if SCHEDULER_STATE.exists():
        try:
            return json.loads(SCHEDULER_STATE.read_text())
        except Exception:
            pass
    return {"last_run_date": None, "run_count": 0, "skip_count": 0}


def _save_state(state: dict):
    SCHEDULER_STATE.parent.mkdir(parents=True, exist_ok=True)
    SCHEDULER_STATE.write_text(json.dumps(state, indent=2))


def _already_ran_today() -> bool:
    state = _load_state()
    last = state.get("last_run_date")
    if not last:
        return False
    return last == date.today().isoformat()


def _check_power() -> dict:
    """
    Check battery/AC state on Linux.
    Returns {"on_ac": bool, "battery_pct": int or None}
    """
    power = {"on_ac": True, "battery_pct": None}

    # /sys/class/power_supply
    ps_dir = Path("/sys/class/power_supply")
    if not ps_dir.exists():
        return power  # assume AC (desktop or VM)

    for supply in ps_dir.iterdir():
        typ_file = supply / "type"
        if not typ_file.exists():
            continue
        try:
            typ = typ_file.read_text().strip()
        except Exception:
            continue

        if typ == "Mains":
            online_file = supply / "online"
            if online_file.exists():
                try:
                    power["on_ac"] = online_file.read_text().strip() == "1"
                except Exception:
                    pass

        elif typ == "Battery":
            cap_file = supply / "capacity"
            if cap_file.exists():
                try:
                    power["battery_pct"] = int(cap_file.read_text().strip())
                except Exception:
                    pass

    return power


def _acquire_lock() -> bool:
    """Try to acquire run lock. Returns True if acquired."""
    if LOCK_FILE.exists():
        try:
            lock_data = json.loads(LOCK_FILE.read_text())
            lock_pid = lock_data.get("pid")
            lock_ts  = lock_data.get("ts", "")
            # Check if process is still running
            if lock_pid:
                try:
                    os.kill(lock_pid, 0)
                    log.info(f"[scheduler] training already running (pid={lock_pid})")
                    return False
                except ProcessLookupError:
                    # Stale lock
                    log.info("[scheduler] removing stale lock")
        except Exception:
            pass

    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOCK_FILE.write_text(json.dumps({
        "pid": os.getpid(),
        "ts":  datetime.now(timezone.utc).isoformat(),
    }))
    return True


def _release_lock():
    LOCK_FILE.unlink(missing_ok=True)


def should_run(force: bool = False, skip_battery_check: bool = False, skip_load_check: bool = False) -> tuple[bool, str]:
    """
    Determine whether to run training now.
    Returns (should_run: bool, reason: str)
    """
    if force:
        return True, "forced"

    # Already ran today
    if _already_ran_today():
        return False, "already ran today"

    # Lock held
    if LOCK_FILE.exists():
        try:
            lock_data = json.loads(LOCK_FILE.read_text())
            pid = lock_data.get("pid")
            if pid:
                try:
                    os.kill(pid, 0)
                    return False, f"training in progress (pid={pid})"
                except ProcessLookupError:
                    pass
        except Exception:
            pass

    # Power check
    power = _check_power()
    if REQUIRE_AC and not power["on_ac"]:
        return False, "on battery power (REQUIRE_AC=True)"
    if (power["battery_pct"] is not None
            and not power["on_ac"]
            and power["battery_pct"] < MIN_BATTERY_PCT):
        return False, (f"battery too low ({power['battery_pct']}% < "
                       f"{MIN_BATTERY_PCT}%)")

    # Corpus readiness
    status = corpus_status()
    if not status["ready_for_run"]:
        return False, (f"corpus not ready — {status['examples_since_last_run']} "
                       f"new examples (need {MIN_EXAMPLES_FOR_RUN})")

    return True, "ready"


def run(force: bool = False, dry_run: bool = False) -> dict:
    """
    Main scheduler entry point.
    Called by systemd timer or python -m skg.training.scheduler_main.

    Returns result dict.
    """
    ok, reason = should_run(force=force)
    if not ok:
        log.info(f"[scheduler] skipping: {reason}")
        state = _load_state()
        state["skip_count"] = state.get("skip_count", 0) + 1
        _save_state(state)
        return {"ran": False, "reason": reason}

    if dry_run:
        log.info("[scheduler] dry run — would start training now")
        return {"ran": False, "reason": "dry_run", "would_run": True}

    if not _acquire_lock():
        return {"ran": False, "reason": "lock held by another process"}

    log.info("[scheduler] starting daily training run...")
    started_at = datetime.now(timezone.utc)

    try:
        from skg.training.trainer import run_training
        result = run_training()
    except Exception as exc:
        log.error(f"[scheduler] training error: {exc}", exc_info=True)
        result = {"success": False, "error": str(exc)}
    finally:
        _release_lock()

    # Update scheduler state
    state = _load_state()
    state["last_run_date"] = date.today().isoformat()
    state["last_run_ts"]   = started_at.isoformat()
    state["run_count"]     = state.get("run_count", 0) + 1
    state["last_result"]   = {
        "success":      result.get("success"),
        "skipped":      result.get("skipped"),
        "model_tag":    result.get("model_tag"),
        "eval_score":   result.get("eval_score"),
        "model_swapped": result.get("model_swapped"),
    }
    _save_state(state)

    elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
    log.info(f"[scheduler] run complete in {elapsed/60:.1f} min — "
             f"success={result.get('success')}, "
             f"swapped={result.get('model_swapped')}")

    return {"ran": True, "elapsed_s": elapsed, **result}


def scheduler_status() -> dict:
    """Current scheduler state for CLI display."""
    state  = _load_state()
    power  = _check_power()
    corpus = corpus_status()
    ok, reason = should_run()

    return {
        "last_run_date":  state.get("last_run_date"),
        "last_run_ts":    state.get("last_run_ts"),
        "run_count":      state.get("run_count", 0),
        "skip_count":     state.get("skip_count", 0),
        "last_result":    state.get("last_result"),
        "power":          power,
        "corpus":         corpus,
        "would_run_now":  ok,
        "reason":         reason,
        "lock_held":      LOCK_FILE.exists(),
        "require_ac":     REQUIRE_AC,
        "min_battery_pct": MIN_BATTERY_PCT,
    }

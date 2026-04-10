"""
skg.sensors.usb_sensor
=======================
Watches USB drop directories for SKG collection output and routes
each drop through the appropriate toolchain adapters.

Drop directory layout:
  /var/lib/skg/usb_drops/<drop_id>/
    meta.json            — device serial, hostname, collection timestamp
    packages.txt         — dpkg/rpm output
    processes.txt        — ps aux
    network.txt          — ss/netstat + iptables
    log4j_jars.txt       — find output for log4j jars
    log4j_configs.txt    — find output for log4j config files
    java_homes.txt       — JAVA_HOME and java binary locations
    env_vars.txt         — printenv output
    docker_inspect.json  — docker inspect output (all containers)
    bh_data/             — BloodHound JSON output directory
    lsass_dump/          — lsass dump files (Windows)

Each drop is processed once. State file tracks processed drops.
All parsing is delegated to toolchain adapters via adapter_runner.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from skg.sensors import BaseSensor, register
from skg.sensors.adapter_runner import run_usb_drop
from skg_core.config.paths import SKG_STATE_DIR
try:
    from skg_protocol.events import build_event_envelope as envelope
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    from skg.sensors import envelope

try:
    from skg_services.gravity.event_writer import emit_events
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    from skg.sensors import emit_events

log = logging.getLogger("skg.sensors.usb")

USB_DROPS_DIR  = SKG_STATE_DIR / "usb_drops"
USB_STATE_FILE = SKG_STATE_DIR / "usb_sensor.state.json"


@register("usb")
class UsbSensor(BaseSensor):
    name = "usb"

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.drops_dir = Path(cfg.get("drops_dir", USB_DROPS_DIR))
        self._state = self._load_state()

    def _load_state(self) -> dict:
        if USB_STATE_FILE.exists():
            try:
                return json.loads(USB_STATE_FILE.read_text())
            except Exception:
                pass
        return {"processed_drops": []}

    def _save_state(self):
        USB_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        USB_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def run(self) -> list[str]:
        if not self.drops_dir.exists():
            return []

        processed = set(self._state["processed_drops"])
        new_drops = [
            d for d in sorted(self.drops_dir.iterdir())
            if d.is_dir() and d.name not in processed
        ]

        all_event_ids: list[str] = []

        for drop in new_drops:
            drop_id = drop.name
            meta = {}
            meta_file = drop / "meta.json"
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text())
                except Exception:
                    pass

            workload_id = meta.get("workload_id") or meta.get("hostname") or f"usb::{drop_id}"
            attack_path_id = meta.get("attack_path_id")
            run_id = str(uuid.uuid4())

            log.info(f"[usb] processing drop {drop_id} (workload={workload_id})")

            try:
                # Route through all applicable adapters
                raw_events = run_usb_drop(drop, workload_id, attack_path_id, run_id)
            except Exception as exc:
                log.error(f"[usb] drop {drop_id} adapter error: {exc}", exc_info=True)
                raw_events = []

            # Apply context calibration to each event and record observations
            calibrated = []
            for ev in raw_events:
                payload = ev.get("payload", {})
                wicket_id = payload.get("wicket_id", "")
                domain = ev.get("source", {}).get("toolchain", "").replace("skg-", "").replace("-toolchain", "")
                rank = ev.get("provenance", {}).get("evidence_rank", 5)
                base_conf = ev.get("provenance", {}).get("evidence", {}).get("confidence", 0.7)
                status = payload.get("status", "unknown")
                realized = True if status == "realized" else (False if status == "blocked" else None)

                if self._ctx and wicket_id:
                    evidence_text = f"{wicket_id}: {payload.get('detail', '')}"
                    conf = self._ctx.calibrate(
                        base_conf,
                        evidence_text,
                        wicket_id,
                        domain,
                        workload_id,
                        source_id=ev.get("source", {}).get("source_id", ""),
                    )
                    ev["provenance"]["evidence"]["confidence"] = conf
                    self._ctx.record(
                        evidence_text=evidence_text,
                        wicket_id=wicket_id, domain=domain,
                        source_kind="usb_collection",
                        evidence_rank=rank,
                        sensor_realized=realized,
                        confidence=conf,
                        workload_id=workload_id,
                    )
                calibrated.append(ev)

            if calibrated:
                ids = emit_events(calibrated, self.events_dir, drop_id)
                all_event_ids.extend(ids)
                log.info(f"[usb] drop {drop_id}: {len(calibrated)} events emitted")

            processed.add(drop_id)

        self._state["processed_drops"] = list(processed)
        self._save_state()
        return all_event_ids

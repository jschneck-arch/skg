"""
skg.sensors.agent_sensor
=========================
Drains the HTTP agent callback queue and routes each payload through
the appropriate toolchain adapters via adapter_runner.

Queue files are written by skg_server.py when agents phone home.
Each file is a JSON payload:
  {
    agent_id:   str,
    hostname:   str,
    timestamp:  str,
    platform:   "linux" | "windows",
    collection: {
      packages:        str,   # dpkg/rpm output
      processes:       str,   # ps output
      network:         str,   # ss/netstat output
      java_homes:      str,
      log4j_jars:      str,
      docker_inspect:  list,  # parsed JSON
      bh_data:         dict,  # {filename: content}
      env_vars:        str,
    }
  }
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from skg.sensors import BaseSensor, register, emit_events
from skg.sensors.adapter_runner import run_agent_callback
from skg.core.paths import SKG_STATE_DIR

log = logging.getLogger("skg.sensors.agent")

AGENT_QUEUE_DIR  = SKG_STATE_DIR / "agent_queue"
AGENT_STATE_FILE = SKG_STATE_DIR / "agent_sensor.state.json"


@register("agent")
class AgentSensor(BaseSensor):
    name = "agent"

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.queue_dir = Path(cfg.get("queue_dir", AGENT_QUEUE_DIR))
        self._state = self._load_state()

    def _load_state(self) -> dict:
        if AGENT_STATE_FILE.exists():
            try:
                return json.loads(AGENT_STATE_FILE.read_text())
            except Exception:
                pass
        return {"processed": []}

    def _save_state(self):
        AGENT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        AGENT_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def run(self) -> list[str]:
        if not self.queue_dir.exists():
            return []

        processed = set(self._state["processed"])
        queue_files = [
            f for f in sorted(self.queue_dir.glob("*.json"))
            if f.name not in processed
        ]

        all_ids: list[str] = []

        for qf in queue_files:
            try:
                payload = json.loads(qf.read_text())
            except Exception as exc:
                log.warning(f"[agent] failed to parse {qf.name}: {exc}")
                processed.add(qf.name)
                continue

            agent_id = payload.get("agent_id", qf.stem)
            hostname = payload.get("hostname", agent_id)
            workload_id = payload.get("workload_id") or f"agent::{hostname}"
            run_id = str(uuid.uuid4())

            log.info(f"[agent] processing callback from {hostname} ({agent_id})")

            try:
                raw_events = run_agent_callback(payload, workload_id, run_id)
            except Exception as exc:
                log.error(f"[agent] {agent_id} adapter error: {exc}", exc_info=True)
                raw_events = []

            # Apply context calibration
            calibrated = []
            for ev in raw_events:
                p = ev.get("payload", {})
                wicket_id = p.get("wicket_id", "")
                domain = ev.get("source", {}).get("toolchain", "").replace("skg-", "").replace("-toolchain", "")
                rank = ev.get("provenance", {}).get("evidence_rank", 4)
                base_conf = ev.get("provenance", {}).get("evidence", {}).get("confidence", 0.7)
                status = p.get("status", "unknown")
                realized = True if status == "realized" else (False if status == "blocked" else None)

                if self._ctx and wicket_id:
                    evidence_text = f"{wicket_id}: {p.get('detail', hostname)}"
                    conf = self._ctx.calibrate(base_conf, evidence_text, wicket_id, domain, workload_id)
                    ev["provenance"]["evidence"]["confidence"] = conf
                    self._ctx.record(
                        evidence_text=evidence_text,
                        wicket_id=wicket_id, domain=domain,
                        source_kind="agent_callback",
                        evidence_rank=rank,
                        sensor_realized=realized,
                        confidence=conf,
                        workload_id=workload_id,
                    )
                calibrated.append(ev)

            if calibrated:
                ids = emit_events(calibrated, self.events_dir, agent_id)
                all_ids.extend(ids)
                log.info(f"[agent] {hostname}: {len(calibrated)} events emitted")

            processed.add(qf.name)

        self._state["processed"] = list(processed)
        self._save_state()
        return all_ids

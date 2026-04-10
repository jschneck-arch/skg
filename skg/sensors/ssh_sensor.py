"""
skg.sensors.ssh_sensor
=======================
Polls credentialed SSH/WinRM targets and routes collection through
canonical host runtime wrappers and domain adapters.

For SSH targets: opens a live paramiko session and routes runtime facts
through the canonical host adapter mapping contract.

For WinRM targets: routes runtime observation through the canonical
host runtime wrapper and host domain adapter mapping.

All AD lateral wickets from domain-joined hosts route through the
BloodHound adapter when bh_data is present in the collection path.

Targets loaded from config/targets.yaml.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from skg.sensors import BaseSensor, register
from skg.sensors.adapter_runner import run_bloodhound
from skg_core.config.paths import SKG_STATE_DIR, SKG_CONFIG_DIR

try:
    from skg_services.gravity.event_writer import emit_events
except Exception:  # pragma: no cover - legacy fallback when canonical packages are unavailable
    from skg.sensors import emit_events

log = logging.getLogger("skg.sensors.ssh")

SSH_STATE_FILE = SKG_STATE_DIR / "ssh_sensor.state.json"


def _load_targets(config_dir: Path) -> list[dict]:
    targets_file = config_dir / "targets.yaml"
    if not targets_file.exists():
        return []
    try:
        import yaml
        data = yaml.safe_load(targets_file.read_text())
        return [t for t in (data or {}).get("targets", []) if t.get("enabled", True)]
    except Exception as exc:
        log.warning(f"targets.yaml load error: {exc}")
        return []


@register("ssh")
class SshSensor(BaseSensor):
    name = "ssh"

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.timeout  = cfg.get("timeout_s", 30)
        self.interval = cfg.get("collect_interval_s", 300)
        self._run_id  = cfg.get("run_id")
        self._state   = self._load_state()

    def _load_state(self) -> dict:
        if SSH_STATE_FILE.exists():
            try:
                return json.loads(SSH_STATE_FILE.read_text())
            except Exception:
                pass
        return {"last_collected": {}}

    def _save_state(self):
        SSH_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        SSH_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def _should_collect(self, host: str) -> bool:
        last = self._state["last_collected"].get(host, 0)
        return (datetime.now(timezone.utc).timestamp() - last) >= self.interval

    def run(self) -> list[str]:
        # Use targets injected via config (single-target collection) if present,
        # otherwise fall back to loading from disk for normal sweep mode.
        injected = self.cfg.get("targets") or []
        targets = injected if injected else _load_targets(SKG_CONFIG_DIR)
        if not targets:
            return []

        all_ids: list[str] = []

        for target in targets:
            host = target.get("host", "")
            if not host:
                continue
            # Injected single-target collection bypasses interval gating;
            # recurring sweep mode respects it.
            if not injected and not self._should_collect(host):
                continue

            proto = target.get("method", target.get("proto", "ssh")).lower()
            workload_id = target.get("workload_id") or f"ssh::{host}"
            attack_path_id = target.get("attack_path_id", "host_ssh_initial_access_v1")
            # Use caller-supplied run_id when available so emitted filenames are
            # predictable (e.g. for auto-project glob in /collect endpoint).
            run_id = self._run_id or str(uuid.uuid4())

            log.info(f"[ssh] collecting from {host} ({proto})")

            raw_events = []
            if proto == "ssh":
                raw_events = self._collect_ssh(
                    target, host, workload_id, attack_path_id, run_id
                )
            elif proto == "winrm":
                raw_events = self._collect_winrm(
                    target, host, workload_id, attack_path_id, run_id
                )
            else:
                log.warning(f"[ssh] unknown proto '{proto}' for {host}")
                continue

            # Apply context calibration
            calibrated = self._calibrate_events(raw_events, workload_id)

            if calibrated:
                ids = emit_events(
                    calibrated, self.events_dir, host.replace(".", "_"),
                    run_id=run_id,
                )
                all_ids.extend(ids)
                log.info(f"[ssh] {host}: {len(calibrated)} events emitted")

            self._state["last_collected"][host] = datetime.now(timezone.utc).timestamp()

        self._save_state()
        return all_ids

    def _collect_ssh(self, target, host, workload_id, attack_path_id, run_id) -> list[dict]:
        try:
            import paramiko
        except ImportError:
            log.warning("paramiko not installed — SSH collection unavailable")
            return []

        user    = target.get("user", "root")
        key     = target.get("key")
        port    = int(target.get("port", 22))

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            if key:
                client.connect(host, port=port, username=user,
                               key_filename=os.path.expanduser(key),
                               timeout=self.timeout)
            elif target.get("password"):
                client.connect(host, port=port, username=user,
                               password=os.path.expandvars(target["password"]),
                               timeout=self.timeout)
            else:
                client.connect(host, port=port, username=user, timeout=self.timeout)
        except Exception as exc:
            log.warning(f"[ssh] {host} connection failed: {exc}")
            return []

        auth_type = "key" if key else ("password" if target.get("password") else "agent/default")

        try:
            try:
                from skg_services.gravity.host_runtime import collect_ssh_session_assessment
            except Exception as exc:
                log.warning(f"[ssh] canonical host ssh runtime unavailable: {exc}")
                return []

            events = collect_ssh_session_assessment(
                client,
                host=host,
                attack_path_id=attack_path_id,
                run_id=run_id,
                workload_id=workload_id,
                username=user,
                auth_type=auth_type,
                port=port,
            )

            # Also check for BloodHound data in ssh collection dirs
            bh_dir = SKG_STATE_DIR / "ssh_collection" / host.replace(".", "_") / "bh_data"
            if bh_dir.exists():
                bh_events = run_bloodhound(bh_dir, workload_id, "ad_kerberoast_v1", run_id)
                events.extend(bh_events)
                log.info(f"[ssh] {host}: bloodhound yielded {len(bh_events)} additional events")

            return events
        finally:
            client.close()

    def _collect_winrm(self, target, host, workload_id, attack_path_id, run_id) -> list[dict]:
        user = target.get("user", "Administrator")
        password = os.path.expandvars(target.get("password", ""))
        port = int(target.get("port", 5985))
        ssl = bool(target.get("ssl", False) or port == 5986)

        try:
            from skg_services.gravity.host_runtime import collect_winrm_assessment
        except Exception as exc:
            log.warning(f"[ssh] canonical winrm runtime unavailable: {exc}")
            return []

        try:
            return collect_winrm_assessment(
                host,
                attack_path_id=attack_path_id,
                run_id=run_id,
                workload_id=workload_id,
                username=user,
                password=password,
                port=port,
                ssl=ssl,
            )
        except Exception as exc:
            log.warning(f"[ssh] canonical winrm collection failed: {exc}")
            return []

    def _calibrate_events(self, events: list[dict], workload_id: str) -> list[dict]:
        if not self._ctx:
            return events
        calibrated = []
        for ev in events:
            payload  = ev.get("payload", {})
            wicket_id = payload.get("wicket_id", "")
            domain   = ev.get("source", {}).get("toolchain", "").replace("skg-", "").replace("-toolchain", "")
            rank     = ev.get("provenance", {}).get("evidence_rank", 3)
            base_conf = ev.get("provenance", {}).get("evidence", {}).get("confidence", 0.7)
            status   = payload.get("status", "unknown")
            realized = True if status == "realized" else (False if status == "blocked" else None)

            if wicket_id:
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
                    source_kind="ssh_collection",
                    evidence_rank=rank,
                    sensor_realized=realized,
                    confidence=conf,
                    workload_id=workload_id,
                )
            calibrated.append(ev)
        return calibrated

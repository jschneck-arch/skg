"""
skg.sensors.ssh_sensor
=======================
Polls credentialed SSH/WinRM targets and routes collection through
the host toolchain adapter (skg-host-toolchain/adapters/ssh_collect/parse.py).

For SSH targets: opens a live paramiko session and passes it directly
to the adapter's eval_ functions — each one runs commands and emits
wickets with full evidence chain.

For WinRM targets: runs PowerShell collection commands, builds a
collection dict, and routes through the APRS/container adapters.

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

from skg.sensors import BaseSensor, register, emit_events
from skg.sensors.adapter_runner import run_ssh_host, run_net_sandbox, run_bloodhound
from skg.core.paths import SKG_STATE_DIR, SKG_CONFIG_DIR

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
        targets = _load_targets(SKG_CONFIG_DIR)
        if not targets:
            return []

        all_ids: list[str] = []

        for target in targets:
            host = target.get("host", "")
            if not host or not self._should_collect(host):
                continue

            proto = target.get("method", target.get("proto", "ssh")).lower()
            workload_id = target.get("workload_id") or f"ssh::{host}"
            attack_path_id = target.get("attack_path_id", "host_ssh_initial_access_v1")
            run_id = str(uuid.uuid4())

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
                ids = emit_events(calibrated, self.events_dir, host.replace(".", "_"))
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

        # HO-03: emit credential valid wicket immediately after successful auth
        auth_type = "key" if key else ("password" if target.get("password") else "agent/default")
        _now = datetime.now(timezone.utc).isoformat()
        ho03 = {
            "id": str(uuid.uuid4()),
            "ts": _now,
            "type": "obs.attack.precondition",
            "source": {"source_id": "ssh_sensor", "toolchain": "skg-host-toolchain", "version": "1.0.0"},
            "payload": {
                "wicket_id":      "HO-03",
                "status":         "realized",
                "attack_path_id": attack_path_id,
                "run_id":         run_id,
                "workload_id":    workload_id,
                "observed_at":    _now,
                "notes":          f"Credential valid for user '{user}' via {auth_type}.",
                "attributes":     {"user": user, "auth_type": auth_type},
            },
            "provenance": {
                "evidence_rank": 1,
                "evidence": {
                    "source_kind": "ssh_auth",
                    "pointer":     f"ssh://{host}:{port}",
                    "collected_at": _now,
                    "confidence":  0.99,
                },
            },
        }

        try:
            # Route through the full host toolchain adapter
            events = run_ssh_host(client, host, workload_id, attack_path_id, run_id,
                                   user=user, auth_type=auth_type, port=port)
            events.insert(0, ho03)

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
        try:
            import winrm
        except ImportError:
            log.warning("pywinrm not installed — WinRM collection unavailable")
            return []

        user     = target.get("user", "Administrator")
        password = os.path.expandvars(target.get("password", ""))

        COMMANDS = {
            "packages":   "Get-WmiObject -Class Win32_Product | Select Name,Version | ConvertTo-Json",
            "processes":  "Get-Process | Select Name,Id,Path | ConvertTo-Json",
            "network":    "netstat -an",
            "java_homes": "where.exe java 2>$null; $env:JAVA_HOME",
            "log4j_jars": "Get-ChildItem -Recurse -Filter 'log4j*.jar' -ErrorAction SilentlyContinue | Select FullName | ConvertTo-Json",
            "env_vars":   "Get-ChildItem Env: | ConvertTo-Json",
        }

        collection: dict[str, str] = {}
        try:
            session = winrm.Session(host, auth=(user, password))
            for key, cmd in COMMANDS.items():
                try:
                    r = session.run_ps(cmd)
                    collection[key] = r.std_out.decode(errors="replace")
                except Exception:
                    collection[key] = ""
        except Exception as exc:
            log.warning(f"[ssh] WinRM {host} failed: {exc}")
            return []

        # Emit WinRM connectivity/auth wickets first
        try:
            from skg.sensors.adapter_runner import _adapter_module
            from pathlib import Path
            import tempfile, uuid as _uuid
            mod = _adapter_module("skg-host-toolchain", "ssh_collect")
            with tempfile.TemporaryDirectory() as tmpdir:
                out_file = Path(tmpdir) / "winrm_conn_events.ndjson"
                port = int(target.get("port", 5985))
                mod.eval_ho04_winrm_exposed(host, port, out_file, attack_path_id, run_id, workload_id)
                mod.eval_ho05_winrm_credential(host, user, out_file, attack_path_id, run_id, workload_id)
                from skg.sensors.adapter_runner import _read_ndjson
                conn_events = _read_ndjson(out_file)
        except Exception:
            conn_events = []

        aprs_events = run_net_sandbox(collection, workload_id, attack_path_id, run_id)
        return conn_events + aprs_events

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
                conf = self._ctx.calibrate(base_conf, evidence_text, wicket_id, domain, workload_id)
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

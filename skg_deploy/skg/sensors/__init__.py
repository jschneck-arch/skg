from __future__ import annotations

import json
import logging
import subprocess
import threading
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("skg.sensors")

# ── Sensor registry ──────────────────────────────────────────────────────────

_SENSOR_REGISTRY: dict[str, type] = {}
_TOOLCHAIN_ALIASES = {
    "aprs": "skg-aprs-toolchain",
    "container_escape": "skg-container-escape-toolchain",
    "ad_lateral": "skg-ad-lateral-toolchain",
    "host": "skg-host-toolchain",
    "web": "skg-web-toolchain",
    "data": "skg-data-toolchain",
}


def register(name: str):
    def _inner(cls):
        _SENSOR_REGISTRY[name] = cls
        cls.name = name
        return cls
    return _inner


def available_sensors() -> list[str]:
    return list(_SENSOR_REGISTRY.keys())


def _safe_condition_id(wicket_id: str | None = None, node_id: str | None = None) -> str:
    return node_id or wicket_id or ""


def _canonical_toolchain_name(toolchain: str) -> str:
    return _TOOLCHAIN_ALIASES.get(toolchain, toolchain)


# ── Envelope factory ─────────────────────────────────────────────────────────

def envelope(
    event_type: str,
    source_id: str,
    toolchain: str,
    payload: dict,
    evidence_rank: int,
    source_kind: str,
    pointer: str,
    confidence: float = 1.0,
    version: str = "1.0.0",
    ts: str | None = None,
    confidence_vector: list[float] | None = None,
    local_energy: float | None = None,
    phase: float | None = None,
    is_latent: bool | None = None,
) -> dict:
    """
    Build a compliant skg.event.envelope.v1 dict.

    evidence_rank:
      1=runtime
      2=build/classpath
      3=config/filesystem
      4=network
      5=static
      6=scanner

    Backward compatible:
    - old callers can ignore all richer fields
    - newer callers can pass optional substrate hints
    """
    now = ts or datetime.now(timezone.utc).isoformat()

    evidence = {
        "source_kind": source_kind,
        "pointer": pointer,
        "collected_at": now,
        "confidence": confidence,
    }

    if confidence_vector is not None:
        evidence["confidence_vector"] = confidence_vector
    if local_energy is not None:
        evidence["local_energy"] = local_energy
    if phase is not None:
        evidence["phase"] = phase

    payload = dict(payload)
    if is_latent is not None and "is_latent" not in payload:
        payload["is_latent"] = bool(is_latent)

    return {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": event_type,
        "source": {
            "source_id": source_id,
            "toolchain": _canonical_toolchain_name(toolchain),
            "version": version,
        },
        "payload": payload,
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": evidence,
        },
    }


def precondition_payload(
    wicket_id: str | None = None,
    label: str = "",
    domain: str = "",
    workload_id: str = "",
    realized: bool | None = None,
    status: str | None = None,
    detail: str = "",
    attack_path_id: str = "",
    node_id: str | None = None,
) -> dict:
    """
    Standard payload for obs.attack.precondition events.

    realized=None preserves the tri-state (unknown ≠ blocked).

    Backward compatible with wicket_id while also carrying node_id alias.
    """
    condition_id = _safe_condition_id(wicket_id=wicket_id, node_id=node_id)

    if status is None:
        if realized is True:
            status = "realized"
        elif realized is False:
            status = "blocked"
        else:
            status = "unknown"

    return {
        "wicket_id": condition_id,
        "node_id": condition_id,
        "label": label,
        "domain": domain,
        "workload_id": workload_id,
        "realized": realized,
        "status": status,
        "detail": detail,
        "attack_path_id": attack_path_id,
    }


# ── Base sensor ──────────────────────────────────────────────────────────────

class BaseSensor(ABC):
    name: str = "base"

    def __init__(self, cfg: dict, events_dir: Path | None = None):
        self.cfg = cfg
        self._ctx = None  # injected by SensorLoop after daemon boot

        if events_dir:
            self.events_dir = events_dir
        else:
            from skg.core.paths import EVENTS_DIR
            self.events_dir = EVENTS_DIR

        self.events_dir.mkdir(parents=True, exist_ok=True)

    def emit(self, events: list[dict]) -> list[str]:
        if not events:
            return []

        slug = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = self.events_dir / f"{self.name}_{slug}.ndjson"
        ids = []

        with out.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
                ids.append(ev["id"])

        log.info(f"[{self.name}] {len(ids)} events → {out.name}")
        return ids

    @abstractmethod
    def run(self) -> list[str]:
        ...


# ── Target config loader ──────────────────────────────────────────────────────

def _load_targets(config_dir: Path) -> list[dict]:
    """
    Load targets.yaml from config_dir.
    Returns list of target dicts with at minimum: host, method, enabled.
    """
    targets_file = config_dir / "targets.yaml"
    if not targets_file.exists():
        return []

    try:
        import yaml
        with targets_file.open() as fh:
            data = yaml.safe_load(fh)

        if isinstance(data, dict):
            return [t for t in data.get("targets", []) if t.get("enabled", True)]
        if isinstance(data, list):
            return [t for t in data if t.get("enabled", True)]
    except ImportError:
        pass
    except Exception as exc:
        log.warning(f"targets.yaml parse error: {exc}")

    return []


def _load_skg_config(config_dir: Path) -> dict:
    """Load skg_config.yaml or skg.yaml from config_dir."""
    for fname in ("skg_config.yaml", "skg.yaml", "config.yaml"):
        f = config_dir / fname
        if f.exists():
            try:
                import yaml
                with f.open() as fh:
                    return yaml.safe_load(fh) or {}
            except Exception:
                pass
    return {}


# ── collect_host / project_host ───────────────────────────────────────────────

def collect_host(
    target: dict,
    events_dir: Path,
    tc_dir: Path,
    run_id: str,
) -> bool:
    """
    Run a single-target collection using the SSH sensor and write
    envelope events to events_dir.

    target keys: host, method (ssh|winrm|agent), user, password, key, port,
                 workload_id, attack_path_id, enabled
    Returns True on success.
    """
    from skg.sensors.ssh_sensor import SshSensor

    host = target.get("host", "")
    method = target.get("method", "ssh").lower()
    wid = target.get("workload_id", host)

    if not host:
        log.warning("collect_host: no host in target dict")
        return False

    sensor_cfg = {
        "targets": [target],
        "timeout_s": 30,
        "collect_interval_s": 0,
    }

    try:
        sensor = SshSensor(sensor_cfg, events_dir=events_dir)
        sensor._force_collect = True
        ids = sensor.run()
        log.info(f"collect_host: {host} → {len(ids)} events (run {run_id})")
        return True
    except Exception as exc:
        log.error(f"collect_host failed for {host}: {exc}", exc_info=True)
        return False


def project_host(
    ev_file: Path,
    interp_dir: Path,
    tc_dir: Path,
    workload_id: str,
    attack_path_id: str,
    run_id: str,
) -> Path | None:
    """
    Run projection on collected events using the host toolchain.
    Returns path to interp output file, or None on failure.
    """
    if not tc_dir.exists():
        log.warning(f"project_host: tc_dir {tc_dir} does not exist")
        return None

    venv_python = tc_dir / ".venv" / "bin" / "python"
    cli = tc_dir / "skg_host.py"
    if not venv_python.exists() or not cli.exists():
        log.warning(f"project_host: host toolchain not bootstrapped at {tc_dir}")
        return None

    out_path = interp_dir / f"host_{workload_id}_{run_id}.json"
    cmd = [
        str(venv_python), str(cli),
        "project",
        "--in", str(ev_file),
        "--out", str(out_path),
        "--attack-path-id", attack_path_id,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode == 0 and out_path.exists():
            log.info(f"project_host: {workload_id} → {out_path.name}")
            return out_path
        else:
            log.warning(f"project_host failed: {result.stderr[:200]}")
            return None
    except Exception as exc:
        log.error(f"project_host exception: {exc}")
        return None


# ── Sensor loop ───────────────────────────────────────────────────────────────

class SensorLoop:
    """
    Background sensor polling loop, driven by daemon mode transitions.

    Instantiated by SKGKernel. The daemon calls:
      .start()
      .stop()
      .trigger()
      .status()
    """

    def __init__(
        self,
        events_dir: Path,
        interp_dir: Path,
        config_dir: Path,
        host_tc_dir: Path,
        interval: int = 60,
        auto_project: bool = False,
        graph=None,
        obs_memory=None,
        feedback=None,
    ):
        self._events_dir = events_dir
        self._interp_dir = interp_dir
        self._config_dir = config_dir
        self._host_tc_dir = host_tc_dir
        self._interval = interval
        self._auto_project = auto_project
        self._running = False
        self._thread: threading.Thread | None = None
        self._sensors: list[BaseSensor] = []
        self._last_run: str = ""
        self._run_count: int = 0
        self._cfg: dict = {}
        self._graph = graph
        self._obs_memory = obs_memory
        self._feedback = feedback
        self._load_sensors()

    def _load_sensors(self):
        """Load all sensor modules (triggers @register decorators)."""
        self._cfg = _load_skg_config(self._config_dir)
        sensor_cfg = self._cfg.get("sensors", {})

        from skg.sensors import (  # noqa: F401
            usb_sensor, ssh_sensor, msf_sensor, cve_sensor, agent_sensor,
            bloodhound_sensor, web_sensor, net_sensor, data_sensor
        )

        enabled = sensor_cfg.get("enabled", list(_SENSOR_REGISTRY.keys()))
        self._sensors = []

        for name in enabled:
            if name not in _SENSOR_REGISTRY:
                continue
            try:
                scfg = sensor_cfg.get(name, {})
                inst = _SENSOR_REGISTRY[name](scfg, events_dir=self._events_dir)
                self._sensors.append(inst)
                log.info(f"Sensor loaded: {name}")
            except Exception as exc:
                log.warning(f"Sensor '{name}' failed to load: {exc}")

        for s in self._sensors:
            if hasattr(s, "_config_dir"):
                s._config_dir = self._config_dir

        if self._graph is not None:
            inject_context(self._sensors, self._graph, self._obs_memory)

    def _sweep(self, run_id: str):
        """Run all sensors once, optionally project, then run feedback loop."""
        log.info(f"[SensorLoop] sweep start (run={run_id})")
        total = 0

        for s in self._sensors:
            try:
                ids = s.run()
                total += len(ids)
            except Exception as exc:
                log.error(f"Sensor {s.name} error: {exc}", exc_info=True)

        self._last_run = datetime.now(timezone.utc).isoformat()
        self._run_count += 1
        log.info(f"[SensorLoop] sweep done: {total} events (run={run_id})")

        if self._auto_project and total > 0:
            self._auto_project_all(run_id)

            try:
                from skg.forge.pipeline import run_forge_pipeline
                resonance = getattr(self, "_resonance", None)
                forge_summary = run_forge_pipeline(
                    events_dir=self._events_dir,
                    resonance_engine=resonance,
                )
                if forge_summary.get("proposed", 0) > 0:
                    log.info(
                        f"[SensorLoop] forge: {forge_summary['proposed']} new proposal(s) — "
                        f"run 'skg proposals list' to review"
                    )
            except Exception as _fe:
                log.debug(f"[SensorLoop] forge pipeline error: {_fe}")

        if self._feedback is not None:
            try:
                fb_result = self._feedback.process_new_interps()
                if fb_result["transitions"] > 0:
                    log.info(
                        f"[SensorLoop] feedback: {fb_result['transitions']} transitions, "
                        f"{fb_result['propagations']} propagated (run={run_id})"
                    )
            except Exception as exc:
                log.error(f"Feedback loop error: {exc}", exc_info=True)

    def _auto_project_all(self, run_id: str):
        """Project all event files from this run across all toolchains."""
        from skg.sensors.projector import project_events_dir

        outputs = project_events_dir(
            self._events_dir, self._interp_dir,
            run_id=run_id, since_run_id=run_id
        )
        if outputs:
            log.info(f"[SensorLoop] projected {len(outputs)} workload+path pairs (run={run_id})")
        else:
            from skg.sensors.projector import project_event_file

            count = 0
            for ev_file in sorted(self._events_dir.glob("*.ndjson"))[-20:]:
                results = project_event_file(ev_file, self._interp_dir, run_id)
                count += len(results)
            if count:
                log.info(f"[SensorLoop] projected {count} results (full scan, run={run_id})")

    def _loop(self):
        while self._running:
            run_id = str(uuid.uuid4())[:8]
            try:
                self._sweep(run_id)
            except Exception as exc:
                log.error(f"SensorLoop sweep error: {exc}", exc_info=True)
            time.sleep(self._interval)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, name="skg-sensor-loop", daemon=True
        )
        self._thread.start()
        log.info(f"SensorLoop started (interval={self._interval}s, auto_project={self._auto_project})")

    def stop(self):
        if not self._running:
            return
        self._running = False
        log.info("SensorLoop stopped")

    def trigger(self) -> str:
        """Run one immediate sweep outside of the polling loop. Returns run_id."""
        run_id = str(uuid.uuid4())[:8]
        t = threading.Thread(
            target=self._sweep, args=(run_id,), name="skg-sensor-trigger", daemon=True
        )
        t.start()
        return run_id

    def status(self) -> dict:
        return {
            "running": self._running,
            "interval_s": self._interval,
            "auto_project": self._auto_project,
            "sensors": [s.name for s in self._sensors],
            "sensor_count": len(self._sensors),
            "run_count": self._run_count,
            "last_run": self._last_run,
        }


# ── Context injection ─────────────────────────────────────────────────────────

def inject_context(sensors: list, graph, obs_memory) -> None:
    """
    Inject SensorContext into all sensors after daemon systems boot.
    Called by SKGKernel.boot() after WorkloadGraph and ObservationMemory load.
    """
    from skg.sensors.context import SensorContext
    ctx = SensorContext(graph=graph, obs_memory=obs_memory)
    for s in sensors:
        s._ctx = ctx
    log.info(f"SensorContext injected into {len(sensors)} sensors")


def emit_events(events: list[dict], events_dir, source_tag: str = "sensor") -> list[str]:
    """
    Write a list of pre-built envelope events to EVENTS_DIR.
    Returns list of event IDs written.
    Used by sensors that get events from adapter_runner.
    """
    import uuid as _uuid
    from datetime import datetime, timezone as _tz

    if events_dir is None:
        return []

    events_dir = Path(events_dir)
    events_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(_tz.utc).strftime("%Y%m%dT%H%M%S")
    tag = source_tag.replace("/", "_").replace(":", "_")[:40]
    out_path = events_dir / f"{ts}_{tag}.ndjson"
    ids = []

    with out_path.open("a") as fh:
        for ev in events:
            if "id" not in ev:
                ev["id"] = str(_uuid.uuid4())
            fh.write(json.dumps(ev) + "\n")
            ids.append(ev["id"])

    return ids

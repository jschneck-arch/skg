"""
skg.core.daemon
===============
The SKG daemon. Single entry point. Owns everything.

- Manages operational mode (Kernel/Resonance/Unified/Anchor)
- Maintains append-only identity journal
- Orchestrates toolchain runs based on mode
- Dispatches to domain-specific toolchains (aprs, container_escape)
- Exposes FastAPI for CLI IPC on 127.0.0.1:5055

The toolchains manage their own venvs and projection logic.
The daemon calls them as subprocesses — no duplication.
"""
import glob, hashlib, json, logging, math, os, selectors, signal, subprocess, sys, threading, time
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from skg.core.assistant_contract import (
    DERIVED_ADVICE,
    MUTATION_ARTIFACT,
    assistant_output_metadata,
)
from skg_core.config.paths import EVENTS_DIR, INTERP_DIR, SKG_HOME, SKG_CONFIG_DIR, SKG_STATE_DIR, DISCOVERY_DIR
from skg_services.gravity.path_policy import (
    AD_TOOLCHAIN_DIR,
    CE_TOOLCHAIN_DIR,
    HOST_TOOLCHAIN_DIR,
    IDENTITY_FILE,
    LOG_FILE,
    PID_FILE,
    RESONANCE_DIR,
    TOOLCHAIN_DIR,
    ensure_runtime_dirs,
)
from skg_registry import DomainRegistry as _CanonicalDomainRegistry
from skg_services.gravity.domain_runtime import (
    load_daemon_domains_from_inventory as _service_load_daemon_domains_from_inventory,
)
from skg.modes import Mode, ModeTransition, MODE_BEHAVIOR, valid_transition
from skg.identity import Identity, parse_workload_ref
from skg.resonance.engine import ResonanceEngine
from skg.resonance.ingester import ingest_all
from skg.temporal import DeltaStore
from skg.temporal.feedback import FeedbackIngester
from skg.graph import WorkloadGraph
from skg.sensors import SensorLoop
from skg.kernel.pearls import Pearl, PearlLedger

UI_DIR = SKG_HOME / "ui"


def _surface_score(path: str) -> tuple[int, int, float]:
    try:
        data = json.loads(Path(path).read_text())
        targets = data.get("targets", []) or []
        target_count = sum(1 for t in targets if t.get("ip") or t.get("host"))
        service_count = sum(len(t.get("services", []) or []) for t in targets)
        return (target_count + service_count, target_count, os.path.getmtime(path))
    except Exception:
        return (0, 0, os.path.getmtime(path))


def _select_surface_path() -> str | None:
    surfaces = glob.glob(str(DISCOVERY_DIR / "surface_*.json"))
    if not surfaces:
        return None
    return max(surfaces, key=_surface_score)


def _load_interp_payload(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return None
    return data.get("payload", data) if isinstance(data, dict) else None


_DOMAIN_ALIAS_GROUPS: list[set[str]] = [
    {"binary", "binary_analysis"},
    {"data", "data_pipeline"},
    {"container", "container_escape"},
    {"lateral", "ad", "ad_lateral"},
    {"iot", "iot_firmware"},
]


def _projection_domain_aliases(domain: str) -> set[str]:
    raw = str(domain or "").strip() or "unknown"
    for group in _DOMAIN_ALIAS_GROUPS:
        if raw in group:
            return group | {raw}
    return {raw}


def _infer_projection_domain(payload: dict, filename: str) -> str:
    explicit = str(payload.get("domain") or "").strip()
    if explicit:
        return explicit

    for key, domain_name in [
        ("aprs", "aprs"),
        ("lateral_score", "ad_lateral"),
        ("escape_score", "container_escape"),
        ("host_score", "host"),
        ("web_score", "web"),
        ("ai_score", "ai_target"),
        ("data_score", "data"),
        ("supply_chain_score", "supply_chain"),
        ("iot_score", "iot_firmware"),
        ("binary_score", "binary"),
    ]:
        if key in payload:
            return domain_name

    lower_name = filename.lower()
    if "binary" in lower_name:
        return "binary"
    if "host" in lower_name:
        return "host"
    if "web" in lower_name:
        return "web"
    if "data" in lower_name:
        return "data"
    if "lateral" in lower_name or "ad_" in lower_name:
        return "ad_lateral"
    if "escape" in lower_name or "container" in lower_name:
        return "container_escape"
    if "aprs" in lower_name or "log4j" in lower_name:
        return "aprs"
    return ""


def _find_projection_files(interp_dir: Path, domain: str, workload_id: str) -> list[Path]:
    aliases = _projection_domain_aliases(domain)
    candidates: list[Path] = []
    seen: set[Path] = set()

    for alias in aliases:
        for path in list(interp_dir.glob(f"{alias}_{workload_id}_*.json")) + list(interp_dir.glob(f"{alias}_{workload_id}_*_interp.ndjson")):
            if path not in seen:
                seen.add(path)
                candidates.append(path)

    for path in list(interp_dir.glob("*.json")) + list(interp_dir.glob("*_interp.ndjson")):
        if path in seen:
            continue
        payload = _load_interp_payload(path)
        if not payload:
            continue
        if str(payload.get("workload_id") or "") != workload_id:
            continue
        payload_domain = _infer_projection_domain(payload, path.name)
        if payload_domain not in aliases:
            continue
        seen.add(path)
        candidates.append(path)

    return sorted(candidates, key=lambda f: f.stat().st_mtime)


def _configured_local_targets() -> list[dict[str, Any]]:
    try:
        import yaml
        from urllib.parse import urlparse

        cfg_path = SKG_CONFIG_DIR / "skg_config.yaml"
        if not cfg_path.exists():
            cfg_path = SKG_HOME / "config" / "skg_config.yaml"
        cfg = yaml.safe_load(cfg_path.read_text()) or {}
        resonance = cfg.get("resonance", {}) or {}
        ollama = resonance.get("ollama", {}) or {}
        url = str(ollama.get("url") or "").strip()
        if not url:
            return []
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip().lower()
        if host not in {"127.0.0.1", "localhost"}:
            return []
        port = int(parsed.port or 11434)
        model = str(ollama.get("model") or "").strip()
        banner = "Ollama API" + (f" ({model})" if model else "")
        return [{
            "host": "127.0.0.1",
            "ip": "127.0.0.1",
            "hostname": "localhost",
            "os": "local",
            "kind": "local-ai-service",
            "services": [{"port": port, "service": "ollama", "banner": banner}],
            "domains": ["ai_target", "web"],
            "applicable_attack_paths": [],
        }]
    except Exception:
        return []


def _resonance_boot_timeout_s(default: float = 5.0) -> float:
    try:
        import yaml

        cfg_path = SKG_CONFIG_DIR / "skg_config.yaml"
        if not cfg_path.exists():
            cfg_path = SKG_HOME / "config" / "skg_config.yaml"
        cfg = yaml.safe_load(cfg_path.read_text()) or {}
        resonance = cfg.get("resonance", {}) or {}
        timeout_s = float(resonance.get("boot_timeout_s", default) or default)
        return max(0.5, timeout_s)
    except Exception:
        return default

def _canonical_inventory_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for domain in _CanonicalDomainRegistry.discover().list_domains():
        metadata = dict(domain.manifest.metadata or {})
        project_sub = metadata.get("project_sub") or []
        if not isinstance(project_sub, list):
            project_sub = []

        default_path = str(
            metadata.get("default_path")
            or metadata.get("default_attack_path")
            or ""
        ).strip()

        projector_path = ""
        projector_available = False
        if domain.projectors_dir.exists():
            run_root = domain.projectors_dir / "run.py"
            if run_root.exists():
                projector_available = True
                projector_path = str(run_root.relative_to(domain.root_dir))
            else:
                nested = sorted(domain.projectors_dir.glob("*/run.py"))
                if nested:
                    projector_available = True
                    projector_path = str(nested[0].relative_to(domain.root_dir))

        rows.append(
            {
                "name": domain.name,
                "runtime": domain.manifest.runtime,
                "daemon_native": bool(metadata.get("daemon_native", False)),
                "dir": domain.root_dir,
                "root_dir": domain.root_dir,
                "toolchain": domain.root_dir.name,
                "description": str(metadata.get("description") or ""),
                "default_path": default_path,
                "project_sub": [str(part) for part in project_sub],
                "interp_type": str(metadata.get("interp_type") or ""),
                "manifest_present": domain.manifest_path.exists(),
                "manifest_path": str(domain.manifest_path),
                "catalog_count": len(list(domain.catalogs_dir.glob("*.json"))) if domain.catalogs_dir.exists() else 0,
                "projector_available": projector_available,
                "projector_path": projector_path,
                "cli_available": bool(metadata.get("cli")),
                "cli": str(metadata.get("cli") or ""),
                "bootstrapped": bool(metadata.get("bootstrapped", False)),
            }
        )

    return rows


def _summarize_inventory(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": row.get("name", ""),
            "daemon_native": bool(row.get("daemon_native", False)),
            "dir": str(row.get("dir", "")),
            "default_path": row.get("default_path", ""),
            "description": row.get("description", ""),
            "manifest_present": bool(row.get("manifest_present", False)),
            "catalog_count": int(row.get("catalog_count", 0) or 0),
            "projector_available": bool(row.get("projector_available", False)),
            "projector_path": row.get("projector_path", ""),
            "cli_available": bool(row.get("cli_available", False)),
            "bootstrapped": bool(row.get("bootstrapped", False)),
        }
        for row in rows
    ]


def _load_domains_and_inventory() -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    rows = _canonical_inventory_rows()
    domains = _service_load_daemon_domains_from_inventory(rows)
    return domains, _summarize_inventory(rows)


DOMAINS, DOMAIN_INVENTORY = _load_domains_and_inventory()


def setup_logging() -> logging.Logger:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_FILE)],
    )
    return logging.getLogger("skg.daemon")


class Toolchain:
    """
    Domain-aware toolchain interface.
    Each domain (aprs, container_escape) has its own venv and CLI.
    This class wraps any of them via the DOMAINS registry.
    """

    def __init__(self, domain: str):
        if domain not in DOMAINS:
            raise ValueError(f"Unknown domain '{domain}'. Known: {list(DOMAINS)}")
        self.domain  = domain
        cfg          = DOMAINS[domain]
        self.dir     = cfg["dir"]
        self._py     = self.dir / ".venv" / "bin" / "python"
        self._cli    = self.dir / cfg["cli"]
        self._proj   = cfg["project_sub"]
        self._itype  = cfg["interp_type"]
        self.log     = logging.getLogger(f"skg.toolchain.{domain}")

    def available(self) -> bool:
        return self._py.exists() and self._cli.exists()

    def _run(self, *args) -> int:
        cmd = [str(self._py), str(self._cli)] + list(args)
        return subprocess.call(cmd, cwd=str(self.dir))

    def ingest(self, adapter: str, attack_path_id: str,
               run_id: str, workload_id: str, **kwargs) -> tuple[bool, Path]:
        if not self.available():
            self.log.warning(f"{self.domain} toolchain not bootstrapped.")
            return False, Path()
        out = EVENTS_DIR / f"{self.domain}_{workload_id}_{run_id}.ndjson"
        args = ["ingest", adapter,
                "--out", str(out),
                "--attack-path-id", attack_path_id,
                "--run-id", run_id,
                "--workload-id", workload_id]
        for k, v in kwargs.items():
            args += [f"--{k.replace('_','-')}", str(v)]
        self.log.info(f"ingest [{self.domain}] {adapter} → {out.name}")
        return self._run(*args) == 0, out

    def project(self, attack_path_id: str, run_id: str,
                workload_id: str, events_file: Path) -> Path | None:
        if not self.available():
            return None
        out = INTERP_DIR / f"{self.domain}_{workload_id}_{run_id}_interp.ndjson"
        args = self._proj + [
            "--in", str(events_file),
            "--out", str(out),
            "--attack-path-id", attack_path_id,
            "--run-id", run_id,
            "--workload-id", workload_id,
        ]
        self.log.info(f"project [{self.domain}] {attack_path_id} → {out.name}")
        return out if self._run(*args) == 0 else None

    def latest(self, attack_path_id: str,
               workload_id: str, interp_file: Path) -> dict | None:
        if not self.available() or not interp_file.exists():
            return None
        r = subprocess.run(
            [str(self._py), str(self._cli), "latest",
             "--interp", str(interp_file),
             "--attack-path-id", attack_path_id,
             "--workload-id", workload_id],
            capture_output=True, text=True, cwd=str(self.dir)
        )
        if r.returncode == 0 and r.stdout.strip():
            try:
                return json.loads(r.stdout)
            except Exception:
                pass
        return None


class SKGKernel:
    def __init__(self):
        self.log        = logging.getLogger("skg.kernel")
        # Read default mode from config
        try:
            import yaml
            cfg = yaml.safe_load(open(SKG_CONFIG_DIR / 'skg_config.yaml'))
            _default = cfg.get('default_mode', 'kernel').upper()
            self._mode = Mode[_default]
        except Exception:
            self._mode = Mode.KERNEL
        self._started   = datetime.now(timezone.utc).isoformat()
        self.identity   = Identity(IDENTITY_FILE)
        self.toolchains = {d: Toolchain(d) for d in DOMAINS}
        self.resonance  = ResonanceEngine(RESONANCE_DIR)
        self.sphere_gpu = None  # lazy-initialized virtual local accelerator
        self.mcp_threading = None  # lazy-initialized layered MCP orchestrator
        self.delta      = DeltaStore(SKG_STATE_DIR / "delta")
        self.graph      = WorkloadGraph(SKG_STATE_DIR / "graph")
        self.feedback   = None  # initialized in boot() after resonance loads
        self.sensors    = SensorLoop(
            events_dir   = EVENTS_DIR,
            interp_dir   = INTERP_DIR,
            config_dir   = SKG_CONFIG_DIR,
            host_tc_dir  = HOST_TOOLCHAIN_DIR,
            interval     = MODE_BEHAVIOR[Mode.RESONANCE]["sensor_interval_s"],
            auto_project = True,
            graph        = self.graph,
            obs_memory   = None,     # updated in boot() after resonance loads
            feedback     = None,     # updated in boot() after feedback initializes
        )
        # Gravity field loop — runs as a background thread
        self._gravity_thread:  threading.Thread | None = None
        self._gravity_focus_thread: threading.Thread | None = None
        self._gravity_stop:    threading.Event = threading.Event()
        self._gravity_state:   dict = {
            "running":      False,
            "cycle":        0,
            "total_entropy": None,
            "total_unknowns": None,
            "field_pull_boost": None,
            "last_cycle_at": None,
            "cycle_started_at": None,
            "current_surface": None,
            "current_activity": None,
            "recent_output": [],
            "last_returncode": None,
            "error":        None,
        }

    def get_toolchain(self, domain: str) -> "Toolchain":
        if domain not in self.toolchains:
            raise ValueError(f"Unknown domain '{domain}'. Known: {list(DOMAINS)}")
        return self.toolchains[domain]

    def boot(self) -> None:
        ensure_runtime_dirs()
        self.log.info("SKG kernel booting...")
        ident = self.identity.load()
        self.log.info(f"Identity: {ident.name} v{ident.version} | sessions={ident.sessions}")
        self.identity.update({"mode": self._mode.value, "sessions": ident.sessions + 1},
                             source="system.daemon.boot")
        for domain, tc in self.toolchains.items():
            status = "ready" if tc.available() else "not bootstrapped — run bootstrap.sh"
            self.log.info(f"Toolchain [{domain}]: {status}")

        # Boot resonance engine and ingest toolchains if memory is empty,
        # but do not let a slow embedder block the whole daemon.
        try:
            boot_timeout_s = _resonance_boot_timeout_s()
            pool = ThreadPoolExecutor(max_workers=1)
            future = pool.submit(self.resonance.boot)
            future.result(timeout=boot_timeout_s)
            pool.shutdown(wait=False, cancel_futures=False)

            rs = self.resonance.status()
            mem = rs.get("memory", {}) or {}
            total = sum(v for v in mem.values() if isinstance(v, (int, float)))
            if total == 0:
                self.log.info("Resonance memory empty — ingesting toolchains...")
                summary = ingest_all(self.resonance, SKG_HOME)
                self.log.info(f"Resonance ingestion complete: {summary}")
            else:
                self.log.info(f"Resonance memory: "
                              f"wickets={mem.get('wickets', 0)} "
                              f"adapters={mem.get('adapters', 0)} "
                              f"domains={mem.get('domains', 0)}")
        except FutureTimeoutError:
            try:
                pool.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            self.log.warning(
                f"Resonance engine boot timed out after {boot_timeout_s:.1f}s — continuing without it"
            )
        except Exception as e:
            try:
                pool.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
            self.log.warning(f"Resonance engine failed to boot: {e} — continuing without it")

        # Boot temporal delta store and workload graph
        try:
            self.graph.load()
            self.log.info(f"WorkloadGraph: {self.graph.status()['edge_count']} edges loaded")
        except Exception as e:
            self.log.warning(f"WorkloadGraph failed to load: {e}")

        # Initialize feedback ingester (links delta, graph, obs memory)
        try:
            obs_memory = getattr(self.resonance, "observations", None)
            self.feedback = FeedbackIngester(
                delta_store=self.delta,
                graph=self.graph,
                obs_memory=obs_memory,
                interp_dir=INTERP_DIR,
                events_dir=EVENTS_DIR,
            )
            # Process any interp files that arrived before this boot
            # Wire feedback and obs_memory into the sensor loop now that they exist
            self.sensors._feedback  = self.feedback
            self.sensors._obs_memory = obs_memory
            if obs_memory is not None and self.sensors._sensors:
                from skg.sensors import inject_context
                inject_context(self.sensors._sensors, self.graph, obs_memory)
            result = self.feedback.process_new_interps()
            if result["processed"] > 0:
                self.log.info(
                    f"Feedback boot catch-up: {result['processed']} interps, "
                    f"{result['transitions']} transitions, "
                    f"{result['propagations']} propagations"
                )
        except Exception as e:
            self.log.warning(f"Feedback ingester failed to initialize: {e}")

        # Initialize SphereGPU virtual accelerator after resonance is available.
        try:
            self.ensure_sphere_gpu()
        except Exception as e:
            self.log.warning(f"SphereGPU failed to initialize: {e}")

        # Initialize layered MCP threading orchestrator after resonance is available.
        try:
            self.ensure_mcp_threading()
        except Exception as e:
            self.log.warning(f"MCP threading failed to initialize: {e}")

        self.log.info(f"Mode: {self._mode.value} | online.")
        # Start gravity field loop only when explicitly configured.
        try:
            import yaml as _yaml
            cfg = _yaml.safe_load(open(SKG_CONFIG_DIR / "skg_config.yaml")) or {}
            gravity_cfg = cfg.get("gravity", {}) or {}
            autostart = bool(gravity_cfg.get("autostart", cfg.get("gravity_autostart", False)))
        except Exception:
            autostart = False
        if autostart:
            self.gravity_start()
        else:
            self.log.info("Gravity autostart disabled; operator must start the loop explicitly.")

    def shutdown(self) -> None:
        self.log.info("SKG shutting down...")
        self.gravity_stop()
        self.sensors.stop()
        PID_FILE.unlink(missing_ok=True)
        self.log.info("SKG offline.")

    def gravity_start(self) -> None:
        """Start the gravity field loop as a background thread."""
        if self._gravity_thread and self._gravity_thread.is_alive():
            return
        self._gravity_stop.clear()
        self._gravity_thread = threading.Thread(
            target=self._gravity_loop,
            name="skg-gravity",
            daemon=True,
        )
        self._gravity_thread.start()
        self.log.info("Gravity field loop started.")

    def gravity_stop(self) -> None:
        """Signal the gravity loop to stop and wait for it to exit."""
        self._gravity_stop.set()
        if self._gravity_thread and self._gravity_thread.is_alive():
            self._gravity_thread.join(timeout=10)
        self._gravity_state["running"] = False
        self.log.info("Gravity field loop stopped.")

    def gravity_status(self) -> dict:
        return dict(self._gravity_state)

    def _run_gravity_cycle(self, surface_path: str, cycle_label: str, focus_target: str | None = None,
                           authorized: bool = False) -> None:
        gravity_dir = SKG_HOME / "skg-gravity"
        gravity_script = gravity_dir / "gravity_field.py"
        self._gravity_state["error"] = None
        self._gravity_state["cycle_started_at"] = datetime.now(timezone.utc).isoformat()
        self._gravity_state["current_surface"] = surface_path
        self._gravity_state["current_activity"] = f"Starting {cycle_label}"
        self._gravity_state["recent_output"] = []
        self._gravity_state["last_returncode"] = None
        self._gravity_state["field_pull_boost"] = None

        cmd = [
            sys.executable, "-u", str(gravity_script),
            "--surface", surface_path,
            "--cycles", "1",
            "--out-dir", str(DISCOVERY_DIR),
        ]
        if focus_target:
            cmd.extend(["--target", focus_target])
        if authorized:
            cmd.append("--authorized")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        sel = selectors.DefaultSelector()
        if proc.stdout:
            sel.register(proc.stdout, selectors.EVENT_READ)

        start = time.time()
        recent_lines: list[str] = []
        saw_completion = False
        completion_seen_at: float | None = None

        def _terminate_proc_group(sig=signal.SIGTERM) -> None:
            try:
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                pass
            except Exception:
                try:
                    proc.send_signal(sig)
                except Exception:
                    pass

        while True:
            if time.time() - start > 90:
                _terminate_proc_group(signal.SIGTERM)
                try:
                    proc.wait(timeout=2)
                except Exception:
                    _terminate_proc_group(signal.SIGKILL)
                self._gravity_state["error"] = f"{cycle_label} timed out"
                self._gravity_state["current_activity"] = f"{cycle_label} timed out"
                self.log.warning(f"{cycle_label} timed out (90s)")
                break

            events = sel.select(timeout=0.5)
            for key, _ in events:
                line = key.fileobj.readline()
                if not line:
                    continue
                line = line.rstrip()
                if not line:
                    continue
                recent_lines.append(line)
                recent_lines = recent_lines[-24:]
                self._gravity_state["recent_output"] = list(recent_lines)
                self._gravity_state["current_activity"] = line[:240]
                if "Field dynamics complete." in line:
                    saw_completion = True
                    completion_seen_at = time.time()
                if "total E=" in line:
                    try:
                        e_val = float(line.split("total E=")[1].split()[0])
                        self._gravity_state["total_entropy"] = round(e_val, 2)
                    except Exception:
                        pass
                if "Unresolved:" in line:
                    try:
                        u_val = float(line.split("Unresolved:")[1].split()[0])
                        self._gravity_state["total_unknowns"] = round(u_val, 2)
                    except Exception:
                        pass
                if "Field+" in line and "Fold+" in line:
                    try:
                        parts = line.split()
                        for idx, token in enumerate(parts):
                            if token == "Field+" and idx + 1 < len(parts):
                                field_token = parts[idx + 1].strip()
                                if field_token.startswith("+"):
                                    self._gravity_state["field_pull_boost"] = round(float(field_token[1:]), 2)
                    except Exception:
                        pass
                if "total unknowns," in line or "total unknowns" in line:
                    try:
                        u_val = int(line.strip().split()[0])
                        self._gravity_state["total_unknowns"] = u_val
                    except Exception:
                        pass

            if saw_completion and proc.poll() is None and completion_seen_at is not None:
                if time.time() - completion_seen_at > 3:
                    self.log.info(f"{cycle_label} reached completion banner but process lingered; terminating wrapper process group")
                    _terminate_proc_group(signal.SIGTERM)
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        _terminate_proc_group(signal.SIGKILL)

            if proc.poll() is not None:
                if proc.stdout:
                    for line in proc.stdout:
                        line = line.rstrip()
                        if not line:
                            continue
                        recent_lines.append(line)
                        recent_lines = recent_lines[-24:]
                self._gravity_state["recent_output"] = list(recent_lines)
                self._gravity_state["last_returncode"] = proc.returncode
                self._gravity_state["last_cycle_at"] = datetime.now(timezone.utc).isoformat()
                self._gravity_state["current_activity"] = (
                    recent_lines[-1][:240] if recent_lines else f"{cycle_label} complete"
                )
                if proc.returncode != 0:
                    self.log.debug(f"{cycle_label} exited rc={proc.returncode}")
                break

    def gravity_run_target(self, node_key: str, authorized: bool = False) -> None:
        if self._gravity_thread and self._gravity_thread.is_alive():
            raise ValueError("Stop the continuous gravity loop before running a focused target cycle.")
        if self._gravity_focus_thread and self._gravity_focus_thread.is_alive():
            raise ValueError("A focused gravity cycle is already running.")

        focus_key = str(node_key or "").strip()
        if not focus_key:
            raise ValueError("No focus identity supplied.")
        surface_path = _select_surface_path()
        if not surface_path:
            raise ValueError("No surface file — run discovery first")

        def _worker():
            self._gravity_state["running"] = True
            self._gravity_state["cycle"] = int(self._gravity_state.get("cycle") or 0) + 1
            try:
                self._run_gravity_cycle(surface_path, f"focused cycle for {focus_key}", focus_target=focus_key, authorized=authorized)
            except Exception as exc:
                self._gravity_state["error"] = str(exc)
                self.log.warning(f"Focused gravity cycle error: {exc}")
            finally:
                self._gravity_state["running"] = False

        self._gravity_focus_thread = threading.Thread(
            target=_worker,
            name=f"skg-gravity-focus-{focus_key}",
            daemon=True,
        )
        self._gravity_focus_thread.start()

    def _gravity_loop(self) -> None:
        """
        Continuous gravity field dynamics — the daemon's primary observational loop.

        Reads gravity cycle interval from config (gravity_cycle_interval_s, default 120).
        Uses gravity_field_loop() logic inline to avoid subprocess overhead and share
        instrument state across cycles.
        """
        try:
            import yaml as _yaml
            cfg = _yaml.safe_load(open(SKG_CONFIG_DIR / "skg_config.yaml")) or {}
            gravity_cfg = cfg.get("gravity", {}) or {}
            interval = int(gravity_cfg.get("cycle_interval_s", cfg.get("gravity_cycle_interval_s", 120)))
            epsilon  = float(gravity_cfg.get("convergence_epsilon", cfg.get("gravity_convergence_epsilon", 0.01)))
        except Exception:
            interval = 120
            epsilon  = 0.01

        self._gravity_state["running"] = True
        self.log.info(f"Gravity loop: interval={interval}s epsilon={epsilon}")

        cycle = 0
        while not self._gravity_stop.is_set():
            surface_path = _select_surface_path()
            if not surface_path:
                self._gravity_state["error"] = "No surface file — run discovery first"
                self._gravity_stop.wait(timeout=interval)
                continue
            cycle += 1
            self._gravity_state["cycle"] = cycle
            try:
                self._run_gravity_cycle(surface_path, f"cycle {cycle}")
            except Exception as exc:
                self._gravity_state["error"] = str(exc)
                self.log.warning(f"Gravity cycle error: {exc}")

            self._gravity_stop.wait(timeout=interval)

        self._gravity_state["running"] = False

    def set_mode(self, new_mode: Mode, reason: str = "") -> ModeTransition:
        valid, msg = valid_transition(self._mode, new_mode)
        if not valid:
            raise ValueError(msg)
        t = ModeTransition(from_mode=self._mode, to_mode=new_mode, reason=reason)
        self.identity.lock(new_mode == Mode.ANCHOR)
        if new_mode != Mode.ANCHOR:
            self.identity.update({"mode": new_mode.value}, source="system.daemon.mode_change")
        self._mode = new_mode

        # Sensor loop: run in RESONANCE and UNIFIED, stop in KERNEL and ANCHOR
        behavior = MODE_BEHAVIOR[new_mode]
        if behavior.get("toolchain_runs"):
            auto_project = (new_mode == Mode.UNIFIED)
            self.sensors._interval     = behavior["sensor_interval_s"]
            self.sensors._auto_project = auto_project
            self.sensors.start()
        else:
            self.sensors.stop()

        self.log.info(f"Mode: {t.from_mode.value} → {t.to_mode.value}" +
                      (f" ({reason})" if reason else ""))
        return t

    def status(self) -> dict:
        ident = self.identity.current
        b     = MODE_BEHAVIOR[self._mode]
        tc_status = {
            domain: "ready" if tc.available() else "not bootstrapped"
            for domain, tc in self.toolchains.items()
        }
        try:
            rs = self.resonance.status()
        except Exception:
            rs = {
                "ready": False,
                "memory": {
                    "wickets": 0,
                    "adapters": 0,
                    "domains": 0,
                    "observations": None,
                },
            }
        return {
            "status": "online",
            "mode": self._mode.value,
            "mode_description": b["description"],
            "toolchain_runs_enabled": b["toolchain_runs"],
            "toolchains": tc_status,
            "resonance": rs,
            "sensors": self.sensors.status(),
            "started_at": self._started,
            "identity": {
                "name":      ident.name      if ident else "unknown",
                "version":   ident.version   if ident else "unknown",
                "coherence": ident.coherence if ident else 0.0,
                "sessions":  ident.sessions  if ident else 0,
            },
        }

    def ensure_sphere_gpu(self):
        if self.sphere_gpu is not None:
            return self.sphere_gpu
        try:
            from skg.resonance.sphere_gpu import SphereGPU

            self.sphere_gpu = SphereGPU.from_config(self.resonance)
            return self.sphere_gpu
        except Exception as exc:
            self.log.warning(f"SphereGPU unavailable: {exc}")
            self.sphere_gpu = None
            return None

    def ensure_mcp_threading(self):
        if self.mcp_threading is not None:
            return self.mcp_threading
        try:
            from skg.resonance.mcp_threading import MCPThreadingOrchestrator

            self.mcp_threading = MCPThreadingOrchestrator.from_config(self.resonance)
            return self.mcp_threading
        except Exception as exc:
            self.log.warning(f"MCP threading unavailable: {exc}")
            self.mcp_threading = None
            return None


# --- FastAPI ---

kernel = SKGKernel()
app    = FastAPI(title="SKG", version="1.0.0")
if UI_DIR.exists():
    app.mount("/ui/static", StaticFiles(directory=str(UI_DIR)), name="ui-static")


class ModeRequest(BaseModel):
    mode:   str
    reason: str = ""


class IngestRequest(BaseModel):
    domain:         str        = "aprs"
    adapter:        str        = "config_effective"
    attack_path_id: str | None = None   # defaults to domain's default_path
    workload_id:    str        = "default"
    run_id:         str | None = None
    kwargs:         dict       = {}


@app.get("/api")
def api_root():
    return {"skg": "online",
            "domains": list(DOMAINS.keys()),
            "domain_inventory": DOMAIN_INVENTORY,
            "endpoints": ["/status", "/mode", "/identity", "/identity/history",
                          "/ingest", "/projections/{workload_id}",
                          "/gravity/status", "/gravity/start", "/gravity/stop"]}


@app.get("/")
def root():
    return RedirectResponse(url="/ui", status_code=307)


@app.get("/ui")
def ui_index():
    index = UI_DIR / "index.html"
    if not index.exists():
        raise HTTPException(404, "UI not installed")
    return FileResponse(index)


@app.get("/status")
def status():
    base = kernel.status()
    # Inject field_state — this is what separates a projection engine from a scanner.
    # E = H(projection | telemetry): entropy of projection outcome given current measurements.
    # E = 0  → projection is fully determined (emergent or collapsed).
    # E > 0  → unknown nodes remain; value identifies the observational deficit.
    try:
        base["field_state"] = _compute_field_state()
    except Exception as exc:
        base["field_state"] = {"error": str(exc)}
    base["gravity_state"] = kernel.gravity_status()
    return base


@app.post("/status/refresh")
def status_refresh():
    """Invalidate the field_state cache so the next /status call recomputes."""
    _field_state_cache["ts"] = 0.0
    _field_state_cache["data"] = {}
    return {"ok": True, "message": "field_state cache cleared"}


@app.get("/gravity/status")
def gravity_status():
    """Current gravity field state — cycle count, entropy, last run timestamp."""
    return kernel.gravity_status()


@app.post("/gravity/start")
def gravity_start():
    """Start (or restart) the gravity field loop."""
    kernel.gravity_start()
    return {"ok": True, "gravity_state": kernel.gravity_status()}


@app.post("/gravity/stop")
def gravity_stop():
    """Stop the gravity field loop."""
    kernel.gravity_stop()
    return {"ok": True, "gravity_state": kernel.gravity_status()}


@app.post("/gravity/run")
def gravity_run(target_ip: str = "", identity_key: str = "", authorized: bool = False):
    """Run one focused gravity cycle for a selected target."""
    focus_key = str(identity_key or target_ip or "").strip()
    if not focus_key:
        raise HTTPException(400, "target_ip or identity_key required")
    try:
        kernel.gravity_run_target(focus_key, authorized=authorized)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {
        "ok": True,
        "gravity_state": kernel.gravity_status(),
        "target_ip": target_ip,
        "identity_key": focus_key,
    }


_field_state_cache: dict = {"ts": 0.0, "data": {}}
_field_state_computing = threading.Event()
_FIELD_STATE_TTL = 60.0  # seconds


def _refresh_field_state_bg() -> None:
    """Compute field state in a background thread and update the cache."""
    if _field_state_computing.is_set():
        return  # already running
    _field_state_computing.set()
    try:
        result = _compute_field_state_inner()
        import time as _t
        _field_state_cache["ts"] = _t.monotonic()
        _field_state_cache["data"] = result
    except Exception:
        pass
    finally:
        _field_state_computing.clear()


def _compute_field_state() -> dict:
    """Return cached field state, triggering a background refresh if stale.
    If the cache is empty (cold start or after explicit invalidation), compute
    synchronously so the first caller never gets {} (MED-65 fix).
    """
    import time as _time
    now = _time.monotonic()
    stale = now - _field_state_cache["ts"] >= _FIELD_STATE_TTL
    if stale:
        if not _field_state_cache["data"]:
            # Cold cache — compute synchronously so this caller gets a result.
            _refresh_field_state_bg()
        else:
            # Warm cache, just stale — return cached data while refreshing in bg.
            t = threading.Thread(target=_refresh_field_state_bg, daemon=True)
            t.start()
    return _field_state_cache["data"]


def _compute_field_state_inner() -> dict:
    """
    Compute field energy E per active attack path from latest interp files.
    Also loads persisted fold state from the gravity field engine and adds
    fold contribution to E.

    E = |unknown| / |required| + fold_boost (normalized per path)
    """
    from pathlib import Path as _P

    interp_dir = INTERP_DIR
    folds_dir  = DISCOVERY_DIR / "folds"

    # Load fold managers per IP from persisted gravity cycle data
    fold_boost_by_wid: dict[str, float] = {}
    fold_summary_by_wid: dict[str, dict] = {}
    if folds_dir.exists():
        try:
            from skg.kernel.folds import FoldManager
            for fold_file in folds_dir.glob("folds_*.json"):
                fm = FoldManager.load(fold_file)
                # Extract IP from filename: folds_172_17_0_2.json → 172.17.0.2
                ip = fold_file.stem.replace("folds_", "").replace("_", ".")
                boost = fm.total_gravity_weight()
                if boost > 0:
                    fold_boost_by_wid[ip] = boost
                    fold_summary_by_wid[ip] = fm.summary()
        except Exception:
            pass

    def _load_interp_payload(path: _P) -> dict | None:
        try:
            data = json.loads(path.read_text())
        except Exception:
            return None
        return data.get("payload", data) if isinstance(data, dict) else None

    def _normalize_projection_classification(classification: str) -> str:
        if classification in {"realized", "not_realized", "indeterminate",
                               "indeterminate_h1", "unknown"}:
            return classification
        if classification in {"fully_realized"}:
            return "realized"
        if classification in {"blocked"}:
            return "not_realized"
        if classification in {"partial"}:
            return "indeterminate"
        return classification or "unknown"

    field_map: dict[str, float] = {}
    persistence_map: dict[str, float] = {}
    fiber_clusters: dict[str, object] = {}
    try:
        from skg.topology.energy import anchored_field_pull, compute_field_fibers, compute_field_topology

        topo = compute_field_topology(DISCOVERY_DIR, interp_dir).as_dict()
        for sphere, row in (topo.get("spheres") or {}).items():
            field_map[sphere] = float((row or {}).get("gravity_pull", 0.0) or 0.0)
            persistence_map[sphere] = float((row or {}).get("pearl_persistence", 0.0) or 0.0)
        fiber_clusters = {c.anchor: c for c in compute_field_fibers()}
    except Exception:
        anchored_field_pull = None
        field_map = {}
        persistence_map = {}
        fiber_clusters = {}

    # Group interp files by (workload_id, attack_path_id), take latest per group
    latest: dict[tuple, dict] = {}
    for f in sorted(list(interp_dir.glob("*.json")) + list(interp_dir.glob("*_interp.ndjson"))):
        d = _load_interp_payload(f)
        if not d:
            continue
        key = (d.get("workload_id", "?"), d.get("attack_path_id", "?"))
        existing = latest.get(key)
        if existing is None or f.stat().st_mtime > existing["_mtime"]:
            d["_mtime"] = f.stat().st_mtime
            d["_file"]  = str(f)
            latest[key] = d

    field_state: dict[str, dict] = {}
    for (wid, apid), d in sorted(
        latest.items(),
        key=lambda item: (str(item[0][0] or ""), str(item[0][1] or "")),
    ):
        wid = str(wid or "")
        apid = str(apid or "")
        if not wid:
            continue
        required = d.get("required_wickets", [])
        unknown  = d.get("unknown", [])
        blocked  = d.get("blocked", [])
        realized = d.get("realized", [])
        n = len(required)
        if n == 0:
            continue

        # Base E = |unknown| / |required|  (Work 3 Section 4.2)
        E_base = len(unknown) / n

        # Fold boost — structural/contextual/projection/temporal gaps
        # Extract IP from workload_id (e.g. "ssh::172.17.0.2")
        wid_ip = parse_workload_ref(wid).get("identity_key", wid)
        fold_boost   = fold_boost_by_wid.get(wid_ip, 0.0)
        fold_summary = fold_summary_by_wid.get(wid_ip, {})

        # Normalize fold boost relative to required path length so it's
        # comparable across paths of different sizes
        fold_contribution = fold_boost / max(n, 1) if fold_boost > 0 else 0.0
        E = E_base + fold_contribution

        # Resolution hints: what sensors/evidence would close each unknown node
        resolution_required = {}
        for w in unknown:
            resolution_required[w] = _resolution_hint(w)

        classification = _normalize_projection_classification(d.get("classification", "unknown"))
        ident = parse_workload_ref(wid)
        target_domains = set()
        if apid.startswith("host_"):
            target_domains.add("host")
        elif apid.startswith("web_"):
            target_domains.add("web")
        elif apid.startswith("container_escape_"):
            target_domains.add("container_escape")
        elif apid.startswith("data_"):
            target_domains.add("data_pipeline")
        elif apid.startswith("ad_") or apid.startswith("lateral_"):
            target_domains.add("ad_lateral")
        elif apid.startswith("ai_"):
            target_domains.add("ai_target")
        elif apid.startswith("iot_") or apid.startswith("firmware_"):
            target_domains.add("iot_firmware")
        elif apid.startswith("supply_chain_"):
            target_domains.add("supply_chain")
        elif apid.startswith("binary_") or apid.startswith("stack_") or apid.startswith("heap_"):
            target_domains.add("binary_analysis")

        field_pull = (
            anchored_field_pull(
                ident["identity_key"],
                target_domains,
                field_map,
                fiber_clusters,
                sphere_persistence=persistence_map,
            )
            if anchored_field_pull is not None else 0.0
        )
        key = f"{wid}/{apid}"
        field_state[key] = {
            "workload_id":          wid,
            "identity_key":         ident["identity_key"],
            "manifestation_key":    ident["manifestation_key"],
            "attack_path_id":       apid,
            "classification":       classification,
            "E":                    round(E + field_pull, 4),
            "E_base":               round(E_base, 4),
            "fold_contribution":    round(fold_contribution, 4),
            "field_pull":           round(field_pull, 4),
            "E_note":               (
                "0.0 = fully determined" if E == 0.0
                else (
                    f"{round(E_base * 100)}% nodes unobserved"
                    + (f" + {fold_boost:.1f} fold weight" if fold_boost > 0 else "")
                    + (f" + {field_pull:.1f} field pull" if field_pull > 0 else "")
                )
            ),
            "n_required":           n,
            "n_realized":           len(realized),
            "n_blocked":            len(blocked),
            "n_unknown":            len(unknown),
            "unknown_nodes":        unknown,
            "compatibility_score":  round(float(d.get("compatibility_score", 0.0) or 0.0), 4),
            "compatibility_span":   int(d.get("compatibility_span", 0) or 0),
            "decoherence":          round(float(d.get("decoherence", 0.0) or 0.0), 4),
            "unresolved_reason":    d.get("unresolved_reason", ""),
            "resolution_required":  resolution_required,
            "folds":                fold_summary,
            "computed_at":          d.get("computed_at", ""),
        }

    return field_state


def _resolution_hint(wicket_id: str) -> str:
    """
    Return a human-readable hint describing what telemetry would resolve this wicket.
    Derived from wicket ID prefix — no AI, no inference, just pattern rules.
    """
    prefix = wicket_id.split("-")[0].upper() if "-" in wicket_id else wicket_id[:3].upper()
    hints = {
        "HO": "SSH sensor sweep — requires live connection to target host",
        "CE": "Container inspection — docker inspect or USB drop with docker_inspect.json",
        "AD": "BloodHound ingest — requires domain-joined host or bh_data USB drop",
        "AP": "APRS adapter — requires packages.txt + log4j_jars.txt artifact",
        "WB": "Web sensor sweep — HTTP/HTTPS probe against target surface",
        "WEB": "Web sensor sweep — HTTP/HTTPS probe against target surface",
        "WE": "Web sensor sweep — HTTP/HTTPS probe against target surface",
        "SC": "CVE sensor — NVD feed cross-reference against installed package list",
        "DP": "Data pipeline profiler — connect to database and run: skg data profile --url <db_url> --table <table>",
        "BA": "Binary analysis — run: skg exploit binary <path> (requires checksec, rabin2, ROPgadget)",
    }
    return hints.get(prefix, f"Sensor sweep required for {wicket_id} — check catalog for evidence_hints")


@app.get("/mode")
def get_mode():
    return {"mode": kernel._mode.value,
            "description": MODE_BEHAVIOR[kernel._mode]["description"]}


@app.post("/mode")
def set_mode(req: ModeRequest):
    try:
        new_mode = Mode(req.mode)
    except ValueError:
        raise HTTPException(400, f"Unknown mode: {req.mode}")
    try:
        t = kernel.set_mode(new_mode, reason=req.reason)
        return {"ok": True, "transition": t.to_dict()}
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.get("/identity")
def get_identity():
    i = kernel.identity.current
    if not i:
        raise HTTPException(503, "Identity not loaded.")
    return i.to_dict()


@app.get("/identity/history")
def identity_history():
    return kernel.identity.history()


@app.post("/ingest")
def ingest(req: IngestRequest):
    if not MODE_BEHAVIOR[kernel._mode]["toolchain_runs"]:
        raise HTTPException(409, f"Toolchain disabled in {kernel._mode.value} mode. "
                                 f"Switch to resonance or unified first.")
    try:
        tc = kernel.get_toolchain(req.domain)
    except ValueError as e:
        raise HTTPException(400, str(e))

    import uuid
    run_id         = req.run_id or str(uuid.uuid4())
    attack_path_id = req.attack_path_id or DOMAINS[req.domain]["default_path"]

    ok, events_file = tc.ingest(
        adapter=req.adapter, attack_path_id=attack_path_id,
        run_id=run_id, workload_id=req.workload_id, **req.kwargs)
    if not ok:
        raise HTTPException(500, f"Ingest failed [{req.domain}]. Check logs.")

    interp_file = tc.project(
        attack_path_id=attack_path_id, run_id=run_id,
        workload_id=req.workload_id, events_file=events_file)

    return {"ok": True, "domain": req.domain, "run_id": run_id,
            "workload_id": req.workload_id, "attack_path_id": attack_path_id,
            "events": str(events_file),
            "interp": str(interp_file) if interp_file else None}


@app.get("/projections/{workload_id}/field")
def get_projection_field(workload_id: str, domain: str = "host"):
    """
    Field state view — E, state history, resolution requirements.
    This is the primary endpoint for the projection engine.
    Use /projections/{workload_id} for the raw interp data.
    """
    import math, json
    from pathlib import Path as _P
    from fastapi import HTTPException as _H

    def _normalize_projection_classification(classification: str) -> str:
        if classification in {"realized", "not_realized", "indeterminate",
                               "indeterminate_h1", "unknown"}:
            return classification
        if classification in {"fully_realized"}:
            return "realized"
        if classification in {"blocked"}:
            return "not_realized"
        if classification in {"partial"}:
            return "indeterminate"
        return classification or "unknown"

    files = _find_projection_files(INTERP_DIR, domain, workload_id)
    if not files:
        raise _H(404, f"No projection data for {domain}/{workload_id}")

    history = []
    import math as _math
    for f in files:
        try:
            d = _load_interp_payload(f)
            if not d:
                continue
            n = len(d.get("required_wickets", []))
            unknown = d.get("unknown", [])
            # E = |unknown| / |required|  (Work 3 Section 4.2)
            E = round(len(unknown) / n, 4) if n else 0.0
            history.append({
                "run_id":         d.get("run_id", ""),
                "computed_at":    d.get("computed_at", ""),
                "classification": _normalize_projection_classification(d.get("classification", "")),
                "E":              round(E, 4),
                "n_realized":     len(d.get("realized", [])),
                "n_blocked":      len(d.get("blocked", [])),
                "n_unknown":      len(unknown),
            })
        except Exception:
            continue

    latest = _load_interp_payload(files[-1]) or {}
    required = latest.get("required_wickets", [])
    unknown  = latest.get("unknown", [])
    n = len(required)
    # E = |unknown| / |required|  (Work 3 Section 4.2)
    E = len(unknown) / n if n else 0.0

    return {
        "substrate": "SKG projection engine — not a findings list",
        "framing": (
            "Tri-state: R=realized (telemetry confirms), B=blocked (constraint prevents), "
            "U=unknown (unmeasured — E>0 while any remain). "
            "E=H(projection|T): entropy of projection outcome given current telemetry. "
            "E=0 means fully determined. E>0 identifies the observational deficit."
        ),
        "workload_id":              workload_id,
        "attack_path_id":           latest.get("attack_path_id", ""),
        "classification":           _normalize_projection_classification(latest.get("classification", "")),
        "E":                        round(E, 4),
        "n_required":               n,
        "n_realized":               len(latest.get("realized", [])),
        "n_blocked":                len(latest.get("blocked", [])),
        "n_unknown":                len(unknown),
        "realized_nodes":           latest.get("realized", []),
        "blocked_nodes":            latest.get("blocked", []),
        "unknown_nodes":            unknown,
        "resolution_required":      {w: _resolution_hint(w) for w in unknown},
        "state_transition_history": history,
        "computed_at":              latest.get("computed_at", ""),
    }


@app.get("/projections/{workload_id}")
def get_projection(workload_id: str,
                   domain: str = "aprs",
                   attack_path_id: str | None = None):
    matches = _find_projection_files(INTERP_DIR, domain, workload_id)
    if not matches:
        raise HTTPException(404, f"No projections for workload '{workload_id}' domain '{domain}'")
    result = _load_interp_payload(matches[-1])
    if result:
        if attack_path_id and result.get("attack_path_id") != attack_path_id:
            raise HTTPException(404, "No matching projection.")
        return result

    try:
        tc = kernel.get_toolchain(domain)
    except ValueError as e:
        raise HTTPException(400, str(e))

    attack_path_id = attack_path_id or DOMAINS[domain]["default_path"]
    result = tc.latest(attack_path_id, workload_id, matches[-1])
    if not result:
        raise HTTPException(404, "No matching projection.")
    return result


# --- Resonance endpoints ---

@app.get("/resonance/status")
def resonance_status():
    try:
        return kernel.resonance.status()
    except Exception:
        return kernel.resonance.status_offline()


@app.get("/resonance/query")
def resonance_query(q: str, k: int = 5, type: str = "all"):
    try:
        if type == "wickets":
            results = kernel.resonance.query_wickets(q, k=k)
            return {"wickets": [(r.to_dict(), s) for r, s in results]}
        elif type == "adapters":
            results = kernel.resonance.query_adapters(q, k=k)
            return {"adapters": [(r.to_dict(), s) for r, s in results]}
        elif type == "domains":
            results = kernel.resonance.query_domains(q, k=k)
            return {"domains": [(r.to_dict(), s) for r, s in results]}
        elif type == "corpus":
            results = kernel.resonance.query_corpus(q, k=k)
            return {"corpus": [(r.to_dict(), s) for r, s in results]}
        else:
            return kernel.resonance.surface(q, k_each=k)
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/resonance/local-capabilities")
def resonance_local_capabilities():
    try:
        from skg.resonance.local_corpus import discover_local_capabilities

        return discover_local_capabilities()
    except Exception as e:
        raise HTTPException(500, str(e))


class ResonanceSmartIndexRequest(BaseModel):
    query: str = ""
    theta: str = "general"
    force: bool = False


class ResonanceMCPThreadRequest(BaseModel):
    query: str | None = None
    text: str | None = None
    theta: str = "general"
    prefer: str | None = None
    k_each: int | None = None
    max_workers: int | None = None


@app.post("/resonance/index-smart")
def resonance_index_smart(req: ResonanceSmartIndexRequest):
    try:
        from skg.resonance.local_corpus import smart_index_local_corpus

        return smart_index_local_corpus(
            kernel.resonance,
            query=req.query,
            theta=req.theta,
            force=bool(req.force),
        )
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/resonance/mcp/status")
def resonance_mcp_status():
    try:
        mcp = kernel.ensure_mcp_threading()
        if mcp is None:
            raise RuntimeError("MCP threading is unavailable")
        return mcp.status()
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/resonance/mcp/thread")
def resonance_mcp_thread(req: ResonanceMCPThreadRequest):
    try:
        mcp = kernel.ensure_mcp_threading()
        if mcp is None:
            raise RuntimeError("MCP threading is unavailable")
        text = (req.query or req.text or "").strip()
        if not text:
            raise HTTPException(400, "query text is required")
        return mcp.thread(
            text,
            theta=req.theta,
            prefer=req.prefer,
            k_each=req.k_each,
            max_workers=req.max_workers,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/resonance/index-micro")
def resonance_index_micro(req: ResonanceSmartIndexRequest):
    try:
        from skg.resonance.local_corpus import micro_index_local_corpus

        return micro_index_local_corpus(
            kernel.resonance,
            query=req.query,
            theta=req.theta,
            force=bool(req.force),
        )
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/resonance/ingest")
def resonance_ingest():
    try:
        from skg.resonance.ingester import ingest_all
        summary = ingest_all(kernel.resonance, SKG_HOME)
        return {"ok": True, "summary": summary}
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/resonance/ollama/status")
def resonance_ollama_status():
    """Check ollama availability and selected model."""
    try:
        from skg.resonance.ollama_backend import OllamaBackend
        backend = OllamaBackend()
        return backend.status()
    except Exception as e:
        return {"available": False, "error": str(e)}


@app.get("/resonance/llm-pool/status")
def resonance_llm_pool_status():
    """Return LLM pool status: strategy, backends, availability."""
    try:
        from skg.resonance.llm_pool import get_pool
        return get_pool().status()
    except Exception as e:
        return {"error": str(e)}


@app.get("/resonance/drafts")
def resonance_drafts():
    try:
        return {"drafts": kernel.resonance.list_drafts()}
    except Exception as e:
        raise HTTPException(500, str(e))


class SphereAskRequest(BaseModel):
    query: str | None = None
    text: str | None = None
    r: float = 0.35
    theta: str = "general"
    phi: float = 0.5
    stream: int = 0
    k_each: int | None = None


class SphereBatchRequest(BaseModel):
    requests: list[dict[str, Any]] = []
    max_workers: int | None = None


@app.get("/resonance/sphere/status")
def resonance_sphere_status():
    try:
        sphere = kernel.ensure_sphere_gpu()
        if sphere is None:
            raise RuntimeError("SphereGPU is unavailable")
        return sphere.status()
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/resonance/sphere/ask")
def resonance_sphere_ask(req: SphereAskRequest):
    try:
        from skg.resonance.sphere_gpu import SpherePoint

        sphere = kernel.ensure_sphere_gpu()
        if sphere is None:
            raise RuntimeError("SphereGPU is unavailable")
        text = (req.query or req.text or "").strip()
        if not text:
            raise HTTPException(400, "query text is required")
        point = SpherePoint.from_values(
            r=req.r,
            theta=req.theta,
            phi=req.phi,
            stream=req.stream,
        )
        return sphere.infer(query=text, point=point, k_each=req.k_each)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/resonance/sphere/batch")
def resonance_sphere_batch(req: SphereBatchRequest):
    try:
        sphere = kernel.ensure_sphere_gpu()
        if sphere is None:
            raise RuntimeError("SphereGPU is unavailable")
        requests = list(req.requests or [])
        if not requests:
            raise HTTPException(400, "requests list is required")
        results = sphere.infer_batch(requests, max_workers=req.max_workers)
        return {
            "results": results,
            "status": sphere.status(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# --- Sensors / collect endpoints ---

class CollectRequest(BaseModel):
    target:         str | None = None   # specific host IP, or None for all targets
    method:         str        = "ssh"
    user:           str | None = None
    password:       str | None = None
    key:            str | None = None
    port:           int        = 22
    workload_id:    str | None = None
    attack_path_id: str        = "host_ssh_initial_access_v1"
    auto_project:   bool       = False


class ProposalRejectRequest(BaseModel):
    reason: str = ""
    cooldown_days: int = 30


class ProposalDeferRequest(BaseModel):
    days: int = 7


class AssistantExplainRequest(BaseModel):
    kind: str
    id: str = ""
    identity_key: str = ""
    limit: int = 6
    context: dict[str, Any] | None = None
    task: str = ""


class AssistantWhatIfRequest(BaseModel):
    kind: str
    id: str = ""
    identity_key: str = ""
    limit: int = 6
    context: dict[str, Any] | None = None
    question: str = ""
    action: dict[str, Any] | None = None


class AssistantDemandRequest(BaseModel):
    kind: str
    id: str = ""
    identity_key: str = ""
    limit: int = 6
    context: dict[str, Any] | None = None


class AssistantDraftDemandRequest(BaseModel):
    demand: dict[str, Any] | None = None
    demand_id: str = ""
    demand_kind: str = ""
    kind: str = ""
    id: str = ""
    identity_key: str = ""
    limit: int = 6
    context: dict[str, Any] | None = None
    use_llm: bool = True


@app.post("/collect")
def collect(req: CollectRequest):
    """Trigger an immediate host collection sweep (or single-target collection)."""
    if not MODE_BEHAVIOR[kernel._mode]["toolchain_runs"]:
        raise HTTPException(409, f"Collection disabled in {kernel._mode.value} mode. "
                                 f"Switch to resonance or unified first.")

    if req.target:
        # Single-target: build synthetic target dict and run directly
        import uuid as _uuid
        run_id = str(_uuid.uuid4())[:8]
        target = {
            "host":           req.target,
            "method":         req.method,
            "user":           req.user or "root",
            "password":       req.password,
            "key":            req.key,
            "port":           req.port,
            "workload_id":    req.workload_id or f"ssh::{req.target}",
            "attack_path_id": req.attack_path_id,
            "enabled":        True,
        }
        from skg.sensors import collect_host
        from skg_services.gravity.projector_runtime import project_events_dir as _proj_dir
        ok = collect_host(target, EVENTS_DIR, HOST_TOOLCHAIN_DIR, run_id)
        # Locate the emitted file(s) by run_id suffix — the filename is not
        # predictable from workload_id alone after the emit_events refactor.
        ev_files = list(EVENTS_DIR.glob(f"*_{run_id}.ndjson")) if ok else []
        interp_path = None
        if ok and req.auto_project and ev_files:
            results = _proj_dir(EVENTS_DIR, INTERP_DIR, since_run_id=run_id)
            interp_path = results[0] if results else None
        return {
            "ok": ok,
            "run_id": run_id,
            "target": req.target,
            "events_file": str(ev_files[0]) if ev_files else None,
            "interp_file": str(interp_path) if interp_path else None,
        }
    else:
        # Trigger sweep of all targets.yaml entries
        run_id = kernel.sensors.trigger()
        return {"ok": True, "run_id": run_id, "mode": "sweep_all"}


@app.get("/sensors")
def sensors_status():
    return kernel.sensors.status()


@app.post("/sensors/trigger")
def sensors_trigger():
    """Trigger an immediate sensor sweep outside of the polling interval."""
    if not MODE_BEHAVIOR[kernel._mode]["toolchain_runs"]:
        raise HTTPException(409, f"Sensors disabled in {kernel._mode.value} mode.")
    run_id = kernel.sensors.trigger()
    return {"ok": True, "run_id": run_id}


@app.get("/targets")
def list_targets():
    from skg.sensors import _load_targets

    def _view_index() -> dict[str, dict[str, Any]]:
        try:
            current_surface = field_surface()
        except Exception:
            return {}

        grouped: dict[str, dict[str, Any]] = {}
        for row in current_surface.get("workloads") or []:
            identity_key = str(
                row.get("identity_key")
                or parse_workload_ref(str(row.get("workload_id") or "")).get("identity_key")
                or ""
            ).strip()
            if not identity_key:
                continue
            group = grouped.setdefault(identity_key, {
                "identity_key": identity_key,
                "domains": set(),
                "manifestations": set(),
                "fresh_unknown_mass": 0,
                "observed_tools": {},
            })
            domain = str(row.get("domain") or "").strip()
            if domain:
                group["domains"].add(domain)
            manifestation_key = str(row.get("manifestation_key") or "").strip()
            if manifestation_key:
                group["manifestations"].add(manifestation_key)
            group["fresh_unknown_mass"] += len(row.get("unknown") or [])
            tool_overlay = dict(row.get("observed_tools", {}) or {})
            if tool_overlay.get("tool_names") or tool_overlay.get("observed_tools"):
                group["observed_tools"] = tool_overlay

        for group in grouped.values():
            group["domains"] = sorted(group["domains"])
            group["manifestations"] = sorted(group["manifestations"])
        return grouped

    merged: dict[str, dict[str, Any]] = {}
    for target in _all_targets_index():
        identity_key = str(
            target.get("identity_key")
            or parse_workload_ref(
                str(target.get("workload_id") or target.get("ip") or target.get("host") or "")
            ).get("identity_key")
            or ""
        ).strip()
        if not identity_key:
            continue
        current = dict(merged.get(identity_key, {}))
        current.update(dict(target))
        current["identity_key"] = identity_key
        merged[identity_key] = current

    for identity_key, view in _view_index().items():
        current = dict(merged.get(identity_key, {}))
        current.setdefault("identity_key", identity_key)
        current.setdefault("ip", identity_key if identity_key.count(".") == 3 else "")
        current.setdefault("host", current.get("ip") or identity_key)
        domains = set(current.get("domains") or [])
        domains.update(view.get("domains") or [])
        current["domains"] = sorted(domains)
        current["manifestations"] = list(view.get("manifestations") or [])
        current["fresh_unknown_mass"] = int(view.get("fresh_unknown_mass") or 0)
        current["observed_tools"] = dict(view.get("observed_tools", {}) or {})
        merged[identity_key] = current

    for identity_key, target in list(merged.items()):
        try:
            target["profile"] = _identity_profile(identity_key)
        except Exception:
            target["profile"] = {"evidence_count": 0}
        try:
            target["world_summary"] = _identity_world(identity_key, target).get("world_summary", {})
        except Exception:
            target["world_summary"] = {}
        try:
            target["relations"] = _identity_relations(identity_key, target)[:12]
        except Exception:
            target["relations"] = []
        merged[identity_key] = target

    targets = sorted(
        merged.values(),
        key=lambda row: (
            str(row.get("identity_key") or row.get("ip") or row.get("host") or ""),
            str(row.get("workload_id") or ""),
        ),
    )
    return {"targets": targets}


@app.get("/world/{identity_key}")
def identity_world(identity_key: str):
    try:
        targets = list_targets().get("targets", [])
        target = next(
            (
                t for t in targets
                if _identity_matches(
                    identity_key,
                    t.get("identity_key"),
                    t.get("ip"),
                    t.get("host"),
                    t.get("hostname"),
                )
            ),
            {},
        )
        # Canonicalize to the matched target's identity key so that
        # manifestation lookup uses the same form as the measured state (MED-78)
        canonical_key = (
            target.get("identity_key") or target.get("host") or target.get("hostname") or identity_key
        ) if target else identity_key
        world = _identity_world(canonical_key, target)
        world["computed_at"] = datetime.now(timezone.utc).isoformat()
        return world
    except Exception as exc:
        raise HTTPException(500, f"World error: {exc}")


@app.get("/surface")
def field_surface(min_score: float = 0.0):
    """Current operator-facing attack surface synthesized from latest projections."""
    try:
        from skg.intel.surface import surface as build_surface

        result = build_surface(
            interp_dir=INTERP_DIR,
            delta_store=kernel.delta,
            graph=kernel.graph,
            min_score=min_score,
        )
        result["computed_at"] = datetime.now(timezone.utc).isoformat()
        return result
    except Exception as exc:
        raise HTTPException(500, f"Surface error: {exc}")


def _normalized_identity_token(identity_key: str) -> str:
    return (identity_key or "").replace(".", "_").replace(":", "_").lower()


def _identity_aliases(*values: str) -> set[str]:
    aliases: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        aliases.add(text)
        parsed = parse_workload_ref(text)
        for candidate in (
            parsed.get("identity_key"),
            parsed.get("host"),
            parsed.get("locator"),
            parsed.get("manifestation_key"),
        ):
            candidate_text = str(candidate or "").strip()
            if candidate_text:
                aliases.add(candidate_text)
    return aliases


def _identity_matches(identity_key: str, *values: str) -> bool:
    needle = str(identity_key or "").strip()
    if not needle:
        return False
    return needle in _identity_aliases(*values)


def _proposal_identity_key(proposal: dict[str, Any]) -> str:
    hosts = list(proposal.get("hosts") or [])
    action = proposal.get("action") or {}
    parsed = parse_workload_ref(
        str(
            proposal.get("identity_key")
            or (hosts[0] if hosts else "")
            or action.get("workload_id")
            or ""
        )
    )
    return str(parsed.get("identity_key") or proposal.get("identity_key") or (hosts[0] if hosts else "")).strip()


def _proposal_matches_identity(proposal: dict[str, Any], identity_key: str) -> bool:
    if not identity_key:
        return True
    hosts = list(proposal.get("hosts") or [])
    action = proposal.get("action") or {}
    return identity_key in _identity_aliases(
        proposal.get("identity_key"),
        action.get("workload_id"),
        *hosts,
    )


def _latest_matching_files(patterns: list[str], limit: int = 12, per_pattern: int = 3) -> list[str]:
    seen: set[str] = set()
    files: list[str] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
        for path in matches[:max(1, int(per_pattern))]:
            if path in seen:
                continue
            seen.add(path)
            files.append(path)
    files.sort(key=os.path.getmtime, reverse=True)
    return files[:limit]


def _identity_profile(identity_key: str) -> dict[str, Any]:
    token = _normalized_identity_token(identity_key)
    rows: list[dict[str, Any]] = []
    patterns = [
        str(DISCOVERY_DIR / f"gravity_ssh_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_ssh_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_audit_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_audit_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_sysaudit_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_sysaudit_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_postexp_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_http_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_http_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_auth_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_auth_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_nmap_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_nmap_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_pcap_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_pcap_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_binary_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_binary_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_data_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_data_{token}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_data_*_{identity_key}*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_data_*_{token}*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_ce_{identity_key}_*.ndjson"),
        str(DISCOVERY_DIR / f"gravity_ce_{token}_*.ndjson"),
    ]
    for path in _latest_matching_files(patterns, limit=12):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    ev = json.loads(line)
                    payload = ev.get("payload", {}) or {}
                    wid = payload.get("workload_id", "")
                    target_ip = payload.get("target_ip") or ""
                    if identity_key not in wid and identity_key != target_ip:
                        continue
                    rows.append(ev)
        except Exception:
            continue

    profile: dict[str, Any] = {
        "users": [],
        "groups": [],
        "id_output": None,
        "passwd_samples": [],
        "kernel_version": None,
        "package_count": None,
        "package_manager": None,
        "packages_sample": [],
        "docker_access": None,
        "interesting_suid": [],
        "credential_indicators": [],
        "env_key_samples": [],
        "ssh_keys": [],
        "av_edr": None,
        "domain_membership": None,
        "sudo_state": None,
        "process_count": None,
        "process_findings": [],
        "datastore_access": [],
        "datastore_observations": [],
        "network_findings": [],
        "network_flows": [],
        "listening_baseline": None,
        "container": {},
        "notes": [],
        "evidence_count": len(rows),
    }

    for ev in rows:
        payload = ev.get("payload", {}) or {}
        wicket = payload.get("wicket_id")
        attrs = payload.get("attributes", {}) or {}
        notes = payload.get("notes") or payload.get("detail") or ""
        if notes and notes not in profile["notes"]:
            profile["notes"].append(notes)
        lowered_notes = str(notes).lower() if notes else ""
        if any(token in lowered_notes for token in ("no route to host", "connection refused", "target unreachable", "timed out")):
            finding = {
                "wicket_id": wicket,
                "detail": str(notes).strip(),
                "pointer": ((ev.get("provenance") or {}).get("evidence") or {}).get("pointer"),
            }
            if finding not in profile["network_findings"]:
                profile["network_findings"].append(finding)
        if notes and "→" in str(notes):
            m = re.search(r"([A-Z0-9_-]+)\s+([0-9.]+)→([0-9.]+):(\d+)", str(notes))
            if m:
                flow = {
                    "protocol": m.group(1),
                    "src": m.group(2),
                    "dst": m.group(3),
                    "port": int(m.group(4)),
                }
                if flow not in profile["network_flows"]:
                    profile["network_flows"].append(flow)

        if wicket == "HO-03" and attrs.get("user"):
            if attrs["user"] not in profile["users"]:
                profile["users"].append(attrs["user"])
        if wicket == "HO-03" and notes:
            sample = str(notes).strip()
            if sample and sample not in profile["passwd_samples"]:
                profile["passwd_samples"].append(sample)
        if wicket == "HO-10":
            profile["sudo_state"] = notes or profile["sudo_state"]
            id_output = attrs.get("id_output", "")
            if id_output:
                profile["id_output"] = id_output
            if "groups=" in id_output:
                try:
                    groups = id_output.split("groups=", 1)[1]
                    for raw in groups.split(","):
                        group = raw.strip()
                        if group and group not in profile["groups"]:
                            profile["groups"].append(group)
                except Exception:
                    pass
        if wicket == "HO-06":
            profile["sudo_state"] = notes or profile["sudo_state"]
        if wicket == "HO-07":
            for item in attrs.get("interesting_suid", []) or []:
                if item not in profile["interesting_suid"]:
                    profile["interesting_suid"].append(item)
        if wicket == "HO-09":
            for item in attrs.get("sources_with_hits", []) or []:
                if item not in profile["credential_indicators"]:
                    profile["credential_indicators"].append(item)
            for item in attrs.get("sample_keys", []) or []:
                if item not in profile["env_key_samples"]:
                    profile["env_key_samples"].append(item)
        if wicket == "HO-11":
            profile["package_count"] = attrs.get("package_count") or profile["package_count"]
            profile["package_manager"] = attrs.get("package_manager") or profile["package_manager"]
            for item in attrs.get("packages_sample", []) or []:
                if item not in profile["packages_sample"]:
                    profile["packages_sample"].append(item)
        if wicket == "HO-12":
            profile["kernel_version"] = attrs.get("kernel_version") or profile["kernel_version"]
        if wicket == "HO-13":
            for item in attrs.get("key_files", []) or []:
                if item not in profile["ssh_keys"]:
                    profile["ssh_keys"].append(item)
        if wicket == "HO-15" and attrs.get("docker_accessible") is not None:
            profile["docker_access"] = bool(attrs.get("docker_accessible"))
        if wicket == "HO-23":
            profile["av_edr"] = notes or profile["av_edr"]
            if attrs.get("checked_procs") is not None:
                profile["process_count"] = attrs.get("checked_procs")
        if wicket and str(wicket).startswith("PI-") and notes:
            finding = {
                "wicket_id": wicket,
                "detail": str(notes).strip(),
            }
            if finding not in profile["process_findings"]:
                profile["process_findings"].append(finding)
            if wicket == "PI-03":
                baseline_match = re.search(r"Listening port baseline:\s*(.+)$", str(notes))
                if baseline_match:
                    profile["listening_baseline"] = baseline_match.group(1).strip()
        if wicket == "HO-24":
            profile["domain_membership"] = notes or profile["domain_membership"]
        if wicket == "DP-10" and notes:
            access = str(notes).strip()
            if access and access not in profile["datastore_access"]:
                profile["datastore_access"].append(access)
            workload_id = payload.get("workload_id", "")
            service = workload_id.split("::", 1)[0] if "::" in workload_id else None
            observation = {
                "service": service,
                "workload_id": workload_id or None,
                "detail": access,
            }
            if observation not in profile["datastore_observations"]:
                profile["datastore_observations"].append(observation)
        if wicket and wicket.startswith("CE-"):
            if "privileged" in payload:
                profile["container"]["privileged"] = payload.get("privileged")
            if "network_mode" in payload:
                profile["container"]["network_mode"] = payload.get("network_mode")
            if "cap_add" in payload:
                profile["container"]["cap_add"] = payload.get("cap_add")

    profile["notes"] = profile["notes"][:8]
    profile["passwd_samples"] = profile["passwd_samples"][:4]
    profile["packages_sample"] = profile["packages_sample"][:20]
    profile["env_key_samples"] = profile["env_key_samples"][:12]
    profile["datastore_access"] = profile["datastore_access"][:8]
    profile["datastore_observations"] = profile["datastore_observations"][:12]
    profile["network_findings"] = profile["network_findings"][:16]
    profile["network_flows"] = profile["network_flows"][:32]
    profile["process_findings"] = profile["process_findings"][:16]
    return profile


def _service_world_views(services: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    web_surfaces = []
    remote_access = []
    datastores = []
    runtime_edges = []

    for svc in services or []:
        port = int(svc.get("port", 0) or 0)
        name = (svc.get("service") or svc.get("name") or "").lower()
        banner = svc.get("banner", "")
        row = {"port": port, "service": name or svc.get("service") or "", "banner": banner}

        if port in {80, 443, 8080, 8443, 8008, 8009} or any(x in name for x in ("http", "https", "ajp")):
            web_surfaces.append(row)
        if port in {21, 22, 23, 25, 139, 445, 5900, 3389} or name in {"ssh", "ftp", "telnet", "smtp", "vnc", "netbios-ssn"}:
            remote_access.append(row)
        if port in {3306, 5432, 5433, 6379, 27017} or name in {"mysql", "postgresql", "redis", "mongodb"}:
            datastores.append(row)
        if port in {2375, 2376, 8009} or name in {"docker", "ajp13"}:
            runtime_edges.append(row)

    return {
        "web_surfaces": web_surfaces,
        "remote_access": remote_access,
        "datastores": datastores,
        "runtime_edges": runtime_edges,
    }


def _all_targets_index() -> list[dict[str, Any]]:
    from skg.sensors import _load_targets

    merged: dict[str, dict[str, Any]] = {}
    for target in _load_targets(SKG_CONFIG_DIR):
        key = target.get("ip") or target.get("host") or target.get("workload_id") or ""
        if key:
            merged[key] = dict(target)

    for surface_path in sorted(glob.glob(str(DISCOVERY_DIR / "surface_*.json")), key=_surface_score):
        try:
            surface_data = json.loads(Path(surface_path).read_text())
        except Exception:
            continue
        for target in surface_data.get("targets", []) or []:
            key = target.get("ip") or target.get("host") or target.get("workload_id") or ""
            if not key:
                continue
            current = dict(merged.get(key, {}))
            current.setdefault("host", target.get("ip") or key)
            current["ip"] = target.get("ip") or current.get("ip") or current.get("host") or ""
            current["os"] = target.get("os") or current.get("os")
            current["kind"] = target.get("kind") or current.get("kind")
            if len(target.get("services") or []) >= len(current.get("services") or []):
                current["services"] = target.get("services") or current.get("services") or []
            domains = set(current.get("domains") or [])
            domains.update(target.get("domains") or [])
            current["domains"] = sorted(domains)
            merged[key] = current

    for target in _configured_local_targets():
        key = target.get("ip") or target.get("host") or target.get("workload_id") or ""
        if key:
            current = dict(merged.get(key, {}))
            current.update({k: v for k, v in target.items() if v})
            merged[key] = current

    return sorted(
        merged.values(),
        key=lambda row: (
            str(row.get("ip") or row.get("host") or ""),
            str(row.get("workload_id") or ""),
        ),
    )


def _identity_relations(identity_key: str, target: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    target = dict(target or {})
    ip = target.get("ip") or identity_key
    all_targets = _all_targets_index()
    bonds: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add_relation(other_ip: str, relation: str, strength: float, detail: str = "") -> None:
        if not other_ip or other_ip == ip:
            return
        key = tuple(sorted((other_ip, relation)))
        if key in seen:
            return
        seen.add(key)
        bonds.append({
            "other_identity": other_ip,
            "relation": relation,
            "strength": round(float(strength), 4),
            "detail": detail,
        })

    parts = ip.rsplit(".", 1)
    if len(parts) == 2:
        subnet_prefix = parts[0] + "."
        for other in all_targets:
            other_ip = other.get("ip") or ""
            if other_ip.startswith(subnet_prefix) and other_ip != ip:
                add_relation(other_ip, "same_subnet", 0.40, f"shared /24 {parts[0]}.0/24")

    if ip.startswith(("172.17.", "172.18.")):
        gateway = ".".join(ip.split(".")[:3]) + ".1"
        if gateway != ip:
            add_relation(gateway, "docker_host", 0.90, "shared bridge gateway")
        bridge_prefix = ".".join(ip.split(".")[:2]) + "."
        for other in all_targets:
            other_ip = other.get("ip") or ""
            if other_ip.startswith(bridge_prefix) and other_ip != ip and not other_ip.endswith(".1"):
                add_relation(other_ip, "same_compose", 0.80, "shared bridge/network family")

    ssh_keys = set((_identity_profile(identity_key).get("ssh_keys") or []))
    if ssh_keys:
        for other in all_targets:
            other_ip = other.get("ip") or ""
            if other_ip == ip:
                continue
            other_keys = set((_identity_profile(other_ip).get("ssh_keys") or []))
            if ssh_keys & other_keys:
                add_relation(other_ip, "shared_cred", 0.70, "shared key material observed")

    return sorted(bonds, key=lambda row: (-row["strength"], row["other_identity"]))


def _world_access_paths(target: dict[str, Any], profile: dict[str, Any], service_views: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    access_paths: list[dict[str, Any]] = []
    users = list(profile.get("users") or [])
    ssh_keys = list(profile.get("ssh_keys") or [])
    env_keys = list(profile.get("env_key_samples") or [])
    datastore_obs = list(profile.get("datastore_observations") or [])
    network_findings = list(profile.get("network_findings") or [])

    for svc in service_views.get("remote_access", []):
        service = str(svc.get("service") or "").lower()
        candidates: list[str] = []
        if service in {"ssh", "ftp", "telnet", "smb", "netbios-ssn", "vnc", "rdp"}:
            candidates.extend(users)
        if service == "ssh":
            candidates.extend(ssh_keys)
            candidates.extend(env_keys)
        constraints = [
            finding["detail"]
            for finding in network_findings
            if str(svc.get("port")) in str(finding.get("pointer") or "")
        ][:4]
        access_paths.append({
            "kind": "remote_access",
            "service": service or svc.get("service"),
            "port": svc.get("port"),
            "banner": svc.get("banner"),
            "credential_candidates": candidates[:8],
            "network_constraints": constraints,
        })

    for svc in service_views.get("datastores", []):
        service = str(svc.get("service") or "").lower()
        confirmed = [
            obs["detail"]
            for obs in datastore_obs
            if (obs.get("service") or "").lower() in {service, ""}
        ]
        access_paths.append({
            "kind": "datastore",
            "service": service or svc.get("service"),
            "port": svc.get("port"),
            "banner": svc.get("banner"),
            "confirmed_access": confirmed[:4],
        })

    if profile.get("docker_access"):
        access_paths.append({
            "kind": "runtime_control",
            "service": "docker",
            "port": 2375 if any(int(s.get("port", 0) or 0) == 2375 for s in target.get("services", []) or []) else None,
            "banner": "docker runtime access observed",
            "credential_candidates": users[:4],
        })

    return access_paths[:24]


def _credential_bindings(profile: dict[str, Any], service_views: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    bindings: list[dict[str, Any]] = []
    users = list(profile.get("users") or [])
    ssh_keys = list(profile.get("ssh_keys") or [])
    env_keys = list(profile.get("env_key_samples") or [])
    indicators = list(profile.get("credential_indicators") or [])

    for svc in service_views.get("remote_access", []):
        service = str(svc.get("service") or "").lower()
        candidates: list[str] = []
        rationale: list[str] = []

        if service in {"ssh", "ftp", "telnet", "smb", "netbios-ssn", "vnc", "rdp"} and users:
            candidates.extend(users)
            rationale.append("observed local principals")
        if service == "ssh" and ssh_keys:
            candidates.extend(ssh_keys)
            rationale.append("observed ssh key material")
        if env_keys:
            candidates.extend(env_keys)
            rationale.append("observed env-key indicators")
        if indicators and not rationale:
            rationale.append("generic credential indicators")

        deduped: list[str] = []
        for item in candidates:
            if item not in deduped:
                deduped.append(item)

        bindings.append({
            "service": service or svc.get("service"),
            "port": svc.get("port"),
            "credentials": deduped[:8],
            "rationale": rationale[:4],
        })

    return bindings[:24]


def _network_topology(identity_key: str, profile: dict[str, Any], relations: list[dict[str, Any]]) -> dict[str, Any]:
    flows = list(profile.get("network_flows") or [])
    inbound_peers: dict[str, dict[str, Any]] = {}
    outbound_peers: dict[str, dict[str, Any]] = {}
    local_ports: dict[int, dict[str, Any]] = {}

    for flow in flows:
        src = str(flow.get("src") or "")
        dst = str(flow.get("dst") or "")
        port = int(flow.get("port") or 0)
        proto = str(flow.get("protocol") or "")
        if dst == identity_key:
            row = inbound_peers.setdefault(src, {"peer": src, "ports": set(), "protocols": set()})
            row["ports"].add(port)
            row["protocols"].add(proto)
            local_ports.setdefault(port, {"port": port, "protocols": set(), "peer_count": 0})
            local_ports[port]["protocols"].add(proto)
            local_ports[port]["peer_count"] += 1
        elif src == identity_key:
            row = outbound_peers.setdefault(dst, {"peer": dst, "ports": set(), "protocols": set()})
            row["ports"].add(port)
            row["protocols"].add(proto)

    relation_peers = [row.get("other_identity") for row in relations if row.get("other_identity")]

    return {
        "findings": list(profile.get("network_findings") or []),
        "flows": flows[:24],
        "inbound_peers": [
            {
                "peer": row["peer"],
                "ports": sorted(row["ports"]),
                "protocols": sorted(row["protocols"]),
            }
            for row in sorted(inbound_peers.values(), key=lambda r: r["peer"])
        ][:16],
        "outbound_peers": [
            {
                "peer": row["peer"],
                "ports": sorted(row["ports"]),
                "protocols": sorted(row["protocols"]),
            }
            for row in sorted(outbound_peers.values(), key=lambda r: r["peer"])
        ][:16],
        "local_ports": [
            {
                "port": row["port"],
                "protocols": sorted(row["protocols"]),
                "peer_count": row["peer_count"],
            }
            for row in sorted(local_ports.values(), key=lambda r: r["port"])
        ][:16],
        "listening_baseline": profile.get("listening_baseline"),
        "relation_peers": relation_peers[:16],
    }


def _identity_manifestations(identity_key: str, limit: int = 64) -> list[dict[str, Any]]:
    # Newest-wins: collect all candidates with mtime, then dedupe on (workload_id, attack_path_id)
    candidates: list[tuple[float, dict[str, Any]]] = []
    for interp_file in list(INTERP_DIR.glob("*.json")) + list(INTERP_DIR.glob("*_interp.ndjson")):
        try:
            mtime = interp_file.stat().st_mtime
            data = json.loads(interp_file.read_text())
        except Exception:
            continue
        payload = data.get("payload", data) if isinstance(data, dict) else {}
        workload_id = payload.get("workload_id")
        if not workload_id:
            continue
        parsed = parse_workload_ref(workload_id)
        if parsed.get("identity_key") != identity_key:
            continue
        candidates.append((mtime, payload, parsed))

    # Sort newest-first so the first occurrence wins
    candidates.sort(key=lambda t: t[0], reverse=True)
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for _mtime, payload, parsed in candidates:
        workload_id = payload.get("workload_id", "")
        key = (workload_id, payload.get("attack_path_id", ""))
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "workload_id": workload_id,
            "manifestation_key": parsed.get("manifestation_key"),
            "attack_path_id": payload.get("attack_path_id", ""),
            "classification": payload.get("classification", "unknown"),
            "score": next(
                (payload[k] for k in (
                    "host_score", "web_score", "data_score", "escape_score",
                    "ai_score", "binary_score", "lateral_score", "iot_score",
                    "supply_chain_score", "aprs",
                ) if payload.get(k) is not None),
                0.0,
            ),
        })
    rows.sort(key=lambda row: (str(row.get("manifestation_key") or ""), str(row.get("attack_path_id") or "")))
    return rows[:limit]


def _identity_world(identity_key: str, target: dict[str, Any] | None = None) -> dict[str, Any]:
    target = dict(target or {})
    profile = _identity_profile(identity_key)
    services = list(target.get("services") or [])
    service_views = _service_world_views(services)
    manifestations = _identity_manifestations(identity_key)
    likely_containerized = bool(
        target.get("kind") == "container"
        or identity_key.startswith(("172.17.", "172.18."))
        or "container_escape" in (target.get("domains") or [])
        or profile.get("container")
    )

    neighbors = []
    seen_neighbors: set[str] = set()
    try:
        candidate_workloads = [m["workload_id"] for m in manifestations if m.get("workload_id")]
        for workload_id in candidate_workloads:
            for neighbor_id, relationship, weight in kernel.graph.neighbors(workload_id):
                if neighbor_id in seen_neighbors:
                    continue
                seen_neighbors.add(neighbor_id)
                neighbors.append({
                    "workload_id": neighbor_id,
                    "relationship": relationship,
                    "weight": round(float(weight), 4),
                    "identity_key": parse_workload_ref(neighbor_id).get("identity_key"),
                })
    except Exception:
        neighbors = []

    relations = _identity_relations(identity_key, target)
    access_paths = _world_access_paths(target, profile, service_views)
    credential_bindings = _credential_bindings(profile, service_views)
    network_topology = _network_topology(identity_key, profile, relations)

    world = {
        "identity_key": identity_key,
        "hostname": target.get("hostname"),
        "kind": target.get("kind"),
        "os": target.get("os"),
        "domains": list(target.get("domains") or []),
        "services": services,
        "manifestations": manifestations,
        "principals": {
            "users": list(profile.get("users") or []),
            "groups": list(profile.get("groups") or []),
            "id_output": profile.get("id_output"),
            "passwd_samples": list(profile.get("passwd_samples") or []),
        },
        "credentials": {
            "indicators": list(profile.get("credential_indicators") or []),
            "env_key_samples": list(profile.get("env_key_samples") or []),
            "ssh_keys": list(profile.get("ssh_keys") or []),
            "sudo_state": profile.get("sudo_state"),
            "bindings": credential_bindings,
        },
        "network": network_topology,
        "runtime": {
            "container": dict(profile.get("container") or {}),
            "docker_access": profile.get("docker_access"),
            "interesting_suid": list(profile.get("interesting_suid") or []),
            "package_manager": profile.get("package_manager"),
            "package_count": profile.get("package_count"),
            "packages_sample": list(profile.get("packages_sample") or []),
            "process_count": profile.get("process_count"),
            "process_findings": list(profile.get("process_findings") or []),
            "kernel_version": None if likely_containerized else profile.get("kernel_version"),
            "shared_kernel_version": profile.get("kernel_version") if likely_containerized else None,
            "kernel_scope": "shared_container_host" if likely_containerized and profile.get("kernel_version") else ("host_runtime" if profile.get("kernel_version") else None),
            "av_edr": profile.get("av_edr"),
            "domain_membership": profile.get("domain_membership"),
            "manifestation_scope": "containerized" if likely_containerized else "host_like",
        },
        "surfaces": service_views,
        "access_paths": access_paths,
        "datastore_access": list(profile.get("datastore_access") or []),
        "datastore_observations": list(profile.get("datastore_observations") or []),
        "neighbors": neighbors[:24],
        "relations": relations[:24],
        "notes": list(profile.get("notes") or []),
        "evidence_count": int(profile.get("evidence_count") or 0),
        "world_summary": {
            "service_count": len(services),
            "manifestation_count": len({m.get("manifestation_key") for m in manifestations if m.get("manifestation_key")}),
            "principal_count": len(profile.get("users") or []) + len(profile.get("groups") or []),
            "credential_count": len(profile.get("credential_indicators") or []) + len(profile.get("ssh_keys") or []),
            "datastore_count": len(service_views["datastores"]),
            "web_surface_count": len(service_views["web_surfaces"]),
            "remote_access_count": len(service_views["remote_access"]),
            "neighbor_count": len(neighbors),
            "relation_count": len(relations),
            "access_path_count": len(access_paths),
            "credential_binding_count": len(credential_bindings),
            "inbound_peer_count": len(network_topology.get("inbound_peers") or []),
            "outbound_peer_count": len(network_topology.get("outbound_peers") or []),
            "containerized_manifestation": likely_containerized,
        },
    }
    if likely_containerized and profile.get("kernel_version"):
        world["notes"].append(
            "Kernel version is observed from a containerized manifestation and may reflect a shared host kernel rather than guest userspace vintage."
        )
    world["notes"] = world["notes"][:12]
    return world


def _artifact_matches_identity(path: Path, identity_key: str) -> tuple[bool, str | None]:
    identity = (identity_key or "").strip()
    if not identity:
        return False, None
    token = _normalized_identity_token(identity)
    name = path.name.lower()
    filename_match = identity.lower() in name or token in name

    # For structured files with parseable payload, prefer payload identity over
    # filename heuristics.  A filename match that contradicts payload identity is
    # rejected so that noise-named files are not attributed to the wrong identity
    # (MED-70 fix).
    try:
        if path.suffix == ".json":
            data = json.loads(path.read_text())
            payload = data.get("payload", data) if isinstance(data, dict) else {}
            workload_id = payload.get("workload_id")
            if workload_id:
                parsed = parse_workload_ref(workload_id)
                if parsed.get("identity_key") == identity:
                    return True, workload_id
                # Payload has a workload_id but it belongs to a different identity —
                # reject even if the filename looked like a match.
                return False, None
            # No workload_id in payload — fall back to filename heuristic.
            return filename_match, None
        elif path.suffix == ".ndjson":
            found_wid: str | None = None
            found_mismatch = False
            for line in path.read_text(errors="replace").splitlines()[:40]:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except Exception:
                    continue
                payload = event.get("payload", event) if isinstance(event, dict) else {}
                workload_id = payload.get("workload_id")
                if workload_id:
                    parsed = parse_workload_ref(workload_id)
                    if parsed.get("identity_key") == identity:
                        found_wid = workload_id
                        break
                    else:
                        found_mismatch = True
            if found_wid:
                return True, found_wid
            if found_mismatch:
                # At least one line had a workload_id pointing at a different identity.
                return False, None
            # No workload_id found in any line — fall back to filename heuristic.
            return filename_match, None
        # Non-JSON file — filename heuristic is all we have.
        return filename_match, None
    except Exception:
        # Can't parse — fall back to filename heuristic.
        return filename_match, None


@app.get("/artifacts/{identity_key}")
def identity_artifacts(identity_key: str, limit: int = 12):
    """Recent runtime artifacts tied to one parsed identity."""
    try:
        limit = max(1, min(limit, 40))
        buckets = [
            ("events", EVENTS_DIR, ("*.ndjson", "*.json")),
            ("interp", INTERP_DIR, ("*.json", "*_interp.ndjson")),
            ("discovery", SKG_STATE_DIR / "discovery", ("*.ndjson", "*.json")),
        ]
        rows: list[dict] = []
        for category, base_dir, patterns in buckets:
            if not base_dir.exists():
                continue
            for pattern in patterns:
                for path in base_dir.glob(pattern):
                    matched, workload_id = _artifact_matches_identity(path, identity_key)
                    if not matched:
                        continue
                    stat = path.stat()
                    rows.append({
                        "category": category,
                        "file": path.name,
                        "path": str(path),
                        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                        "size": stat.st_size,
                        "workload_id": workload_id,
                    })
        rows.sort(key=lambda row: row["mtime"], reverse=True)
        return {
            "identity_key": identity_key,
            "count": len(rows),
            "artifacts": rows[:limit],
        }
    except Exception as exc:
        raise HTTPException(500, f"Artifact lookup error: {exc}")


@app.get("/timeline/{identity_key}")
def identity_timeline(identity_key: str, limit: int = 40):
    """Aggregate timeline across workload manifestations of one identity."""
    try:
        if kernel.feedback is None:
            raise HTTPException(503, "Feedback ingester not initialized")

        limit = max(1, min(limit, 200))
        workloads: set[str] = set()

        # Primary source: interp files
        for interp_file in list(INTERP_DIR.glob("*.json")) + list(INTERP_DIR.glob("*_interp.ndjson")):
            try:
                data = json.loads(interp_file.read_text())
            except Exception:
                continue
            payload = data.get("payload", data) if isinstance(data, dict) else {}
            workload_id = payload.get("workload_id")
            if not workload_id:
                continue
            parsed = parse_workload_ref(workload_id)
            if parsed.get("identity_key") == identity_key:
                workloads.add(workload_id)

        # Secondary source: recent events files — covers identities whose interp
        # artifacts may have been archived or not yet produced (MED-66 fix).
        if EVENTS_DIR.exists():
            _recent_events = sorted(
                EVENTS_DIR.glob("*.ndjson"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )[:50]
            for ev_file in _recent_events:
                try:
                    for _line in ev_file.read_text(errors="replace").splitlines():
                        if not _line.strip():
                            continue
                        try:
                            _ev = json.loads(_line)
                        except Exception:
                            continue
                        _payload = _ev.get("payload", {})
                        _wid = _payload.get("workload_id") or _ev.get("workload_id")
                        if not _wid:
                            continue
                        _parsed = parse_workload_ref(_wid)
                        if _parsed.get("identity_key") == identity_key:
                            workloads.add(_wid)
                except Exception:
                    continue

        timeline_rows = []
        transition_rows = []
        neighbor_rows = {}
        for workload_id in sorted(workloads):
            item = kernel.feedback.timeline(workload_id)
            for snapshot in item.get("snapshots", []):
                snapshot["_workload_id"] = workload_id
                timeline_rows.append(snapshot)
            for transition in item.get("transitions", []):
                transition["_workload_id"] = workload_id
                transition_rows.append(transition)
            for neighbor in item.get("graph_neighbors", []):
                try:
                    neighbor_id, weight = neighbor
                    neighbor_rows[neighbor_id] = max(float(weight), float(neighbor_rows.get(neighbor_id, 0.0)))
                except Exception:
                    continue

        def _sort_key(row: dict) -> str:
            return row.get("computed_at") or row.get("ts") or ""

        timeline_rows.sort(key=_sort_key, reverse=True)
        transition_rows.sort(key=_sort_key, reverse=True)

        return {
            "identity_key": identity_key,
            "workload_count": len(workloads),
            "workloads": sorted(workloads),
            "snapshot_count": len(timeline_rows),
            "transition_count": len(transition_rows),
            "snapshots": timeline_rows[:limit],
            "transitions": transition_rows[:limit],
            "graph_neighbors": [
                {"workload_id": wid, "weight": round(weight, 4)}
                for wid, weight in sorted(neighbor_rows.items(), key=lambda item: -item[1])[:20]
            ],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Timeline error: {exc}")


@app.get("/history/actions")
def action_history(limit: int = 30):
    """Recent operator-visible lifecycle actions across proposals and folds."""
    try:
        limit = max(1, min(limit, 100))
        ledger = PearlLedger(SKG_STATE_DIR / "pearls.jsonl")
        rows: list[dict] = []
        for pearl in ledger.all():
            ts = pearl.timestamp.isoformat()
            identity_key = (
                pearl.energy_snapshot.get("identity_key")
                or pearl.target_snapshot.get("identity_key")
                or ""
            )
            for reason in pearl.reason_changes or []:
                kind = reason.get("kind")
                if kind not in {"proposal_lifecycle", "operator_action"}:
                    continue
                rows.append({
                    "timestamp": ts,
                    "kind": kind,
                    "identity_key": identity_key,
                    "domain": reason.get("domain") or pearl.energy_snapshot.get("domain") or "",
                    "proposal_id": reason.get("proposal_id"),
                    "proposal_kind": reason.get("proposal_kind"),
                    "status": reason.get("status"),
                    "reason": reason.get("reason"),
                    "fold_id": reason.get("fold_id"),
                    "action": reason.get("action"),
                    "target_ip": reason.get("target_ip") or pearl.energy_snapshot.get("target_ip") or "",
                })
        rows.sort(key=lambda row: row.get("timestamp", ""), reverse=True)
        bounded = rows[:limit]
        return {"count": len(rows), "actions": bounded, "items": bounded}
    except Exception as exc:
        raise HTTPException(500, f"Action history error: {exc}")


def _assistant_group_surface(workloads: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for row in workloads or []:
        identity_key = row.get("identity_key") or row.get("workload_id") or "unknown"
        group = groups.setdefault(identity_key, {
            "identity_key": identity_key,
            "manifestations": set(),
            "paths": [],
        })
        if row.get("manifestation_key"):
            group["manifestations"].add(row["manifestation_key"])
        group["paths"].append(row)
    for group in groups.values():
        group["manifestations"] = sorted(group["manifestations"])
        group["paths"] = sorted(group["paths"], key=lambda item: float(item.get("score", 0.0) or 0.0), reverse=True)
    return groups


def _assistant_compact_target(group: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    paths = []
    for row in (group.get("paths") or [])[:6]:
        paths.append({
            "workload_id": row.get("workload_id"),
            "manifestation_key": row.get("manifestation_key"),
            "domain": row.get("domain"),
            "attack_path_id": row.get("attack_path_id"),
            "classification": row.get("classification"),
            "score": row.get("score"),
            "realized": len(row.get("realized") or []),
            "blocked": len(row.get("blocked") or []),
            "unknown": len(row.get("unknown") or []),
        })
    return {
        "identity_key": group.get("identity_key"),
        "manifestations": group.get("manifestations") or [],
        "services": [
            f"{svc.get('port')}/{svc.get('service')}"
            for svc in (target.get("services") or [])[:8]
        ],
        "os": target.get("os"),
        "kind": target.get("kind"),
        "profile": target.get("profile") or {},
        "paths": paths,
    }


def _assistant_compact_fold(fold: dict[str, Any]) -> dict[str, Any]:
    why = fold.get("why") or {}
    parsed = parse_workload_ref(
        str(
            fold.get("identity_key")
            or why.get("identity_key")
            or fold.get("workload_id")
            or why.get("workload_id")
            or fold.get("target_ip")
            or fold.get("location")
            or ""
        )
    )
    identity_key = str(parsed.get("identity_key") or fold.get("target_ip") or fold.get("location") or "").strip()
    return {
        "fold_id": fold.get("fold_id"),
        "fold_type": fold.get("fold_type"),
        "identity_key": identity_key,
        "target_ip": fold.get("target_ip") or fold.get("location"),
        "gravity_weight": fold.get("gravity_weight"),
        "detail": fold.get("detail"),
        "why": {
            "mismatch": why.get("mismatch"),
            "service": why.get("service"),
            "attack_path_id": why.get("attack_path_id"),
        },
    }


def _assistant_compact_proposal(proposal: dict[str, Any]) -> dict[str, Any]:
    growth = ((proposal.get("recall") or {}).get("growth_memory") or {})
    return {
        "id": proposal.get("id"),
        "kind": proposal.get("proposal_kind"),
        "identity_key": _proposal_identity_key(proposal),
        "status": proposal.get("status"),
        "description": proposal.get("description"),
        "domain": proposal.get("domain"),
        "hosts": proposal.get("hosts") or [],
        "confidence": proposal.get("confidence"),
        "fold_ids": proposal.get("fold_ids") or [],
        "growth_memory": {
            "delta": growth.get("delta"),
            "proposal_reasons": growth.get("proposal_reasons") or [],
        },
        "command_hint": ((proposal.get("action") or {}).get("command_hint")),
    }


def _assistant_compact_memory(neighborhood: dict[str, Any]) -> dict[str, Any]:
    return {
        "identity_key": neighborhood.get("identity_key"),
        "domain": neighborhood.get("domain"),
        "pearl_count": neighborhood.get("pearl_count"),
        "mean_energy": neighborhood.get("mean_energy"),
        "transition_density": neighborhood.get("transition_density"),
        "manifestation_keys": neighborhood.get("manifestation_keys") or [],
        "reinforced_wickets": neighborhood.get("reinforced_wickets") or [],
        "reinforced_reasons": neighborhood.get("reinforced_reasons") or [],
    }


def _assistant_compact_field_row(row: dict[str, Any]) -> dict[str, Any]:
    unknown_nodes = list(row.get("unknown_nodes") or [])[:4]
    resolution_required = row.get("resolution_required") or {}
    return {
        "workload_id": row.get("workload_id"),
        "manifestation_key": row.get("manifestation_key"),
        "attack_path_id": row.get("attack_path_id"),
        "classification": row.get("classification"),
        "E": row.get("E"),
        "E_base": row.get("E_base"),
        "fold_contribution": row.get("fold_contribution"),
        "field_pull": row.get("field_pull"),
        "compatibility_score": row.get("compatibility_score"),
        "compatibility_span": row.get("compatibility_span"),
        "decoherence": row.get("decoherence"),
        "n_required": row.get("n_required"),
        "n_realized": row.get("n_realized"),
        "n_blocked": row.get("n_blocked"),
        "n_unknown": row.get("n_unknown"),
        "unknown_nodes": unknown_nodes,
        "resolution_required": {
            node: resolution_required.get(node)
            for node in unknown_nodes
            if node in resolution_required
        },
        "unresolved_reason": row.get("unresolved_reason"),
        "computed_at": row.get("computed_at"),
    }


def _assistant_compact_transition(row: dict[str, Any]) -> dict[str, Any]:
    keep = [
        "computed_at",
        "ts",
        "timestamp",
        "wicket_id",
        "node_id",
        "domain",
        "attack_path_id",
        "from_state",
        "to_state",
        "kind",
        "reason",
        "_workload_id",
    ]
    compact = {
        key: row.get(key)
        for key in keep
        if key in row and row.get(key) not in (None, "", [], {})
    }
    if not compact:
        for key in sorted(row.keys())[:8]:
            value = row.get(key)
            if value not in (None, "", [], {}):
                compact[key] = value
    return compact


def _assistant_compact_value(value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return value[:180]
    if depth >= 2:
        if isinstance(value, dict):
            return {"keys": sorted(list(value.keys()))[:12], "count": len(value)}
        if isinstance(value, list):
            return [str(item)[:80] for item in value[:4]]
        return value
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        keys = sorted(value.keys())[:8]
        for key in keys:
            compact[key] = _assistant_compact_value(value.get(key), depth + 1)
        if len(value) > len(keys):
            compact["_truncated_keys"] = len(value) - len(keys)
        return compact
    if isinstance(value, list):
        items = [_assistant_compact_value(item, depth + 1) for item in value[:4]]
        if len(value) > 4:
            items.append(f"... +{len(value) - 4} more")
        return items
    return value


def _assistant_compact_artifact_preview(preview: dict[str, Any], lines: int = 3) -> dict[str, Any]:
    rows = []
    for row in (preview.get("rows") or [])[:lines]:
        compact_row = {}
        if "line" in row:
            compact_row["line"] = row.get("line")
        if "keys" in row:
            compact_row["keys"] = row.get("keys")
        if "data" in row:
            compact_row["data"] = _assistant_compact_value(row.get("data"))
        elif "raw" in row:
            compact_row["raw"] = str(row.get("raw") or "")[:180]
        else:
            compact_row.update(_assistant_compact_value(row))
        rows.append(compact_row)
    return {
        "path": preview.get("path"),
        "file": preview.get("file"),
        "preview_kind": preview.get("preview_kind"),
        "rows": rows,
    }


def _assistant_find_memory(neighborhoods: list[dict[str, Any]], selection_id: str, identity_key: str) -> dict[str, Any] | None:
    for index, row in enumerate(neighborhoods):
        row_id = f"{row.get('identity_key')}:{row.get('domain') or 'unknown'}:{index}"
        if selection_id and row_id == selection_id:
            return row
    for row in neighborhoods:
        if identity_key and row.get("identity_key") == identity_key:
            return row
    return None


def _assistant_find_fold(folds: list[dict[str, Any]], selection_id: str, identity_key: str) -> dict[str, Any] | None:
    for index, row in enumerate(folds):
        parsed = parse_workload_ref(
            str(row.get("identity_key") or row.get("workload_id") or row.get("target_ip") or row.get("location") or "")
        )
        fold_identity = str(parsed.get("identity_key") or row.get("target_ip") or row.get("location") or "").strip()
        row_id = row.get("fold_id") or f"{fold_identity or 'fold'}:{index}"
        if selection_id and row_id == selection_id:
            return row
    for row in folds:
        parsed = parse_workload_ref(
            str(row.get("identity_key") or row.get("workload_id") or row.get("target_ip") or row.get("location") or "")
        )
        fold_identity = str(parsed.get("identity_key") or row.get("target_ip") or row.get("location") or "").strip()
        if identity_key and fold_identity == identity_key:
            return row
    return None


def _assistant_graph_context(
    identity_key: str,
    workloads: list[str],
    field_rows: list[dict[str, Any]],
    limit: int = 6,
) -> dict[str, Any]:
    neighbors: list[dict[str, Any]] = []
    priors: list[dict[str, Any]] = []
    seen_neighbors: set[tuple[str, str]] = set()
    seen_priors: set[tuple[str, str]] = set()

    for workload_id in workloads:
        if not workload_id:
            continue
        try:
            rows = kernel.graph.neighbors(workload_id, min_weight=0.1)
        except Exception:
            rows = []
        for neighbor_id, relationship, weight in rows:
            key = (neighbor_id, relationship)
            if key in seen_neighbors:
                continue
            seen_neighbors.add(key)
            neighbors.append({
                "workload_id": neighbor_id,
                "identity_key": parse_workload_ref(neighbor_id).get("identity_key"),
                "relationship": relationship,
                "weight": round(float(weight or 0.0), 4),
            })

    for row in field_rows:
        workload_id = row.get("workload_id") or ""
        attack_path_id = row.get("attack_path_id") or ""
        for wicket_id in (row.get("unknown_nodes") or [])[:4]:
            key = (workload_id, wicket_id)
            if key in seen_priors:
                continue
            seen_priors.add(key)
            try:
                prior = float(kernel.graph.get_prior(workload_id, wicket_id=wicket_id) or 0.0)
            except Exception:
                prior = 0.0
            if prior <= 0.0:
                continue
            priors.append({
                "workload_id": workload_id,
                "identity_key": parse_workload_ref(workload_id).get("identity_key", identity_key),
                "attack_path_id": attack_path_id,
                "wicket_id": wicket_id,
                "prior": round(prior, 4),
            })

    neighbors.sort(key=lambda item: (-float(item.get("weight") or 0.0), str(item.get("workload_id") or "")))
    priors.sort(key=lambda item: (-float(item.get("prior") or 0.0), str(item.get("wicket_id") or "")))
    return {
        "neighbor_count": len(neighbors),
        "neighbors": neighbors[:limit],
        "prior_count": len(priors),
        "priors": priors[:limit],
    }


def _assistant_gravity_context(identity_key: str) -> dict[str, Any]:
    gravity_state = kernel.gravity_status() or {}
    return {
        "running": gravity_state.get("running"),
        "cycle": gravity_state.get("cycle"),
        "total_entropy": gravity_state.get("total_entropy"),
        "total_unknowns": gravity_state.get("total_unknowns"),
        "field_pull_boost": gravity_state.get("field_pull_boost"),
        "last_cycle_at": gravity_state.get("last_cycle_at"),
        "cycle_started_at": gravity_state.get("cycle_started_at"),
        "current_activity": gravity_state.get("current_activity"),
        "current_surface": gravity_state.get("current_surface"),
        "last_returncode": gravity_state.get("last_returncode"),
        "error": gravity_state.get("error"),
        "recent_output": [str(line)[:180] for line in (gravity_state.get("recent_output") or [])[-4:]],
        "identity_key": identity_key,
    }


def _assistant_reasoning_bundle(
    *,
    kind: str,
    selection_id: str,
    identity_key: str,
    subject: dict[str, Any],
    target: dict[str, Any],
    group: dict[str, Any],
    field_rows: list[dict[str, Any]],
    field_row_count: int,
    folds: list[dict[str, Any]],
    fold_count: int,
    proposals: list[dict[str, Any]],
    proposal_count: int,
    memory: list[dict[str, Any]],
    memory_count: int,
    timeline: dict[str, Any],
    artifacts: list[dict[str, Any]],
    artifact_count: int,
    limit: int,
) -> dict[str, Any]:
    surface_snapshot = _assistant_compact_target(
        group or {
            "identity_key": identity_key,
            "manifestations": [],
            "paths": [],
        },
        target or {},
    )
    workload_ids = sorted({
        *(row.get("workload_id") for row in (group.get("paths") or []) if row.get("workload_id")),
        *(row.get("workload_id") for row in field_rows if row.get("workload_id")),
        *(row.get("workload_id") for row in (timeline.get("graph_neighbors") or []) if row.get("workload_id")),
        *(wid for wid in (timeline.get("workloads") or []) if wid),
    })
    return {
        "version": 1,
        "selection": {
            "kind": kind,
            "id": selection_id,
            "identity_key": identity_key,
        },
        "subject": subject,
        "surface": surface_snapshot,
        "field_state": {
            "count": field_row_count,
            "paths": field_rows[:limit],
        },
        "folds": {
            "count": fold_count,
            "items": folds[:limit],
        },
        "proposals": {
            "count": proposal_count,
            "items": proposals[:limit],
        },
        "memory": {
            "count": memory_count,
            "items": memory[:limit],
        },
        "timeline": timeline,
        "graph": _assistant_graph_context(identity_key, workload_ids[: max(limit * 2, 4)], field_rows, limit=limit),
        "artifacts": {
            "count": artifact_count,
            "items": artifacts[: max(1, min(limit, 3))],
        },
        "gravity": _assistant_gravity_context(identity_key),
    }


def _assistant_prompt_view(context: dict[str, Any]) -> dict[str, Any]:
    bundle = context.get("bundle")
    if not isinstance(bundle, dict):
        return {
            "kind": context.get("kind"),
            "identity_key": context.get("identity_key"),
            "task": context.get("task"),
            "subject": context.get("subject"),
            "fold_count": context.get("fold_count"),
            "proposal_count": context.get("proposal_count"),
            "related_folds": (context.get("related_folds") or [])[:3],
            "related_proposals": (context.get("related_proposals") or [])[:3],
            "timeline": {
                key: value
                for key, value in (context.get("timeline") or {}).items()
                if key != "recent_transitions"
            },
        }

    prompt_view = {
        "kind": context.get("kind"),
        "id": context.get("id"),
        "identity_key": context.get("identity_key"),
        "task": context.get("task"),
        "subject": context.get("subject"),
        "bundle": bundle,
    }
    if context.get("question"):
        prompt_view["question"] = context.get("question")
    if context.get("action"):
        prompt_view["action"] = context.get("action")
    return prompt_view


def _assistant_prompt_schema(task: str) -> str:
    if task == "what_if":
        return (
            '{"summary":"string","assumptions":["string"],'
            '"predicted_effects":["string"],"next_observations":["string"],'
            '"cautions":["string"]}'
        )
    return '{"summary":"string","findings":["string"],"next_actions":["string"],"cautions":["string"]}'


def _assistant_json_prompt(context: dict[str, Any]) -> str:
    task = str(context.get("task") or "target_summary")
    task_notes = str((context.get("assistant_config") or {}).get("task_prompt") or "")
    note_line = f"Task note: {task_notes}\n" if task_notes else ""
    task_guardrail = ""
    if task == "what_if":
        task_guardrail = (
            "Treat this as counterfactual planning over measured state.\n"
            "Do not claim the action already happened.\n"
            "Predict only likely effects on uncertainty, folds, proposals, graph pressure, or observation priority.\n"
        )
    return (
        "You are the SKG AI assistant. You are not the substrate and you may not invent measurements.\n"
        "Use only the provided JSON context. Treat realized/blocked/indeterminate exactly as given.\n"
        "If something is unresolved, say it is indeterminate or unsupported.\n"
        f"{task_guardrail}"
        f"Current task: {task}.\n"
        f"{note_line}"
        "Return only valid JSON with this schema:\n"
        f"{_assistant_prompt_schema(task)}\n"
        "Context JSON:\n"
        f"{json.dumps(context, ensure_ascii=True)}"
    )


def _assistant_parse_json(raw: str) -> dict[str, Any] | None:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    if start < 0:
        return None
    decoder = json.JSONDecoder()
    try:
        obj, _ = decoder.raw_decode(text[start:])
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


# ── Async Ollama assistant cache ─────────────────────────────────────────────
# tinyllama on CPU takes 30-60s per inference — far too slow for real-time
# requests. Strategy: return from cache if fresh; spawn a background thread to
# (re)compute when the cache is missing or stale. The UI always gets an instant
# response; the next poll gets the LLM result once ready.

_OLLAMA_CACHE: dict[str, dict[str, Any]] = {}   # key → {result, model, computed_at}
_OLLAMA_INFLIGHT: set[str] = set()               # keys currently being computed
_OLLAMA_CACHE_TTL_S = 600                        # 10 minutes
_OLLAMA_LOCK = threading.Lock()


def _assistant_cache_key(context: dict[str, Any]) -> str:
    payload = {
        "kind": context.get("kind"),
        "id": context.get("id"),
        "identity_key": context.get("identity_key"),
        "task": context.get("task"),
        "question": context.get("question"),
        "action": context.get("action"),
    }
    digest = hashlib.sha1(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8", errors="replace")
    ).hexdigest()[:12]
    return f"{context.get('identity_key','')}:{context.get('task','')}:{digest}"


def _assistant_ollama_background(context: dict[str, Any], model: str, num_predict: int) -> None:
    """Run LLM inference via pool in a background thread and store result in cache."""
    key = _assistant_cache_key(context)
    try:
        from skg.resonance.llm_pool import get_pool
        pool = get_pool()
        prompt = _assistant_json_prompt(_assistant_prompt_view(context))
        raw = pool.generate(prompt, num_predict=num_predict)
        payload = _assistant_parse_json(raw)
        if isinstance(payload, dict):
            winner_model = pool.primary_model_name() or model
            with _OLLAMA_LOCK:
                _OLLAMA_CACHE[key] = {
                    "result": payload,
                    "model": winner_model,
                    "computed_at": time.time(),
                }
    except Exception as exc:
        log.debug(f"[assistant] background LLM pool error for {key}: {exc}")
    finally:
        with _OLLAMA_LOCK:
            _OLLAMA_INFLIGHT.discard(key)


def _assistant_try_ollama(context: dict[str, Any], timeout_s: float = 8.0) -> tuple[dict[str, Any] | None, str | None]:
    try:
        from skg.resonance.llm_pool import get_pool
    except Exception:
        return None, None

    pool = get_pool()
    if not pool.any_available():
        return None, None

    model = pool.primary_model_name() or "llm"
    key = _assistant_cache_key(context)
    num_predict = int((context.get("assistant_config") or {}).get("num_predict") or 220)

    with _OLLAMA_LOCK:
        cached = _OLLAMA_CACHE.get(key)
        if cached and (time.time() - cached["computed_at"]) < _OLLAMA_CACHE_TTL_S:
            return cached["result"], cached.get("model", model)
        if key not in _OLLAMA_INFLIGHT:
            _OLLAMA_INFLIGHT.add(key)
            t = threading.Thread(
                target=_assistant_ollama_background,
                args=(context, model, num_predict),
                daemon=True,
            )
            t.start()

    # Cache miss — background task is now running; caller will use fallback
    return None, model


def _assistant_action_label(context: dict[str, Any]) -> str:
    action = context.get("action") or {}
    subject = context.get("subject") or {}
    if isinstance(action, dict):
        for key in ("description", "command_hint", "command", "kind", "proposal_kind", "proposal_id"):
            value = str(action.get(key) or "").strip()
            if value:
                return value
    for key in ("description", "command_hint", "kind", "fold_type", "attack_path_id"):
        value = str(subject.get(key) or "").strip()
        if value:
            return value
    question = str(context.get("question") or "").strip()
    if question:
        return question
    return "the proposed action"


def _assistant_counterfactual_fallback(context: dict[str, Any]) -> dict[str, Any]:
    bundle = context.get("bundle") or {}
    field_state = ((bundle.get("field_state") or {}).get("paths") or [])[:4]
    folds = ((bundle.get("folds") or {}).get("items") or [])[:4]
    proposals = ((bundle.get("proposals") or {}).get("items") or [])[:4]
    graph = bundle.get("graph") or {}
    artifacts = ((bundle.get("artifacts") or {}).get("items") or [])[:2]
    action = context.get("action") or {}
    subject = context.get("subject") or {}
    identity_key = context.get("identity_key") or "the selected identity"
    label = _assistant_action_label(context)
    lower_label = label.lower()
    lower_question = str(context.get("question") or "").lower()
    top_path = field_state[0] if field_state else {}

    summary = (
        f"If SKG takes {label}, the immediate effect is most likely on uncertainty and routing around "
        f"{identity_key}, not on measured state."
    )
    assumptions = [
        "This is a counterfactual over the current substrate snapshot, not an executed action.",
        "Any predicted change remains hypothetical until new observation lands in SKG.",
    ]
    predicted_effects: list[str] = []
    next_observations: list[str] = []
    cautions = [
        "Counterfactual output is not canonical state.",
        "Small-model reasoning should be checked against the attached field, fold, proposal, and artifact objects.",
    ]

    if top_path:
        predicted_effects.append(
            f"Primary pressure remains {top_path.get('attack_path_id') or 'the top path'} "
            f"with classification {top_path.get('classification') or 'unknown'} and E {float(top_path.get('E') or 0.0):.2f}."
        )
        if int(top_path.get("n_unknown") or 0) > 0:
            predicted_effects.append(
                f"It could reduce uncertainty on {int(top_path.get('n_unknown') or 0)} unresolved nodes "
                f"if it produces the telemetry listed in resolution_required."
            )
        hints = top_path.get("resolution_required") or {}
        if hints:
            wicket_id = next(iter(hints))
            next_observations.append(f"Best validation target is {wicket_id}: {hints[wicket_id]}.")

    if folds:
        predicted_effects.append(
            f"Current fold pressure count is {len(folds)}; the action is useful only if it resolves a real fold or closes an observation gap."
        )

    if proposals:
        predicted_effects.append(
            f"Proposal pressure count is {len(proposals)}; executing a plan does not reduce that pressure until support changes are observed."
        )

    graph_priors = graph.get("priors") or []
    if graph_priors:
        top_prior = graph_priors[0]
        predicted_effects.append(
            f"Graph memory is already biasing {top_prior.get('wicket_id') or 'a wicket'} "
            f"on {top_prior.get('workload_id') or 'the selected workload'} with prior {float(top_prior.get('prior') or 0.0):.2f}."
        )

    if subject.get("kind") == "catalog_growth" or action.get("proposal_kind") == "catalog_growth":
        predicted_effects.append("Catalog growth would change SKG coverage and future fold pressure, not current measured target state.")
        next_observations.append("After catalog growth, rerun observation on the same identity before treating any new path as realized.")
    elif subject.get("kind") == "field_action" or action.get("proposal_kind") == "field_action" or action.get("command") or subject.get("command_hint"):
        predicted_effects.append("Executing a field action could change the target, but SKG must re-observe before promoting that effect into state.")
        next_observations.append("Plan a re-observation immediately after execution so intended change and stale evidence do not get conflated.")
    elif any(token in lower_label or token in lower_question for token in ("observe", "sensor", "collect", "profile", "sweep", "probe")):
        predicted_effects.append("Observation-focused actions mainly attack E_base and unresolved nodes; they do not by themselves collapse structural gaps.")
    elif any(token in lower_label or token in lower_question for token in ("review", "note", "report")):
        predicted_effects.append("Narrative actions change operator understanding, not SKG substrate state.")
    else:
        predicted_effects.append("Without new evidence, the likely effect is a change in operator priority rather than a substrate transition.")

    if artifacts:
        next_observations.append("Check the newest supporting artifact preview first so the counterfactual is grounded in the latest measured file.")

    if not next_observations:
        next_observations.append("Pick the action that closes the highest-E path or top unresolved fold before expanding scope.")

    return {
        "summary": summary,
        "assumptions": assumptions[:4],
        "predicted_effects": predicted_effects[:5],
        "next_observations": next_observations[:4],
        "cautions": cautions[:4],
    }


def _assistant_fallback(context: dict[str, Any]) -> dict[str, Any]:
    kind = context.get("kind")
    task = str(context.get("task") or "")
    subject = context.get("subject") or {}
    if task == "what_if":
        return _assistant_counterfactual_fallback(context)
    summary = "SKG assistant could not derive a summary."
    findings: list[str] = []
    next_actions: list[str] = []
    cautions: list[str] = [
        "This explanation is grounded only in the current SKG substrate snapshot.",
        "Do not treat remembered state as current state without re-observation.",
    ]

    if task == "fold_cluster_summary":
        summary = (
            f"Structural pressure around {context.get('identity_key') or 'the selected identity'} "
            f"is clustering into {context.get('fold_count') or 0} folds and {context.get('proposal_count') or 0} related proposals."
        )
        if context.get("related_folds"):
            services = sorted({
                (fold.get("why") or {}).get("service") or fold.get("fold_type") or "unknown"
                for fold in (context.get("related_folds") or [])
            })
            findings.append(f"Clustered pressure centers on {', '.join(services[:4])}.")
        findings.append("Treat this as one structural deficit until new observation separates it into distinct causes.")
        next_actions.append("Review the clustered growth proposal and the top supporting fold together.")
    elif task == "engagement_note":
        summary = (
            f"Engagement note for {context.get('identity_key') or 'selection'}: "
            f"{context.get('fold_count') or 0} folds, {context.get('proposal_count') or 0} proposals, "
            f"{(context.get('timeline') or {}).get('transition_count', 0)} transitions."
        )
        findings.append("Preserve explicit uncertainty and measured classification labels in operator notes.")
        if subject.get("paths"):
            top_path = (subject.get("paths") or [{}])[0]
            findings.append(
                f"Top current path: {top_path.get('attack_path_id') or 'n/a'} as {top_path.get('classification') or 'unknown'}."
            )
        next_actions.append("Capture measured support references and the next bounded observation in the engagement note.")
    elif kind == "target":
        top_path = ((subject.get("paths") or [{}])[0]) if subject.get("paths") else {}
        summary = (
            f"SKG currently sees {subject.get('identity_key') or 'this identity'} through "
            f"{len(subject.get('manifestations') or [])} manifestations and "
            f"{len(subject.get('paths') or [])} active attack-path rows."
        )
        if top_path:
            findings.append(
                f"Strongest current path is {top_path.get('attack_path_id') or 'n/a'} "
                f"as {top_path.get('classification') or 'unknown'} with score {float(top_path.get('score') or 0.0):.2f}."
            )
        if subject.get("services"):
            findings.append(f"Observed services include {', '.join(subject.get('services')[:5])}.")
        if task == "next_observation":
            if context.get("related_folds"):
                fold = (context.get("related_folds") or [{}])[0]
                next_actions.append(
                    f"Start with fold pressure around {fold.get('why', {}).get('service') or fold.get('fold_type') or 'the target'} before proposing growth."
                )
            if context.get("related_memory"):
                memory = (context.get("related_memory") or [{}])[0]
                wickets = memory.get("reinforced_wickets") or []
                if wickets:
                    next_actions.append(f"Bias observation toward reinforced wickets {', '.join(wickets[:4])}.")
            if context.get("artifacts"):
                next_actions.append("Inspect the newest measured-support artifact before selecting the next live instrument.")
        else:
            next_actions.append("Use folds and proposal pressure to decide whether the next move is observation, growth, or review.")
    elif kind == "fold":
        summary = (
            f"This {subject.get('fold_type') or 'fold'} fold marks unresolved structure around "
            f"{subject.get('target_ip') or 'the selected identity'}."
        )
        why = subject.get("why") or {}
        if why.get("mismatch"):
            findings.append(f"Mismatch is {why.get('mismatch')}.")
        if why.get("service"):
            findings.append(f"Service context is {why.get('service')}.")
        next_actions.append("Decide whether this requires re-observation, catalog growth, or toolchain growth.")
    elif kind == "proposal":
        summary = (
            f"This {subject.get('kind') or 'proposal'} proposal is a bounded response to structural pressure, "
            f"not a measurement."
        )
        growth = subject.get("growth_memory") or {}
        findings.append(
            f"Status is {subject.get('status') or 'unknown'} with confidence {float(subject.get('confidence') or 0.0):.3f}."
        )
        if growth.get("delta"):
            findings.append(f"Growth memory delta is {float(growth.get('delta') or 0.0):.3f}.")
        if subject.get("command_hint"):
            next_actions.append(f"Review command hint: {subject.get('command_hint')}")
    elif kind == "memory":
        summary = (
            f"This pearl neighborhood is structural memory for {subject.get('identity_key') or 'the selected identity'} "
            f"in domain {subject.get('domain') or 'unknown'}."
        )
        if subject.get("reinforced_wickets"):
            findings.append(f"Reinforced wickets: {', '.join(subject.get('reinforced_wickets')[:6])}.")
        if subject.get("reinforced_reasons"):
            findings.append(f"Reinforced reasons: {', '.join(subject.get('reinforced_reasons')[:4])}.")
        next_actions.append("Use reinforced neighborhoods to bias observation, not to assign new state.")

    if context.get("timeline", {}).get("transition_count"):
        findings.append(
            f"Timeline contains {context['timeline'].get('transition_count')} recorded transitions and "
            f"{context['timeline'].get('snapshot_count')} snapshots."
        )
    if context.get("fold_count"):
        findings.append(f"Related fold pressure count is {context.get('fold_count')}.")
    if context.get("proposal_count"):
        findings.append(f"Related proposal count is {context.get('proposal_count')}.")
    if context.get("artifacts"):
        next_actions.append("Inspect measured-support artifacts before making any destructive or growth decision.")

    return {
        "summary": summary,
        "findings": findings[:5],
        "next_actions": next_actions[:4],
        "cautions": cautions[:4],
    }


def _assistant_config() -> dict[str, Any]:
    try:
        import yaml
        candidates = [
            SKG_CONFIG_DIR / "skg_config.yaml",
            SKG_HOME / "config" / "skg_config.yaml",
        ]
        for cfg_path in candidates:
            if not cfg_path.exists():
                continue
            data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            resonance = data.get("resonance", {}) or {}
            assistant = resonance.get("assistant", {}) or {}
            if isinstance(assistant, dict):
                return assistant
    except Exception:
        pass
    return {}


def _assistant_default_task(kind: str) -> str:
    return {
        "target": "target_summary",
        "fold": "fold_explanation",
        "proposal": "proposal_explanation",
        "memory": "memory_summary",
    }.get(kind, "target_summary")


def _assistant_context(req: AssistantExplainRequest) -> dict[str, Any]:
    limit = max(1, min(int(getattr(req, "limit", 6) or 6), 12))
    targets = list_targets()
    surface = field_surface()
    folds = folds_summary()
    proposals = list_proposals(status="all")
    memory = pearl_memory_manifold()
    field_state = _compute_field_state()

    groups = _assistant_group_surface(surface.get("workloads") or [])
    targets_by_identity = {
        (row.get("identity_key") or row.get("ip") or row.get("host") or ""): row
        for row in targets.get("targets") or []
        if (row.get("identity_key") or row.get("ip") or row.get("host"))
    }
    identity_key = req.identity_key or ""

    subject: dict[str, Any] | None = None
    group: dict[str, Any] | None = None
    target_row: dict[str, Any] = {}
    if req.kind == "target":
        identity_key = identity_key or req.id
        group = groups.get(identity_key)
        target_row = targets_by_identity.get(identity_key, {})
        if group is None and identity_key:
            group = {
                "identity_key": identity_key,
                "manifestations": [],
                "paths": [],
            }
        if group:
            subject = _assistant_compact_target(group, target_row)
    elif req.kind == "fold":
        fold = _assistant_find_fold(folds.get("folds") or [], req.id, identity_key)
        if fold:
            subject = _assistant_compact_fold(fold)
            identity_key = identity_key or subject.get("identity_key") or fold.get("target_ip") or fold.get("location") or ""
            group = groups.get(identity_key)
            target_row = targets_by_identity.get(identity_key, {})
    elif req.kind == "proposal":
        proposal = None
        for row in proposals.get("proposals") or []:
            if row.get("id") == req.id:
                proposal = row
                break
        if proposal:
            subject = _assistant_compact_proposal(proposal)
            identity_key = identity_key or _proposal_identity_key(proposal)
            group = groups.get(identity_key)
            target_row = targets_by_identity.get(identity_key, {})
    elif req.kind == "memory":
        neighborhood = _assistant_find_memory(memory.get("neighborhoods") or [], req.id, identity_key)
        if neighborhood:
            subject = _assistant_compact_memory(neighborhood)
            identity_key = identity_key or neighborhood.get("identity_key") or ""
            group = groups.get(identity_key)
            target_row = targets_by_identity.get(identity_key, {})

    if not subject:
        raise HTTPException(404, f"Assistant subject not found for {req.kind}:{req.id}")

    identity_folds = [
        _assistant_compact_fold(fold)
        for fold in (folds.get("folds") or [])
        if identity_key and _assistant_compact_fold(fold).get("identity_key") == identity_key
    ]
    identity_proposals = [
        _assistant_compact_proposal(proposal)
        for proposal in (proposals.get("proposals") or [])
        if _proposal_matches_identity(proposal, identity_key)
    ]
    identity_memory = [
        _assistant_compact_memory(row)
        for row in (memory.get("neighborhoods") or [])
        if not identity_key or row.get("identity_key") == identity_key
    ]
    identity_field_rows = sorted(
        [
            _assistant_compact_field_row(row)
            for row in (field_state.values() if isinstance(field_state, dict) else [])
            if not identity_key or row.get("identity_key") == identity_key
        ],
        key=lambda row: (-float(row.get("E") or 0.0), str(row.get("attack_path_id") or "")),
    )
    timeline_raw = identity_timeline(identity_key, limit=max(4, limit * 2)) if identity_key else {}
    # Use a generous limit to get the true count, but only preview a few rows.
    # Preserve the upstream total count so assistant references reflect how much
    # artifact context was actually available, not just the preview size (LOW-10 fix).
    _artifacts_result = identity_artifacts(identity_key, limit=40) if identity_key else {}
    artifacts_raw = _artifacts_result.get("artifacts", [])
    artifacts_total_count = _artifacts_result.get("count", len(artifacts_raw))
    artifact_rows = []
    for row in artifacts_raw[: max(1, min(limit, 3))]:
        item = {
            "file": row.get("file"),
            "category": row.get("category"),
            "mtime": row.get("mtime"),
            "workload_id": row.get("workload_id"),
            "path": row.get("path"),
        }
        if row.get("path"):
            try:
                preview = _artifact_preview_payload(row["path"], lines=min(limit, 4))
                item["preview"] = _assistant_compact_artifact_preview(preview, lines=min(limit, 3))
            except Exception:
                pass
        artifact_rows.append(item)

    timeline = {
        "workload_count": timeline_raw.get("workload_count", 0),
        "snapshot_count": timeline_raw.get("snapshot_count", 0),
        "transition_count": timeline_raw.get("transition_count", 0),
        "recent_transitions": [
            _assistant_compact_transition(row)
            for row in (timeline_raw.get("transitions") or [])[:limit]
        ],
        "graph_neighbors": (timeline_raw.get("graph_neighbors") or [])[:limit],
    }
    bundle = _assistant_reasoning_bundle(
        kind=req.kind,
        selection_id=req.id,
        identity_key=identity_key,
        subject=subject,
        target=target_row,
        group=group or {},
        field_rows=identity_field_rows[:limit],
        field_row_count=len(identity_field_rows),
        folds=identity_folds[:limit],
        fold_count=len(identity_folds),
        proposals=identity_proposals[:limit],
        proposal_count=len(identity_proposals),
        memory=identity_memory[:limit],
        memory_count=len(identity_memory),
        timeline=timeline,
        artifacts=artifact_rows,
        artifact_count=artifacts_total_count,
        limit=limit,
    )

    return {
        "kind": req.kind,
        "id": req.id,
        "identity_key": identity_key,
        "subject": subject,
        "fold_count": len(identity_folds),
        "proposal_count": len(identity_proposals),
        "field_path_count": len(identity_field_rows),
        "related_folds": identity_folds[:limit],
        "related_proposals": identity_proposals[:limit],
        "related_memory": identity_memory[:limit],
        "field_state": {
            "count": len(identity_field_rows),
            "paths": identity_field_rows[:limit],
        },
        "timeline": timeline,
        "artifacts": [
            {
                "file": row.get("file"),
                "category": row.get("category"),
                "mtime": row.get("mtime"),
                "workload_id": row.get("workload_id"),
            }
            for row in artifact_rows[:limit]
        ],
        "bundle": bundle,
    }


def _assistant_task_prompt(assistant_cfg: dict[str, Any], task: str) -> str:
    tasks = assistant_cfg.get("tasks") or {}
    return (tasks.get(task) if isinstance(tasks, dict) else "") or ""


def _assistant_prepare_context(req: Any, default_task: str) -> tuple[dict[str, Any], str]:
    base_context: dict[str, Any] | None = None
    try:
        if getattr(req, "kind", ""):
            base_context = _assistant_context(req)
    except HTTPException:
        if not isinstance(getattr(req, "context", None), dict):
            raise

    override = getattr(req, "context", None)
    if override is not None and not isinstance(override, dict):
        raise HTTPException(400, "Assistant context must be an object")

    if isinstance(override, dict):
        context = dict(base_context or {})
        context.update(override)
        if base_context:
            context.setdefault("bundle", base_context.get("bundle"))
            context.setdefault("field_state", base_context.get("field_state"))
            context.setdefault("timeline", base_context.get("timeline"))
    elif isinstance(base_context, dict):
        context = base_context
    else:
        raise HTTPException(404, f"Assistant subject not found for {getattr(req, 'kind', '')}:{getattr(req, 'id', '')}")

    assistant_cfg = _assistant_config()
    task = getattr(req, "task", "") or default_task
    task_prompt = _assistant_task_prompt(assistant_cfg, task)
    context.setdefault("kind", getattr(req, "kind", ""))
    context.setdefault("id", getattr(req, "id", ""))
    context.setdefault("identity_key", getattr(req, "identity_key", ""))
    context["task"] = task
    context["assistant_config"] = {
        "enabled": bool(assistant_cfg.get("enabled", True)),
        "timeout_s": float(assistant_cfg.get("timeout_s", 8.0) or 8.0),
        "num_predict": int(assistant_cfg.get("num_predict", 220) or 220),
        "task_prompt": task_prompt,
    }
    return context, task


def _assistant_bundle_context(req: Any) -> dict[str, Any]:
    context, _task = _assistant_prepare_context(
        req,
        _assistant_default_task(getattr(req, "kind", "") or "target"),
    )
    bundle = context.get("bundle")
    if not isinstance(bundle, dict):
        raise HTTPException(400, "Assistant bundle unavailable")
    return context


def _assistant_draft_context_request(req: Any, demand: dict[str, Any] | None = None) -> Any:
    import types as _types

    selection = dict((demand or {}).get("selection") or {})
    kind = str(getattr(req, "kind", "") or selection.get("kind") or "").strip()
    if not kind:
        raise HTTPException(400, "kind is required to draft an assistant demand")
    return _types.SimpleNamespace(
        kind=kind,
        id=str(getattr(req, "id", "") or selection.get("id") or ""),
        identity_key=str(getattr(req, "identity_key", "") or selection.get("identity_key") or ""),
        limit=int(getattr(req, "limit", 6) or 6),
        context=getattr(req, "context", None),
        question="",
        action=None,
    )


def _assistant_authority(
    output_class: str,
    *,
    task: str = "",
    contract_name: str = "",
    demand: dict[str, Any] | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    return assistant_output_metadata(
        output_class,
        task=task,
        contract_name=contract_name,
        demand=demand,
        model=model,
    )


@app.post("/assistant/explain")
def assistant_explain(req: AssistantExplainRequest):
    try:
        context, task = _assistant_prepare_context(req, _assistant_default_task(req.kind))
        context["task"] = task
        mode = "fallback"
        model = None
        computing = False
        if context["assistant_config"]["enabled"]:
            rendered, model = _assistant_try_ollama(
                context,
                timeout_s=float(context["assistant_config"]["timeout_s"]),
            )
            if rendered:
                mode = "ollama"
            else:
                # Check if a background compute was just kicked off
                with _OLLAMA_LOCK:
                    computing = _assistant_cache_key(context) in _OLLAMA_INFLIGHT
        else:
            rendered = None

        if not isinstance(rendered, dict):
            rendered = _assistant_fallback(context)
        authority = _assistant_authority(
            DERIVED_ADVICE,
            task=task,
            model=model,
        )
        return {
            "assistant_output_class": DERIVED_ADVICE,
            "authority": authority,
            "mode": mode,
            "model": model,
            "computing": computing,
            "task": task,
            "selection": {
                "kind": req.kind,
                "id": req.id,
                "identity_key": context.get("identity_key"),
            },
            "summary": rendered.get("summary") or "",
            "findings": list(rendered.get("findings") or []),
            "next_actions": list(rendered.get("next_actions") or []),
            "cautions": list(rendered.get("cautions") or []),
            "references": {
                "identity_key": context.get("identity_key"),
                "fold_count": context.get("fold_count"),
                "proposal_count": context.get("proposal_count"),
                "field_path_count": context.get("field_path_count"),
                "artifact_count": len(context.get("artifacts") or []),
                "graph_neighbor_count": len((((context.get("bundle") or {}).get("graph") or {}).get("neighbors") or [])),
                "bundle_version": ((context.get("bundle") or {}).get("version")),
                "timeline": context.get("timeline") or {},
            },
            "assistant_config": context.get("assistant_config") or {},
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Assistant error: {exc}")


@app.post("/assistant/what-if")
def assistant_what_if(req: AssistantWhatIfRequest):
    try:
        context, task = _assistant_prepare_context(req, "what_if")
        context["task"] = task
        if req.question:
            context["question"] = str(req.question)
        elif context.get("question") is None:
            context["question"] = ""
        if isinstance(req.action, dict) and req.action:
            context["action"] = dict(req.action)
        elif not context.get("action") and req.kind == "proposal" and isinstance(context.get("subject"), dict):
            subject = context.get("subject") or {}
            context["action"] = {
                "proposal_id": subject.get("id"),
                "proposal_kind": subject.get("kind"),
                "description": subject.get("description"),
                "command_hint": subject.get("command_hint"),
            }

        mode = "fallback"
        model = None
        computing = False
        if context["assistant_config"]["enabled"]:
            rendered, model = _assistant_try_ollama(
                context,
                timeout_s=float(context["assistant_config"]["timeout_s"]),
            )
            if rendered:
                mode = "ollama"
            else:
                with _OLLAMA_LOCK:
                    computing = _assistant_cache_key(context) in _OLLAMA_INFLIGHT
        else:
            rendered = None

        if not isinstance(rendered, dict):
            rendered = _assistant_fallback(context)
        authority = _assistant_authority(
            DERIVED_ADVICE,
            task=task,
            model=model,
        )
        return {
            "assistant_output_class": DERIVED_ADVICE,
            "authority": authority,
            "mode": mode,
            "model": model,
            "computing": computing,
            "task": task,
            "selection": {
                "kind": req.kind,
                "id": req.id,
                "identity_key": context.get("identity_key"),
            },
            "question": context.get("question") or "",
            "action": context.get("action") or {},
            "summary": rendered.get("summary") or "",
            "assumptions": list(rendered.get("assumptions") or []),
            "predicted_effects": list(rendered.get("predicted_effects") or []),
            "next_observations": list(rendered.get("next_observations") or []),
            "cautions": list(rendered.get("cautions") or []),
            "references": {
                "identity_key": context.get("identity_key"),
                "field_path_count": context.get("field_path_count"),
                "fold_count": context.get("fold_count"),
                "proposal_count": context.get("proposal_count"),
                "artifact_count": len(context.get("artifacts") or []),
                "graph_neighbor_count": len((((context.get("bundle") or {}).get("graph") or {}).get("neighbors") or [])),
                "bundle_version": ((context.get("bundle") or {}).get("version")),
                "timeline": context.get("timeline") or {},
            },
            "assistant_config": context.get("assistant_config") or {},
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Assistant what-if error: {exc}")


@app.post("/assistant/demands")
def assistant_demands(req: AssistantDemandRequest):
    try:
        from skg.assistant import derive_demands

        context = _assistant_bundle_context(req)
        bundle = context.get("bundle") or {}
        demands = derive_demands(bundle, limit=req.limit)
        authority = _assistant_authority(
            DERIVED_ADVICE,
            task="derive_demands",
        )
        return {
            "assistant_output_class": DERIVED_ADVICE,
            "authority": authority,
            "selection": bundle.get("selection") or {
                "kind": req.kind,
                "id": req.id,
                "identity_key": context.get("identity_key"),
            },
            "bundle_version": bundle.get("version"),
            "count": len(demands),
            "demands": demands,
            "references": {
                "identity_key": context.get("identity_key"),
                "field_path_count": context.get("field_path_count"),
                "fold_count": context.get("fold_count"),
                "proposal_count": context.get("proposal_count"),
                "artifact_count": len(context.get("artifacts") or []),
            },
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Assistant demand error: {exc}")


@app.post("/assistant/draft-demand")
def assistant_draft_demand(req: AssistantDraftDemandRequest):
    try:
        from skg.assistant import derive_demands, draft_demand, select_demand

        inline_demand = dict(req.demand or {}) if isinstance(req.demand, dict) else None
        context_req = _assistant_draft_context_request(req, inline_demand)
        context = _assistant_bundle_context(context_req)
        bundle = context.get("bundle") or {}
        derived = derive_demands(bundle, limit=12)
        demand = select_demand(
            derived,
            demand_id=str((inline_demand or {}).get("id") or req.demand_id or ""),
            demand_kind=str((inline_demand or {}).get("demand_kind") or req.demand_kind or ""),
        )
        if not isinstance(demand, dict) or not demand:
            raise HTTPException(404, "Assistant demand not found for current physics state")

        drafted = draft_demand(demand, use_llm=bool(req.use_llm))
        authority = _assistant_authority(
            MUTATION_ARTIFACT,
            task="draft_demand",
            contract_name=str(drafted.get("contract") or demand.get("contract") or ""),
            demand=demand,
            model=drafted.get("model"),
        )
        return {
            "ok": True,
            "assistant_output_class": MUTATION_ARTIFACT,
            "authority": authority,
            "selection": (context.get("bundle") or {}).get("selection") or demand.get("selection") or {},
            "derived_count": len(derived),
            "draft": drafted,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Assistant draft error: {exc}")


def _artifact_preview_payload(path: str, lines: int = 12) -> dict[str, Any]:
    preview_lines = max(1, min(lines, 40))
    candidate = Path(path)
    allowed_roots = [EVENTS_DIR, INTERP_DIR, SKG_STATE_DIR / "discovery"]
    resolved = candidate.resolve()
    if not any(str(resolved).startswith(str(root.resolve())) for root in allowed_roots if root.exists()):
        raise HTTPException(403, "Artifact path outside allowed runtime roots")
    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(404, "Artifact not found")

    payload: dict[str, object] = {
        "path": str(resolved),
        "file": resolved.name,
        "preview_kind": "text",
        "rows": [],
    }

    if resolved.suffix == ".ndjson":
        payload["preview_kind"] = "ndjson"
        rows = []
        for index, line in enumerate(resolved.read_text(errors="replace").splitlines()):
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except Exception:
                parsed = {"raw": line[:500]}
            rows.append({"line": index + 1, "data": parsed})
            if len(rows) >= preview_lines:
                break
        payload["rows"] = rows
        return payload

    if resolved.suffix == ".json":
        payload["preview_kind"] = "json"
        data = json.loads(resolved.read_text())
        # Bound the JSON preview so large files don't blow up the response (LOW-11 fix).
        # Keep at most preview_lines top-level keys; truncate long string values.
        MAX_VALUE_CHARS = 500
        if isinstance(data, dict):
            bounded: dict[str, object] = {}
            for k in sorted(data.keys())[:preview_lines]:
                v = data[k]
                if isinstance(v, str) and len(v) > MAX_VALUE_CHARS:
                    v = v[:MAX_VALUE_CHARS] + "…"
                bounded[k] = v
            payload["rows"] = [{
                "keys": sorted(list(data.keys()))[:40],
                "data": bounded,
                "truncated": len(data) > preview_lines,
            }]
        elif isinstance(data, list):
            payload["rows"] = [{"data": item} for item in data[:preview_lines]]
        else:
            payload["rows"] = [{"data": data}]
        return payload

    payload["rows"] = [{"raw": line} for line in resolved.read_text(errors="replace").splitlines()[:preview_lines]]
    return payload


@app.get("/artifact/preview")
def artifact_preview(path: str, lines: int = 12):
    """Bounded preview of one runtime artifact file."""
    try:
        return _artifact_preview_payload(path, lines=lines)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Artifact preview error: {exc}")


@app.get("/proposals")
def list_proposals(status: str = "all"):
    try:
        from skg.forge import proposals as forge_proposals
        rows = forge_proposals.list_proposals(status=status)
        return {
            "count": len(rows),
            "status": status,
            "proposals": rows,
        }
    except Exception as exc:
        raise HTTPException(500, f"Proposal error: {exc}")


@app.get("/proposals/{proposal_id}")
def proposal_detail(proposal_id: str):
    try:
        from skg.forge import proposals as forge_proposals

        row = forge_proposals.get(proposal_id)
        if not row:
            raise HTTPException(404, f"Proposal not found: {proposal_id}")
        return row
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"Proposal detail error: {exc}")


@app.post("/proposals/{proposal_id}/accept")
def proposal_accept(proposal_id: str):
    try:
        from skg.forge import proposals as forge_proposals
        return forge_proposals.accept(proposal_id)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(404, msg)
        if "not pending" in msg.lower():
            raise HTTPException(409, msg)
        raise HTTPException(400, msg)
    except Exception as exc:
        raise HTTPException(500, f"Proposal accept error: {exc}")


@app.post("/proposals/{proposal_id}/launch-terminal")
def proposal_launch_terminal(proposal_id: str):
    """
    Spawn an xterm running msfconsole with the proposal's RC file.
    Called by the UI after a field_action proposal is accepted.
    Requires DISPLAY to be set (X11 session) or a compositor.
    """
    import subprocess, shutil, os
    try:
        from skg.forge.proposals import _proposal_path, ACCEPTED_DIR
        p = _proposal_path(proposal_id)
        if not p.exists():
            # check accepted dir
            p = ACCEPTED_DIR / f"{proposal_id}.json"
        if not p.exists():
            raise HTTPException(404, f"Proposal {proposal_id} not found")
        import json as _json
        proposal = _json.loads(p.read_text())
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(404, str(exc))

    rc_file = (proposal.get("action") or {}).get("rc_file") or ""
    if not rc_file or not Path(rc_file).exists():
        raise HTTPException(400, f"No RC file for proposal {proposal_id}")

    # Prefer konsole, then fallback to others
    env = {**os.environ}
    if "DISPLAY" not in env:
        env["DISPLAY"] = ":0"
    if "WAYLAND_DISPLAY" not in env:
        env["WAYLAND_DISPLAY"] = "wayland-0"

    for term, args in [
        ("konsole",         ["konsole", "--new-tab", "-e", "msfconsole", "-q", "-r", rc_file]),
        ("xterm",           ["xterm", "-title", f"SKG :: {proposal_id[:8]}", "-e",
                             "msfconsole", "-q", "-r", rc_file]),
        ("gnome-terminal",  ["gnome-terminal", "--", "msfconsole", "-q", "-r", rc_file]),
        ("kitty",           ["kitty", "msfconsole", "-q", "-r", rc_file]),
        ("alacritty",       ["alacritty", "-e", "msfconsole", "-q", "-r", rc_file]),
    ]:
        if shutil.which(term):
            try:
                subprocess.Popen(args, env=env, start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return {"ok": True, "terminal": term, "rc_file": rc_file}
            except Exception:
                continue

    # Fallback: launch msfconsole in a detached background process (no GUI)
    try:
        subprocess.Popen(
            ["msfconsole", "-q", "-r", rc_file],
            start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return {"ok": True, "terminal": "background", "rc_file": rc_file,
                "note": "No GUI terminal found — msfconsole launched in background"}
    except Exception as e:
        raise HTTPException(500, f"Could not launch terminal: {e}")


@app.post("/proposals/{proposal_id}/reset")
def proposal_reset(proposal_id: str):
    """Reset an error/expired/executed proposal back to pending so it can be re-triggered."""
    import json as _json
    from skg.forge.proposals import _proposal_path, ACCEPTED_DIR
    proposals_dir = SKG_STATE_DIR / "proposals"
    for search_dir in [proposals_dir, ACCEPTED_DIR]:
        p = search_dir / f"{proposal_id}.json"
        if not p.exists():
            # prefix match
            matches = list(search_dir.glob(f"{proposal_id}*.json")) if search_dir.exists() else []
            p = matches[0] if matches else p
        if p.exists():
            try:
                data = _json.loads(p.read_text())
                old_status = data.get("status")
                data["status"] = "pending"
                data["generated_at"] = datetime.now(timezone.utc).isoformat()
                data.pop("reviewed_at", None)
                data.pop("triggered_at", None)
                # Move back to proposals dir if in accepted
                dest = proposals_dir / p.name
                dest.write_text(_json.dumps(data, indent=2))
                if str(p) != str(dest):
                    p.unlink(missing_ok=True)
                return {"ok": True, "reset": proposal_id, "from_status": old_status}
            except Exception as exc:
                raise HTTPException(500, str(exc))
    raise HTTPException(404, f"Proposal {proposal_id} not found")


@app.post("/proposals/{proposal_id}/defer")
def proposal_defer(proposal_id: str, req: ProposalDeferRequest):
    try:
        from skg.forge import proposals as forge_proposals
        return forge_proposals.defer(proposal_id, days=req.days)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(404, msg)
        raise HTTPException(400, msg)
    except Exception as exc:
        raise HTTPException(500, f"Proposal defer error: {exc}")


@app.post("/proposals/{proposal_id}/reject")
def proposal_reject(proposal_id: str, req: ProposalRejectRequest):
    try:
        from skg.forge import proposals as forge_proposals
        return forge_proposals.reject(
            proposal_id,
            reason=req.reason,
            cooldown_days=req.cooldown_days,
        )
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg.lower():
            raise HTTPException(404, msg)
        raise HTTPException(400, msg)
    except Exception as exc:
        raise HTTPException(500, f"Proposal reject error: {exc}")


# --- Temporal / graph / feedback endpoints ---

@app.post("/feedback/process")
def feedback_process():
    """Process any unprocessed projection results — update delta, graph, obs memory."""
    if kernel.feedback is None:
        raise HTTPException(503, "Feedback ingester not initialized")
    result = kernel.feedback.process_new_interps()
    return {"ok": True, **result}


@app.get("/topology/energy")
def topology_energy():
    """Live G(t) — information field energy per domain sphere."""
    try:
        from skg.topology.energy import compute_field_energy_all
        results = compute_field_energy_all(DISCOVERY_DIR, INTERP_DIR)
        return {
            "spheres": {s: e.as_dict() for s, e in results.items()},
            "computed_at": __import__('datetime').datetime.now(
                __import__('datetime').timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(500, f"Topology energy error: {exc}")


@app.get("/topology/field")
def topology_field():
    """Decomposed field topology: self-energy, coupling, dissipation, curvature,
    and protected-state detection over the current substrate."""
    try:
        from skg.topology.energy import compute_field_topology
        result = compute_field_topology(DISCOVERY_DIR, INTERP_DIR)
        return result.as_dict()
    except Exception as exc:
        raise HTTPException(500, f"Topology field error: {exc}")


@app.get("/topology/fibers")
def topology_fibers():
    """Overlapping field fibers built from canonical world snapshots."""
    try:
        from skg.topology.energy import compute_field_fibers
        clusters = compute_field_fibers()
        return {
            "clusters": [c.as_dict() for c in clusters],
            "count": len(clusters),
            "computed_at": __import__('datetime').datetime.now(
                __import__('datetime').timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(500, f"Topology fibers error: {exc}")


@app.get("/topology/manifold")
def topology_manifold():
    """Simplicial complex over the wicket graph — Betti numbers, coupling matrix,
    and H¹ cohomological obstructions to global realizability."""
    try:
        from skg.topology.manifold import (
            build_full_complex, sphere_coupling_matrix, find_h1_obstructions
        )
        sc = build_full_complex(DISCOVERY_DIR)
        summary = sc.summary()
        C = sphere_coupling_matrix(sc)
        obstructions = find_h1_obstructions(sc)
        return {
            "complex":      summary,
            "coupling":     C,
            "h1_obstructions": obstructions,
            "h1_note": (
                "β₁ > 0 indicates mutually conditional preconditions — "
                "cycles in the wicket dependency graph that cannot be resolved "
                "by observation alone. These are H¹ cohomological obstructions "
                "to global section existence (Work3 Section 4)."
            ) if obstructions else (
                "β₁ = 0 — no H¹ obstructions. "
                "All indeterminate paths can be resolved by further observation."
            ),
            "computed_at": __import__('datetime').datetime.now(
                __import__('datetime').timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(500, f"Manifold error: {exc}")


@app.get("/memory/pearls/manifold")
def pearl_memory_manifold():
    """Derived pearl neighborhoods over the append-only pearl ledger."""
    try:
        from skg.kernel.pearl_manifold import load_pearl_manifold
        manifold = load_pearl_manifold(SKG_STATE_DIR / "pearls.jsonl")
        neighborhoods = [n.as_dict() for n in manifold.neighborhoods()]
        return {
            "neighborhoods": neighborhoods,
            "count": len(neighborhoods),
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        raise HTTPException(500, f"Pearl manifold error: {exc}")


@app.get("/topology/dynamics")
def topology_dynamics(steps: int = 200, K: float = 2.0):
    """Kuramoto phase dynamics on the live wicket graph."""
    try:
        from skg.topology.kuramoto import run_dynamics
        history = run_dynamics(EVENTS_DIR, INTERP_DIR,
                               steps=steps, dt=0.05, K=K)
        return {
            "K":       K,
            "steps":   steps,
            "R_init":  round(history[0].R, 6) if history else 0,
            "R_final": round(history[-1].R, 6) if history else 0,
            "delta_R": round(history[-1].R - history[0].R, 6) if history else 0,
            "series":  [s.as_dict() for s in history],
        }
    except Exception as exc:
        raise HTTPException(500, f"Dynamics error: {exc}")


@app.get("/topology/energy/history")
def topology_energy_history(sphere: str = "host"):
    """G(t) trajectory for a sphere across all historical sweeps."""
    try:
        from skg.topology.energy import compute_energy_timeseries
        series = compute_energy_timeseries(EVENTS_DIR, sphere=sphere)
        return {"sphere": sphere, "series": series}
    except Exception as exc:
        raise HTTPException(500, f"Topology history error: {exc}")


@app.get("/feedback/status")
def feedback_status():
    if kernel.feedback is None:
        return {"error": "Feedback ingester not initialized"}
    return kernel.feedback.status()


@app.get("/feedback/surface")
def feedback_surface(min_weight: float = 0.8):
    """High-signal wicket transitions across all workloads."""
    if kernel.feedback is None:
        raise HTTPException(503, "Feedback ingester not initialized")
    return kernel.feedback.surface(min_weight=min_weight)


@app.get("/feedback/timeline/{workload_id}")
def feedback_timeline(workload_id: str, attack_path_id: str | None = None):
    """State history and transition log for a specific workload."""
    if kernel.feedback is None:
        raise HTTPException(503, "Feedback ingester not initialized")
    return kernel.feedback.timeline(workload_id, attack_path_id)


@app.get("/graph/status")
def graph_status():
    return kernel.graph.status()


@app.post("/graph/edge")
def graph_add_edge(source: str, target: str, relationship: str, metadata: dict = {}):
    """Manually add a workload relationship edge."""
    edge = kernel.graph.add_edge(source, target, relationship,
                                  metadata=metadata, edge_source="manual_api")
    return {"ok": True, "edge": edge.to_dict()}


@app.get("/delta/summary")
def delta_summary():
    return kernel.delta.environment_summary()


@app.get("/delta/workloads")
def delta_workloads():
    return {"workloads": kernel.delta.all_workloads_latest()}


# --- Folds endpoints ---

@app.get("/folds")
def folds_summary():
    """
    Active folds across all targets — missing structural knowledge.

    Folds are added to field energy E because they represent regions of
    state space the system cannot yet evaluate:
      structural  — service running with no toolchain (e.g. redis, jenkins)
      projection  — attack path implied by observed conditions but not catalogued
      contextual  — CVE with no wicket mapping
      temporal    — stale evidence past its decay TTL, may have changed

    Each fold increases E by fold.gravity_weight(). Gravity pulls toward
    targets with high fold weight to direct operator attention.
    """
    folds_dir = SKG_STATE_DIR / "discovery" / "folds"
    all_folds = []
    summary   = {"total": 0, "by_type": {}, "total_gravity_weight": 0.0}

    if folds_dir.exists():
        try:
            from skg.kernel.folds import FoldManager
            for fold_file in sorted(folds_dir.glob("folds_*.json")):
                ip = fold_file.stem.replace("folds_", "").replace("_", ".")
                fm = FoldManager.load(fold_file)
                for fold in fm.all():
                    fd = fold.as_dict()
                    fd["identity_key"] = str(parse_workload_ref(fd.get("location", "")).get("identity_key") or ip).strip()
                    fd["target_ip"] = ip
                    all_folds.append(fd)
                    ft = fold.fold_type
                    summary["by_type"][ft] = summary["by_type"].get(ft, 0) + 1
                    summary["total_gravity_weight"] += fold.gravity_weight()
        except Exception as exc:
            return {"error": str(exc), "folds": []}

    summary["total"] = len(all_folds)
    summary["total_gravity_weight"] = round(summary["total_gravity_weight"], 4)

    # Sort by gravity weight descending — most impactful folds first
    all_folds.sort(key=lambda f: -f.get("gravity_weight", 0))

    return {
        "summary": summary,
        "folds":   all_folds,
        "note": (
            "Folds add to field energy E. "
            "structural: no toolchain coverage for observed service. "
            "projection: implied attack path not yet catalogued. "
            "contextual: CVE with no wicket mapping. "
            "temporal: evidence past decay TTL, may be stale."
        ),
    }


@app.get("/folds/structural")
def folds_structural():
    """
    Structural folds only — services running with no toolchain.
    These are the highest-priority operator action items:
    each one is a dark region with unknown attack surface.
    Resolve by running: skg catalog compile --domain <service> --description '<description>'
    """
    result = folds_summary()
    folds = [f for f in result.get("folds", [])
             if f.get("fold_type") == "structural"]
    return {
        "count": len(folds),
        "folds": folds,
        "action": "skg catalog compile --domain <service> --description '<attack surface>'",
    }


@app.post("/folds/resolve/{fold_id}")
def fold_resolve(fold_id: str, target_ip: str = "", identity_key: str = ""):
    """
    Mark a fold as resolved — removes it from E.

    Call this after:
      - Creating a toolchain for a structural fold
      - Mapping a CVE to wickets (contextual fold)
      - Re-observing a stale condition (temporal fold)
      - Cataloguing a new attack path (projection fold)
    """
    folds_dir  = SKG_STATE_DIR / "discovery" / "folds"
    subject_key = str(identity_key or target_ip or "").strip()
    if not subject_key:
        return {"error": "identity_key or target_ip required"}

    try:
        from skg.kernel.folds import FoldManager
        for fold_file in sorted(folds_dir.glob("folds_*.json")):
            fm = FoldManager.load(fold_file)
            if not fm.all():
                continue
            file_identity = str(parse_workload_ref(fm.all()[0].location).get("identity_key") or "").strip()
            legacy_identity = fold_file.stem.replace("folds_", "").replace("_", ".")
            if not _identity_matches(subject_key, file_identity, legacy_identity):
                continue
            resolved = fm.resolve(fold_id)
            if not resolved:
                continue
            fm.persist(fold_file)
            resolved_identity = file_identity or subject_key
            resolved_target_ip = target_ip if target_ip else (resolved_identity if resolved_identity.count(".") == 3 else "")
            try:
                PearlLedger(SKG_STATE_DIR / "pearls.jsonl").record(Pearl(
                    reason_changes=[{
                        "kind": "operator_action",
                        "action": "fold_resolved",
                        "fold_id": fold_id,
                        "target_ip": resolved_target_ip,
                        "identity_key": resolved_identity,
                    }],
                    energy_snapshot={
                        "target_ip": resolved_target_ip,
                        "identity_key": resolved_identity,
                        "workload_id": f"growth::{resolved_identity}",
                        "domain": "folds",
                    },
                    target_snapshot={
                        "workload_id": f"growth::{resolved_identity}",
                        "hosts": [resolved_identity],
                        "identity_key": resolved_identity,
                    },
                ))
            except Exception:
                pass
            return {
                "ok": True,
                "resolved": fold_id,
                "identity_key": resolved_identity,
                "remaining_folds": len(fm.all()),
                "remaining_gravity_weight": round(fm.total_gravity_weight(), 4),
            }
        return {"ok": False, "error": f"fold {fold_id} not found for {subject_key}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# --- Entry point ---

def _load_skg_env() -> None:
    """Load /etc/skg/skg.env key=value pairs into os.environ (do not override existing)."""
    env_file = SKG_CONFIG_DIR / "skg.env"
    if not env_file.exists():
        return
    try:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except Exception:
        pass


def run():
    _load_skg_env()
    log = setup_logging()

    def _shutdown(sig, _):
        log.info(f"Signal {sig}.")
        kernel.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))
    # Signal that the daemon loop is active so topology callers know they can
    # perform expensive per-target identity_world lookups safely.
    try:
        from skg.core import daemon_registry as _dr
        _dr._daemon_loop_running = True
    except Exception:
        pass
    kernel.boot()
    # Pre-warm the field_state cache in background so /status is fast on first call
    threading.Thread(target=_refresh_field_state_bg, daemon=True).start()
    log.info("API: 127.0.0.1:5055")
    uvicorn.run(app, host="127.0.0.1", port=5055, log_level="warning")


if __name__ == "__main__":
    run()

# Populate the thin registry so topology/energy.py can reach these functions
# without importing the full daemon.  Runs at module import time — safe because
# _all_targets_index and _identity_world don't start any server or threads.
try:
    from skg.core import daemon_registry as _dr
    _dr._all_targets_index = _all_targets_index
    _dr._identity_world    = _identity_world
except Exception:
    pass

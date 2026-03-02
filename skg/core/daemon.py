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
import json, logging, os, signal, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from skg.core.paths import (
    ensure_runtime_dirs, TOOLCHAIN_DIR, CE_TOOLCHAIN_DIR, AD_TOOLCHAIN_DIR,
    IDENTITY_FILE, EVENTS_DIR, INTERP_DIR, LOG_FILE, PID_FILE,
    RESONANCE_DIR, SKG_HOME,
)
from skg.modes import Mode, ModeTransition, MODE_BEHAVIOR, valid_transition
from skg.identity import Identity
from skg.resonance.engine import ResonanceEngine
from skg.resonance.ingester import ingest_all

# Registered domains: name → (cli_script, project_subcommand, interp_event_type)
DOMAINS = {
    "aprs": {
        "dir":        TOOLCHAIN_DIR,
        "cli":        "skg.py",
        "project_sub": ["project", "aprs"],
        "interp_type": "interp.attack_path.realizability",
        "default_path": "log4j_jndi_rce_v1",
    },
    "container_escape": {
        "dir":        CE_TOOLCHAIN_DIR,
        "cli":        "skg_escape.py",
        "project_sub": ["project"],
        "interp_type": "interp.container_escape.realizability",
        "default_path": "container_escape_privileged_v1",
    },
    "ad_lateral": {
        "dir":        AD_TOOLCHAIN_DIR,
        "cli":        "skg_lateral.py",
        "project_sub": ["project"],
        "interp_type": "interp.ad_lateral.realizability",
        "default_path": "ad_kerberoast_v1",
    },
}


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
        self._mode      = Mode.KERNEL
        self._started   = datetime.now(timezone.utc).isoformat()
        self.identity   = Identity(IDENTITY_FILE)
        self.toolchains = {d: Toolchain(d) for d in DOMAINS}
        self.resonance  = ResonanceEngine(RESONANCE_DIR)

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

        # Boot resonance engine and ingest toolchains if memory is empty
        try:
            self.resonance.boot()
            rs = self.resonance.status()
            total = sum(rs["memory"].values())
            if total == 0:
                self.log.info("Resonance memory empty — ingesting toolchains...")
                summary = ingest_all(self.resonance, SKG_HOME)
                self.log.info(f"Resonance ingestion complete: {summary}")
            else:
                self.log.info(f"Resonance memory: "
                              f"wickets={rs['memory']['wickets']} "
                              f"adapters={rs['memory']['adapters']} "
                              f"domains={rs['memory']['domains']}")
        except Exception as e:
            self.log.warning(f"Resonance engine failed to boot: {e} — continuing without it")

        self.log.info(f"Mode: {self._mode.value} | online.")

    def shutdown(self) -> None:
        self.log.info("SKG shutting down...")
        PID_FILE.unlink(missing_ok=True)
        self.log.info("SKG offline.")

    def set_mode(self, new_mode: Mode, reason: str = "") -> ModeTransition:
        valid, msg = valid_transition(self._mode, new_mode)
        if not valid:
            raise ValueError(msg)
        t = ModeTransition(from_mode=self._mode, to_mode=new_mode, reason=reason)
        self.identity.lock(new_mode == Mode.ANCHOR)
        if new_mode != Mode.ANCHOR:
            self.identity.update({"mode": new_mode.value}, source="system.daemon.mode_change")
        self._mode = new_mode
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
            rs = self.resonance.status_offline()
        return {
            "status": "online",
            "mode": self._mode.value,
            "mode_description": b["description"],
            "toolchain_runs_enabled": b["toolchain_runs"],
            "toolchains": tc_status,
            "resonance": rs,
            "started_at": self._started,
            "identity": {
                "name":      ident.name      if ident else "unknown",
                "version":   ident.version   if ident else "unknown",
                "coherence": ident.coherence if ident else 0.0,
                "sessions":  ident.sessions  if ident else 0,
            },
        }


# --- FastAPI ---

kernel = SKGKernel()
app    = FastAPI(title="SKG", version="1.0.0")


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


@app.get("/")
def root():
    return {"skg": "online",
            "domains": list(DOMAINS.keys()),
            "endpoints": ["/status", "/mode", "/identity", "/identity/history",
                          "/ingest", "/projections/{workload_id}"]}


@app.get("/status")
def status():
    return kernel.status()


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


@app.get("/projections/{workload_id}")
def get_projection(workload_id: str,
                   domain: str = "aprs",
                   attack_path_id: str | None = None):
    try:
        tc = kernel.get_toolchain(domain)
    except ValueError as e:
        raise HTTPException(400, str(e))

    attack_path_id = attack_path_id or DOMAINS[domain]["default_path"]
    prefix = f"{domain}_{workload_id}_"
    matches = sorted(INTERP_DIR.glob(f"{prefix}*_interp.ndjson"))
    if not matches:
        raise HTTPException(404, f"No projections for workload '{workload_id}' domain '{domain}'")
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
        else:
            return kernel.resonance.surface(q, k_each=k)
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


@app.get("/resonance/drafts")
def resonance_drafts():
    try:
        return {"drafts": kernel.resonance.list_drafts()}
    except Exception as e:
        raise HTTPException(500, str(e))


# --- Entry point ---

def run():
    log = setup_logging()

    def _shutdown(sig, _):
        log.info(f"Signal {sig}.")
        kernel.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))
    kernel.boot()
    log.info("API: 127.0.0.1:5055")
    uvicorn.run(app, host="127.0.0.1", port=5055, log_level="warning")


if __name__ == "__main__":
    run()

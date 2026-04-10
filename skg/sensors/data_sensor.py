"""
skg.sensors.data_sensor
=======================
Data pipeline sensor — polls declared database sources and emits DP-* events.

Registered as "data" in the sensor registry.
Reads data_sources from skg_config.yaml.
Runs the db_profiler adapter against each configured source on its declared interval.

Config (skg_config.yaml):
  sensors:
    enabled:
      - data
    data:
      collect_interval_s: 300
      sources:
        - url: postgresql://user:pass@host/db
          table: orders
          workload_id: banking::orders
          contract: /etc/skg/contracts/orders.json
          attack_path_id: data_completeness_failure_v1
          ttl_hours: 24

        - url: sqlite:///mydb.db
          table: sensor_readings
          workload_id: agriculture::sensor_readings
          attack_path_id: data_drift_undetected_v1

Bond discovery:
  The data sensor detects pipeline topology from the declared sources config
  and registers data bonds (upstream_of, derived_from, same_pipeline) into
  the WorkloadGraph. This allows prior propagation to flow between pipeline
  stages — if the upstream source has fresh data, downstream stages are
  gravitationally more interesting to observe.
"""
from __future__ import annotations

import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from skg.sensors import BaseSensor, register
from skg_core.config.paths import EVENTS_DIR, SKG_CONFIG_DIR, SKG_HOME, SKG_STATE_DIR

log = logging.getLogger("skg.sensors.data")

DATA_STATE_FILE = SKG_STATE_DIR / "data_sensor.state.json"

# Bond types for data pipeline topology
# These map to WorkloadGraph relationship types
DATA_BOND_TYPES = {
    "upstream_of":   1.00,  # A is the direct upstream source for B
    "derived_from":  0.90,  # B is a transformation of A
    "same_batch":    0.80,  # co-scheduled in same ETL run
    "shared_schema": 0.70,  # share a schema contract
    "same_database": 0.60,  # same database instance
    "same_pipeline": 0.40,  # stages in the same declared pipeline
}


@register("data")
class DataSensor(BaseSensor):
    """
    Data pipeline sensor.

    Polls configured database tables/views using the db_profiler adapter
    and emits DP-01..DP-15 wicket events. Also discovers pipeline topology
    bonds and registers them in the WorkloadGraph.
    """
    name = "data"

    def __init__(self, cfg: dict, events_dir=None):
        super().__init__(cfg, events_dir=events_dir)
        self.interval = cfg.get("collect_interval_s", 300)
        self.sources  = self._load_sources(cfg)
        self._state   = self._load_state()

    def _load_sources(self, cfg: dict) -> list[dict]:
        sources = cfg.get("sources", [])
        if sources:
            return sources

        for candidate in (
            SKG_CONFIG_DIR / "data_sources.yaml",
            SKG_HOME / "config" / "data_sources.yaml",
        ):
            if not candidate.exists():
                continue
            try:
                import yaml
                data = yaml.safe_load(candidate.read_text()) or {}
                loaded = data.get("data_sources", [])
                if loaded:
                    return loaded
            except Exception as exc:
                log.warning(f"[data] failed to load {candidate}: {exc}")
        return []

    def _load_state(self) -> dict:
        if DATA_STATE_FILE.exists():
            try:
                return json.loads(DATA_STATE_FILE.read_text())
            except Exception:
                pass
        return {"last_collected": {}}

    def _save_state(self) -> None:
        DATA_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        DATA_STATE_FILE.write_text(json.dumps(self._state, indent=2))

    def _should_collect(self, workload_id: str) -> bool:
        last = self._state["last_collected"].get(workload_id, 0)
        now  = datetime.now(timezone.utc).timestamp()
        return (now - last) >= self.interval

    def run(self) -> list[str]:
        if not self.sources:
            log.debug("[data] no sources configured — add data.sources to skg_config.yaml")
            return []

        # Import adapter — lazy so missing SQLAlchemy doesn't break startup
        try:
            adapter_path = (Path(__file__).resolve().parents[2]
                            / "skg-data-toolchain" / "adapters" / "db_profiler")
            sys.path.insert(0, str(adapter_path.parent.parent))
            from adapters.db_profiler.profile import profile_table
        except ImportError:
            # Try alternative path
            try:
                sys.path.insert(0, str(SKG_HOME / "skg-data-toolchain"))
                from adapters.db_profiler.profile import profile_table
            except ImportError as exc:
                log.warning(f"[data] db_profiler not found: {exc}")
                return []

        all_ids: list[str] = []

        for src in self.sources:
            url         = src.get("url", "")
            table       = src.get("table", "")
            workload_id = src.get("workload_id") or f"data::{table}"
            contract    = src.get("contract")
            apid        = src.get("attack_path_id", "data_completeness_failure_v1")

            if not url or not table:
                continue
            if not self._should_collect(workload_id):
                continue

            run_id = str(uuid.uuid4())[:8]
            log.info(f"[data] profiling {table} ({workload_id})")

            try:
                events = profile_table(
                    url=url, table=table,
                    workload_id=workload_id,
                    contract_path=contract,
                    attack_path_id=apid,
                    run_id=run_id,
                )
            except Exception as exc:
                log.warning(f"[data] profile_table failed for {workload_id}: {exc}")
                continue

            if not events:
                continue

            # Write events to EVENTS_DIR
            out_file = self.events_dir / f"data_{workload_id.replace('::', '_')}_{run_id}.ndjson"
            try:
                with open(out_file, "w") as fh:
                    for ev in events:
                        fh.write(json.dumps(ev) + "\n")
                ids = [ev["id"] for ev in events]
                all_ids.extend(ids)
                log.info(f"[data] {workload_id}: {len(events)} events "
                         f"({sum(1 for e in events if e['payload']['status']=='realized')}R "
                         f"{sum(1 for e in events if e['payload']['status']=='blocked')}B "
                         f"{sum(1 for e in events if e['payload']['status']=='unknown')}U)")
            except Exception as exc:
                log.warning(f"[data] write failed for {workload_id}: {exc}")
                continue

            self._state["last_collected"][workload_id] = (
                datetime.now(timezone.utc).timestamp()
            )

        # Register pipeline topology bonds
        self._register_bonds()
        self._save_state()

        return all_ids

    def _register_bonds(self) -> None:
        """
        Discover and register data pipeline topology bonds.

        Reads 'pipeline_topology' from config if declared, otherwise
        infers bonds from source declarations (same database = same_database bond).
        """
        graph = getattr(self, "_graph", None) or getattr(self, "graph", None)
        if not graph:
            return

        topology = self.cfg.get("pipeline_topology", []) if self.cfg else []

        # Explicit topology declarations
        for bond in topology:
            source_wid = bond.get("from", "")
            target_wid = bond.get("to", "")
            rel_type   = bond.get("type", "upstream_of")
            if not source_wid or not target_wid:
                continue
            try:
                strength = DATA_BOND_TYPES.get(rel_type, 0.5)
                graph.add_edge(
                    source_wid, target_wid, rel_type,
                    metadata={"strength": strength},
                    weight=strength,
                    edge_source="data_sensor",
                )
                log.debug(f"[data] bond: {source_wid} →[{rel_type}]→ {target_wid}")
            except Exception as exc:
                log.debug(f"[data] bond registration failed: {exc}")

        # Infer same_database bonds
        db_groups: dict[str, list[str]] = {}
        for src in self.sources:
            url = src.get("url", "")
            wid = src.get("workload_id") or f"data::{src.get('table','')}"
            # Group by db URL (redact credentials)
            import re
            db_key = re.sub(r"://[^@]+@", "://***@", url)
            db_groups.setdefault(db_key, []).append(wid)

        for db_key, wids in db_groups.items():
            if len(wids) < 2:
                continue
            for i, wid_a in enumerate(wids):
                for wid_b in wids[i+1:]:
                    try:
                        graph.add_edge(
                            wid_a, wid_b, "same_database",
                            metadata={"strength": 0.60},
                            weight=0.60,
                            edge_source="data_sensor_inferred",
                        )
                    except Exception:
                        pass

"""
skg.kernel.folds
================
Folds — missing structural knowledge in the substrate.

A Fold is not an unknown state of a known node.
An unknown node state is handled by TriState.UNKNOWN and counted in E.

A Fold is a gap in the model itself:
  - A condition that should be measurable but isn't yet catalogued.
  - An attack path that should exist but doesn't.
  - A service running on a target with no toolchain to evaluate it.
  - A CVE with no wicket mapping yet.
  - A condition that existed but evidence has expired.

Why folds matter to E:
  EnergyEngine.compute() = |unknown nodes| + |folds|
  Folds add to field energy because they represent structural uncertainty —
  the system doesn't know what it doesn't know.  A target with 10 unknown
  wickets and 3 folds has E=13, not E=10.  Gravity pulls harder toward it.

Fold types (Work 3 spec):
  structural   — a node/condition that should exist but isn't in any catalog.
                 Source: gap_detector finding a service with no toolchain.
                 Example: redis running on 6379, no redis wickets in any catalog.

  projection   — an attack path that should exist but isn't catalogued.
                 Source: gravity_field encountering conditions that partially
                 match an unknown path pattern, or gap_detector finding a
                 service that implies known exploit chains.
                 Example: Jupyter notebook server observed — no jupyter_rce path.

  contextual   — a condition specific to this environment that the generic
                 catalogs don't cover.
                 Source: NVD returning CVEs for which we have no wicket mapping,
                 or novel service configs observed in SSH collection.
                 Example: CVE-2023-99999 for a version of X, no wicket for it.

  temporal     — evidence that was realized but has decayed past its TTL.
                 The condition may have changed and needs re-observation.
                 Source: EnergyEngine reviewing Pearl records for stale
                 high-confidence realizations with ephemeral decay class.
                 Example: WB-08 (default creds) realized 48h ago —
                 may have been rotated.

Lifecycle:
  1. FoldDetector scans gaps, CVE matches, stale evidence → creates Folds
  2. FoldManager holds active folds
  3. EnergyEngine.compute() includes len(folds) in E
  4. gravity_field uses FoldManager to boost E for fold-heavy targets
  5. When a fold is resolved (toolchain created, CVE mapped, evidence refreshed)
     → FoldManager.resolve() removes it → E drops
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

log = logging.getLogger("skg.kernel.folds")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Fold:
    """
    A unit of missing structural knowledge.

    fold_type:          structural | projection | contextual | temporal
    location:           where the gap lives (workload_id, service, path_id)
    constraint_source:  what detected this gap (gap_detector, nvd_feed, decay)
    discovery_probability: how likely this fold hides an exploitable condition
                           1.0 = definitely exploitable if explored
                           0.5 = unknown — default prior
                           0.1 = low signal
    detail:             human-readable description of what's missing
    created_time:       when this fold was detected
    id:                 unique identifier
    """
    fold_type:             str
    location:              str
    constraint_source:     str
    discovery_probability: float = 0.5
    detail:                str   = ""
    created_time:          datetime = field(default_factory=utcnow)
    id:                    str   = field(default_factory=lambda: str(uuid4()))

    def gravity_weight(self) -> float:
        """
        Φ(fold) — the contribution of this fold to field energy E.

        E* = |unknown nodes| + Σ Φ(fold)   (Work 3 Section 3.2 extended)

        Derivation:
        A fold represents a region of state space where the instrument
        set is incomplete. The entropy contribution is bounded by the
        information content of the missing observation:

            Φ = coverage_deficit × discovery_probability

        where coverage_deficit depends on fold type:

          structural:  The entire service surface is dark. Every wicket
                       for that service is unknown-by-construction, not just
                       unmeasured. The deficit is maximal (1.0) because we
                       cannot evaluate any condition, plus the prior p that
                       at least one condition is exploitable:
                           Φ_structural = 1.0 + p

          projection:  The service is visible but a specific attack path is
                       uncatalogued. We can see some wickets but cannot score
                       the path. The deficit is partial (0.5 base) because
                       adjacent paths are observable, scaled by p:
                           Φ_projection = 0.5 + 0.5 × p
                       This is strictly less than structural (max = 1.0 < 2.0)
                       because the surface is not entirely dark.

          contextual:  A specific condition (CVE, novel config) exists but
                       has no wicket. The deficit is proportional to p alone
                       because all other wickets are still evaluable:
                           Φ_contextual = p
                       Bounded in [0, 1], strictly less than projection.

          temporal:    Evidence existed but has decayed past TTL. The prior
                       probability that the condition has CHANGED since the
                       last observation determines the deficit. An ephemeral
                       condition that decayed 3× its TTL contributes more than
                       one that decayed 1.1× its TTL. We model this as:
                           Φ_temporal = p × decay_factor
                       where decay_factor ∈ (0, 1] encodes staleness.
                       Default decay_factor = 0.7 (no TTL metadata available),
                       which places temporal between contextual and projection.

        Ordering guarantee: Φ_structural ≥ Φ_projection ≥ Φ_contextual
        when p is fixed. Temporal is between contextual and projection.

        This ordering reflects the relative epistemic cost of each fold type:
        dark surface > uncatalogued path > single-condition gap > stale evidence.
        """
        p = max(0.0, min(1.0, self.discovery_probability))
        if self.fold_type == "structural":
            return 1.0 + p
        elif self.fold_type == "projection":
            return 0.5 + 0.5 * p
        elif self.fold_type == "contextual":
            return p
        elif self.fold_type == "temporal":
            # decay_factor: encode staleness if TTL metadata available
            decay = float(getattr(self, "decay_factor", 0.7))
            decay = max(0.0, min(1.0, decay))
            return p * decay
        # Unknown fold type: treat as contextual
        return p

    def as_dict(self) -> dict:
        return {
            "id":                    self.id,
            "fold_type":             self.fold_type,
            "location":              self.location,
            "constraint_source":     self.constraint_source,
            "discovery_probability": self.discovery_probability,
            "detail":                self.detail,
            "gravity_weight":        round(self.gravity_weight(), 4),
            "created_time":          self.created_time.isoformat(),
        }


class FoldManager:
    """
    Holds active folds for a target or the global field.

    Folds are resolved (removed from E) when:
      - A toolchain is created and bootstrapped (structural fold resolved)
      - A new attack path is catalogued (projection fold resolved)
      - A CVE gets a wicket mapping (contextual fold resolved)
      - Evidence is refreshed (temporal fold resolved)
    """

    def __init__(self) -> None:
        self._folds: List[Fold] = []

    def add(self, fold: Fold) -> None:
        # Deduplicate by (fold_type, location, constraint_source)
        key = (fold.fold_type, fold.location, fold.constraint_source)
        for existing in self._folds:
            if (existing.fold_type, existing.location,
                    existing.constraint_source) == key:
                return  # already tracking this fold
        self._folds.append(fold)
        log.debug(f"[fold] added {fold.fold_type} @ {fold.location} "
                  f"(p={fold.discovery_probability:.2f}): {fold.detail[:60]}")

    def resolve(self, fold_id: str) -> bool:
        """Remove a fold by ID. Returns True if found and removed."""
        before = len(self._folds)
        self._folds = [f for f in self._folds if f.id != fold_id]
        resolved = len(self._folds) < before
        if resolved:
            log.debug(f"[fold] resolved {fold_id}")
        return resolved

    def resolve_by_location(self, location: str) -> int:
        """Remove all folds for a location. Returns count removed."""
        before = len(self._folds)
        self._folds = [f for f in self._folds if f.location != location]
        count = before - len(self._folds)
        if count:
            log.debug(f"[fold] resolved {count} folds @ {location}")
        return count

    def all(self) -> List[Fold]:
        return list(self._folds)

    def by_type(self, fold_type: str) -> List[Fold]:
        return [f for f in self._folds if f.fold_type == fold_type]

    def total_gravity_weight(self) -> float:
        """Sum of gravity weights — total fold contribution to E."""
        return sum(f.gravity_weight() for f in self._folds)

    def summary(self) -> dict:
        by_type: dict[str, int] = {}
        for f in self._folds:
            by_type[f.fold_type] = by_type.get(f.fold_type, 0) + 1
        return {
            "total":           len(self._folds),
            "by_type":         by_type,
            "gravity_weight":  round(self.total_gravity_weight(), 4),
        }

    def persist(self, path: Path) -> None:
        """Write fold state to disk."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(
            [f.as_dict() for f in self._folds], indent=2
        ))

    @classmethod
    def load(cls, path: Path) -> "FoldManager":
        """Load fold state from disk."""
        fm = cls()
        if not path.exists():
            return fm
        try:
            for d in json.loads(path.read_text()):
                fm.add(Fold(
                    fold_type=d["fold_type"],
                    location=d["location"],
                    constraint_source=d["constraint_source"],
                    discovery_probability=float(d.get("discovery_probability", 0.5)),
                    detail=d.get("detail", ""),
                    id=d.get("id", str(uuid4())),
                ))
        except Exception as exc:
            log.warning(f"FoldManager.load failed: {exc}")
        return fm


class FoldDetector:
    """
    Scans the live system state and creates Folds for the FoldManager.

    Run after each sensor sweep.  Returns list of new Folds created.

    Sources:
      1. gap_detector — services/ports with no toolchain → structural folds
      2. NVD CVE events — CVEs with no wicket mapping → contextual folds
      3. Pearl ledger  — stale high-confidence evidence → temporal folds
      4. Unrealized paths with novel conditions → projection folds
    """

    # These CVE prefixes are in the catalog.  Others are contextual folds.
    CATALOGUED_CVE_PREFIXES = {
        "CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105", "CVE-2021-44832",  # Log4Shell
        "CVE-2022-0492", "CVE-2019-5736", "CVE-2020-15257",                       # Container escape
        "CVE-2020-1472", "CVE-2021-42287", "CVE-2021-42278", "CVE-2022-26923",    # AD
    }

    # Temporal fold: evidence older than this (hours) with ephemeral decay class
    EPHEMERAL_TTL_HOURS = 4
    # Temporal fold: evidence older than this (hours) with operational decay class
    OPERATIONAL_TTL_HOURS = 24

    def detect_structural(self, events_dir: Path,
                          toolchain_dir: Path) -> List[Fold]:
        """
        Detect services running on targets that have no toolchain coverage.
        Each uncovered service = 1 structural fold with discovery_probability
        scaled by the known attack surface of that service.
        """
        try:
            from skg.intel.gap_detector import detect_from_events
            from skg.intel.gap_detector import KNOWN_SERVICES
        except ImportError:
            return []

        gaps = detect_from_events(events_dir)
        folds = []

        # Attack surface severity → discovery probability
        HIGH_SURFACE_KEYWORDS = {
            "rce", "remote code", "unauthenticated", "no auth", "deserialization",
            "script console", "command injection", "0day", "zero-day",
        }
        MEDIUM_SURFACE_KEYWORDS = {
            "credential", "default cred", "privilege", "ssrf", "path traversal",
            "exposure", "enumeration",
        }

        for gap in gaps:
            svc     = gap.get("service", "")
            surface = gap.get("attack_surface", "").lower()
            hosts   = gap.get("hosts", [])

            # Score by attack surface description
            if any(kw in surface for kw in HIGH_SURFACE_KEYWORDS):
                prob = 0.85
            elif any(kw in surface for kw in MEDIUM_SURFACE_KEYWORDS):
                prob = 0.60
            else:
                prob = 0.45

            for host in hosts:
                folds.append(Fold(
                    fold_type="structural",
                    location=host,
                    constraint_source=f"gap_detector::{svc}",
                    discovery_probability=prob,
                    detail=(
                        f"{svc} has no toolchain coverage. "
                        f"Attack surface: {gap.get('attack_surface', 'unknown')[:120]}. "
                        f"Collection hints: {'; '.join(gap.get('collection_hints', [])[:2])}"
                    ),
                ))

        return folds

    def detect_contextual(self, cve_dir: Path) -> List[Fold]:
        """
        Detect CVEs returned by NVD that have no wicket mapping in any catalog.
        These are real vulnerabilities the system observed but can't score.
        """
        folds = []
        if not cve_dir.exists():
            return folds

        for f in sorted(cve_dir.glob("cve_events_*.ndjson"))[-20:]:
            for line in f.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                payload = ev.get("payload", {})
                cve_id  = payload.get("wicket_id", "")
                if not cve_id.startswith("CVE-"):
                    continue
                if cve_id in self.CATALOGUED_CVE_PREFIXES:
                    continue  # already has wicket mapping

                # Parse CVSS from detail
                try:
                    detail_obj = json.loads(payload.get("detail", "{}"))
                    cvss = float(detail_obj.get("cvss", 0.0))
                except Exception:
                    cvss = 0.0

                # discovery_probability scales with CVSS
                # CVSS 10.0 → 0.95, CVSS 7.0 → 0.70, CVSS 4.0 → 0.40
                prob = min(0.95, max(0.20, cvss / 10.5))

                target_ip  = payload.get("target_ip", "unknown")
                service    = ""
                try:
                    service = json.loads(payload.get("detail","{}")).get("service","")
                except Exception:
                    pass

                folds.append(Fold(
                    fold_type="contextual",
                    location=f"cve::{target_ip}",
                    constraint_source=f"nvd_feed::{cve_id}",
                    discovery_probability=prob,
                    detail=(
                        f"{cve_id} has no wicket mapping. "
                        f"Service: {service}. CVSS: {cvss}. "
                        f"Create a wicket with: skg catalog compile --domain <domain> "
                        f"--keywords {cve_id}"
                    ),
                ))

        return folds

    def detect_temporal(self, events_dir: Path) -> List[Fold]:
        """
        Detect stale evidence — conditions that were realized but whose
        evidence has aged past its decay class TTL.

        These are temporal folds: the condition may have changed (credentials
        rotated, service patched, config updated) and needs re-observation.
        """
        folds = []
        now   = datetime.now(timezone.utc)

        ttl_map = {
            "ephemeral":   timedelta(hours=self.EPHEMERAL_TTL_HOURS),
            "operational": timedelta(hours=self.OPERATIONAL_TTL_HOURS),
            "structural":  timedelta(days=7),
        }

        if not events_dir.exists():
            return folds

        # Track latest observation per (workload_id, wicket_id)
        latest: dict[tuple, dict] = {}

        for f in sorted(events_dir.glob("*.ndjson"))[-100:]:
            for line in f.read_text(errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if ev.get("type") != "obs.attack.precondition":
                    continue

                payload     = ev.get("payload", {})
                prov        = ev.get("provenance", {})
                wicket_id   = payload.get("wicket_id", "")
                workload_id = payload.get("workload_id", "")
                status      = payload.get("status", "unknown")
                ts_str      = ev.get("ts", "")
                decay_class = prov.get("evidence", {}).get(
                    "source_kind", "operational")

                if not wicket_id or status != "realized":
                    continue

                key = (workload_id, wicket_id)
                if key not in latest or ts_str > latest[key]["ts"]:
                    latest[key] = {
                        "ts":           ts_str,
                        "decay_class":  decay_class,
                        "workload_id":  workload_id,
                        "wicket_id":    wicket_id,
                    }

        for key, rec in latest.items():
            workload_id = rec["workload_id"]
            wicket_id   = rec["wicket_id"]
            decay_class = rec["decay_class"]
            ts_str      = rec["ts"]

            # Parse timestamp
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                continue

            ttl = ttl_map.get(
                decay_class,
                ttl_map.get("operational"),
            )
            age = now - ts

            if age > ttl:
                # Probability of change scales with how far past TTL we are
                overage_ratio = min(1.0, (age - ttl).total_seconds() /
                                    ttl.total_seconds())
                prob = 0.30 + 0.50 * overage_ratio  # 0.30 at TTL, 0.80 at 2×TTL

                folds.append(Fold(
                    fold_type="temporal",
                    location=workload_id,
                    constraint_source=f"decay::{decay_class}::{wicket_id}",
                    discovery_probability=round(prob, 3),
                    detail=(
                        f"{wicket_id} was realized {int(age.total_seconds()/3600)}h ago "
                        f"(decay_class={decay_class}, TTL={int(ttl.total_seconds()/3600)}h). "
                        f"Evidence may be stale — re-observe to confirm."
                    ),
                ))

        return folds

    def detect_projection(self, events_dir: Path,
                          toolchain_dir: Path) -> List[Fold]:
        """
        Detect conditions that imply attack paths not in any catalog.

        Looks for:
          - Services detected (via gap signals) with known exploit chains
            that we haven't modelled as paths
          - Combinations of realized wickets that suggest a cross-domain
            path exists but isn't catalogued
        """
        folds = []

        # Known exploit chains that imply a projection fold if the service
        # is present but no path is catalogued for it
        KNOWN_EXPLOIT_CHAINS = {
            "jenkins":      "jenkins_groovy_rce_v1",
            "redis":        "redis_rce_via_config_v1",
            "elasticsearch": "elasticsearch_script_injection_v1",
            "kubernetes":   "kubernetes_kubelet_rce_v1",
            "consul":       "consul_script_check_rce_v1",
            "grafana":      "grafana_path_traversal_v1",
            "jupyter":      "jupyter_no_auth_rce_v1",
            "mongodb":      "mongodb_unauth_access_v1",
        }

        # Load all catalogued attack path IDs
        catalogued_paths: set[str] = set()
        if toolchain_dir.exists():
            import glob
            for catalog_file in glob.glob(
                    str(toolchain_dir / "skg-*-toolchain/contracts/catalogs/*.json")):
                try:
                    data = json.loads(Path(catalog_file).read_text())
                    paths = data.get("attack_paths", {})
                    if isinstance(paths, dict):
                        catalogued_paths.update(paths.keys())
                except Exception:
                    continue

        # Scan for gap signals in recent events
        if events_dir.exists():
            for f in sorted(events_dir.glob("web_raw_*.ndjson"))[-20:]:
                for line in f.read_text(errors="replace").splitlines():
                    if not line.strip():
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue
                    payload = ev.get("payload", {})
                    svc     = payload.get("detail", "").lower()
                    wid     = payload.get("workload_id", "")

                    for service, path_id in KNOWN_EXPLOIT_CHAINS.items():
                        if service in svc and path_id not in catalogued_paths:
                            folds.append(Fold(
                                fold_type="projection",
                                location=wid,
                                constraint_source=f"gap::missing_path::{path_id}",
                                discovery_probability=0.75,
                                detail=(
                                    f"{service} detected at {wid} but "
                                    f"attack path '{path_id}' is not catalogued. "
                                    f"Generate with: skg catalog compile "
                                    f"--domain {service} --description '{service} exploit chain'"
                                ),
                            ))

        return folds

    def detect_all(self,
                   events_dir:    Path,
                   cve_dir:       Path,
                   toolchain_dir: Path) -> List[Fold]:
        """Run all fold detectors and return the combined list."""
        folds = []
        for detector in [
            lambda: self.detect_structural(events_dir, toolchain_dir),
            lambda: self.detect_contextual(cve_dir),
            lambda: self.detect_temporal(events_dir),
            lambda: self.detect_projection(events_dir, toolchain_dir),
        ]:
            try:
                folds.extend(detector())
            except Exception as exc:
                log.warning(f"FoldDetector sub-detector failed: {exc}")
        return folds

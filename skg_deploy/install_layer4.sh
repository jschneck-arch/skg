#!/usr/bin/env bash
# =============================================================================
# SKG Install — Layer 4
# Sensors, gravity engines, toolchains, resonance, forge, discovery, CLI
#
# Run AFTER install.sh (Layers 1-3) completes.
# Usage: sudo bash install_layer4.sh
# =============================================================================
set -euo pipefail

SKG_HOME="${SKG_HOME:-/opt/skg}"
SKG_STATE="${SKG_STATE_DIR:-/var/lib/skg}"
SKG_CONFIG="${SKG_CONFIG_DIR:-/etc/skg}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON=$(command -v python3)

log()  { echo "[skg-install-l4] $*"; }
ok()   { echo "[skg-install-l4]   OK  $*"; }
die()  { echo "[skg-install-l4] ERROR: $*" >&2; exit 1; }

# ── Preflight ─────────────────────────────────────────────────────────────────

[ -d "$SKG_HOME/skg/kernel" ] || die "Layer 1-3 not installed — run install.sh first"
$PYTHON -c "from skg.kernel import TriState" 2>/dev/null \
    || die "skg.kernel not importable — run install.sh first"

# ── skg package modules (sensors, resonance, forge, catalog, intel, etc.) ─────

log "Installing skg package modules..."
for mod in sensors resonance forge catalog intel identity modes training domains; do
    src="$SCRIPT_DIR/skg/$mod"
    [ -d "$src" ] || continue
    cp -r "$src" "$SKG_HOME/skg/"
    ok "skg.$mod"
done

# ── Gravity engines ────────────────────────────────────────────────────────────

log "Installing gravity engines..."
install -d "$SKG_HOME/skg-gravity"
install -m644 "$SCRIPT_DIR/skg-gravity/gravity.py"          "$SKG_HOME/skg-gravity/"
install -m644 "$SCRIPT_DIR/skg-gravity/gravity_field.py"    "$SKG_HOME/skg-gravity/"
install -m644 "$SCRIPT_DIR/skg-gravity/gravity_web.py"      "$SKG_HOME/skg-gravity/"
install -m644 "$SCRIPT_DIR/skg-gravity/exploit_proposals.py" "$SKG_HOME/skg-gravity/"
ok "gravity.py  (web-strategy loop)"
ok "gravity_field.py  (entropy field engine — canonical)"

# ── Discovery ─────────────────────────────────────────────────────────────────

log "Installing discovery engine..."
install -d "$SKG_HOME/skg-discovery"
install -m644 "$SCRIPT_DIR/skg-discovery/discovery.py" "$SKG_HOME/skg-discovery/"
ok "discovery.py"

# ── NVD feed ──────────────────────────────────────────────────────────────────

log "Installing NVD feed pipeline..."
install -d "$SKG_HOME/feeds"
install -m644 "$SCRIPT_DIR/feeds/nvd_ingester.py" "$SKG_HOME/feeds/"
ok "nvd_ingester.py"

# ── Toolchains ────────────────────────────────────────────────────────────────

log "Installing toolchains..."
for tc in skg-aprs-toolchain skg-container-escape-toolchain \
          skg-ad-lateral-toolchain skg-host-toolchain skg-web-toolchain \
          skg-iot_firmware-toolchain skg-supply-chain-toolchain; do
    src="$SCRIPT_DIR/$tc"
    [ -d "$src" ] || continue
    cp -r "$src" "$SKG_HOME/"
    ok "$tc"
done

# Bootstrap each active toolchain's venv (projectors run in-process but
# the bootstrap.sh installs toolchain-specific deps)
for tc in skg-aprs-toolchain skg-container-escape-toolchain \
          skg-ad-lateral-toolchain skg-host-toolchain skg-web-toolchain; do
    bs="$SKG_HOME/$tc/bootstrap.sh"
    if [ -f "$bs" ]; then
        log "Bootstrapping $tc..."
        bash "$bs" "$SKG_HOME/$tc" >/dev/null 2>&1 \
            && ok "$tc bootstrap" \
            || log "  (bootstrap warning — check $tc/bootstrap.sh manually)"
    fi
done

# ── Resonance seed records ─────────────────────────────────────────────────────

log "Seeding resonance records..."
install -d "$SKG_STATE/resonance/records"
if [ -d "$SCRIPT_DIR/resonance/records" ]; then
    cp "$SCRIPT_DIR/resonance/records"/*.jsonl "$SKG_STATE/resonance/records/" 2>/dev/null || true
    ok "resonance seed records"
fi

# ── Config ────────────────────────────────────────────────────────────────────

log "Installing config..."
install -d "$SKG_CONFIG"
# Only install config files if they don't already exist (preserve operator edits)
for f in skg_config.yaml targets.yaml; do
    src="$SCRIPT_DIR/config/$f"
    dst="$SKG_CONFIG/$f"
    if [ -f "$src" ] && [ ! -f "$dst" ]; then
        install -m644 "$src" "$dst"
        ok "config/$f"
    elif [ -f "$dst" ]; then
        log "  config/$f already exists — skipping (preserved)"
    fi
done

# ── CLI ───────────────────────────────────────────────────────────────────────

log "Installing CLI..."
install -d "$SKG_HOME/bin"
install -m755 "$SCRIPT_DIR/bin/skg" "$SKG_HOME/bin/skg"

# Symlink to /usr/local/bin for system-wide access
if [ -d /usr/local/bin ]; then
    ln -sf "$SKG_HOME/bin/skg" /usr/local/bin/skg
    ok "CLI: /usr/local/bin/skg → $SKG_HOME/bin/skg"
fi

# ── Smoke test — import all Layer 4 modules ───────────────────────────────────

log "Running Layer 4 smoke tests..."
$PYTHON - <<'PYEOF'
# Layer 1-3 still intact
from skg.kernel import TriState, EnergyEngine
from skg.substrate import NodeState, project_path, Path
from skg.substrate.node import TriState as ST
assert TriState is ST, "TriState unification broken"

# Layer 4 — sensors
from skg.sensors import (
    BaseSensor, SensorLoop, envelope, precondition_payload,
    available_sensors, emit_events,
)
from skg.sensors.context import SensorContext
from skg.sensors.projector import TOOLCHAIN_PROJECTOR

# Layer 4 — resonance
from skg.resonance.engine import ResonanceEngine
from skg.resonance.memory import MemoryStore
from skg.resonance.ingester import Ingester
from skg.resonance.observation_memory import ObservationMemory

# Layer 4 — forge
from skg.forge.proposals import create_action
from skg.forge.pipeline import run_forge_pipeline
from skg.forge.compiler import ForgeCompiler

# Layer 4 — catalog
from skg.catalog.compiler import CatalogCompiler

# Layer 4 — intel
from skg.intel.gap_detector import GapDetector
from skg.intel.surface import SurfaceBuilder

# Layer 4 — temporal feedback with full dependency chain
from skg.temporal.feedback import FeedbackIngester
from skg.temporal import DeltaStore
from skg.graph import WorkloadGraph

print("  [OK] sensors: BaseSensor, SensorLoop, envelope, SensorContext")
print("  [OK] resonance: ResonanceEngine, MemoryStore, Ingester, ObservationMemory")
print("  [OK] forge: create_action, run_forge_pipeline, ForgeCompiler")
print("  [OK] catalog: CatalogCompiler")
print("  [OK] intel: GapDetector, SurfaceBuilder")
print("  [OK] temporal+feedback: FeedbackIngester, DeltaStore, WorkloadGraph")
print()
print("  Toolchain projectors registered:")
for tc, (_, path, fn) in TOOLCHAIN_PROJECTOR.items():
    print(f"    {tc}: {path}::{fn}")
PYEOF

ok "Layer 4 imports verified"

# ── Final layout summary ──────────────────────────────────────────────────────

log ""
log "=================================================================="
log "  INSTALL COMPLETE — All layers"
log "  SKG_HOME  : $SKG_HOME"
log "  SKG_STATE : $SKG_STATE"
log "  SKG_CONFIG: $SKG_CONFIG"
log "  CLI       : $(command -v skg 2>/dev/null || echo '/usr/local/bin/skg')"
log ""
log "  Quick check:"
log "    skg status"
log "    skg field --auto --cycles 1"
log "    skg collect --target 172.17.0.2"
log ""
log "  NVD feed (set NIST_NVD_API_KEY env var for full access):"
log "    python3 /opt/skg/feeds/nvd_ingester.py --help"
log ""
log "  Gravity engines:"
log "    python3 /opt/skg/skg-gravity/gravity_field.py --auto --cycles 3"
log "    python3 /opt/skg/skg-gravity/gravity.py --auto --cycles 3"
log "=================================================================="

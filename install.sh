#!/usr/bin/env bash
# =============================================================================
# SKG Install — Layers 1–3
# Kernel + Substrate + Topology + Temporal + Graph
#
# Layout: /opt/skg/skg/ is a single flat Python package.
#         No editable pip installs. /opt/skg goes on sys.path via .pth.
#
# Usage: sudo bash install.sh
# =============================================================================
set -euo pipefail

SKG_HOME="${SKG_HOME:-/opt/skg}"
SKG_STATE="${SKG_STATE_DIR:-/var/lib/skg}"
SKG_CONFIG="${SKG_CONFIG_DIR:-/etc/skg}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

log()  { echo "[skg-install] $*"; }
die()  { echo "[skg-install] ERROR: $*" >&2; exit 1; }
ok()   { echo "[skg-install]   OK  $*"; }

log "Checking Python..."
PYTHON=$(command -v python3 || die "python3 not found")
PY_VER=$($PYTHON -c "import sys; v=sys.version_info; print(f'{v.major}{v.minor:02d}')")
[ "$PY_VER" -ge 311 ] || die "Python 3.11+ required"
log "  $($PYTHON --version)"

log "Creating directory layout..."
install -d \
    "$SKG_HOME/skg" \
    "$SKG_STATE/events" "$SKG_STATE/interp" \
    "$SKG_STATE/delta/snapshots" "$SKG_STATE/delta/transitions" \
    "$SKG_STATE/graph" "$SKG_STATE/brain/evolution" "$SKG_STATE/logs" \
    "$SKG_STATE/resonance/index" "$SKG_STATE/resonance/records" "$SKG_STATE/resonance/drafts" \
    "$SKG_STATE/proposals" "$SKG_STATE/bh_cache" \
    "$SKG_STATE/discovery" "$SKG_STATE/cve" "$SKG_STATE/forge_staging" \
    "$SKG_CONFIG"
ok "Runtime directories"

log "Installing skg package to $SKG_HOME/skg/ ..."
cp -r "$SCRIPT_DIR/skg" "$SKG_HOME/"
ok "skg package tree installed"

log "Wiring sys.path..."
SITE=$($PYTHON -c "import site; print(site.getsitepackages()[0])")
echo "$SKG_HOME" > "$SITE/skg.pth"
ok "sys.path: $SITE/skg.pth → $SKG_HOME"

REQS="$SCRIPT_DIR/requirements.txt"
if [ -f "$REQS" ]; then
    log "Installing Python dependencies..."
    $PYTHON -m pip install -q --break-system-packages -r "$REQS" \
        || $PYTHON -m pip install -q --user -r "$REQS"
    ok "Python dependencies"
fi

log "Running smoke tests..."
$PYTHON - <<'PYEOF'
from skg.kernel import TriState as KT
from skg.substrate.node import TriState as ST
assert KT is ST, "TriState mismatch — single canonical enum required"

from skg.kernel import (EnergyEngine, GravityScheduler, Fold, FoldManager,
    StateEngine, SupportContribution, ProjectionEngine)
from skg.kernel.state import CollapseThresholds
from skg.substrate import NodeState, Path, project_path
from skg.substrate.bond import BondState
from skg.substrate.state import SKGState
from skg.topology.manifold import build_from_causal
from skg.temporal import DeltaStore
from skg.graph import WorkloadGraph
import tempfile, pathlib

TriState = KT

# Kernel
e = EnergyEngine(); f = FoldManager()
f.add(Fold(fold_type="structural", location="net", constraint_source="skg"))
assert e.compute([TriState.UNKNOWN, TriState.REALIZED], f.all()) == 2
g = GravityScheduler()
assert g.rank([{"instrument":"a","expected_energy_reduction":5,"cost":5},
               {"instrument":"b","expected_energy_reduction":4,"cost":1}])[0]["instrument"] == "b"
se = StateEngine(CollapseThresholds())
assert se.collapse(SupportContribution(1.5, 0.0)) == TriState.REALIZED
assert se.collapse(SupportContribution(0.0, 1.5)) == TriState.BLOCKED
assert se.collapse(SupportContribution(0.5, 0.5)) == TriState.UNKNOWN
print("  [OK] kernel")

# Substrate
ns_r = NodeState(node_id="HO-01", state=TriState.REALIZED, confidence=0.9, observed_at="2026-03-13T00:00:00Z")
ns_u = NodeState.unknown("HO-02")
ns_b = NodeState(node_id="HO-03", state=TriState.BLOCKED, confidence=0.8, observed_at="2026-03-13T00:00:00Z")
assert project_path(Path("p1",["HO-01","HO-02"]),{"HO-01":ns_r,"HO-02":ns_u}).classification == "indeterminate"
assert project_path(Path("p2",["HO-01"]),{"HO-01":ns_r}).classification == "realized"
assert project_path(Path("p3",["HO-01","HO-03"]),{"HO-01":ns_r,"HO-03":ns_b}).classification == "not_realized"
b = BondState.from_type("192.168.1.1","172.17.0.2","docker_host")
assert b.strength == 0.9 and abs(b.prior_influence - 0.9) < 1e-6
sk = SKGState.build("wl",{"HO-01":ns_r,"HO-02":ns_u})
assert sk.E == 0.5
print("  [OK] substrate")

# Topology
sc = build_from_causal(); sm = sc.summary()
assert sm["vertices"] > 0 and sm["edges"] > 0
print(f"  [OK] topology: {sm['vertices']}v {sm['edges']}e {sm['faces']}f")

# Temporal + Graph
with tempfile.TemporaryDirectory() as td:
    tdp = pathlib.Path(td)
    delta = DeltaStore(tdp/"delta")
    t1 = delta.ingest_projection({"attack_path_id":"p","realized":["HO-01"],"blocked":[],"unknown":["HO-02"],"aprs":0.5,"classification":"indeterminate"},"wl-A","host","r1")
    assert t1 == []
    t2 = delta.ingest_projection({"attack_path_id":"p","realized":["HO-01","HO-02"],"blocked":[],"unknown":[],"aprs":1.0,"classification":"realized"},"wl-A","host","r2")
    assert any(t.wicket_id=="HO-02" and t.meaning=="surface_expansion" for t in t2)
    print("  [OK] temporal: DeltaStore")
    gr = WorkloadGraph(tdp/"graph"); gr.load()
    gr.add_edge("wl-A","wl-B","same_domain")
    gr.propagate_transition("wl-A",wicket_id="AD-01",domain="ad_lateral",to_state="realized",signal_weight=1.0)
    assert gr.get_prior("wl-B",wicket_id="AD-01") > 0.0
    print("  [OK] graph: WorkloadGraph")

print()
print("  Layers 1-3 installed and verified.")
PYEOF

log ""
log "=================================================================="
log "  INSTALL COMPLETE — Layers 1-3"
log "  SKG_HOME  : $SKG_HOME"
log "  SKG_STATE : $SKG_STATE"
log "  Verify:   python3 -c 'from skg.kernel import TriState; print(TriState.REALIZED)'"
log "  Next:     bash install_layer4.sh   (sensors, gravity, toolchains)"
log "=================================================================="

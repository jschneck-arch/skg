#!/usr/bin/env bash
# =============================================================================
# SKG Arch Linux Setup — Complete bootstrap from zero to operational
#
# Run as root on a fresh Arch install.
# Idempotent — safe to re-run.
#
# What this does:
#   1.  Install system deps (python, nmap, tshark, docker, nmap)
#   2.  Install Python deps (fastapi, uvicorn, paramiko, faiss-cpu, etc.)
#   3.  Copy the SKG package tree to /opt/skg
#   4.  Wire sys.path via .pth
#   5.  Bootstrap toolchain venvs
#   6.  Install systemd service
#   7.  Seed resonance memory
#   8.  Install CLI to /usr/local/bin
#   9.  Smoke test
#  10.  Drop first-run instructions
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SKG_HOME=/opt/skg
SKG_STATE=/var/lib/skg
SKG_CONFIG=/etc/skg

log()  { echo ""; echo "==> $*"; }
ok()   { echo "    ✓  $*"; }
warn() { echo "    ⚠  $*"; }
die()  { echo ""; echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash setup_arch.sh"

# ── 1. System packages ────────────────────────────────────────────────────────
log "Installing system packages..."
pacman -Sy --noconfirm --needed \
    python python-pip python-virtualenv \
    nmap wireshark-cli \
    docker docker-compose \
    git curl wget \
    2>/dev/null || warn "Some packages may have failed — continuing"

# tshark cap so it runs without root after setup
if command -v tshark &>/dev/null; then
    setcap cap_net_raw,cap_net_admin=eip "$(command -v tshark)" 2>/dev/null || \
        warn "setcap on tshark failed — may need manual: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark"
    ok "tshark: cap_net_raw,cap_net_admin set"
fi

# Enable docker
systemctl enable --now docker 2>/dev/null || warn "docker not starting — check manually"
ok "system packages"

# ── 2. Directory layout ───────────────────────────────────────────────────────
log "Creating directory layout..."
install -d \
    "$SKG_HOME/skg" \
    "$SKG_STATE"/{events,interp,delta/{snapshots,transitions},graph,\
brain/evolution,logs,resonance/{index,records,drafts},proposals,\
bh_cache,discovery,cve,forge_staging,usb_drops,agent_queue,ssh_collection,\
msf_audit} \
    "$SKG_CONFIG"
ok "directories"

# ── 3. Python deps ────────────────────────────────────────────────────────────
log "Installing Python dependencies..."
pip install --break-system-packages -q \
    fastapi uvicorn pydantic \
    paramiko pywinrm \
    requests pyyaml \
    numpy faiss-cpu sentence-transformers \
    pymetasploit3 \
    2>/dev/null || warn "Some pip installs failed — check manually"
ok "Python dependencies"

# ── 4. Copy SKG package tree ──────────────────────────────────────────────────
log "Installing SKG to $SKG_HOME..."
cp -r "$SCRIPT_DIR/skg"       "$SKG_HOME/"
cp -r "$SCRIPT_DIR/skg-gravity"    "$SKG_HOME/" 2>/dev/null || true
cp -r "$SCRIPT_DIR/skg-discovery"  "$SKG_HOME/" 2>/dev/null || true
cp -r "$SCRIPT_DIR/feeds"          "$SKG_HOME/" 2>/dev/null || true

for tc in skg-aprs-toolchain skg-container-escape-toolchain \
          skg-ad-lateral-toolchain skg-host-toolchain skg-web-toolchain \
          skg-iot_firmware-toolchain skg-supply-chain-toolchain; do
    [ -d "$SCRIPT_DIR/$tc" ] && cp -r "$SCRIPT_DIR/$tc" "$SKG_HOME/"
done
ok "SKG package tree"

# ── 5. sys.path wiring ────────────────────────────────────────────────────────
log "Wiring sys.path..."
SITE=$(python3 -c "import site; print(site.getsitepackages()[0])")
echo "$SKG_HOME" > "$SITE/skg.pth"
ok "sys.path: $SITE/skg.pth → $SKG_HOME"

# ── 6. Config ─────────────────────────────────────────────────────────────────
log "Installing config..."
for f in skg_config.yaml targets.yaml data_sources.yaml; do
    src="$SCRIPT_DIR/config/$f"
    dst="$SKG_CONFIG/$f"
    if [ -f "$src" ] && [ ! -f "$dst" ]; then
        install -m640 "$src" "$dst"
        ok "config/$f"
    else
        warn "config/$f already exists — not overwritten"
    fi
done

# Install schema contract templates
install -d "$SKG_CONFIG/contracts"
for f in "$SCRIPT_DIR"/config/contracts/*.json; do
    [ -f "$f" ] || continue
    dst="$SKG_CONFIG/contracts/$(basename $f)"
    if [ ! -f "$dst" ]; then
        install -m640 "$f" "$dst"
        ok "contracts/$(basename $f)"
    fi
done

# skg.env — secrets file
ENV_FILE="$SKG_CONFIG/skg.env"
if [ ! -f "$ENV_FILE" ]; then
    install -m600 "$SCRIPT_DIR/scripts/skg.env.template" "$ENV_FILE"
    ok "secrets: $ENV_FILE (edit this — chmod 600 already set)"
else
    warn "secrets: $ENV_FILE already exists — not overwritten"
fi

# ── 7. Toolchain bootstrap ────────────────────────────────────────────────────
log "Bootstrapping toolchains..."
for tc in skg-aprs-toolchain skg-container-escape-toolchain \
          skg-ad-lateral-toolchain skg-host-toolchain skg-web-toolchain \
          skg-data-toolchain skg-iot_firmware-toolchain \
          skg-supply-chain-toolchain skg-binary-toolchain; do
    bs="$SKG_HOME/$tc/bootstrap.sh"
    if [ -f "$bs" ]; then
        bash "$bs" "$SKG_HOME/$tc" >/dev/null 2>&1 \
            && ok "$tc" \
            || warn "$tc bootstrap had issues — check $bs"
    fi
done

# ── 8. Resonance seed records ─────────────────────────────────────────────────
log "Seeding resonance memory..."
if [ -d "$SCRIPT_DIR/resonance/records" ]; then
    cp "$SCRIPT_DIR/resonance/records"/*.jsonl "$SKG_STATE/resonance/records/" 2>/dev/null || true
    ok "seed records copied to $SKG_STATE/resonance/records/"
fi

# ── 9. CLI ────────────────────────────────────────────────────────────────────
log "Installing CLI..."
install -m755 "$SCRIPT_DIR/bin/skg" "$SKG_HOME/bin/skg"
ln -sf "$SKG_HOME/bin/skg" /usr/local/bin/skg
ok "skg CLI → /usr/local/bin/skg"

# ── 10. Systemd service ───────────────────────────────────────────────────────
log "Installing systemd service..."
install -m644 "$SCRIPT_DIR/scripts/skg.service" /etc/systemd/system/skg.service
systemctl daemon-reload
systemctl enable skg
ok "systemd: skg.service installed and enabled"
ok "  start: systemctl start skg"
ok "  logs:  journalctl -u skg -f"

# ── 11. Smoke test ────────────────────────────────────────────────────────────
log "Running smoke tests..."
python3 - <<'PYEOF'
from skg.kernel import TriState as KT
from skg.substrate.node import TriState as ST
assert KT is ST, "TriState unification broken"

from skg.kernel import EnergyEngine, GravityScheduler, Fold, FoldManager, StateEngine, SupportContribution
from skg.kernel.state import CollapseThresholds
from skg.substrate import NodeState, Path, project_path
from skg.substrate.bond import BondState
from skg.substrate.state import SKGState
from skg.topology.manifold import build_from_causal
from skg.temporal import DeltaStore
from skg.graph import WorkloadGraph
from skg.sensors import envelope, precondition_payload
from skg.forge.proposals import create_action
from skg.temporal.feedback import FeedbackIngester
import tempfile, pathlib

# TriState unified
assert KT.REALIZED.value == "realized"
assert KT.BLOCKED.value  == "blocked"
assert KT.UNKNOWN.value  == "unknown"

# StateEngine uses canonical TriState
se = StateEngine(CollapseThresholds())
assert se.collapse(SupportContribution(1.5, 0.0)) == KT.REALIZED
assert se.collapse(SupportContribution(0.0, 1.5)) == KT.BLOCKED
assert se.collapse(SupportContribution(0.5, 0.5)) == KT.UNKNOWN

# Projection
ns_r = NodeState(node_id="HO-01", state=KT.REALIZED, confidence=0.9, observed_at="2026-03-13T00:00:00Z")
ns_u = NodeState.unknown("HO-02")
score = project_path(Path("p", ["HO-01", "HO-02"]), {"HO-01": ns_r, "HO-02": ns_u})
assert score.classification == "indeterminate"
score2 = project_path(Path("p", ["HO-01"]), {"HO-01": ns_r})
assert score2.classification == "realized"

# Bond prior
b = BondState.from_type("192.168.1.1", "172.17.0.2", "docker_host")
assert abs(b.prior_influence - 0.45) < 1e-6

# SKGState field energy
sk = SKGState.build("wl", {"HO-01": ns_r, "HO-02": ns_u})
assert sk.E == 0.5

# SimplicialComplex
sc = build_from_causal()
assert sc.summary()["edges"] > 0

# DeltaStore → transitions
with tempfile.TemporaryDirectory() as td:
    tdp = pathlib.Path(td)
    delta = DeltaStore(tdp / "delta")
    i1 = {"attack_path_id":"p","realized":["HO-01"],"blocked":[],"unknown":["HO-02"],"aprs":0.5,"classification":"indeterminate"}
    delta.ingest_projection(i1, "wl-A", "host", "r1")
    i2 = dict(i1, realized=["HO-01","HO-02"], unknown=[], classification="realized", aprs=1.0)
    t2 = delta.ingest_projection(i2, "wl-A", "host", "r2")
    assert any(t.wicket_id == "HO-02" and t.meaning == "surface_expansion" for t in t2)

    # WorkloadGraph propagation
    gr = WorkloadGraph(tdp / "graph"); gr.load()
    gr.add_edge("wl-A", "wl-B", "same_domain")
    gr.propagate_transition("wl-A", wicket_id="AD-01", domain="ad_lateral",
                            to_state="realized", signal_weight=1.0)
    assert gr.get_prior("wl-B", wicket_id="AD-01") > 0.0

print("  [OK] All systems nominal.")
PYEOF

# ── 12. First-run instructions ────────────────────────────────────────────────
echo ""
echo "=========================================================="
echo "  SKG INSTALLATION COMPLETE"
echo "=========================================================="
echo ""
echo "  Before starting:"
echo "    1. Edit secrets:   nano $SKG_CONFIG/skg.env"
echo "    2. Edit targets:   nano $SKG_CONFIG/targets.yaml"
echo "    3. Edit config:    nano $SKG_CONFIG/skg_config.yaml"
echo ""
echo "  Start:"
echo "    systemctl start skg"
echo "    journalctl -u skg -f          # watch logs"
echo ""
echo "  First engagement:"
echo "    skg target add-subnet 192.168.1.0/24    # discover hosts"
echo "    skg status                               # entropy landscape"
echo "    skg gravity --cycles 3                  # run field"
echo "    skg observe 192.168.1.10 --with ssh     # collect from target"
echo "    skg observe 192.168.1.10 --with web     # web fingerprint"
echo "    skg surface                              # full attack surface"
echo ""
echo "  NVD feed (requires NIST_NVD_API_KEY in skg.env):"
echo "    skg feed nvd"
echo ""
echo "  Gravity field (autonomous instrument selection):"
echo "    skg gravity --cycles 5"
echo ""
echo "  API:  http://127.0.0.1:5055"
echo "  Docs: http://127.0.0.1:5055/docs"
echo ""
echo "  skg status | skg surface | skg web | skg gravity"
echo "=========================================================="

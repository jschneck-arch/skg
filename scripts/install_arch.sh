#!/usr/bin/env bash
# =============================================================================
# SKG Install Script — Arch Linux
# =============================================================================
# Layout:
#   /opt/skg/          — SKG platform (this repo)
#   /opt/msf/          — Metasploit Framework (expected pre-installed)
#   /opt/BloodHound/   — BloodHound CE (expected pre-installed)
#   /var/lib/skg/      — runtime state (events, interp, resonance memory)
#   /etc/skg/          — configuration
#   ~/.local/bin/skg   — CLI symlink
#
# Run as your normal user (gristlefist). Uses sudo where needed.
# Safe to re-run — idempotent.
#
# Usage:
#   chmod +x scripts/install_arch.sh
#   ./scripts/install_arch.sh [--skip-deps] [--skip-venv] [--skip-ssh]
# =============================================================================

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/skg"
STATE_DIR="/var/lib/skg"
CONFIG_DIR="/etc/skg"
MSF_DIR="/opt/msf"
BH_DIR="/opt/BloodHound"
SERVICE_NAME="skg"
USER="$(whoami)"
HOSTNAME_FQDN="$(hostname)"

# Parse flags
SKIP_DEPS=0
SKIP_VENV=0
SKIP_SSH=0
for arg in "$@"; do
    case $arg in
        --skip-deps) SKIP_DEPS=1 ;;
        --skip-venv) SKIP_VENV=1 ;;
        --skip-ssh)  SKIP_SSH=1  ;;
    esac
done

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[ERR]${NC} $*"; }
section() { echo -e "\n${BOLD}$*${NC}"; echo "$(printf '─%.0s' {1..60})"; }

export TMPDIR=/var/tmp

# =============================================================================
section "SKG Install — archbox (${USER}@${HOSTNAME_FQDN})"
# =============================================================================
echo "  repo:      $REPO_DIR"
echo "  install:   $INSTALL_DIR"
echo "  state:     $STATE_DIR"
echo "  config:    $CONFIG_DIR"
echo "  msf:       $MSF_DIR"
echo "  bloodhound: $BH_DIR"
echo ""

# =============================================================================
section "1. System packages"
# =============================================================================
if [ "$SKIP_DEPS" -eq 0 ]; then
    info "Installing system packages..."
    sudo pacman -Sy --needed --noconfirm \
        python python-pip git base-devel rsync \
        openssh curl wget nmap net-tools 2>/dev/null || \
    sudo pacman -Sy --needed --noconfirm python python-pip git base-devel rsync openssh curl
    ok "System packages ready"
else
    warn "Skipping system packages (--skip-deps)"
fi

# =============================================================================
section "2. Directory structure"
# =============================================================================
info "Creating directories..."

sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p "$STATE_DIR"/{events,interp,delta,logs,usb_drops,agent_queue,ssh_collection}
sudo mkdir -p "$STATE_DIR"/{brain,resonance,proposals,proposals_rejected,proposals_accepted}
sudo mkdir -p "$STATE_DIR"/bh_cache
sudo mkdir -p "$CONFIG_DIR"

# External tool directories (create if not present — don't overwrite if existing)
sudo mkdir -p "$MSF_DIR"
sudo mkdir -p "$BH_DIR"

# Ownership — SKG dirs to current user
sudo chown -R "${USER}:${USER}" "$INSTALL_DIR"
sudo chown -R "${USER}:${USER}" "$STATE_DIR"
sudo chown -R "${USER}:${USER}" "$CONFIG_DIR"
# MSF/BH ownership only if we created them (don't steal from existing installs)
[ "$(stat -c '%U' "$MSF_DIR")" = "root" ] && sudo chown "${USER}:${USER}" "$MSF_DIR" || true
[ "$(stat -c '%U' "$BH_DIR")" = "root"  ] && sudo chown "${USER}:${USER}" "$BH_DIR"  || true

ok "Directories ready"

# =============================================================================
section "3. Deploy SKG to /opt/skg"
# =============================================================================
info "Syncing $REPO_DIR → $INSTALL_DIR..."
rsync -a --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.venv' \
    --exclude='forge_staging' \
    "$REPO_DIR/" "$INSTALL_DIR/"
ok "Files deployed"

# =============================================================================
section "4. Python venv"
# =============================================================================
if [ "$SKIP_VENV" -eq 0 ]; then
    info "Creating venv at $INSTALL_DIR/.venv..."
    info "(sentence-transformers pulls ~2GB on first run — patience)"
    if [ ! -d "$INSTALL_DIR/.venv" ]; then
        python3 -m venv "$INSTALL_DIR/.venv"
    fi
    "$INSTALL_DIR/.venv/bin/pip" install --no-cache-dir -q --upgrade pip
    "$INSTALL_DIR/.venv/bin/pip" install --no-cache-dir -q \
        -r "$INSTALL_DIR/requirements.txt"
    ok "venv ready: $INSTALL_DIR/.venv"
else
    warn "Skipping venv setup (--skip-venv)"
fi

# =============================================================================
section "5. External tool verification"
# =============================================================================

# Metasploit
info "Checking Metasploit at $MSF_DIR..."
if command -v msfconsole &>/dev/null; then
    MSF_BIN="$(command -v msfconsole)"
    ok "Metasploit found: $MSF_BIN"
elif [ -x "$MSF_DIR/msfconsole" ]; then
    ok "Metasploit found: $MSF_DIR/msfconsole"
elif [ -x "/usr/bin/msfconsole" ]; then
    ok "Metasploit found: /usr/bin/msfconsole"
else
    warn "Metasploit not found — MSF sensor will be inactive"
    warn "To install: yay -S metasploit  OR  cd /opt/msf && git clone https://github.com/rapid7/metasploit-framework ."
fi

# BloodHound CE
info "Checking BloodHound CE at $BH_DIR..."
BH_FOUND=0
if [ -x "$BH_DIR/BloodHound" ]; then
    ok "BloodHound CE found: $BH_DIR/BloodHound"
    BH_FOUND=1
elif docker ps 2>/dev/null | grep -q bloodhound; then
    ok "BloodHound CE running in Docker"
    BH_FOUND=1
elif systemctl is-active --quiet bloodhound 2>/dev/null; then
    ok "BloodHound CE service active"
    BH_FOUND=1
else
    warn "BloodHound CE not detected at $BH_DIR"
    warn "To install: https://github.com/SpecterOps/BloodHound"
    warn "  docker run -d -p 8080:8080 specterops/bloodhound-ce"
    warn "  OR: download AppImage to $BH_DIR/BloodHound"
fi

# Ollama (optional — for local catalog generation)
info "Checking Ollama..."
if command -v ollama &>/dev/null; then
    ok "Ollama found: $(command -v ollama)"
    if systemctl is-active --quiet ollama 2>/dev/null; then
        ok "Ollama service running"
    else
        warn "Ollama installed but not running"
        warn "  systemctl enable --now ollama"
        warn "  ollama pull llama3.2:3b"
    fi
else
    warn "Ollama not installed (optional — enables local toolchain generation)"
    warn "  Install: curl -fsSL https://ollama.ai/install.sh | sh"
    warn "  OR:      yay -S ollama"
fi

# =============================================================================
section "6. SSH setup for self-assessment"
# =============================================================================
if [ "$SKIP_SSH" -eq 0 ]; then
    info "Configuring SSH for localhost self-assessment..."

    # Ensure SSH key exists
    if [ ! -f "$HOME/.ssh/id_ed25519" ] && [ ! -f "$HOME/.ssh/id_rsa" ]; then
        info "Generating SSH key..."
        ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" -C "skg@archbox"
        ok "SSH key generated: ~/.ssh/id_ed25519"
    else
        info "SSH key already exists"
    fi

    # Determine which key to use
    if [ -f "$HOME/.ssh/id_ed25519" ]; then
        SSH_KEY="$HOME/.ssh/id_ed25519"
        SSH_PUB="$HOME/.ssh/id_ed25519.pub"
    else
        SSH_KEY="$HOME/.ssh/id_rsa"
        SSH_PUB="$HOME/.ssh/id_rsa.pub"
    fi

    # Authorize key for localhost
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    touch "$HOME/.ssh/authorized_keys"
    chmod 600 "$HOME/.ssh/authorized_keys"

    if ! grep -qF "$(cat "$SSH_PUB")" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
        cat "$SSH_PUB" >> "$HOME/.ssh/authorized_keys"
        ok "Public key added to authorized_keys"
    else
        info "Key already in authorized_keys"
    fi

    # Ensure sshd is configured and running
    info "Checking sshd..."
    if ! systemctl is-active --quiet sshd 2>/dev/null; then
        info "Starting sshd..."
        sudo systemctl enable --now sshd
        ok "sshd started"
    else
        ok "sshd already running"
    fi

    # Verify localhost SSH works
    info "Testing SSH to localhost..."
    if ssh -o StrictHostKeyChecking=no \
           -o ConnectTimeout=5 \
           -o BatchMode=yes \
           -i "$SSH_KEY" \
           "${USER}@127.0.0.1" "echo ok" 2>/dev/null | grep -q ok; then
        ok "SSH to localhost: working"
    else
        warn "SSH to localhost failed — check sshd and authorized_keys"
        warn "  sudo systemctl status sshd"
        warn "  cat ~/.ssh/authorized_keys"
    fi
else
    warn "Skipping SSH setup (--skip-ssh)"
    SSH_KEY="$HOME/.ssh/id_ed25519"
    [ -f "$HOME/.ssh/id_rsa" ] && SSH_KEY="$HOME/.ssh/id_rsa"
fi

# Determine SSH key path for config
if [ -f "$HOME/.ssh/id_ed25519" ]; then
    SSH_KEY="$HOME/.ssh/id_ed25519"
elif [ -f "$HOME/.ssh/id_rsa" ]; then
    SSH_KEY="$HOME/.ssh/id_rsa"
else
    SSH_KEY="$HOME/.ssh/id_ed25519"
fi

# =============================================================================
section "7. Configuration"
# =============================================================================
info "Writing /etc/skg/skg_config.yaml..."
cat > "$CONFIG_DIR/skg_config.yaml" << YAML
# SKG Platform Configuration
# Generated by install_arch.sh — $(date -Iseconds)

sensors:
  enabled:
    - ssh
    - usb
    - agent
    - msf
    - cve
    - bloodhound

  ssh:
    timeout_s: 30
    collect_interval_s: 300

  usb:
    drops_dir: $STATE_DIR/usb_drops

  agent:
    queue_dir: $STATE_DIR/agent_queue

  msf:
    host: 127.0.0.1
    port: 55553
    user: msf
    password: "\${MSF_PASSWORD}"
    loot_dir: $HOME/.msf4/loot
    msf_dir: $MSF_DIR

  cve:
    nvd_api_key: "\${NIST_NVD_API_KEY}"
    packages:
      - log4j
      - log4j2
      - docker
      - containerd
      - runc
      - openssl
      - spring-core
      - apache-struts

  bloodhound:
    url: "http://localhost:8080"
    username: "admin"
    password: "\${BH_PASSWORD}"
    bloodhound_dir: $BH_DIR
    collect_interval_s: 900
    attack_path_id: ad_kerberoast_v1
    # neo4j_url: "bolt://localhost:7687"
    # neo4j_user: "neo4j"
    # neo4j_password: "\${NEO4J_PASSWORD}"

resonance:
  ollama:
    url: "http://localhost:11434"
    temperature: 0.1

paths:
  state_dir: $STATE_DIR
  install_dir: $INSTALL_DIR
  msf_dir: $MSF_DIR
  bloodhound_dir: $BH_DIR
YAML
ok "skg_config.yaml written"

info "Writing /etc/skg/targets.yaml..."
cat > "$CONFIG_DIR/targets.yaml" << YAML
# SKG Target Configuration
# Generated by install_arch.sh — $(date -Iseconds)
#
# Self-assessment: archbox evaluates itself

targets:
  - host: 127.0.0.1
    enabled: true
    method: ssh
    user: $USER
    key: $SSH_KEY
    workload_id: archbox_self
    attack_path_id: host_ssh_initial_access_v1
    tags: [linux, self, archbox]

  # Add additional targets below:
  #
  # - host: 192.168.1.x
  #   enabled: true
  #   method: ssh
  #   user: root
  #   key: $SSH_KEY
  #   workload_id: target-name
  #   attack_path_id: host_ssh_initial_access_v1
  #
  # - host: 192.168.1.x
  #   enabled: true
  #   method: winrm
  #   user: Administrator
  #   password: "\${TARGET_PASSWORD}"
  #   workload_id: dc01
  #   attack_path_id: host_ssh_initial_access_v1
YAML
ok "targets.yaml written"

# =============================================================================
section "8. Resonance memory — initial ingest"
# =============================================================================
info "Ingesting catalog data into resonance memory..."
if [ -d "$INSTALL_DIR/.venv" ]; then
    SKG_HOME="$INSTALL_DIR" \
    "$INSTALL_DIR/.venv/bin/python" -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
try:
    from skg.resonance.engine import ResonanceEngine
    from skg.resonance.ingester import ingest_all
    from pathlib import Path
    engine = ResonanceEngine(Path('$STATE_DIR/resonance'))
    summary = ingest_all(engine, Path('$INSTALL_DIR'))
    print(f'  ingested: {summary}')
except ImportError as e:
    print(f'  skipped (missing deps: {e}) — run after venv deps install')
except Exception as e:
    print(f'  warning: {e}')
" 2>/dev/null || warn "Resonance ingest skipped — run manually: SKG_HOME=$INSTALL_DIR skg resonance ingest"
else
    warn "Skipping resonance ingest — venv not ready"
fi

# =============================================================================
section "9. systemd service"
# =============================================================================
info "Installing systemd user service..."

# Rewrite service file with correct paths
cat > "$INSTALL_DIR/scripts/skg.service" << UNIT
[Unit]
Description=SKG Red Team Intelligence Daemon
After=network.target

[Service]
Type=simple
User=$USER
Environment=SKG_HOME=$INSTALL_DIR
Environment=SKG_STATE_DIR=$STATE_DIR
Environment=SKG_CONFIG_DIR=$CONFIG_DIR
Environment=PATH=$INSTALL_DIR/.venv/bin:/usr/local/bin:/usr/bin:/bin
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python -m uvicorn skg.core.daemon:app \
    --host 127.0.0.1 --port 5055 \
    --log-level warning
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=skg

[Install]
WantedBy=default.target
UNIT

SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"
cp "$INSTALL_DIR/scripts/skg.service" "$SYSTEMD_USER_DIR/${SERVICE_NAME}.service"
systemctl --user daemon-reload
systemctl --user enable "$SERVICE_NAME" 2>/dev/null || true
ok "Service installed: $SYSTEMD_USER_DIR/${SERVICE_NAME}.service"

# Training timer (daily 2am fine-tune)
info "Installing training timer..."
# Patch user into service file
sed "s/%i/$USER/g" "$INSTALL_DIR/scripts/skg-train.service" \
    > "$SYSTEMD_USER_DIR/skg-train.service"
cp "$INSTALL_DIR/scripts/skg-train.timer" \
   "$SYSTEMD_USER_DIR/skg-train.timer"
systemctl --user daemon-reload
systemctl --user enable skg-train.timer 2>/dev/null || true
ok "Training timer installed (daily 02:00)"

# =============================================================================
section "10. CLI"
# =============================================================================
info "Installing CLI symlink..."
chmod +x "$INSTALL_DIR/bin/skg"
mkdir -p "$HOME/.local/bin"
ln -sf "$INSTALL_DIR/bin/skg" "$HOME/.local/bin/skg"

# PATH check
if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    warn "Added ~/.local/bin to PATH — reload shell: source ~/.bashrc"
fi

# SKG_HOME env in shell profile
if ! grep -q "SKG_HOME" "$HOME/.bashrc" 2>/dev/null; then
    cat >> "$HOME/.bashrc" << BASHRC

# SKG environment
export SKG_HOME="$INSTALL_DIR"
export SKG_STATE_DIR="$STATE_DIR"
export SKG_CONFIG_DIR="$CONFIG_DIR"
BASHRC
    info "SKG_HOME added to ~/.bashrc"
fi

ok "CLI ready: $HOME/.local/bin/skg"

# =============================================================================
section "Summary"
# =============================================================================
echo ""
echo -e "  ${GREEN}Install complete.${NC}"
echo ""
echo "  Layout:"
echo "    SKG platform:     $INSTALL_DIR"
echo "    Metasploit:       $MSF_DIR"
echo "    BloodHound CE:    $BH_DIR"
echo "    Runtime state:    $STATE_DIR"
echo "    Config:           $CONFIG_DIR"
echo ""
echo "  Self-assessment target configured:"
echo "    host:  127.0.0.1"
echo "    user:  $USER"
echo "    key:   $SSH_KEY"
echo "    id:    archbox_self"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Reload shell environment:"
echo "       source ~/.bashrc"
echo ""
echo "  2. Start the daemon:"
echo "       systemctl --user start skg"
echo "       systemctl --user status skg"
echo ""
echo "  3. Run first self-assessment:"
echo "       skg mode unified"
echo "       skg collect host 127.0.0.1"
echo "       skg surface report"
echo ""
echo "  4. Optional — set passwords for external tools:"
echo "       export MSF_PASSWORD=your_msf_rpc_password"
echo "       export BH_PASSWORD=your_bloodhound_password"
echo "       # Add to ~/.bashrc to persist"
echo ""
echo "  5. Set up daily training timer:"
echo "       systemctl --user enable --now skg-train.timer"
echo "       systemctl --user list-timers skg-train.timer"
echo ""
echo "  6. Optional — install unsloth for fine-tuning:"
echo "       skg train install-unsloth"
echo "       # or manually: pip install unsloth[cpu]"
echo ""
echo "  7. Optional — enable local toolchain generation:"
echo "       ollama serve &"
echo "       ollama pull llama3.2:3b"
echo "       skg resonance ollama"
echo ""
echo "  Logs:     journalctl --user -u skg -f"
echo "  Surface:  skg surface report"
echo "  Proposals: skg proposals list"
echo ""

#!/usr/bin/env bash
# install_arch.sh — Idempotent SKG install for Arch Linux
# Run as your normal user (not root). Uses sudo where needed.
# Safe to run multiple times.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/skg"
STATE_DIR="/var/lib/skg"
CONFIG_DIR="/etc/skg"
SERVICE_NAME="skg"
USER="$(whoami)"

echo "[*] SKG install — user: $USER"
echo "    repo:    $REPO_DIR"
echo "    install: $INSTALL_DIR"
echo "    state:   $STATE_DIR"

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
echo "[*] Checking system packages..."
sudo pacman -Sy --needed --noconfirm python python-pip git base-devel rsync

# ---------------------------------------------------------------------------
# 2. Create directory structure
# ---------------------------------------------------------------------------
echo "[*] Creating directories..."
sudo mkdir -p "$INSTALL_DIR"
sudo mkdir -p "$STATE_DIR/brain"
sudo mkdir -p "$STATE_DIR/events"
sudo mkdir -p "$STATE_DIR/interp"
sudo mkdir -p "$STATE_DIR/logs"
sudo mkdir -p "$STATE_DIR/brain/evolution"
sudo mkdir -p "$CONFIG_DIR"

sudo chown -R "$USER:$USER" "$STATE_DIR"
sudo chown -R "$USER:$USER" "$INSTALL_DIR"
sudo chown -R "$USER:$USER" "$CONFIG_DIR"

# ---------------------------------------------------------------------------
# 3. Sync repo to install dir
# ---------------------------------------------------------------------------
echo "[*] Syncing files to $INSTALL_DIR..."
rsync -a --delete \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.venv' \
    --exclude='skg-aprs-toolchain/.venv' \
    "$REPO_DIR/" "$INSTALL_DIR/"

# ---------------------------------------------------------------------------
# 4. Daemon venv
# ---------------------------------------------------------------------------
echo "[*] Setting up daemon venv..."
if [ ! -d "$INSTALL_DIR/.venv" ]; then
    python3 -m venv "$INSTALL_DIR/.venv"
fi
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" --quiet
echo "    Daemon venv ready."

# ---------------------------------------------------------------------------
# 5. Toolchain bootstrap
# ---------------------------------------------------------------------------
echo "[*] Bootstrapping toolchain..."
TC_DIR="$INSTALL_DIR/skg-aprs-toolchain"
if [ ! -d "$TC_DIR/.venv" ]; then
    python3 -m venv "$TC_DIR/.venv"
fi
"$TC_DIR/.venv/bin/pip" install --upgrade pip --quiet
"$TC_DIR/.venv/bin/pip" install -r "$TC_DIR/requirements.txt" --quiet

echo "[*] Verifying toolchain (golden test)..."
cd "$TC_DIR"
"$TC_DIR/.venv/bin/python" tests/test_golden.py
cd "$REPO_DIR"
echo "    Toolchain verified."

# ---------------------------------------------------------------------------
# 6. CLI symlink
# ---------------------------------------------------------------------------
echo "[*] Installing CLI..."
chmod +x "$INSTALL_DIR/bin/skg"
mkdir -p "$HOME/.local/bin"
ln -sf "$INSTALL_DIR/bin/skg" "$HOME/.local/bin/skg"

if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo "    Added ~/.local/bin to PATH in .bashrc"
fi

# ---------------------------------------------------------------------------
# 7. systemd user service
# ---------------------------------------------------------------------------
echo "[*] Installing systemd user service..."
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"
cp "$INSTALL_DIR/scripts/skg.service" "$SYSTEMD_USER_DIR/${SERVICE_NAME}.service"
systemctl --user daemon-reload
systemctl --user enable "$SERVICE_NAME"
echo "    Service enabled."

echo ""
echo "[OK] SKG installed successfully."
echo ""
echo "    Start:    systemctl --user start skg"
echo "    Status:   systemctl --user status skg"
echo "    Logs:     journalctl --user -u skg -f"
echo "    CLI:      skg status"
echo ""
echo "    Toolchain quickstart:"
echo "      skg ingest config_effective --root /path/to/scan --out /tmp/events.ndjson --workload-id myapp"
echo "      skg project --in /tmp/events.ndjson --out /tmp/interp.ndjson"
echo "      skg latest --interp /tmp/interp.ndjson --attack-path-id log4j_jndi_rce_v1 --workload-id myapp"

# ---------------------------------------------------------------------------
# Container escape toolchain venv
# ---------------------------------------------------------------------------
CE_TC_DIR="$INSTALL_DIR/skg-container-escape-toolchain"
echo "[*] Setting up container escape toolchain venv..."
if [ ! -d "$CE_TC_DIR/.venv" ]; then
    python3 -m venv "$CE_TC_DIR/.venv"
fi
"$CE_TC_DIR/.venv/bin/pip" install --upgrade pip --quiet
"$CE_TC_DIR/.venv/bin/pip" install -r "$CE_TC_DIR/requirements.txt" --quiet
echo "[*] Running container escape golden test..."
cd "$CE_TC_DIR"
"$CE_TC_DIR/.venv/bin/python" tests/test_golden.py
cd "$REPO_DIR"
echo "    Container escape toolchain ready."

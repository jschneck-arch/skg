# SKG — Archbox Setup Guide

## Layout

```
/opt/skg/           ← SKG platform
/opt/msf/           ← Metasploit Framework
/opt/BloodHound/    ← BloodHound CE
/var/lib/skg/       ← runtime state
/etc/skg/           ← configuration
```

## Install

```bash
cd /opt/skg
chmod +x scripts/install_arch.sh
./scripts/install_arch.sh
source ~/.bashrc
```

Flags:
```bash
--skip-deps   # skip pacman packages
--skip-venv   # skip pip install (if venv exists)
--skip-ssh    # skip SSH key generation and sshd setup
```

## External Tools

### Metasploit

```bash
# AUR install (recommended)
yay -S metasploit

# Or manual
sudo git clone https://github.com/rapid7/metasploit-framework /opt/msf
cd /opt/msf && bundle install

# Start RPC listener (required for MSF sensor)
msfconsole -q -x "load msgrpc Pass=your_password ServerHost=127.0.0.1; exit"
export MSF_PASSWORD=your_password
```

### BloodHound CE

```bash
# Docker (easiest)
docker run -d \
  -p 8080:8080 \
  -v bloodhound-data:/data \
  --name bloodhound \
  specterops/bloodhound-ce:latest

# Or download AppImage to /opt/BloodHound/
# https://github.com/SpecterOps/BloodHound/releases

# Set password
export BH_PASSWORD=your_bloodhound_admin_password
```

### Ollama (local toolchain generation)

```bash
# Install
curl -fsSL https://ollama.ai/install.sh | sh
# OR: yay -S ollama

# Start and pull model
systemctl enable --now ollama
ollama pull llama3.2:3b      # ~2GB, fast, good for structured output
# ollama pull mistral:7b     # ~4GB, better reasoning

# Verify SKG sees it
skg resonance ollama
```

## SSH Self-Assessment Setup

The install script handles this automatically. Manual steps if needed:

```bash
# Generate key
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""

# Authorize for localhost
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Start sshd
sudo systemctl enable --now sshd

# Test
ssh -i ~/.ssh/id_ed25519 gristlefist@127.0.0.1 "echo ok"
```

## Environment Variables

Add to `~/.bashrc`:
```bash
export SKG_HOME=/opt/skg
export SKG_STATE_DIR=/var/lib/skg
export SKG_CONFIG_DIR=/etc/skg
export MSF_PASSWORD=your_msf_rpc_password       # optional
export BH_PASSWORD=your_bloodhound_password     # optional
export NIST_NVD_API_KEY=your_nvd_key            # optional, rate-limits without
```

## Running

```bash
# Start daemon
systemctl --user start skg
systemctl --user status skg
journalctl --user -u skg -f

# First run — populate resonance memory
skg resonance ingest

# Run self-assessment (daemon handles this automatically in UNIFIED mode)
skg mode unified
skg collect host 127.0.0.1

# See what it found
skg surface report

# Review toolchain proposals (generated after first sweep)
skg proposals list
skg proposals show <id>
skg proposals accept <id>
```

## Self-Assessment Target (auto-configured by installer)

`/etc/skg/targets.yaml`:
```yaml
targets:
  - host: 127.0.0.1
    enabled: true
    method: ssh
    user: gristlefist
    key: /home/gristlefist/.ssh/id_ed25519
    workload_id: archbox_self
    attack_path_id: host_ssh_initial_access_v1
```

## What the First Sweep Produces

Against archbox itself, the host toolchain evaluates:
- SSH connectivity + auth (HO-01/02/03)
- Sudo configuration — NOPASSWD, wildcards (HO-06)
- SUID binaries on GTFOBins list (HO-07)
- World-writable cron/service files (HO-08)
- Credentials in env vars / shell history (HO-09)
- Running as root (HO-10)
- Vulnerable packages (HO-11)
- Kernel version vs known LPE CVEs (HO-12)
- SSH keys in ~/.ssh (HO-13)
- Docker socket access (HO-15)
- Cloud metadata reachability (HO-16)
- AV/EDR presence (HO-23)
- Exploitable service ports (HO-25)

After collection, the forge pipeline detects any services running
on archbox without toolchain coverage and generates proposals.

## CLI Reference

```bash
skg status                    # daemon status
skg mode [kernel|resonance|unified|anchor]

# Surface
skg surface report            # full engagement picture
skg surface gaps              # coverage gaps only
skg surface workloads         # per-workload projection state
skg surface json              # machine-readable full report

# Proposals
skg proposals list
skg proposals show <id>
skg proposals accept <id>
skg proposals reject <id>
skg proposals defer  <id> [--days N]

# Forge
skg forge generate <domain>   # manual toolchain generation
skg forge pipeline            # manually run gap detection
skg forge list-staged         # show staged toolchains

# Resonance
skg resonance ingest          # ingest catalog data into memory
skg resonance query <text>    # semantic search
skg resonance draft-generate <domain> <description>  # local generation
skg resonance ollama          # check ollama status

# Collection
skg collect host <ip>         # one-shot host collection

# Logs
journalctl --user -u skg -f
tail -f /var/lib/skg/logs/skg.log
```

#!/usr/bin/env bash
# =============================================================================
# SKG AD Lab Provisioning Script
# =============================================================================
#
# Provisions a minimal Active Directory lab environment for validating
# the skg-ad-lateral-toolchain. The lab exercises all catalogued AD
# lateral movement attack paths:
#
#   - ad_kerberoast_v1         (AD-01, AD-02, AD-03)
#   - ad_asrep_roast_v1        (AD-04, AD-05)
#   - ad_unconstrained_delegation_v1 (AD-06)
#   - ad_acl_abuse_v1          (AD-09, AD-10, AD-11)
#   - ad_dcsync_v1             (AD-14, AD-15)
#   - ad_password_in_description_v1 (AD-16)
#   - ad_laps_absent_v1        (AD-23)
#
# Lab topology:
#   DC01      Windows Server 2022 — Domain Controller
#             IP: 10.10.10.10  /24
#             Domain: lab.skg.local
#             OS: Windows Server 2022 Evaluation
#
#   WS01      Windows 10/11 — Domain Workstation
#             IP: 10.10.10.20  /24
#             Joined: lab.skg.local
#             Local admin: .\admin:Password1!
#
#   attacker  Arch Linux / Kali — red team operator
#             IP: 10.10.10.5   /24
#             Access: this machine (runs skg gravity)
#
# What this script does:
#   1. Creates the lab network (libvirt / VirtualBox depending on platform)
#   2. Provides DC01 setup PowerShell scripts
#   3. Provides WS01 join script
#   4. Provisions intentionally misconfigured AD objects
#   5. Configures BloodHound CE for collection
#   6. Validates the lab with a quick SKG sweep
#
# Prerequisites (attacker box):
#   - libvirt + qemu-kvm OR VirtualBox
#   - Windows Server 2022 Evaluation ISO
#   - Windows 10 Enterprise Evaluation ISO
#   - BloodHound CE (docker compose)
#   - /opt/skg installed and configured
#
# Usage:
#   bash provision_ad_lab.sh [--platform libvirt|vbox] [--setup-vms] [--configure-ad]
#   bash provision_ad_lab.sh --all        # full provision
#   bash provision_ad_lab.sh --validate   # validate lab is working
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="${SCRIPT_DIR}/lab_state"
DOMAIN="lab.skg.local"
DOMAIN_SHORT="LAB"
DC_IP="10.10.10.10"
WS_IP="10.10.10.20"
ATTACKER_IP="10.10.10.5"
ADMIN_PASS="Password1!"          # DC admin password
KRBSVC_PASS="Kerberoast1!"       # Service account password (intentionally crackable)

mkdir -p "$LAB_DIR"

# ── Argument parsing ────────────────────────────────────────────────────────

SETUP_VMS=false
CONFIGURE_AD=false
SETUP_BH=false
VALIDATE=false
PLATFORM="libvirt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform) PLATFORM="$2"; shift 2 ;;
        --setup-vms) SETUP_VMS=true; shift ;;
        --configure-ad) CONFIGURE_AD=true; shift ;;
        --setup-bh) SETUP_BH=true; shift ;;
        --validate) VALIDATE=true; shift ;;
        --all) SETUP_VMS=true; CONFIGURE_AD=true; SETUP_BH=true; VALIDATE=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Utility functions ───────────────────────────────────────────────────────

log()  { echo "[$(date +%T)] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "  → $*"; }

# ── Network Setup (libvirt) ─────────────────────────────────────────────────

setup_network_libvirt() {
    log "Creating lab network: skg-ad-lab (10.10.10.0/24)"

    cat > "$LAB_DIR/skg-ad-lab.xml" <<'NETXML'
<network>
  <name>skg-ad-lab</name>
  <forward mode="nat"/>
  <bridge name="virbr-skg-ad" stp="on" delay="0"/>
  <ip address="10.10.10.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.10.10.100" end="10.10.10.200"/>
      <host mac="52:54:00:ad:00:10" name="dc01"  ip="10.10.10.10"/>
      <host mac="52:54:00:ad:00:20" name="ws01"  ip="10.10.10.20"/>
      <host mac="52:54:00:ad:00:05" name="attk"  ip="10.10.10.5"/>
    </dhcp>
  </ip>
</network>
NETXML

    if virsh net-info skg-ad-lab &>/dev/null; then
        log "Network already exists — skipping"
    else
        virsh net-define "$LAB_DIR/skg-ad-lab.xml"
        virsh net-start skg-ad-lab
        virsh net-autostart skg-ad-lab
        log "Network created and started"
    fi
}

# ── DC01 PowerShell Configuration Scripts ──────────────────────────────────

generate_dc01_scripts() {
    log "Generating DC01 configuration scripts"

    # ── 1. Promote DC ────────────────────────────────────────────────────
    cat > "$LAB_DIR/dc01_01_promote.ps1" <<PWSH
# DC01 Step 1 — Install AD DS and promote to domain controller
# Run on DC01 as local Administrator

\$domainName = "${DOMAIN}"
\$adminPass  = ConvertTo-SecureString "${ADMIN_PASS}" -AsPlainText -Force

Install-WindowsFeature -Name AD-Domain-Services,DNS -IncludeManagementTools

Import-Module ADDSDeployment
Install-ADDSForest \`
    -DomainName \$domainName \`
    -DomainNetbiosName "${DOMAIN_SHORT}" \`
    -SafeModeAdministratorPassword \$adminPass \`
    -InstallDns \`
    -Force \`
    -NoRebootOnCompletion:\$false

Write-Host "[OK] DC promoted. Rebooting..."
PWSH

    # ── 2. Create lab users and misconfigurations ─────────────────────────
    cat > "$LAB_DIR/dc01_02_configure_ad.ps1" <<PWSH
# DC01 Step 2 — Create intentionally misconfigured AD objects
# Run on DC01 after promotion and reboot

Import-Module ActiveDirectory

# ── Regular users ──────────────────────────────────────────────────────────
\$users = @(
    @{Name="alice.smith";   Pass="Summer2024!";   Desc="";                    Groups=@("Domain Users")},
    @{Name="bob.jones";     Pass="Welcome123!";   Desc="";                    Groups=@("Domain Users")},
    @{Name="charlie.admin"; Pass="Admin1234!";    Desc="";                    Groups=@("Domain Users","Domain Admins")},
    @{Name="dave.it";       Pass="ITpass123!";    Desc="";                    Groups=@("Domain Users")},
    @{Name="svc.backup";    Pass="${KRBSVC_PASS}"; Desc="TempPassword=Kerberoast1!"; Groups=@("Domain Users")}
)

foreach (\$u in \$users) {
    \$pass = ConvertTo-SecureString \$u.Pass -AsPlainText -Force
    if (-not (Get-ADUser -Filter {SamAccountName -eq \$u.Name} -ErrorAction SilentlyContinue)) {
        New-ADUser \`
            -Name \$u.Name \`
            -SamAccountName \$u.Name \`
            -UserPrincipalName "\$(\$u.Name)@${DOMAIN}" \`
            -AccountPassword \$pass \`
            -Enabled \$true \`
            -Description \$u.Desc \`
            -PasswordNeverExpires \$true
        Write-Host "[OK] Created user: \$(\$u.Name)"
    }
    foreach (\$g in \$u.Groups) {
        Add-ADGroupMember -Identity \$g -Members \$u.Name -ErrorAction SilentlyContinue
    }
}

# ── Service account with SPN (kerberoastable) ─────────────────────────────
# AD-01 (domain auth reachable) + AD-02 (valid creds) + AD-03 (SPN registered)
Set-ADUser svc.backup -ServicePrincipalNames @{Add="MSSQLSvc/dc01.${DOMAIN}:1433"}
Write-Host "[OK] SPN set on svc.backup — kerberoastable"

# ── AS-REP roastable user (preauth disabled) ──────────────────────────────
# AD-04 (domain accessible) + AD-05 (preauth disabled)
Set-ADAccountControl dave.it -DoesNotRequirePreAuth \$true
Write-Host "[OK] Preauth disabled on dave.it — AS-REP roastable"

# ── Unconstrained delegation ──────────────────────────────────────────────
# AD-06 (trusted for unconstrained delegation)
Set-ADComputer DC01 -TrustedForDelegation \$true
Write-Host "[OK] Unconstrained delegation on DC01"

# ── ACL abuse: alice can GenericAll on bob ────────────────────────────────
# AD-09, AD-10, AD-11
\$bob     = Get-ADUser bob.jones
\$alice   = Get-ADUser alice.smith
\$acl     = Get-Acl "AD:CN=\$(\$bob.DistinguishedName)"
\$identity = [System.Security.Principal.NTAccount]"${DOMAIN_SHORT}\alice.smith"
\$right   = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
\$type    = [System.Security.AccessControl.AccessControlType]::Allow
\$ace     = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(\$identity, \$right, \$type)
\$acl.AddAccessRule(\$ace)
Set-Acl -Path "AD:CN=\$(\$bob.DistinguishedName)" -AclObject \$acl
Write-Host "[OK] GenericAll ACE: alice.smith -> bob.jones"

# ── Password in description (AD-16) ──────────────────────────────────────
# Already set on svc.backup above (TempPassword=Kerberoast1!)
Write-Host "[OK] Password in description: svc.backup"

# ── DCSync rights for charlie.admin ──────────────────────────────────────
# AD-14, AD-15
# charlie.admin is Domain Admin — already has DCSync rights by membership
Write-Host "[OK] DCSync rights: charlie.admin (via Domain Admins)"

# ── LAPS absent — WS01 has no LAPS configured ────────────────────────────
# AD-23 will be detected by the absence of ms-Mcs-AdmPwd attribute on WS01
Write-Host "[OK] LAPS not deployed (AD-23 will realize)"

Write-Host ""
Write-Host "========================================="
Write-Host "Lab configured. Summary:"
Write-Host "  Domain:       ${DOMAIN}"
Write-Host "  DC:           DC01 (${DC_IP})"
Write-Host "  Admin:        ${DOMAIN_SHORT}\\Administrator:${ADMIN_PASS}"
Write-Host "  Kerberoast:   svc.backup (SPN: MSSQLSvc/dc01.${DOMAIN}:1433)"
Write-Host "  AS-REP:       dave.it (preauth disabled)"
Write-Host "  ACL abuse:    alice.smith -[GenericAll]-> bob.jones"
Write-Host "  Delegation:   DC01 (unconstrained)"
Write-Host "  Description:  svc.backup (TempPassword=Kerberoast1!)"
Write-Host "  LAPS:         Not deployed"
Write-Host "========================================="
PWSH

    # ── 3. WS01 domain join ──────────────────────────────────────────────
    cat > "$LAB_DIR/ws01_01_join_domain.ps1" <<PWSH
# WS01 — Join to ${DOMAIN}
# Run on WS01 as local Administrator
# Requires DC01 to be up and DNS to resolve ${DOMAIN}

# Point DNS at DC01
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "${DC_IP}"

\$domainCred = Get-Credential "${DOMAIN_SHORT}\\Administrator"
Add-Computer -DomainName "${DOMAIN}" -Credential \$domainCred -Restart -Force
PWSH

    log "Scripts written to $LAB_DIR/"
    info "DC01 scripts: dc01_01_promote.ps1, dc01_02_configure_ad.ps1"
    info "WS01 scripts: ws01_01_join_domain.ps1"
}

# ── BloodHound CE Setup ─────────────────────────────────────────────────────

setup_bloodhound() {
    log "Setting up BloodHound CE for AD collection"

    # Check if BH is already running
    if docker ps 2>/dev/null | grep -q bloodhound; then
        log "BloodHound CE already running"
    else
        # Use the official BH CE docker-compose
        BH_DIR="$HOME/bloodhound-ce"
        if [[ ! -d "$BH_DIR" ]]; then
            mkdir -p "$BH_DIR"
            # Minimal compose — adjust image tags for your BH version
            cat > "$BH_DIR/docker-compose.yml" <<'BH_COMPOSE'
version: "3"
services:
  bloodhound:
    image: specterops/bloodhound:latest
    ports:
      - "8080:8080"
    environment:
      - bhe_disable_cypher_qc=false
    depends_on:
      - neo4j
      - postgres
  postgres:
    image: docker.io/library/postgres:13
    environment:
      - POSTGRES_USER=bloodhound
      - POSTGRES_PASSWORD=bloodhoundcommunityedition
      - POSTGRES_DB=bloodhound
    volumes:
      - postgres-data:/var/lib/postgresql/data
  neo4j:
    image: docker.io/library/neo4j:4.4
    environment:
      - NEO4J_AUTH=neo4j/bloodhoundcommunityedition
    volumes:
      - neo4j-data:/data
volumes:
  postgres-data:
  neo4j-data:
BH_COMPOSE
        fi

        cd "$BH_DIR"
        docker compose up -d
        log "BloodHound CE starting on http://localhost:8080"
        info "Default login: admin / (check docker logs for initial password)"
        info "After login, update /etc/skg/skg_config.yaml:"
        info "  bloodhound:"
        info "    url: http://localhost:8080"
        info "    username: admin"
        info "    password: <your-bh-password>"
    fi

    # Generate SharpHound collection script
    cat > "$LAB_DIR/collect_bloodhound.ps1" <<'PWSH'
# Run on DC01 or a domain-joined machine after BloodHound CE is available
# Downloads SharpHound and runs a full collection

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$bhDir = "C:\BH"
New-Item -ItemType Directory -Force -Path $bhDir | Out-Null

# Download latest SharpHound (adjust URL for your BH version)
$url = "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.zip"
Invoke-WebRequest -Uri $url -OutFile "$bhDir\SharpHound.zip" -UseBasicParsing
Expand-Archive -Path "$bhDir\SharpHound.zip" -DestinationPath $bhDir -Force

# Run collection
cd $bhDir
.\SharpHound.exe --CollectionMethods All --OutputDirectory $bhDir --ZipFileName lab_collection.zip

Write-Host "[OK] Collection complete: $bhDir\lab_collection.zip"
Write-Host "Upload to BloodHound CE UI at http://10.10.10.5:8080"
PWSH

    info "SharpHound collection script: $LAB_DIR/collect_bloodhound.ps1"
    info "Run on DC01, upload resulting zip to BloodHound CE"
}

# ── SKG Targets Configuration ───────────────────────────────────────────────

configure_skg_targets() {
    log "Writing /etc/skg/targets.yaml for lab AD domain"

    sudo tee /etc/skg/targets.yaml > /dev/null <<YAML
# SKG Lab AD Targets — generated by provision_ad_lab.sh
targets:
  - host: ${DC_IP}
    label: dc01
    domain_hint: ad_lateral
    auth:
      user: administrator
      password: "${ADMIN_PASS}"
    tags:
      - domain_controller
      - lab

  - host: ${WS_IP}
    label: ws01
    domain_hint: host
    auth:
      user: administrator
      password: "${ADMIN_PASS}"
    tags:
      - workstation
      - lab
YAML

    log "Wrote /etc/skg/targets.yaml"
}

# ── Lab Validation ──────────────────────────────────────────────────────────

validate_lab() {
    log "Validating lab environment"

    ERRORS=0

    # DC01 reachability
    if ping -c1 -W2 "${DC_IP}" &>/dev/null; then
        info "✓ DC01 reachable (${DC_IP})"
    else
        info "✗ DC01 unreachable (${DC_IP})"
        ((ERRORS++))
    fi

    # WS01 reachability
    if ping -c1 -W2 "${WS_IP}" &>/dev/null; then
        info "✓ WS01 reachable (${WS_IP})"
    else
        info "✗ WS01 unreachable (${WS_IP}) — may still be provisioning"
    fi

    # DNS resolution
    if host "${DOMAIN}" "${DC_IP}" &>/dev/null 2>&1; then
        info "✓ DNS resolves ${DOMAIN} via ${DC_IP}"
    else
        info "⚠ DNS for ${DOMAIN} not yet resolving — check DC01"
    fi

    # BloodHound CE
    if curl -s --max-time 3 "http://localhost:8080/api/version" | grep -q "version" 2>/dev/null; then
        info "✓ BloodHound CE responding"
    else
        info "⚠ BloodHound CE not responding at localhost:8080"
    fi

    # Kerberos port
    if timeout 3 bash -c "echo > /dev/tcp/${DC_IP}/88" 2>/dev/null; then
        info "✓ Kerberos port 88 open on DC01"
    else
        info "✗ Kerberos port 88 closed — DC01 may not be promoted yet"
        ((ERRORS++))
    fi

    # LDAP port
    if timeout 3 bash -c "echo > /dev/tcp/${DC_IP}/389" 2>/dev/null; then
        info "✓ LDAP port 389 open on DC01"
    else
        info "✗ LDAP port 389 closed"
        ((ERRORS++))
    fi

    if [[ $ERRORS -gt 0 ]]; then
        echo ""
        log "Validation: $ERRORS error(s) — lab may not be ready"
        return 1
    else
        echo ""
        log "Validation: OK — lab is ready"
        return 0
    fi
}

# ── SKG Sweep ───────────────────────────────────────────────────────────────

run_skg_sweep() {
    log "Running initial SKG sweep of AD lab"

    if [[ ! -x /opt/skg/bin/skg ]]; then
        die "skg not found at /opt/skg/bin/skg"
    fi

    # Add DC to the field
    /opt/skg/bin/skg target add "${DC_IP}" --domain ad_lateral
    /opt/skg/bin/skg target add "${WS_IP}" --domain host

    log "Running gravity cycle (1 cycle, BloodHound + SSH)"
    /opt/skg/bin/skg gravity --cycles 1 --target "${DC_IP}"

    log "Surface state after initial sweep:"
    /opt/skg/bin/skg surface

    log "AD lateral paths:"
    /opt/skg/bin/skg lateral paths
}

# ── Main ────────────────────────────────────────────────────────────────────

echo "====================================================="
echo "  SKG AD Lab Provisioner"
echo "  Domain: ${DOMAIN}"
echo "  DC01:   ${DC_IP}"
echo "  WS01:   ${WS_IP}"
echo "====================================================="
echo ""

if [[ "${SETUP_VMS}" == "true" ]]; then
    if [[ "${PLATFORM}" == "libvirt" ]]; then
        setup_network_libvirt
    else
        log "VirtualBox network setup — create host-only network 10.10.10.0/24 manually"
    fi
fi

if [[ "${CONFIGURE_AD}" == "true" ]]; then
    generate_dc01_scripts
    configure_skg_targets
fi

if [[ "${SETUP_BH}" == "true" ]]; then
    setup_bloodhound
fi

if [[ "${VALIDATE}" == "true" ]]; then
    validate_lab || true
fi

echo ""
echo "====================================================="
echo "  Next Steps"
echo "====================================================="
echo ""
echo "  1. Create DC01 VM (Windows Server 2022, 4GB RAM, 60GB disk)"
echo "     Network: skg-ad-lab, IP: ${DC_IP}"
echo "     Run: ${LAB_DIR}/dc01_01_promote.ps1"
echo "     Reboot, then run: ${LAB_DIR}/dc01_02_configure_ad.ps1"
echo ""
echo "  2. Create WS01 VM (Windows 10, 2GB RAM, 40GB disk)"
echo "     Network: skg-ad-lab, IP: ${WS_IP}"
echo "     Run: ${LAB_DIR}/ws01_01_join_domain.ps1"
echo ""
echo "  3. Collect BloodHound data:"
echo "     Copy ${LAB_DIR}/collect_bloodhound.ps1 to DC01"
echo "     Upload zip to BloodHound CE at http://localhost:8080"
echo ""
echo "  4. Validate lab:"
echo "     bash provision_ad_lab.sh --validate"
echo ""
echo "  5. Run SKG sweep:"
echo "     skg target add ${DC_IP} --domain ad_lateral"
echo "     skg gravity --cycles 3"
echo "     skg lateral paths"
echo ""
echo "  Expected realized paths after sweep:"
echo "    ad_kerberoast_v1             (svc.backup has SPN)"
echo "    ad_asrep_roast_v1            (dave.it has preauth disabled)"
echo "    ad_password_in_description_v1 (svc.backup description)"
echo "    ad_laps_absent_v1            (LAPS not deployed)"
echo "    ad_acl_abuse_v1              (alice GenericAll -> bob)"
echo ""

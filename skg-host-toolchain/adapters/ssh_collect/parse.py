#!/usr/bin/env python3
"""
adapter: ssh_collect
====================
Connects to a host via SSH (password or key auth), executes a curated
command suite, and emits obs.attack.precondition events for host wickets.

Evidence ranks used:
  rank 1 = runtime / live system state (id, uname, ps, env)
  rank 2 = build/install artifacts (dpkg/rpm list, ~/.ssh, history)
  rank 3 = config files (sudoers, crontab, service files)
  rank 4 = network (nmap results fed in externally)

All observations are tri-state: realized / blocked / unknown.
Unknown means the evidence was insufficient — never defaulted to blocked.

Usage:
  python parse.py \\
    --host 192.168.1.50 --user root --key ~/.ssh/id_rsa \\
    --out /tmp/host_events.ndjson \\
    --attack-path-id host_linux_privesc_sudo_v1 \\
    --workload-id myhost \\
    [--run-id <uuid>] [--timeout 15]

  python parse.py \\
    --host 192.168.1.50 --user admin --password S3cret \\
    --out /tmp/host_events.ndjson \\
    --attack-path-id host_ssh_initial_access_v1
"""

import argparse, json, re, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN = "skg-host-toolchain"
SOURCE_ID = "adapter.ssh_collect"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# Kernel versions known to be vulnerable to common LPE CVEs
# (dirty cow, dirty pipe, pkexec, etc.) — used for HO-12 heuristic
VULN_KERNEL_PATTERNS = [
    r"^2\.",                         # anything 2.x
    r"^3\.",                         # anything 3.x
    r"^4\.[0-9]\.",                  # 4.0 - 4.9
    r"^4\.1[0-3]\.",                 # 4.10 - 4.13
    r"^5\.[0-9]\.",                  # 5.0 - 5.9
    r"^5\.1[0-5]\.",                 # 5.10 - 5.15 (dirty pipe < 5.16.11)
]

# SUID binaries commonly abusable for privesc (GTFOBins)
SUID_INTERESTING = {
    "bash", "sh", "dash", "python", "python3", "perl", "ruby", "vim", "vi",
    "nmap", "find", "less", "more", "awk", "gawk", "sed", "tee", "cp", "mv",
    "dd", "tar", "zip", "unzip", "curl", "wget", "nc", "ncat", "socat",
    "pkexec", "sudo", "su", "env", "strace", "gdb", "php", "node", "lua",
}

# Credential indicators in env/history
CRED_PATTERNS = [
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|aws[_-]?secret|private[_-]?key)\s*[=:]",
    r"(?i)(ANTHROPIC|OPENAI|GITHUB|GITLAB|AWS|AZURE|GCP)[_-]?(API[_-]?)?KEY\s*=",
    r"(?i)\.aws/credentials",
    r"(?i)\.netrc",
]

# AV/EDR process names
AV_EDR_PROCS = {
    "crowdstrike", "falcon-sensor", "cbdaemon", "cbagentd", "sentinel", "sentineld",
    "cylancesvc", "tetragon", "falco", "clamd", "sophos", "avgd", "avast",
    "wdavdaemon", "mdatp", "elastic-agent", "osqueryd", "auditd",
}


def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path: Path, wicket_id: str, status: str,
         evidence_rank: int, source_kind: str, pointer: str, confidence: float,
         attack_path_id: str, run_id: str, workload_id: str,
         notes: str = "", attributes: dict = None):
    now = iso_now()
    payload = {
        "wicket_id": wicket_id,
        "status": status,
        "attack_path_id": attack_path_id,
        "run_id": run_id,
        "workload_id": workload_id,
        "observed_at": now,
        "notes": notes,
    }
    if attributes:
        payload["attributes"] = attributes

    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "obs.attack.precondition",
        "source": {"source_id": SOURCE_ID, "toolchain": TOOLCHAIN, "version": get_version()},
        "payload": payload,
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": {
                "source_kind": source_kind,
                "pointer": pointer,
                "collected_at": now,
                "confidence": confidence,
            },
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def _run(client, cmd: str, timeout: int = 15) -> tuple[str, str, int]:
    """Execute a command on the SSH client. Returns (stdout, stderr, exit_code)."""
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        rc = stdout.channel.recv_exit_status()
        return out, err, rc
    except Exception as e:
        return "", str(e), -1


# ---------------------------------------------------------------------------
# Wicket evaluators
# ---------------------------------------------------------------------------

def eval_ho01_reachability(host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-01: host reachable — confirmed by the fact we got here."""
    emit(out, "HO-01", "realized", 1, "ssh_auth", f"ssh://{host}", 0.95,
         apid, rid, wid, "SSH authentication succeeded; host is reachable and responsive.")


def eval_ho02_ssh(host: str, port: int, out: Path, apid: str, rid: str, wid: str):
    """HO-02: SSH service exposed — confirmed by successful connection."""
    emit(out, "HO-02", "realized", 1, "ssh_auth", f"ssh://{host}:{port}", 0.95,
         apid, rid, wid, f"SSH service confirmed on {host}:{port}.",
         {"port": port})


def eval_ho03_credential(host: str, user: str, auth_type: str,
                          out: Path, apid: str, rid: str, wid: str):
    """HO-03: SSH credential valid — confirmed by successful auth."""
    emit(out, "HO-03", "realized", 1, "ssh_auth", f"ssh://{host}", 0.99,
         apid, rid, wid, f"Credential valid for user '{user}' via {auth_type}.",
         {"user": user, "auth_type": auth_type})


def eval_ho10_root(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-10: user is root or local admin."""
    stdout, _, rc = _run(client, "id")
    if rc != 0 or not stdout:
        emit(out, "HO-10", "unknown", 1, "ssh_command", f"ssh://{host}/id", 0.4,
             apid, rid, wid, "Could not run 'id' command.")
        return stdout

    uid0 = "uid=0" in stdout or "root" in stdout.lower()
    sudo_grp = re.search(r"(sudo|wheel|admin)", stdout, re.I) is not None

    if uid0:
        emit(out, "HO-10", "realized", 1, "ssh_command", f"ssh://{host}/id", 0.99,
             apid, rid, wid, "Running as uid=0 (root).",
             {"id_output": stdout[:200]})
    elif sudo_grp:
        emit(out, "HO-10", "unknown", 1, "ssh_command", f"ssh://{host}/id", 0.6,
             apid, rid, wid, "User is in sudo/wheel/admin group but not currently root.",
             {"id_output": stdout[:200]})
    else:
        emit(out, "HO-10", "blocked", 1, "ssh_command", f"ssh://{host}/id", 0.75,
             apid, rid, wid, "User has no apparent admin group membership.",
             {"id_output": stdout[:200]})
    return stdout


def eval_ho06_sudo(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-06: sudo misconfigured (NOPASSWD / wildcard exec)."""
    stdout, _, rc = _run(client, "sudo -l -n 2>&1")
    if not stdout or "not allowed" in stdout.lower() or "command not found" in stdout.lower():
        emit(out, "HO-06", "unknown", 3, "ssh_command", f"ssh://{host}/sudo-l", 0.4,
             apid, rid, wid, "Could not enumerate sudo permissions or sudo not present.")
        return

    nopasswd = "NOPASSWD" in stdout
    all_cmds = re.search(r"ALL\s*=\s*(\(ALL\)|\(ALL : ALL\))\s*ALL", stdout) is not None
    exec_entries = re.findall(r"NOPASSWD\s*:\s*([^\n]+)", stdout)

    if nopasswd and (all_cmds or exec_entries):
        emit(out, "HO-06", "realized", 3, "ssh_command", f"ssh://{host}/sudo-l", 0.9,
             apid, rid, wid,
             "NOPASSWD sudo entry found — privilege escalation likely possible.",
             {"entries": exec_entries[:10], "all_commands": all_cmds})
    elif "NOPASSWD" in stdout:
        emit(out, "HO-06", "realized", 3, "ssh_command", f"ssh://{host}/sudo-l", 0.75,
             apid, rid, wid,
             "NOPASSWD present but scope limited; review entries.",
             {"entries": exec_entries[:10]})
    else:
        emit(out, "HO-06", "blocked", 3, "ssh_command", f"ssh://{host}/sudo-l", 0.7,
             apid, rid, wid, "No NOPASSWD entries found.",
             {"sudo_output_snippet": stdout[:300]})


def eval_ho07_suid(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-07: SUID binary present that can be used for privesc."""
    stdout, _, rc = _run(client,
        "find / -perm -4000 -type f 2>/dev/null | head -60", timeout=25)
    if not stdout:
        emit(out, "HO-07", "unknown", 3, "ssh_command", f"ssh://{host}/suid-scan", 0.35,
             apid, rid, wid, "SUID scan returned no output or timed out.")
        return

    found = []
    for line in stdout.splitlines():
        binary = Path(line.strip()).name.lower()
        if binary in SUID_INTERESTING:
            found.append(line.strip())

    if found:
        emit(out, "HO-07", "realized", 3, "ssh_command", f"ssh://{host}/suid-scan", 0.85,
             apid, rid, wid,
             f"Abusable SUID binary found: {found[0]}",
             {"interesting_suid": found[:10]})
    else:
        emit(out, "HO-07", "unknown", 3, "ssh_command", f"ssh://{host}/suid-scan", 0.5,
             apid, rid, wid,
             "No commonly abusable SUID binaries detected; non-standard binaries may still be abusable.",
             {"suid_count": len(stdout.splitlines())})


def eval_ho08_writable_cron(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-08: world-writable cron job or service file."""
    crontab_out, _, _ = _run(client, "crontab -l 2>/dev/null; cat /etc/cron* /etc/cron.d/* 2>/dev/null | head -50")
    writable_out, _, _ = _run(client,
        "find /etc/cron* /etc/systemd/system /lib/systemd/system -writable 2>/dev/null | head -20",
        timeout=20)

    writable_services = [l.strip() for l in writable_out.splitlines() if l.strip()]

    if writable_services:
        emit(out, "HO-08", "realized", 3, "ssh_command", f"ssh://{host}/cron-writable", 0.85,
             apid, rid, wid,
             "Writable cron/service path found.",
             {"writable_paths": writable_services[:10]})
    elif crontab_out:
        emit(out, "HO-08", "unknown", 3, "ssh_command", f"ssh://{host}/cron-writable", 0.45,
             apid, rid, wid,
             "Cron jobs exist but writability could not be confirmed.")
    else:
        emit(out, "HO-08", "unknown", 3, "ssh_command", f"ssh://{host}/cron-writable", 0.35,
             apid, rid, wid, "No crontab entries or writable service paths detected.")


def eval_ho09_cred_in_env(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-09: credential or secret in environment, history, or config files."""
    sources = {
        "env":        ("env 2>/dev/null", 1),
        "bashrc":     ("cat ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null", 3),
        "history":    ("cat ~/.bash_history ~/.zsh_history 2>/dev/null | tail -100", 2),
        "aws_creds":  ("cat ~/.aws/credentials ~/.aws/config 2>/dev/null", 2),
        "etc_env":    ("cat /etc/environment 2>/dev/null", 3),
    }

    hits = {}
    for src_name, (cmd, rank) in sources.items():
        out_txt, _, _ = _run(client, cmd)
        for pat in CRED_PATTERNS:
            matches = re.findall(pat, out_txt)
            if matches:
                hits.setdefault(src_name, []).extend([str(m) for m in matches[:5]])

    if hits:
        top_src = list(hits.keys())[0]
        emit(out, "HO-09", "realized", 2, "ssh_command", f"ssh://{host}/cred-scan", 0.8,
             apid, rid, wid,
             "Credential indicator found in environment/history/config.",
             {"sources_with_hits": list(hits.keys()), "sample_keys": hits.get(top_src, [])[:5]})
    else:
        emit(out, "HO-09", "unknown", 2, "ssh_command", f"ssh://{host}/cred-scan", 0.45,
             apid, rid, wid,
             "No obvious credential patterns detected; manual review recommended.")


def eval_ho11_vuln_packages(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-11: vulnerable package installed. Collects package list; CVE cross-ref is external."""
    # Try multiple package managers
    pkg_out = ""
    pkg_manager = "unknown"

    for cmd, mgr in [
        ("dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null | head -200", "dpkg"),
        ("rpm -qa --queryformat '%{NAME} %{VERSION}\\n' 2>/dev/null | head -200", "rpm"),
        ("apk info -v 2>/dev/null | head -200", "apk"),
        ("pacman -Q 2>/dev/null | head -200", "pacman"),
    ]:
        out_txt, _, rc = _run(client, cmd)
        if out_txt and rc == 0:
            pkg_out = out_txt
            pkg_manager = mgr
            break

    # Emit package list as an observation metadata event for external CVE cross-ref
    if pkg_out:
        pkg_count = len(pkg_out.splitlines())
        # Heuristic: flag as unknown — actual CVE match requires feed cross-ref
        emit(out, "HO-11", "unknown", 2, "ssh_command", f"ssh://{host}/packages", 0.5,
             apid, rid, wid,
             f"Package list collected via {pkg_manager} ({pkg_count} packages). "
             "CVE cross-reference required for definitive status.",
             {"package_manager": pkg_manager, "package_count": pkg_count,
              "packages_sample": pkg_out.splitlines()[:30]})
    else:
        emit(out, "HO-11", "unknown", 2, "ssh_command", f"ssh://{host}/packages", 0.3,
             apid, rid, wid, "Could not enumerate installed packages.")


def eval_ho12_kernel(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-12: unpatched kernel — check uname -r against known-bad patterns."""
    stdout, _, rc = _run(client, "uname -r")
    if rc != 0 or not stdout:
        emit(out, "HO-12", "unknown", 1, "ssh_command", f"ssh://{host}/uname", 0.3,
             apid, rid, wid, "Could not run uname -r.")
        return

    kver = stdout.strip()
    possibly_vuln = any(re.match(pat, kver) for pat in VULN_KERNEL_PATTERNS)

    if possibly_vuln:
        emit(out, "HO-12", "realized", 1, "ssh_command", f"ssh://{host}/uname", 0.7,
             apid, rid, wid,
             f"Kernel {kver} matches known-vulnerable version range; confirm specific CVE applicability.",
             {"kernel_version": kver})
    else:
        emit(out, "HO-12", "unknown", 1, "ssh_command", f"ssh://{host}/uname", 0.55,
             apid, rid, wid,
             f"Kernel {kver} not in known-bad range but LPE CVEs vary; validate against CVE feed.",
             {"kernel_version": kver})


def eval_ho13_ssh_keys(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-13: SSH private key accessible in ~/.ssh."""
    stdout, _, _ = _run(client, "ls -la ~/.ssh/ 2>/dev/null && find ~/.ssh -name 'id_*' ! -name '*.pub' 2>/dev/null")
    if not stdout:
        emit(out, "HO-13", "unknown", 2, "ssh_command", f"ssh://{host}/ssh-keys", 0.4,
             apid, rid, wid, "~/.ssh not readable or empty.")
        return

    private_keys = [l for l in stdout.splitlines() if re.search(r"id_(rsa|ecdsa|ed25519|dsa)$", l)]

    if private_keys:
        emit(out, "HO-13", "realized", 2, "ssh_command", f"ssh://{host}/ssh-keys", 0.9,
             apid, rid, wid,
             f"SSH private key(s) found: {len(private_keys)} key file(s).",
             {"key_files": private_keys[:5]})
    else:
        emit(out, "HO-13", "blocked", 2, "ssh_command", f"ssh://{host}/ssh-keys", 0.65,
             apid, rid, wid, "No standard private key files found in ~/.ssh.")


def eval_ho15_docker(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-15: Docker/container runtime present and accessible."""
    stdout, _, rc = _run(client,
        "which docker 2>/dev/null && ls -la /var/run/docker.sock 2>/dev/null && id")

    has_docker = "docker" in stdout and "/usr/bin/docker" in stdout or "/usr/local/bin/docker" in stdout
    socket_present = "/var/run/docker.sock" in stdout
    socket_accessible = "srw" in stdout  # socket file indicator

    # Try direct test
    test_out, _, test_rc = _run(client, "docker ps 2>&1 | head -5")
    can_run_docker = test_rc == 0

    if can_run_docker:
        emit(out, "HO-15", "realized", 2, "ssh_command", f"ssh://{host}/docker", 0.95,
             apid, rid, wid, "Current user can run docker commands directly.",
             {"docker_accessible": True})
    elif socket_present:
        emit(out, "HO-15", "unknown", 2, "ssh_command", f"ssh://{host}/docker", 0.6,
             apid, rid, wid,
             "Docker socket present; user may lack direct access but socket exposure is a risk.",
             {"socket_present": True, "can_run_docker": False})
    elif has_docker:
        emit(out, "HO-15", "unknown", 2, "ssh_command", f"ssh://{host}/docker", 0.45,
             apid, rid, wid, "Docker binary present; socket status unclear.")
    else:
        emit(out, "HO-15", "blocked", 2, "ssh_command", f"ssh://{host}/docker", 0.7,
             apid, rid, wid, "No Docker binary or socket found.")


def eval_ho16_cloud_metadata(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-16: cloud metadata service reachable and returns credentials."""
    # Try IMDSv1 (AWS), Azure IMDS, GCP metadata
    cmd = (
        "curl -sf --connect-timeout 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || "
        "curl -sf --connect-timeout 3 -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' 2>/dev/null || "
        "curl -sf --connect-timeout 3 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' -H 'Metadata-Flavor: Google' 2>/dev/null"
    )
    stdout, _, rc = _run(client, cmd, timeout=15)

    if stdout and any(k in stdout for k in ["iam", "access_token", "token_type", "expires_in"]):
        emit(out, "HO-16", "realized", 4, "ssh_command", f"ssh://{host}/imds", 0.9,
             apid, rid, wid,
             "Cloud metadata service returned credential material.",
             {"imds_response_snippet": stdout[:200]})
    elif rc == 0 and stdout:
        emit(out, "HO-16", "unknown", 4, "ssh_command", f"ssh://{host}/imds", 0.55,
             apid, rid, wid,
             "Metadata service responded but no clear credential returned.",
             {"response_snippet": stdout[:100]})
    else:
        emit(out, "HO-16", "blocked", 4, "ssh_command", f"ssh://{host}/imds", 0.65,
             apid, rid, wid, "Metadata service not reachable from this host.")


def eval_ho23_av_edr(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-23: AV/EDR absent or weak."""
    stdout, _, _ = _run(client, "ps aux 2>/dev/null | head -80")
    if not stdout:
        emit(out, "HO-23", "unknown", 1, "ssh_command", f"ssh://{host}/ps", 0.3,
             apid, rid, wid, "Could not enumerate running processes.")
        return

    procs_lower = stdout.lower()
    found_av = [av for av in AV_EDR_PROCS if av in procs_lower]

    if not found_av:
        emit(out, "HO-23", "realized", 1, "ssh_command", f"ssh://{host}/ps", 0.7,
             apid, rid, wid,
             "No known AV/EDR processes detected in process list.",
             {"checked_procs": len(stdout.splitlines())})
    else:
        emit(out, "HO-23", "blocked", 1, "ssh_command", f"ssh://{host}/ps", 0.75,
             apid, rid, wid,
             f"AV/EDR process detected: {found_av[0]}",
             {"av_edr_found": found_av[:5]})


def eval_ho24_domain_joined(client, host: str, out: Path, apid: str, rid: str, wid: str):
    """HO-24: host is domain-joined."""
    # Check realm list first — definitive indicator
    realm_out, _, realm_rc = _run(client, "realm list 2>/dev/null")
    realm_joined = realm_rc == 0 and bool(realm_out.strip())

    # Fall back to sssd.conf — real deployments have this populated
    sssd_out, _, _ = _run(client, "cat /etc/sssd/sssd.conf 2>/dev/null | head -20")
    sssd_joined = bool(sssd_out.strip())

    # krb5.conf only counts if it has non-stub content
    krb5_out, _, _ = _run(client, "cat /etc/krb5.conf 2>/dev/null | head -20")
    stub_markers = ["ATHENA.MIT.EDU", "ANDREW.CMU.EDU", "kerberos.mit.edu"]
    krb5_is_stub = sum(1 for m in stub_markers if m in krb5_out) >= 2
    krb5_joined = bool(krb5_out.strip()) and not krb5_is_stub

    has_domain = realm_joined or sssd_joined or krb5_joined
    snippet = (realm_out or sssd_out or krb5_out)[:300]

    if has_domain:
        emit(out, "HO-24", "realized", 2, "ssh_command", f"ssh://{host}/domain", 0.8,
             apid, rid, wid, "Host appears to be domain-joined.",
             {"domain_config_snippet": snippet})
    else:
        emit(out, "HO-24", "unknown", 2, "ssh_command", f"ssh://{host}/domain", 0.4,
             apid, rid, wid, "No clear domain membership indicators found.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------



def eval_ho14_authorized_keys(client, host, out, attack_path_id, run_id, workload_id):
    """HO-14: writable authorized_keys — readable by non-owner."""
    try:
        _, stdout, _ = client.exec_command("stat -c '%a %U %n' ~/.ssh/authorized_keys 2>/dev/null", timeout=10)
        result = stdout.read().decode(errors="replace").strip()
    except Exception:
        result = ""
    if not result:
        emit(out, "HO-14", "unknown", 2, "ssh_command", f"ssh://{host}/stat-authorized-keys", 0.35,
             attack_path_id, run_id, workload_id, "authorized_keys not found or not accessible")
        return
    perms = result.split()[0] if result.split() else "000"
    world_writable = len(perms) >= 3 and int(perms[-1]) >= 2
    emit(out, "HO-14",
         "realized" if world_writable else "blocked",
         2, "ssh_command", f"ssh://{host}/stat-authorized-keys", 0.90,
         attack_path_id, run_id, workload_id, result)


def eval_ho19_smb(client, host, out, attack_path_id, run_id, workload_id):
    """HO-19: SMB service exposed (port 445/139)."""
    try:
        _, stdout, _ = client.exec_command("ss -tnlp 2>/dev/null | grep -E ':445|:139'", timeout=10)
        result = stdout.read().decode(errors="replace").strip()
    except Exception:
        result = ""
    status = "realized" if result else "unknown"
    emit(out, "HO-19", status, 4, "ssh_command", f"ssh://{host}/smb-ports", 0.80 if result else 0.4,
         attack_path_id, run_id, workload_id, result[:120])


def eval_ho20_rdp(client, host, out, attack_path_id, run_id, workload_id):
    """HO-20: RDP service exposed (port 3389)."""
    try:
        _, stdout, _ = client.exec_command("ss -tnlp 2>/dev/null | grep ':3389'", timeout=10)
        result = stdout.read().decode(errors="replace").strip()
    except Exception:
        result = ""
    status = "realized" if result else "unknown"
    emit(out, "HO-20", status, 4, "ssh_command", f"ssh://{host}/rdp-port", 0.80 if result else 0.4,
         attack_path_id, run_id, workload_id, result[:120])


def eval_ho21_nfs(client, host, out, attack_path_id, run_id, workload_id):
    """HO-21: NFS share world-readable."""
    try:
        _, stdout, _ = client.exec_command("cat /etc/exports 2>/dev/null", timeout=10)
        exports = stdout.read().decode(errors="replace").strip()
    except Exception:
        exports = ""
    # Look for no_root_squash or world export (*)
    world_readable = "*(ro" in exports or "*(rw" in exports or "no_root_squash" in exports
    if not exports:
        emit(out, "HO-21", "unknown", 3, "ssh_command", f"ssh://{host}/etc-exports", 0.3,
             attack_path_id, run_id, workload_id, "no /etc/exports found")
    else:
        emit(out, "HO-21", "realized" if world_readable else "blocked",
             3, "ssh_command", f"ssh://{host}/etc-exports", 0.85,
             attack_path_id, run_id, workload_id, exports[:200])


def eval_ho25_nmap_services(client, host, out, attack_path_id, run_id, workload_id):
    """HO-25: Open port running exploitable service version — use ss as proxy."""
    try:
        _, stdout, _ = client.exec_command("ss -tnlp 2>/dev/null", timeout=10)
        result = stdout.read().decode(errors="replace").strip()
    except Exception:
        result = ""
    # Heuristic: known exploitable service ports
    KNOWN_EXPLOITABLE = {21: "FTP", 23: "Telnet", 512: "rexec", 513: "rlogin",
                         514: "rsh", 1099: "RMI", 2049: "NFS", 4848: "GlassFish",
                         8080: "Tomcat/JBoss", 9200: "Elasticsearch", 27017: "MongoDB"}
    found = []
    for port, svc in KNOWN_EXPLOITABLE.items():
        if f":{port}" in result:
            found.append(f"{svc}:{port}")
    status = "realized" if found else ("blocked" if result else "unknown")
    emit(out, "HO-25", status, 4, "ssh_command", f"ssh://{host}/open-ports",
         0.70 if found else (0.50 if result else 0.30),
         attack_path_id, run_id, workload_id,
         f"exploitable services: {found}" if found else result[:120])


def eval_ho04_winrm_exposed(host: str, port: int, out, attack_path_id, run_id, workload_id):
    """HO-04: WinRM service exposed — confirmed by successful WinRM connection attempt."""
    emit(out, "HO-04", "realized", 4, "winrm_connect", f"winrm://{host}:{port}", 0.95,
         attack_path_id, run_id, workload_id, f"WinRM reachable on {host}:{port}")


def eval_ho05_winrm_credential(host: str, user: str, out, attack_path_id, run_id, workload_id):
    """HO-05: WinRM credential valid — confirmed by successful auth."""
    emit(out, "HO-05", "realized", 1, "winrm_auth", f"winrm://{host}", 0.99,
         attack_path_id, run_id, workload_id, f"WinRM authenticated as {user}")


def eval_ho17_msf_session(session_info: dict, out, attack_path_id, run_id, workload_id):
    """HO-17: Active MSF session on this host."""
    emit(out, "HO-17", "realized", 1, "msf_session", f"msf://sessions/{session_info.get('id','')}",
         1.0, attack_path_id, run_id, workload_id,
         f"session type={session_info.get('type','')} user={session_info.get('username','')}")


def eval_ho18_msf_creds(cred_list: list, out, attack_path_id, run_id, workload_id):
    """HO-18: Credentials harvested via MSF."""
    count = len(cred_list)
    emit(out, "HO-18", "realized" if count else "unknown", 1, "msf_creds",
         "msf://creds", 0.95 if count else 0.3,
         attack_path_id, run_id, workload_id, f"{count} credentials in MSF database")


def eval_ho22_password_reuse(collection_results: dict, out, attack_path_id, run_id, workload_id):
    """HO-22: Password reuse likely — same credential seen on multiple hosts."""
    # Heuristic: if credential appears in env or history AND MSF has it
    cred_hints = []
    env = (collection_results.get("env_vars") or "").upper()
    if "PASSWORD" in env or "PASSWD" in env or "SECRET" in env:
        cred_hints.append("credential keyword in env vars")
    status = "realized" if len(cred_hints) >= 1 else "unknown"
    conf = 0.55 if cred_hints else 0.3
    emit(out, "HO-22", status, 2, "ssh_command", "ssh://credential-correlation", conf,
         attack_path_id, run_id, workload_id,
         "; ".join(cred_hints) if cred_hints else "insufficient evidence for reuse assessment")


def main():
    ap = argparse.ArgumentParser(description="SKG SSH host collection adapter")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--key", default=None, help="Path to SSH private key")
    ap.add_argument("--password", default=None, help="SSH password")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--out", required=True, help="Output NDJSON file (append)")
    ap.add_argument("--attack-path-id", default="host_ssh_initial_access_v1")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--workload-id", default=None)
    ap.add_argument("--audit", action="store_true",
                    help="Also run sysaudit checks (FI/PI/LI wickets)")
    ap.add_argument("--audit-only", action="store_true",
                    help="Run sysaudit checks only (skip HO-* collection)")
    ap.add_argument("--audit-checks", default=None,
                    help="Comma-separated subset of audit checks to run "
                         "(e.g. fi01,fi07,li01,li05)")
    args = ap.parse_args()

    try:
        import paramiko
    except ImportError:
        print("ERROR: paramiko is required — pip install paramiko")
        return 1

    rid = args.run_id or str(uuid.uuid4())
    wid = args.workload_id or args.host
    out_path = Path(args.out).expanduser().resolve()
    pointer = f"ssh://{args.host}:{args.port}"

    # Connect
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    auth_type = "unknown"

    try:
        if args.key:
            client.connect(args.host, port=args.port, username=args.user,
                           key_filename=str(Path(args.key).expanduser().resolve()), timeout=args.timeout)
            auth_type = "key"
        elif args.password:
            client.connect(args.host, port=args.port, username=args.user,
                           password=args.password, timeout=args.timeout)
            auth_type = "password"
        else:
            # Try agent / default keys
            client.connect(args.host, port=args.port, username=args.user,
                           timeout=args.timeout)
            auth_type = "agent/default"
    except Exception as e:
        # Emit blocked observations for connectivity wickets
        out_path.parent.mkdir(parents=True, exist_ok=True)
        emit(out_path, "HO-01", "unknown", 4, "ssh_connect_attempt", pointer, 0.5,
             args.attack_path_id, rid, wid, f"Connection attempt failed: {e}")
        emit(out_path, "HO-03", "blocked", 1, "ssh_connect_attempt", pointer, 0.8,
             args.attack_path_id, rid, wid, f"SSH authentication failed: {e}")
        print(f"[WARN] SSH connection failed: {e}", flush=True)
        return 1

    print(f"[*] Connected to {args.host}:{args.port} as {args.user} ({auth_type})", flush=True)

    # Emit connectivity/auth wickets
    eval_ho01_reachability(args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho02_ssh(args.host, args.port, out_path, args.attack_path_id, rid, wid)
    eval_ho03_credential(args.host, args.user, auth_type, out_path, args.attack_path_id, rid, wid)

    if not args.audit_only:
        # Run all host assessments
        eval_ho10_root(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho06_sudo(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho07_suid(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho08_writable_cron(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho09_cred_in_env(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho11_vuln_packages(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho12_kernel(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho13_ssh_keys(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho15_docker(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho16_cloud_metadata(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho23_av_edr(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho24_domain_joined(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho14_authorized_keys(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho19_smb(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho20_rdp(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho21_nfs(client, args.host, out_path, args.attack_path_id, rid, wid)
        eval_ho25_nmap_services(client, args.host, out_path, args.attack_path_id, rid, wid)
        # HO-22: password reuse heuristic from env collection
        try:
            _, stdout, _ = client.exec_command("printenv 2>/dev/null", timeout=10)
            env_out = stdout.read().decode(errors="replace")
            eval_ho22_password_reuse({"env_vars": env_out}, out_path, args.attack_path_id, rid, wid)
        except Exception:
            pass

    # ── Sysaudit: filesystem, process, log integrity ──────────────────────
    if args.audit or args.audit_only:
        print(f"\n[*] Running sysaudit checks (FI/PI/LI)...", flush=True)
        audit_path = (Path(__file__).resolve().parents[1]
                      / "sysaudit" / "audit.py")
        if not audit_path.exists():
            print(f"[WARN] sysaudit adapter not found: {audit_path}")
        else:
            import sys as _sys
            _sys.path.insert(0, str(audit_path.parent))
            from audit import run_sysaudit

            checks = (args.audit_checks.split(",")
                      if args.audit_checks else None)
            audit_apid = "full_system_integrity_v1"
            sysaudit_events = run_sysaudit(
                client, args.host, wid, audit_apid, rid,
                checks=checks,
            )
            # Write sysaudit events to the same output file
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "a", encoding="utf-8") as fh:
                for ev in sysaudit_events:
                    fh.write(json.dumps(ev) + "\n")
            print(f"[*] Sysaudit: {len(sysaudit_events)} FI/PI/LI events → {out_path}")

    client.close()
    print(f"[OK] Collection complete → {out_path}", flush=True)
    return 0

    try:
        import paramiko
    except ImportError:
        print("ERROR: paramiko is required — pip install paramiko")
        return 1

    rid = args.run_id or str(uuid.uuid4())
    wid = args.workload_id or args.host
    out_path = Path(args.out).expanduser().resolve()
    pointer = f"ssh://{args.host}:{args.port}"

    # Connect
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    auth_type = "unknown"

    try:
        if args.key:
            client.connect(args.host, port=args.port, username=args.user,
                           key_filename=str(Path(args.key).expanduser().resolve()), timeout=args.timeout)
            auth_type = "key"
        elif args.password:
            client.connect(args.host, port=args.port, username=args.user,
                           password=args.password, timeout=args.timeout)
            auth_type = "password"
        else:
            # Try agent / default keys
            client.connect(args.host, port=args.port, username=args.user,
                           timeout=args.timeout)
            auth_type = "agent/default"
    except Exception as e:
        # Emit blocked observations for connectivity wickets
        out_path.parent.mkdir(parents=True, exist_ok=True)
        emit(out_path, "HO-01", "unknown", 4, "ssh_connect_attempt", pointer, 0.5,
             args.attack_path_id, rid, wid, f"Connection attempt failed: {e}")
        emit(out_path, "HO-03", "blocked", 1, "ssh_connect_attempt", pointer, 0.8,
             args.attack_path_id, rid, wid, f"SSH authentication failed: {e}")
        print(f"[WARN] SSH connection failed: {e}", flush=True)
        return 1

    print(f"[*] Connected to {args.host}:{args.port} as {args.user} ({auth_type})", flush=True)

    # Emit connectivity/auth wickets
    eval_ho01_reachability(args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho02_ssh(args.host, args.port, out_path, args.attack_path_id, rid, wid)
    eval_ho03_credential(args.host, args.user, auth_type, out_path, args.attack_path_id, rid, wid)

    # Run all host assessments
    eval_ho10_root(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho06_sudo(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho07_suid(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho08_writable_cron(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho09_cred_in_env(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho11_vuln_packages(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho12_kernel(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho13_ssh_keys(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho15_docker(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho16_cloud_metadata(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho23_av_edr(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho24_domain_joined(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho14_authorized_keys(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho19_smb(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho20_rdp(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho21_nfs(client, args.host, out_path, args.attack_path_id, rid, wid)
    eval_ho25_nmap_services(client, args.host, out_path, args.attack_path_id, rid, wid)
    # HO-22: password reuse heuristic from env collection
    try:
        _, stdout, _ = client.exec_command("printenv 2>/dev/null", timeout=10)
        env_out = stdout.read().decode(errors="replace")
        eval_ho22_password_reuse({"env_vars": env_out}, out_path, args.attack_path_id, rid, wid)
    except Exception:
        pass

    client.close()
    print(f"[OK] Collection complete → {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

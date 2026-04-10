"""
ldap_enum.py — LDAP/Active Directory enumeration adapter
=========================================================
Uses the ldap3 Python library (installed: v2.9) to enumerate AD objects.
No binary dependency — pure Python, always available when ldap3 is installed.

Emits obs.attack.precondition events for:
  AD-01  users enumerated               (query CN=Users returns results)
  AD-02  groups enumerated              (query CN=Groups)
  AD-03  password policy extractable    (query domain policy object)
  AD-04  GPO accessible                 (CN=Policies in SYSVOL accessible)
  AD-05  Kerberoastable SPN found       (servicePrincipalName on user object)
  AD-15  LAPS attribute readable        (ms-Mcs-AdmPwd or ms-LAPS-Password readable)
  AD-22-LDAP-LEGACY  quarantined legacy account-enumeration signal
  AD-24  anonymous LDAP bind allowed    (bind with no creds = weak/no password policy)
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

INSTRUMENT_NAME = "ldap_enum"
QUARANTINED_AD22_WICKET = "AD-22-LDAP-LEGACY"
QUARANTINED_AD22_NOTE = (
    "Legacy LDAP account enumeration signal; canonical AD-22 tiering semantics "
    "are owned by the AD domain tiering slice and are not defined here."
)

_PRIV_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "group policy creator owners",
}


def run(
    ip: str,
    target: dict[str, Any],
    run_id: str,
    out_dir: Any,
    result: dict[str, Any],
    *,
    authorized: bool = False,
    node_key: str = "",
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        import ldap3
    except ImportError:
        result["error"] = "ldap3 not installed"
        return result

    from pathlib import Path as _Path
    import json
    from skg.sensors import envelope, precondition_payload

    _node_key = node_key or ip
    _out_dir  = _Path(str(out_dir)) if out_dir else _Path("/tmp/skg_gravity")
    _out_dir.mkdir(parents=True, exist_ok=True)

    creds    = target.get("credentials") or {}
    username = creds.get("username") or ""
    password = creds.get("password") or ""
    domain   = (
        target.get("domain")
        or target.get("ad_domain")
        or creds.get("domain")
        or ""
    )

    events: list[dict] = []

    # ── 1. Attempt bind ───────────────────────────────────────────────────
    server = ldap3.Server(ip, get_info=ldap3.ALL, connect_timeout=10)

    # Try anonymous first; if creds provided, also try authenticated
    conn = None
    anon_ok = False
    auth_ok = False

    try:
        anon_conn = ldap3.Connection(server, auto_bind=True)
        conn = anon_conn
        anon_ok = True
    except Exception:
        pass

    if username and not anon_ok:
        try:
            bind_user = f"{domain}\\{username}" if domain else username
            auth_conn = ldap3.Connection(
                server, user=bind_user, password=password, auto_bind=True,
            )
            conn = auth_conn
            auth_ok = True
        except Exception:
            pass
    elif username and anon_ok:
        try:
            bind_user = f"{domain}\\{username}" if domain else username
            auth_conn = ldap3.Connection(
                server, user=bind_user, password=password, auto_bind=True,
            )
            # prefer authenticated for richer data
            conn = auth_conn
            auth_ok = True
        except Exception:
            pass

    if conn is None:
        result["error"] = "LDAP bind failed (anonymous and authenticated)"
        result["success"] = False
        return result

    if anon_ok:
        events.append(envelope(
            event_type="obs.attack.precondition",
            source_id="ldap_enum_adapter",
            toolchain="skg-ad-lateral-toolchain",
            payload=precondition_payload(
                wicket_id="AD-24",
                label=f"Anonymous LDAP bind allowed on {ip}",
                domain="ad_lateral",
                workload_id=f"host::{_node_key}",
                realized=True,
                detail="ldap3 auto_bind with no credentials succeeded",
            ),
            evidence_rank=2,
            source_kind="ldap3",
            pointer=f"ldap://{ip}",
            confidence=0.92,
        ))

    # ── 2. Extract base DN from server info ───────────────────────────────
    base_dn = ""
    try:
        if server.info and server.info.naming_contexts:
            # Prefer the longest (most specific) context that looks like a domain
            contexts = [str(c) for c in server.info.naming_contexts if "DC=" in str(c).upper()]
            if contexts:
                base_dn = sorted(contexts, key=len, reverse=True)[0]
    except Exception:
        pass

    if not base_dn:
        # Derive from IP/domain hint
        if domain:
            base_dn = ",".join(f"DC={part}" for part in domain.split("."))
        else:
            result["note"] = "Could not determine base DN; limited enumeration"

    # ── 3. User enumeration ───────────────────────────────────────────────
    users: list[str] = []
    if base_dn:
        try:
            conn.search(
                base_dn,
                "(objectClass=user)",
                attributes=["sAMAccountName", "servicePrincipalName",
                            "memberOf", "ms-Mcs-AdmPwd", "ms-LAPS-Password"],
                size_limit=500,
                time_limit=30,
            )
            spn_users: list[str] = []
            priv_users: list[str] = []
            laps_users: list[str] = []

            for entry in conn.entries:
                sam = str(entry.sAMAccountName) if entry.sAMAccountName else ""
                if sam and sam not in ("$",):
                    users.append(sam)
                # Kerberoastable: has SPN, is not a machine account ($)
                spns = entry.servicePrincipalName
                if spns and not sam.endswith("$"):
                    spn_users.append(sam)
                # Privileged groups
                member_of = entry.memberOf
                if member_of:
                    for grp in (member_of if isinstance(member_of, list) else [member_of]):
                        grp_lower = str(grp).lower()
                        if any(pg in grp_lower for pg in _PRIV_GROUPS):
                            priv_users.append(sam)
                            break
                # LAPS
                laps_val = (
                    getattr(entry, "ms-Mcs-AdmPwd", None)
                    or getattr(entry, "ms-LAPS-Password", None)
                )
                if laps_val and str(laps_val).strip() not in ("", "[]"):
                    laps_users.append(sam)

            if users:
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id="ldap_enum_adapter",
                    toolchain="skg-ad-lateral-toolchain",
                    payload=precondition_payload(
                        wicket_id="AD-01",
                        label=f"AD users enumerated via LDAP on {ip}: {len(users)} accounts",
                        domain="ad_lateral",
                        workload_id=f"host::{_node_key}",
                        realized=True,
                        detail=f"Accounts: {', '.join(users[:10])}",
                    ),
                    evidence_rank=2,
                    source_kind="ldap3",
                    pointer=f"ldap://{ip}/CN=Users",
                    confidence=0.92,
                ))
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id="ldap_enum_adapter",
                    toolchain="skg-ad-lateral-toolchain",
                    payload=precondition_payload(
                        wicket_id=QUARANTINED_AD22_WICKET,
                        label=f"Legacy LDAP account enumeration signal: {', '.join(users[:5])}",
                        domain="ad_lateral",
                        workload_id=f"host::{_node_key}",
                        realized=True,
                        detail=f"{len(users)} total user objects. {QUARANTINED_AD22_NOTE}",
                    ),
                    evidence_rank=2,
                    source_kind="ldap3",
                    pointer=f"ldap://{ip}/CN=Users",
                    confidence=0.90,
                ))

            if spn_users:
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id="ldap_enum_adapter",
                    toolchain="skg-ad-lateral-toolchain",
                    payload=precondition_payload(
                        wicket_id="AD-05",
                        label=f"Kerberoastable SPNs found on {ip}: {', '.join(spn_users[:5])}",
                        domain="ad_lateral",
                        workload_id=f"host::{_node_key}",
                        realized=True,
                        detail=f"SPN users: {spn_users}",
                    ),
                    evidence_rank=2,
                    source_kind="ldap3",
                    pointer=f"ldap://{ip}/servicePrincipalName",
                    confidence=0.88,
                ))

            if priv_users:
                # Phase 7T retirement: keep privileged-account enumeration data
                # as adapter-local telemetry, but do not emit AD-06 collision output.
                result["retired_ad06_ldap_legacy_suppressed"] = True
                result["privileged_accounts_detected"] = list(priv_users[:20])

            if laps_users:
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id="ldap_enum_adapter",
                    toolchain="skg-ad-lateral-toolchain",
                    payload=precondition_payload(
                        wicket_id="AD-15",
                        label=f"LAPS password attribute readable on {ip}",
                        domain="ad_lateral",
                        workload_id=f"host::{_node_key}",
                        realized=True,
                        detail=f"LAPS-readable objects: {', '.join(laps_users[:5])}",
                    ),
                    evidence_rank=1,
                    source_kind="ldap3",
                    pointer=f"ldap://{ip}/ms-Mcs-AdmPwd",
                    confidence=0.95,
                ))

        except Exception as exc:
            result["user_enum_error"] = str(exc)

    # ── 4. Group enumeration ──────────────────────────────────────────────
    if base_dn:
        try:
            conn.search(
                base_dn,
                "(objectClass=group)",
                attributes=["cn"],
                size_limit=200,
                time_limit=20,
            )
            groups = [str(e.cn) for e in conn.entries if e.cn]
            if groups:
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id="ldap_enum_adapter",
                    toolchain="skg-ad-lateral-toolchain",
                    payload=precondition_payload(
                        wicket_id="AD-02",
                        label=f"AD groups enumerated on {ip}: {len(groups)} groups",
                        domain="ad_lateral",
                        workload_id=f"host::{_node_key}",
                        realized=True,
                        detail=f"Groups: {', '.join(groups[:10])}",
                    ),
                    evidence_rank=2,
                    source_kind="ldap3",
                    pointer=f"ldap://{ip}/CN=Groups",
                    confidence=0.88,
                ))
        except Exception:
            pass

    # ── 5. Password policy ────────────────────────────────────────────────
    if base_dn:
        try:
            conn.search(
                base_dn,
                "(objectClass=domainDNS)",
                attributes=["minPwdLength", "lockoutThreshold",
                            "maxPwdAge", "pwdHistoryLength"],
                size_limit=1,
                time_limit=10,
            )
            if conn.entries:
                policy_detail = str(conn.entries[0])[:300]
                events.append(envelope(
                    event_type="obs.attack.precondition",
                    source_id="ldap_enum_adapter",
                    toolchain="skg-ad-lateral-toolchain",
                    payload=precondition_payload(
                        wicket_id="AD-03",
                        label=f"Domain password policy readable on {ip}",
                        domain="ad_lateral",
                        workload_id=f"host::{_node_key}",
                        realized=True,
                        detail=policy_detail,
                    ),
                    evidence_rank=2,
                    source_kind="ldap3",
                    pointer=f"ldap://{ip}/domainDNS",
                    confidence=0.85,
                ))
        except Exception:
            pass

    try:
        conn.unbind()
    except Exception:
        pass

    # ── Write NDJSON ──────────────────────────────────────────────────────
    if events:
        ev_file = _out_dir / f"ldap_enum_{ip.replace('.', '_')}_{run_id[:8]}.ndjson"
        ev_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        _ingest(str(ev_file), run_id, result)
        result["events_file"] = str(ev_file)

    result["success"] = True
    result["events"]  = len(events)
    result["users"]   = len(users) if "users" in dir() else 0
    return result


def _ingest(ev_file: str, run_id: str, result: dict) -> None:
    try:
        from skg.kernel.engine import SKGKernel
        kernel = SKGKernel()
        kernel.ingest_events_file(ev_file)
        result["ingested"] = True
    except Exception:
        pass

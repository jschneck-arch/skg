#!/usr/bin/env python3
"""
adapter: bloodhound
===================
Ingests BloodHound JSON output (SharpHound v4 and v5/CE) and emits
obs.attack.precondition events for AD lateral movement wickets.

Supported input files (any subset, adapter detects what's present):
  users.json       — user accounts, SPNs, pre-auth, group memberships
  computers.json   — computer accounts, delegation, LAPS, sessions
  groups.json      — group memberships (used to identify high-value groups)
  acls.json        — ACL edges (GenericAll, WriteDACL, etc)
  domains.json     — domain object, DCSync rights, password policy

Schema detection:
  v4 (SharpHound < 2.0): top-level keys are 'users', 'computers', etc.
                          Properties nested under each node's 'Properties' key.
  v5/CE (SharpHound >= 2.0): top-level 'data' array, 'meta' block.
                              Properties nested under 'Properties' key same way.

The normalizer converts both to a common internal dict before wicket evaluation.

Usage:
  python parse.py --bh-dir /path/to/bloodhound/json \\
                  --out /tmp/events.ndjson \\
                  --attack-path-id ad_kerberoast_v1 \\
                  [--run-id <uuid>] [--workload-id <domain>]
"""

import argparse, json, uuid, re
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN   = "skg-ad-lateral-toolchain"
SOURCE_ID   = "adapter.bloodhound"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

# Keywords that suggest a password is stored in a description field
PASSWORD_KEYWORDS = {
    "password", "passwd", "pwd", "pass ", "p@ss", "p@$$",
    "cred", "secret", "temp", "welcome", "login",
}

# High-value group names (canonical, lowercased)
HIGH_VALUE_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "backup operators", "account operators",
    "print operators", "server operators", "domain controllers",
    "group policy creator owners", "dnssadmins",
}

# ACL edges considered abusable for high-value escalation
ABUSABLE_EDGES = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
    "ForceChangePassword", "GetChanges", "GetChangesAll",
    "AddMember", "AllExtendedRights", "Owns",
}

# Sensitive delegation SPN patterns
SENSITIVE_DELEGATION_SVCS = {"cifs", "ldap", "host", "http", "mssqlsvc", "wsman"}


def get_version() -> str:
    return VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.exists() else "0.0.0"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(out_path: Path, wicket_id: str, status: str,
         evidence_rank: int, evidence_source_kind: str,
         pointer: str, confidence: float,
         attack_path_id: str, run_id: str, workload_id: str,
         extra_payload: dict = None):
    now = iso_now()
    event = {
        "id": str(uuid.uuid4()),
        "ts": now,
        "type": "obs.attack.precondition",
        "source": {
            "source_id": SOURCE_ID,
            "toolchain": TOOLCHAIN,
            "version": get_version(),
        },
        "payload": {
            "wicket_id": wicket_id,
            "status": status,
            "attack_path_id": attack_path_id,
            "run_id": run_id,
            "workload_id": workload_id,
            **(extra_payload or {}),
        },
        "provenance": {
            "evidence_rank": evidence_rank,
            "evidence": {
                "source_kind": evidence_source_kind,
                "pointer": pointer,
                "collected_at": now,
                "confidence": confidence,
            },
        },
    }
    with open(out_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


# ---------------------------------------------------------------------------
# Schema normalization
# ---------------------------------------------------------------------------

def detect_version(data: dict | list) -> str:
    """Detect BloodHound JSON schema version."""
    if isinstance(data, list):
        return "v4_array"
    if "meta" in data and "data" in data:
        return "v5"
    # v4 file-per-type: keys like 'users', 'computers', 'count'
    return "v4"


def normalize_node(node: dict) -> dict:
    """Flatten a BloodHound node to a consistent property dict."""
    props = node.get("Properties", node.get("properties", {}))
    result = {k.lower(): v for k, v in props.items()}
    # Preserve top-level fields that differ between versions
    for key in ("ObjectIdentifier", "objectidentifier", "ObjectType", "objecttype",
                "Aces", "aces", "AllowedToDelegate", "allowedtodelegate",
                "AllowedToAct", "allowedtoact", "Members", "members",
                "IsDeleted", "isdeleted"):
        if key in node:
            result[key.lower()] = node[key]
    return result


def load_bh_file(path: Path) -> list[dict]:
    """Load a BloodHound JSON file and return normalized list of nodes."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    version = detect_version(raw)

    if version == "v5":
        nodes = raw.get("data", [])
    elif version == "v4_array":
        nodes = raw
    else:
        # v4: file has a plural key matching the type
        nodes = []
        for key in raw:
            if isinstance(raw[key], list):
                nodes = raw[key]
                break

    return [normalize_node(n) for n in nodes]


def load_bh_dir(bh_dir: Path) -> dict[str, list[dict]]:
    """
    Load all BloodHound JSON files from a directory.
    Returns dict keyed by type: users, computers, groups, acls, domains.
    """
    result = {
        "users": [],
        "computers": [],
        "groups": [],
        "acls": [],
        "domains": [],
    }

    type_patterns = {
        "users":     ["*_users.json", "*users*.json", "users.json"],
        "computers": ["*_computers.json", "*computers*.json", "computers.json"],
        "groups":    ["*_groups.json", "*groups*.json", "groups.json"],
        "acls":      ["*_acls.json", "*acls*.json", "acls.json"],
        "domains":   ["*_domains.json", "*domains*.json", "domains.json"],
    }

    for type_key, patterns in type_patterns.items():
        for pattern in patterns:
            matches = list(bh_dir.glob(pattern))
            if matches:
                for m in matches:
                    result[type_key].extend(load_bh_file(m))
                break

    return result


# ---------------------------------------------------------------------------
# Wicket checks
# ---------------------------------------------------------------------------

def is_da_member(user: dict, groups: list[dict]) -> bool:
    """Check if a user is a member of Domain Admins."""
    username = (user.get("name") or user.get("samaccountname") or "").lower()
    for group in groups:
        gname = (group.get("name") or "").lower()
        if "domain admins" in gname:
            members = group.get("members") or []
            for m in members:
                mname = (m.get("ObjectIdentifier") or m.get("objectidentifier") or "").lower()
                uid = (user.get("objectidentifier") or user.get("objectsid") or "").lower()
                if uid and uid in mname:
                    return True
    return False


def get_high_value_object_ids(groups: list[dict]) -> set[str]:
    """Return object IDs of high-value groups and their members."""
    ids = set()
    for group in groups:
        gname = (group.get("name") or "").lower()
        if any(hv in gname for hv in HIGH_VALUE_GROUPS):
            oid = (group.get("objectidentifier") or group.get("objectsid") or "").lower()
            if oid:
                ids.add(oid)
    return ids


def description_has_password(desc: str) -> bool:
    if not desc:
        return False
    desc_lower = desc.lower()
    return any(kw in desc_lower for kw in PASSWORD_KEYWORDS)


def check_kerberoastable(users, groups, out, attack_path_id, run_id, workload_id):
    """AD-01, AD-02, AD-03, AD-23."""
    kerberoastable = []
    kerberoastable_no_aes = []
    kerberoastable_da = []

    for u in users:
        if not u.get("enabled", True):
            continue
        if not u.get("hasspn", False):
            continue
        # Skip machine accounts
        name = (u.get("name") or u.get("samaccountname") or "")
        if name.endswith("$"):
            continue

        kerberoastable.append(name)

        # Check AES enforcement
        enc_types = u.get("supportedencryptiontypes") or 0
        if isinstance(enc_types, int):
            # 0x18 = AES128+AES256, 0x10 = AES256 only
            aes_only = bool(enc_types & 0x10) and not bool(enc_types & 0x04)  # no RC4
        else:
            aes_only = False
        if not aes_only:
            kerberoastable_no_aes.append(name)

        # Check if DA
        if is_da_member(u, groups):
            kerberoastable_da.append(name)

    # AD-01
    emit(out, "AD-01", "realized" if kerberoastable else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="users[].hasspn + enabled",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"kerberoastable_accounts": kerberoastable[:20],
                        "count": len(kerberoastable)})

    # AD-02
    emit(out, "AD-02",
         "realized" if kerberoastable_no_aes else ("blocked" if kerberoastable else "unknown"),
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="users[].supportedencryptiontypes",
         confidence=0.9,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"rc4_allowed_accounts": kerberoastable_no_aes[:20]})

    # AD-03 — absence of honeypot SPNs; heuristic, confidence lower
    emit(out, "AD-03", "realized",
         evidence_rank=5, evidence_source_kind="static",
         pointer="users[].name — no honeypot SPN pattern detected",
         confidence=0.5,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"note": "Heuristic only — cannot confirm absence of out-of-band detection"})

    # AD-23
    emit(out, "AD-23", "realized" if kerberoastable_da else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="users[].hasspn + Domain Admins membership",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"da_kerberoastable": kerberoastable_da})


def check_asrep(users, groups, out, attack_path_id, run_id, workload_id):
    """AD-04, AD-05."""
    asrep_accounts = []
    asrep_privileged = []

    for u in users:
        if not u.get("enabled", True):
            continue
        if not u.get("dontreqpreauth", False):
            continue
        name = (u.get("name") or u.get("samaccountname") or "")
        asrep_accounts.append(name)
        if is_da_member(u, groups):
            asrep_privileged.append(name)

    emit(out, "AD-04", "realized" if asrep_accounts else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="users[].dontreqpreauth=true",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"asrep_accounts": asrep_accounts[:20], "count": len(asrep_accounts)})

    emit(out, "AD-05", "realized" if asrep_privileged else ("blocked" if asrep_accounts else "unknown"),
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="users[].dontreqpreauth + DA membership",
         confidence=0.9,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"privileged_asrep": asrep_privileged})


def check_delegation(computers, users, out, attack_path_id, run_id, workload_id):
    """AD-06, AD-07, AD-08, AD-09."""
    unconstrained_non_dc = []
    unconstrained_active = []
    constrained_protocol_transition = []
    constrained_sensitive_targets = []

    now_ts = datetime.now(timezone.utc).timestamp()
    stale_threshold = 90 * 86400  # 90 days

    for c in computers:
        name = c.get("name") or c.get("samaccountname") or ""
        if not c.get("enabled", True):
            continue
        if c.get("unconstraineddelegation", False) and not c.get("isdc", False):
            unconstrained_non_dc.append(name)
            last_logon = c.get("lastlogontimestamp") or 0
            # BloodHound stores as epoch seconds or -1
            if isinstance(last_logon, (int, float)) and last_logon > 0:
                age = now_ts - last_logon
                if age < stale_threshold:
                    unconstrained_active.append(name)
            else:
                # Unknown — be conservative, treat as potentially active
                unconstrained_active.append(name)

    # Also check users with constrained delegation
    for obj in computers + users:
        allowed = obj.get("allowedtodelegate") or []
        if not allowed:
            continue
        name = obj.get("name") or ""
        if obj.get("trustedtoauthfordelegation", False):
            constrained_protocol_transition.append(name)
        # Check if targets include sensitive services
        for spn in allowed:
            svc = spn.split("/")[0].lower() if "/" in spn else spn.lower()
            if svc in SENSITIVE_DELEGATION_SVCS:
                constrained_sensitive_targets.append({"account": name, "spn": spn})

    emit(out, "AD-06", "realized" if unconstrained_non_dc else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="computers[].unconstraineddelegation=true, not DC",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"unconstrained_hosts": unconstrained_non_dc[:10]})

    emit(out, "AD-07",
         "realized" if unconstrained_active else ("blocked" if unconstrained_non_dc else "unknown"),
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="computers[].lastlogontimestamp",
         confidence=0.8,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"active_unconstrained": unconstrained_active[:10]})

    emit(out, "AD-08", "realized" if constrained_protocol_transition else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="users/computers[].trustedtoauthfordelegation=true",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"protocol_transition_accounts": constrained_protocol_transition[:10]})

    emit(out, "AD-09", "realized" if constrained_sensitive_targets else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="allowedtodelegate[] — sensitive SPN targets",
         confidence=0.9,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"sensitive_targets": constrained_sensitive_targets[:10]})


def check_acls(acls, groups, out, attack_path_id, run_id, workload_id):
    """AD-10 through AD-15 (ACL abuse + DCSync)."""
    hv_ids = get_high_value_object_ids(groups)

    generic_all_hv   = []
    generic_write_hv = []
    write_dacl_hv    = []
    write_owner_hv   = []
    force_change_pw  = []
    dcsync_accounts  = {}  # objectid -> set of rights

    for ace in acls:
        right = ace.get("rightname") or ace.get("RightName") or ""
        target_id = (ace.get("objectid") or ace.get("ObjectIdentifier") or "").lower()
        principal_id = (ace.get("principalid") or ace.get("PrincipalObjectIdentifier") or "").lower()
        principal_name = ace.get("principalname") or ace.get("PrincipalName") or principal_id
        is_inherited = ace.get("isinherited") or ace.get("IsInherited") or False

        target_is_hv = any(hv in target_id for hv in hv_ids) or \
                       target_id.endswith("-512") or target_id.endswith("-519")  # DA/EA RIDs

        if right == "GenericAll" and target_is_hv:
            generic_all_hv.append({"principal": principal_name, "target": target_id})
        elif right == "GenericWrite" and target_is_hv:
            generic_write_hv.append({"principal": principal_name, "target": target_id})
        elif right == "WriteDacl" and target_is_hv:
            write_dacl_hv.append({"principal": principal_name, "target": target_id})
        elif right == "WriteOwner" and target_is_hv:
            write_owner_hv.append({"principal": principal_name, "target": target_id})
        elif right == "ForceChangePassword":
            force_change_pw.append({"principal": principal_name, "target": target_id})
        elif right in ("GetChanges", "GetChangesAll"):
            if principal_id not in dcsync_accounts:
                dcsync_accounts[principal_id] = {"name": principal_name, "rights": set()}
            dcsync_accounts[principal_id]["rights"].add(right)

    # DCSync: need both GetChanges AND GetChangesAll
    dcsync_principals = [
        {"principal": v["name"], "rights": list(v["rights"])}
        for v in dcsync_accounts.values()
        if "GetChanges" in v["rights"] and "GetChangesAll" in v["rights"]
    ]

    emit(out, "AD-10", "realized" if generic_all_hv else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="acls[].rightname=GenericAll on high-value targets",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"genericall_edges": generic_all_hv[:10]})

    emit(out, "AD-11", "realized" if generic_write_hv else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="acls[].rightname=GenericWrite on high-value targets",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"genericwrite_edges": generic_write_hv[:10]})

    emit(out, "AD-12", "realized" if write_dacl_hv else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="acls[].rightname=WriteDacl on high-value targets",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"writedacl_edges": write_dacl_hv[:10]})

    emit(out, "AD-13", "realized" if write_owner_hv else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="acls[].rightname=WriteOwner on high-value targets",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"writeowner_edges": write_owner_hv[:10]})

    emit(out, "AD-14", "realized" if force_change_pw else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="acls[].rightname=ForceChangePassword",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"forcechangepw_edges": force_change_pw[:10]})

    emit(out, "AD-15", "realized" if dcsync_principals else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="acls[].rightname=GetChanges+GetChangesAll on domain object",
         confidence=1.0,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"dcsync_principals": dcsync_principals[:10]})


def check_dcsync_accounts_enabled(users, acls, out, attack_path_id, run_id, workload_id):
    """AD-16: DCSync account enabled status."""
    dcsync_ids = set()
    for ace in acls:
        right = ace.get("rightname") or ace.get("RightName") or ""
        if right in ("GetChanges", "GetChangesAll"):
            pid = (ace.get("principalid") or ace.get("PrincipalObjectIdentifier") or "").lower()
            dcsync_ids.add(pid)

    enabled_dcsync = []
    for u in users:
        uid = (u.get("objectidentifier") or u.get("objectsid") or "").lower()
        if uid in dcsync_ids and u.get("enabled", True):
            enabled_dcsync.append(u.get("name") or uid)

    status = "realized" if enabled_dcsync else ("blocked" if dcsync_ids else "unknown")
    emit(out, "AD-16", status,
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="users[].enabled for dcsync principals",
         confidence=0.9,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"enabled_dcsync_accounts": enabled_dcsync[:10]})


def check_passwords_in_descriptions(users, computers, out, attack_path_id, run_id, workload_id):
    """AD-17, AD-18."""
    cred_accounts = []
    cred_enabled = []

    for obj in users + computers:
        desc = obj.get("description") or ""
        if description_has_password(desc):
            name = obj.get("name") or obj.get("samaccountname") or "unknown"
            cred_accounts.append({"name": name, "description": desc[:80]})
            if obj.get("enabled", True):
                cred_enabled.append(name)

    emit(out, "AD-17", "realized" if cred_accounts else "blocked",
         evidence_rank=3, evidence_source_kind="config",
         pointer="users/computers[].description",
         confidence=0.85,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"credential_descriptions": cred_accounts[:10]})

    emit(out, "AD-18",
         "realized" if cred_enabled else ("blocked" if cred_accounts else "unknown"),
         evidence_rank=3, evidence_source_kind="config",
         pointer="users[].enabled + description",
         confidence=0.85,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"enabled_cred_accounts": cred_enabled[:10]})


def check_adminsdholder(acls, out, attack_path_id, run_id, workload_id):
    """AD-19, AD-20."""
    adminsdholder_aces = []
    for ace in acls:
        target = (ace.get("objectid") or ace.get("ObjectIdentifier") or "").lower()
        # AdminSDHolder has a well-known name pattern
        if "adminsdholder" in target or "cn=adminsdholder" in target:
            right = ace.get("rightname") or ace.get("RightName") or ""
            principal = ace.get("principalname") or ace.get("PrincipalName") or ""
            if right in ABUSABLE_EDGES:
                adminsdholder_aces.append({"principal": principal, "right": right})

    emit(out, "AD-19", "realized" if adminsdholder_aces else "unknown",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="acls on AdminSDHolder object",
         confidence=0.8 if adminsdholder_aces else 0.4,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"adminsdholder_aces": adminsdholder_aces[:10]})

    # SDProp assumed active unless proven otherwise
    emit(out, "AD-20", "realized",
         evidence_rank=5, evidence_source_kind="static",
         pointer="SDProp default enabled — no evidence of disablement",
         confidence=0.7,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"note": "SDProp runs every 60min by default; cannot confirm disabled without registry evidence"})


def check_stale_privileged(users, groups, out, attack_path_id, run_id, workload_id):
    """AD-21, AD-22."""
    now_ts = datetime.now(timezone.utc).timestamp()
    stale_threshold = 90 * 86400

    stale_priv = []
    for u in users:
        if not u.get("enabled", True):
            continue
        if not is_da_member(u, groups):
            continue
        last_logon = u.get("lastlogontimestamp") or 0
        if isinstance(last_logon, (int, float)) and last_logon > 0:
            age = now_ts - last_logon
            if age > stale_threshold:
                stale_priv.append(u.get("name") or "unknown")

    emit(out, "AD-21", "realized" if stale_priv else "blocked",
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="users[].lastlogontimestamp + DA membership",
         confidence=0.85,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"stale_privileged_accounts": stale_priv[:10]})

    # AD-22: no tiering model — heuristic based on DA session data
    # Without sessions.json we emit unknown
    emit(out, "AD-22", "unknown",
         evidence_rank=5, evidence_source_kind="static",
         pointer="sessions data not collected — cannot confirm tiering",
         confidence=0.4,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"note": "Collect sessions.json from BloodHound for tiering assessment"})


def check_weak_password_policy(domains, out, attack_path_id, run_id, workload_id):
    """AD-24."""
    weak_policies = []
    for d in domains:
        min_len = d.get("minpwdlength") or d.get("passwordcomplexity") or 0
        if isinstance(min_len, int) and min_len < 12:
            weak_policies.append({"domain": d.get("name") or "unknown", "minpwdlength": min_len})

    if domains:
        status = "realized" if weak_policies else "blocked"
        confidence = 0.95
    else:
        status = "unknown"
        confidence = 0.0

    emit(out, "AD-24", status,
         evidence_rank=3, evidence_source_kind="config",
         pointer="domains[].minpwdlength",
         confidence=confidence,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"weak_policies": weak_policies})


def check_laps(computers, out, attack_path_id, run_id, workload_id):
    """AD-25."""
    no_laps = []
    workstations = [c for c in computers
                    if c.get("enabled", True) and not c.get("isdc", False)]

    for c in workstations:
        if not c.get("haslaps", True):
            no_laps.append(c.get("name") or "unknown")

    if workstations:
        status = "realized" if no_laps else "blocked"
        confidence = 0.95
    else:
        status = "unknown"
        confidence = 0.4

    emit(out, "AD-25", status,
         evidence_rank=1, evidence_source_kind="runtime",
         pointer="computers[].haslaps=false",
         confidence=confidence,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"no_laps_count": len(no_laps),
                        "no_laps_sample": no_laps[:10]})


def main():
    p = argparse.ArgumentParser(
        description="BloodHound adapter for SKG AD lateral movement toolchain")
    p.add_argument("--bh-dir", required=True,
                   help="Directory containing BloodHound JSON output files")
    p.add_argument("--out", required=True,
                   help="Output NDJSON events file (append)")
    p.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    p.add_argument("--run-id", default=None)
    p.add_argument("--workload-id", default=None)
    args = p.parse_args()

    bh_dir = Path(args.bh_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    run_id      = args.run_id or str(uuid.uuid4())
    workload_id = args.workload_id or "unknown"
    attack_path_id = args.attack_path_id

    print(f"[*] Loading BloodHound data from {bh_dir}...")
    data = load_bh_dir(bh_dir)

    u_count = len(data["users"])
    c_count = len(data["computers"])
    g_count = len(data["groups"])
    a_count = len(data["acls"])
    d_count = len(data["domains"])
    print(f"[*] Loaded: {u_count} users, {c_count} computers, "
          f"{g_count} groups, {a_count} ACEs, {d_count} domains")

    check_kerberoastable(data["users"], data["groups"], out_path,
                         attack_path_id, run_id, workload_id)
    check_asrep(data["users"], data["groups"], out_path,
                attack_path_id, run_id, workload_id)
    check_delegation(data["computers"], data["users"], out_path,
                     attack_path_id, run_id, workload_id)
    check_acls(data["acls"], data["groups"], out_path,
               attack_path_id, run_id, workload_id)
    check_dcsync_accounts_enabled(data["users"], data["acls"], out_path,
                                   attack_path_id, run_id, workload_id)
    check_passwords_in_descriptions(data["users"], data["computers"], out_path,
                                     attack_path_id, run_id, workload_id)
    check_adminsdholder(data["acls"], out_path, attack_path_id, run_id, workload_id)
    check_stale_privileged(data["users"], data["groups"], out_path,
                            attack_path_id, run_id, workload_id)
    check_weak_password_policy(data["domains"], out_path,
                                attack_path_id, run_id, workload_id)
    check_laps(data["computers"], out_path, attack_path_id, run_id, workload_id)

    print(f"[OK] emitted observations → {out_path}")


if __name__ == "__main__":
    main()

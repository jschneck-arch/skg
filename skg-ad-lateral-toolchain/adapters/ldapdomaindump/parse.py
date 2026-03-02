#!/usr/bin/env python3
"""
adapter: ldapdomaindump
========================
Ingests ldapdomaindump JSON output and emits obs.attack.precondition events.

ldapdomaindump produces these relevant files:
  domain_users.json       — user accounts
  domain_computers.json   — computer accounts
  domain_groups.json      — group memberships
  domain_policy.json      — password policy, lockout policy

Covers wickets addressable from LDAP without BloodHound ACL graph:
  AD-01, AD-02, AD-04, AD-17, AD-18, AD-24, AD-25

For full ACL coverage, pair with the bloodhound adapter.

Usage:
  python parse.py --dump-dir /path/to/ldapdomaindump/output \\
                  --out /tmp/events.ndjson \\
                  --attack-path-id ad_kerberoast_v1 \\
                  [--run-id <uuid>] [--workload-id <domain>]
"""

import argparse, json, uuid
from pathlib import Path
from datetime import datetime, timezone

TOOLCHAIN    = "skg-ad-lateral-toolchain"
SOURCE_ID    = "adapter.ldapdomaindump"
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"

PASSWORD_KEYWORDS = {
    "password", "passwd", "pwd", "pass ", "p@ss", "p@$$",
    "cred", "secret", "temp", "welcome", "login",
}


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


def load_json(path: Path) -> list | dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def get_attr(obj: dict, *keys, default=None):
    """Try multiple key names for ldapdomaindump's inconsistent casing."""
    for k in keys:
        if k in obj:
            v = obj[k]
            if isinstance(v, list) and len(v) == 1:
                return v[0]
            return v
    return default


def description_has_password(desc: str) -> bool:
    if not desc:
        return False
    return any(kw in desc.lower() for kw in PASSWORD_KEYWORDS)


def main():
    p = argparse.ArgumentParser(
        description="ldapdomaindump adapter for SKG AD lateral movement toolchain")
    p.add_argument("--dump-dir", required=True,
                   help="Directory containing ldapdomaindump JSON output")
    p.add_argument("--out", required=True)
    p.add_argument("--attack-path-id", default="ad_kerberoast_v1")
    p.add_argument("--run-id", default=None)
    p.add_argument("--workload-id", default=None)
    args = p.parse_args()

    dump_dir    = Path(args.dump_dir)
    out_path    = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    run_id      = args.run_id or str(uuid.uuid4())
    workload_id = args.workload_id or "unknown"
    attack_path_id = args.attack_path_id

    users     = load_json(dump_dir / "domain_users.json") or []
    computers = load_json(dump_dir / "domain_computers.json") or []
    policy    = load_json(dump_dir / "domain_policy.json") or {}

    kerberoastable = []
    kerberoastable_no_aes = []
    asrep_accounts = []
    cred_descriptions = []
    cred_enabled = []

    for u in users:
        attrs = u.get("attributes", u)
        sam = get_attr(attrs, "sAMAccountName", "samaccountname", default="")
        enabled_flag = get_attr(attrs, "userAccountControl", "useraccountcontrol", default=0)
        # UAC bit 2 = ACCOUNTDISABLE
        enabled = not bool(int(enabled_flag) & 0x2) if isinstance(enabled_flag, (int, str)) else True

        if not enabled:
            continue

        spn = get_attr(attrs, "servicePrincipalName", "serviceprincipalname", default=[])
        spn = spn if isinstance(spn, list) else [spn] if spn else []
        if spn and not str(sam).endswith("$"):
            kerberoastable.append(sam)
            enc = get_attr(attrs, "msDS-SupportedEncryptionTypes",
                           "msds-supportedencryptiontypes", default=0)
            try:
                enc_int = int(enc)
            except (TypeError, ValueError):
                enc_int = 0
            if not (enc_int & 0x10) or (enc_int & 0x04):
                kerberoastable_no_aes.append(sam)

        uac = int(enabled_flag) if isinstance(enabled_flag, (int, str)) else 0
        # UAC bit 22 = DONT_REQUIRE_PREAUTH (0x400000)
        if uac & 0x400000:
            asrep_accounts.append(sam)

        desc = get_attr(attrs, "description", default="")
        if description_has_password(str(desc)):
            cred_descriptions.append({"name": sam, "description": str(desc)[:80]})
            cred_enabled.append(sam)

    # AD-01
    emit(out_path, "AD-01", "realized" if kerberoastable else "blocked",
         evidence_rank=3, evidence_source_kind="config",
         pointer="domain_users.json[].servicePrincipalName",
         confidence=0.95,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"kerberoastable_accounts": kerberoastable[:20],
                        "count": len(kerberoastable)})

    # AD-02
    emit(out_path, "AD-02",
         "realized" if kerberoastable_no_aes else ("blocked" if kerberoastable else "unknown"),
         evidence_rank=3, evidence_source_kind="config",
         pointer="domain_users.json[].msDS-SupportedEncryptionTypes",
         confidence=0.9,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"rc4_allowed": kerberoastable_no_aes[:20]})

    # AD-04
    emit(out_path, "AD-04", "realized" if asrep_accounts else "blocked",
         evidence_rank=3, evidence_source_kind="config",
         pointer="domain_users.json[].userAccountControl DONT_REQUIRE_PREAUTH",
         confidence=0.95,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"asrep_accounts": asrep_accounts[:20],
                        "count": len(asrep_accounts)})

    # AD-17
    emit(out_path, "AD-17", "realized" if cred_descriptions else "blocked",
         evidence_rank=3, evidence_source_kind="config",
         pointer="domain_users.json[].description",
         confidence=0.85,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"credential_descriptions": cred_descriptions[:10]})

    # AD-18
    emit(out_path, "AD-18",
         "realized" if cred_enabled else ("blocked" if cred_descriptions else "unknown"),
         evidence_rank=3, evidence_source_kind="config",
         pointer="domain_users.json[].description + enabled status",
         confidence=0.85,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"enabled_cred_accounts": cred_enabled[:10]})

    # AD-24 — password policy
    min_len = 0
    if isinstance(policy, dict):
        attrs = policy.get("attributes", policy)
        raw = get_attr(attrs, "minPwdLength", "minpwdlength", default=0)
        try:
            min_len = int(raw)
        except (TypeError, ValueError):
            min_len = 0

    if policy:
        status = "realized" if min_len < 12 else "blocked"
        confidence = 0.95
    else:
        status = "unknown"
        confidence = 0.0

    emit(out_path, "AD-24", status,
         evidence_rank=3, evidence_source_kind="config",
         pointer="domain_policy.json.minPwdLength",
         confidence=confidence,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"minpwdlength": min_len})

    # AD-25 — LAPS via computer attributes
    no_laps = []
    for c in computers:
        attrs = c.get("attributes", c)
        laps_attr = get_attr(attrs, "ms-Mcs-AdmPwd", "ms-mcs-admpwd",
                             "msLAPS-Password", default=None)
        name = get_attr(attrs, "dNSHostName", "dnshostname",
                        "sAMAccountName", default="unknown")
        if laps_attr is None:
            no_laps.append(name)

    if computers:
        status = "realized" if no_laps else "blocked"
        confidence = 0.9
    else:
        status = "unknown"
        confidence = 0.3

    emit(out_path, "AD-25", status,
         evidence_rank=3, evidence_source_kind="config",
         pointer="domain_computers.json[].ms-Mcs-AdmPwd",
         confidence=confidence,
         attack_path_id=attack_path_id, run_id=run_id, workload_id=workload_id,
         extra_payload={"no_laps_count": len(no_laps),
                        "no_laps_sample": no_laps[:10]})

    print(f"[OK] emitted observations → {out_path}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
apply_gravity_fix.py — run as root on archbox in /opt/skg
Patches gravity_field.py, discovery.py, and collector.py in-place.
"""
import ast, sys
from pathlib import Path

SKG = Path(__file__).resolve().parent

def patch(relpath, old, new, label):
    p = SKG / relpath
    if not p.exists():
        print(f"  SKIP {label} — file not found: {p}")
        return
    src = p.read_text()
    if old not in src:
        print(f"  SKIP {label} — pattern not found (already applied?)")
        return
    p.write_text(src.replace(old, new))
    print(f"  OK   {label}")

# ── 1. load_wicket_states: add gravity_http + gravity_nmap patterns ───────
patch(
    "skg-gravity/gravity_field.py",
    '    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_pcap_{ip}_*.ndjson"):\n        _load_events_file(ef, states)',
    ('    # HTTP collector output (gravity_http_{ip}_{port}.ndjson)\n'
     '    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_http_{ip}_*.ndjson"):\n'
     '        _load_events_file(ef, states)\n'
     '    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_nmap_{ip}_*.ndjson"):\n'
     '        _load_events_file(ef, states)\n'
     '    for ef in glob.glob(f"{DISCOVERY_DIR}/gravity_pcap_{ip}_*.ndjson"):\n'
     '        _load_events_file(ef, states)'),
    "load_wicket_states: gravity_http + gravity_nmap globs"
)

# ── 2. Normalise workload_id in http_collector ────────────────────────────
patch(
    "skg-gravity/gravity_field.py",
    'workload_id=f"web::{ip}:{port}",\n                    timeout=8.0)',
    'workload_id=f"web::{ip}",\n                    timeout=8.0)',
    "http_collector: workload_id → web::{ip}"
)

# ── 3. auth_scanner: targets.yaml creds + normalise workload_id ──────────
OLD_AUTH = (
    '    for port, scheme in web_ports[:1]:\n'
    '        url = f"{scheme}://{ip}:{port}"\n'
    '        events_file = out_dir / f"gravity_auth_{ip}_{port}.ndjson"\n'
    '        try:\n'
    '            from auth_scanner import auth_scan\n'
    '            auth_scan(target=url, out_path=str(events_file),\n'
    '                      attack_path_id="web_sqli_to_shell_v1",\n'
    '                      try_defaults=True, run_id=run_id,\n'
    '                      workload_id=f"web::{ip}:{port}",\n'
    '                      timeout=10.0)\n'
    '            result["success"] = True\n'
    '        except Exception as e:\n'
    '            result["error"] = str(e)\n'
    '\n'
    '    return result'
)
NEW_AUTH = (
    '    # Load per-target web credentials from /etc/skg/targets.yaml\n'
    '    username = None\n'
    '    password = None\n'
    '    targets_file = Path("/etc/skg/targets.yaml")\n'
    '    if targets_file.exists():\n'
    '        try:\n'
    '            import yaml as _yaml\n'
    '            data = _yaml.safe_load(targets_file.read_text())\n'
    '            for t in (data or {}).get("targets", []):\n'
    '                if t.get("host") == ip or t.get("url","").find(ip) >= 0:\n'
    '                    auth = t.get("auth", {})\n'
    '                    username = auth.get("user") or t.get("web_user")\n'
    '                    password = auth.get("password") or t.get("web_password")\n'
    '                    break\n'
    '        except Exception:\n'
    '            pass\n'
    '\n'
    '    for port, scheme in web_ports[:1]:\n'
    '        url = f"{scheme}://{ip}:{port}"\n'
    '        events_file = out_dir / f"gravity_auth_{ip}_{port}.ndjson"\n'
    '        try:\n'
    '            from auth_scanner import auth_scan\n'
    '            auth_scan(target=url, out_path=str(events_file),\n'
    '                      attack_path_id="web_sqli_to_shell_v1",\n'
    '                      try_defaults=True, run_id=run_id,\n'
    '                      workload_id=f"web::{ip}",\n'
    '                      username=username,\n'
    '                      password=password,\n'
    '                      timeout=10.0)\n'
    '            result["success"] = True\n'
    '        except Exception as e:\n'
    '            result["error"] = str(e)\n'
    '\n'
    '    return result'
)
patch("skg-gravity/gravity_field.py", OLD_AUTH, NEW_AUTH,
      "auth_scanner: targets.yaml creds + web::{ip} workload_id")

# ── 4. DEFAULT_CREDS: admin:password first (DVWA) ────────────────────────
patch(
    "skg-web-toolchain/adapters/web_active/collector.py",
    '    ("admin", "admin"),\n    ("admin", "password"),',
    ('    # DVWA default — first in list\n'
     '    ("admin",         "password"),\n'
     '    ("admin",         "admin"),'),
    "DEFAULT_CREDS: admin:password first"
)

# ── 5. Syntax check ───────────────────────────────────────────────────────
print()
ok = True
for relpath in ["skg-gravity/gravity_field.py",
                "skg-web-toolchain/adapters/web_active/collector.py",
                "skg-discovery/discovery.py"]:
    p = SKG / relpath
    if not p.exists():
        continue
    try:
        ast.parse(p.read_text())
        print(f"  SYNTAX OK  {p.name}")
    except SyntaxError as e:
        print(f"  SYNTAX ERR {p.name}: line {e.lineno}: {e.msg}")
        ok = False

print()
if ok:
    print("Patches applied successfully.")
    print()
    print("Next steps:")
    print("  # Clear stale collected events so gravity recalculates E from scratch")
    print("  rm -f /var/lib/skg/discovery/gravity_http_*.ndjson")
    print("  rm -f /var/lib/skg/discovery/gravity_auth_*.ndjson")
    print()
    print("  # Rediscover with full port scan (finds TV, PS5, phone, etc.)")
    print("  python /opt/skg/skg-discovery/discovery.py \\")
    print("    --auto --docker --out-dir /var/lib/skg/discovery")
    print()
    print("  # Run gravity — E should now drop as events are ingested")
    print("  skg gravity --cycles 5")
else:
    print("Patch failed — syntax errors above. Do not run gravity.")
    sys.exit(1)

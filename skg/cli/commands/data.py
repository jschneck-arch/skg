from __future__ import annotations
import json, sys
from pathlib import Path
from skg.cli.utils import SKG_HOME, DISCOVERY_DIR


def cmd_data(a):
    """
    Data pipeline integrity — profile database tables against declared contracts.

    Applies the same substrate physics as security:
      DP-01..DP-15 are wickets. E = unknown wickets. Gravity directs the
      profiler toward highest-entropy pipeline stages. Failure paths are
      projections — not rules, not scores, not static checklists.

    Works against any SQLAlchemy-compatible database:
      PostgreSQL, MySQL, SQLite, and more.
    """
    subcmd = getattr(a, "data_cmd", "profile")
    sys.path.insert(0, str(SKG_HOME / "skg-data-toolchain"))

    if subcmd == "profile":
        if not a.url or not a.table:
            print("  Usage: skg data profile --url <db_url> --table <table>")
            print("  Example: skg data profile --url sqlite:///mydb.db --table orders")
            return

        from adapters.db_profiler.profile import profile_table
        workload_id = getattr(a, "workload_id", None) or f"data::{a.table}"
        contract    = getattr(a, "contract", None)
        apid        = getattr(a, "attack_path_id", "data_completeness_failure_v1")

        print(f"\n  Profiling {a.table} @ {a.url[:40]}...")
        events = profile_table(
            url=a.url, table=a.table,
            workload_id=workload_id,
            contract_path=contract,
            attack_path_id=apid,
        )

        out = getattr(a, "out", None) or \
              str(DISCOVERY_DIR / f"data_{a.table}_{events[0]['payload']['run_id'] if events else 'x'}.ndjson")
        DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

        r = sum(1 for e in events if e["payload"]["status"] == "realized")
        b = sum(1 for e in events if e["payload"]["status"] == "blocked")
        u = sum(1 for e in events if e["payload"]["status"] == "unknown")
        print(f"\n  {len(events)} wicket events: {r}R {b}B {u}U → {out}")

        if b > 0:
            print(f"\n  Blocked conditions (definite failures):")
            for ev in events:
                if ev["payload"]["status"] == "blocked":
                    print(f"    ✗ {ev['payload']['wicket_id']:6s}  {ev['payload']['detail'][:80]}")

        print(f"\n  Run gravity to update field energy:")
        print(f"    skg gravity --cycles 1")
        print(f"  Or project directly:")
        print(f"    skg data project --in {out} --path-id {apid}")

    elif subcmd == "project":
        if not a.infile or not a.path_id:
            print("  Usage: skg data project --in <events.ndjson> --path-id <path_id>")
            return

        from projections.data.run import compute_data_score
        catalog_file = (SKG_HOME / "skg-data-toolchain" / "contracts" / "catalogs" /
                        "attack_preconditions_catalog.data.v1.json")
        if not catalog_file.exists():
            print(f"  Catalog not found: {catalog_file}")
            return

        catalog = json.loads(catalog_file.read_text())
        events = []
        for line in Path(a.infile).read_text().splitlines():
            if line.strip():
                try: events.append(json.loads(line))
                except: pass

        result = compute_data_score(events, catalog, a.path_id)
        if not result:
            print(f"  Unknown path_id: {a.path_id}")
            print(f"  Available: {list(catalog.get('attack_paths', {}).keys())}")
            return

        p = result["payload"]
        cls = p["classification"]
        marker = "✓" if cls == "realized" else ("✗" if cls == "not_realized" else "?")
        print(f"\n  {marker} {p['attack_path_id']}")
        print(f"  Classification : {cls}")
        print(f"  Interpretation : {p['interpretation']}")
        print(f"  Score          : {p['data_score']:.0%}")
        print(f"  Realized  ({len(p['realized'])}): {p['realized']}")
        print(f"  Blocked   ({len(p['blocked'])}): {p['blocked']}")
        print(f"  Unknown   ({len(p['unknown'])}): {p['unknown']}")

    elif subcmd == "paths":
        catalog_file = (SKG_HOME / "skg-data-toolchain" / "contracts" / "catalogs" /
                        "attack_preconditions_catalog.data.v1.json")
        if not catalog_file.exists():
            print("  Catalog not found. Run setup_arch.sh first.")
            return
        catalog = json.loads(catalog_file.read_text())
        print(f"\n  Data pipeline failure paths:\n")
        for pid, path in catalog.get("attack_paths", {}).items():
            print(f"  {pid}")
            print(f"    {path['description']}")
            print(f"    required: {path['required_wickets']}")
            print(f"    domains:  {', '.join(path.get('domains', []))}")
            print()

    elif subcmd == "catalog":
        catalog_file = (SKG_HOME / "skg-data-toolchain" / "contracts" / "catalogs" /
                        "attack_preconditions_catalog.data.v1.json")
        if catalog_file.exists():
            print(catalog_file.read_text())
        else:
            print("  Catalog not found.")

    elif subcmd == "discover":
        if not a.host or not a.user:
            print("  Usage: skg data discover --host <ip> --user <user> [--password <pw>]")
            return

        sys.path.insert(0, str(SKG_HOME / "skg-data-toolchain"))
        try:
            from adapters.db_discovery.parse import run_with_profiling
        except ImportError as exc:
            print(f"  db_discovery adapter not found: {exc}")
            return

        workload_id  = getattr(a, "workload_id", None) or f"db::{a.host}"
        profile_tbls = None
        if getattr(a, "tables", None):
            profile_tbls = [t.strip() for t in a.tables.split(",") if t.strip()]
        out_dir = Path(getattr(a, "out_dir", None) or DISCOVERY_DIR)
        out_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n  Discovering databases on {a.host}...")
        de_events, dp_events = run_with_profiling(
            host=a.host,
            ssh_port=getattr(a, "ssh_port", 22),
            user=a.user,
            password=getattr(a, "password", None),
            key=getattr(a, "key", None),
            workload_id=workload_id,
            profile_tables=profile_tbls,
        )

        def _counts(evs):
            r = sum(1 for e in evs if e["payload"]["status"] == "realized")
            b = sum(1 for e in evs if e["payload"]["status"] == "blocked")
            u = sum(1 for e in evs if e["payload"]["status"] == "unknown")
            return r, b, u

        if de_events:
            de_file = out_dir / f"db_discovery_{a.host.replace('.','_')}.ndjson"
            with de_file.open("w") as fh:
                for ev in de_events: fh.write(json.dumps(ev) + "\n")
            r, b, u = _counts(de_events)
            print(f"\n  Security surface (DE-*): {len(de_events)} events  {r}R {b}B {u}U")
            if b:
                print(f"  Findings:")
                for ev in de_events:
                    if ev["payload"]["status"] == "realized":
                        print(f"    ✓ {ev['payload']['wicket_id']:6s}  {ev['payload']['detail'][:80]}")
                    elif ev["payload"]["status"] == "blocked":
                        print(f"    ✗ {ev['payload']['wicket_id']:6s}  {ev['payload']['detail'][:80]}")
            print(f"  Events: {de_file}")
        else:
            print(f"\n  No DE-* events — SSH connection failed or no DB services found")

        if dp_events:
            dp_file = out_dir / f"db_profile_{a.host.replace('.','_')}.ndjson"
            with dp_file.open("w") as fh:
                for ev in dp_events: fh.write(json.dumps(ev) + "\n")
            r, b, u = _counts(dp_events)
            print(f"\n  Data quality (DP-*): {len(dp_events)} events  {r}R {b}B {u}U")
            if b:
                print(f"  Violations:")
                for ev in dp_events:
                    if ev["payload"]["status"] == "blocked":
                        print(f"    ✗ {ev['payload']['wicket_id']:6s}  {ev['payload']['workload_id']}: {ev['payload']['detail'][:70]}")
            print(f"  Events: {dp_file}")
        elif de_events:
            print(f"\n  No DP-* profiling ran (no working DB auth or pymysql not installed)")

    else:
        print("  Usage: skg data [profile|project|paths|catalog|discover]")

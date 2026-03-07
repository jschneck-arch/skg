"""
skg.resonance.cli
=================
CLI for the resonance engine. Used both standalone and as a subcommand
via the main skg CLI.

Commands:
  status                   — show engine status, memory counts
  ingest                   — ingest all toolchains into memory
  query  <text>            — query memory for similar records
  draft  <domain> <desc>   — propose a new domain catalog
  drafts                   — list pending drafts
"""

from __future__ import annotations
import argparse, json, sys
from pathlib import Path


def _get_engine(resonance_dir: Path):
    from skg.resonance.engine import ResonanceEngine
    engine = ResonanceEngine(resonance_dir)
    engine.boot()
    return engine


def cmd_status(args):
    from skg.core.paths import RESONANCE_DIR
    engine = _get_engine(RESONANCE_DIR)
    print(json.dumps(engine.status(), indent=2))


def cmd_ingest(args):
    from skg.core.paths import RESONANCE_DIR, SKG_HOME
    from skg.resonance.ingester import ingest_all
    engine = _get_engine(RESONANCE_DIR)
    summary = ingest_all(engine, SKG_HOME)
    print(json.dumps(summary, indent=2))


def cmd_query(args):
    from skg.core.paths import RESONANCE_DIR
    engine = _get_engine(RESONANCE_DIR)
    k = args.k or 5

    if args.type in ("wickets", "all"):
        results = engine.query_wickets(args.text, k=k)
        print(f"\n=== Wickets (top {len(results)}) ===")
        for rec, score in results:
            print(f"  [{score:.3f}] {rec.record_id}")
            print(f"    {rec.label}")
            print(f"    {rec.description[:80]}")

    if args.type in ("adapters", "all"):
        results = engine.query_adapters(args.text, k=k)
        print(f"\n=== Adapters (top {len(results)}) ===")
        for rec, score in results:
            print(f"  [{score:.3f}] {rec.record_id}")
            sources = "; ".join(rec.evidence_sources[:2])
            print(f"    {sources}")

    if args.type in ("domains", "all"):
        results = engine.query_domains(args.text, k=min(k, 3))
        print(f"\n=== Domains (top {len(results)}) ===")
        for rec, score in results:
            print(f"  [{score:.3f}] {rec.domain} — {rec.description[:80]}")


def cmd_draft(args):
    from skg.core.paths import RESONANCE_DIR
    from skg.resonance.drafter import draft_catalog
    engine = _get_engine(RESONANCE_DIR)

    print(f"[*] Drafting catalog for: {args.domain}")
    print(f"[*] Description: {args.description}")
    print(f"[*] Surfacing memory context...")

    result = draft_catalog(engine, args.domain, args.description,
                           api_key=args.api_key)

    errors = result["validation_errors"]
    if errors:
        print(f"\n[WARN] Validation issues ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
    else:
        print("\n[OK] Draft passed validation")

    print(f"\n[*] Context used:")
    ctx = result["context_used"]
    print(f"    {ctx['wickets_surfaced']} wickets, "
          f"{ctx['adapters_surfaced']} adapters, "
          f"{ctx['domains_surfaced']} domains surfaced")

    print(f"\n[*] Draft saved: {result['draft_path']}")
    print(f"\n[*] Wickets proposed: "
          f"{len(result['catalog'].get('wickets', {}))}")
    print(f"[*] Attack paths proposed: "
          f"{len(result['catalog'].get('attack_paths', {}))}")
    print("\n[*] Review draft at:")
    print(f"    {result['draft_path']}")
    print("\n[*] To promote to a toolchain, copy catalog to:")
    print(f"    /opt/skg/skg-{args.domain}-toolchain/contracts/catalogs/")


def cmd_drafts(args):
    from skg.core.paths import RESONANCE_DIR
    engine = _get_engine(RESONANCE_DIR)
    drafts = engine.list_drafts()
    if not drafts:
        print("No pending drafts.")
        return
    print(f"{len(drafts)} pending draft(s):\n")
    for d in drafts:
        meta = d.get("meta", {})
        print(f"  {d['file']}")
        print(f"    domain: {meta.get('domain', '?')}")
        print(f"    drafted: {meta.get('drafted_at', '?')}")
        print(f"    status: {meta.get('status', '?')}")
        print()


def main():
    p = argparse.ArgumentParser(description="SKG resonance engine CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Show engine status and memory counts")

    sub.add_parser("ingest", help="Ingest all toolchains into memory")

    pq = sub.add_parser("query", help="Query memory for similar records")
    pq.add_argument("text", help="Query text")
    pq.add_argument("--type", default="all",
                    choices=["all", "wickets", "adapters", "domains"])
    pq.add_argument("--k", type=int, default=5, help="Results per type")

    pd = sub.add_parser("draft", help="Propose a catalog for a new domain")
    pd.add_argument("domain",      help="Domain name (e.g. aws_privesc)")
    pd.add_argument("description", help="What this domain covers")
    pd.add_argument("--api-key",   default=None, help="Anthropic API key")

    sub.add_parser("drafts", help="List pending drafts")

    args = p.parse_args()

    dispatch = {
        "status":  cmd_status,
        "ingest":  cmd_ingest,
        "query":   cmd_query,
        "draft":   cmd_draft,
        "drafts":  cmd_drafts,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()

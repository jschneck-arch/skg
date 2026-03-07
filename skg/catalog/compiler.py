"""
skg.catalog.compiler
====================
Compiles YAML catalog definitions to the JSON format consumed
by toolchain projectors.

CLI:
  python -m skg.catalog.compiler compile <yaml_file> [--out <dir>]
  python -m skg.catalog.compiler validate <yaml_file>
  python -m skg.catalog.compiler scaffold <domain_name> [--out <file>]
  python -m skg.catalog.compiler lint <catalog_json>

Also callable from `skg catalog` CLI subcommand.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# YAML optional — degrade gracefully
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ── Schema ────────────────────────────────────────────────────────────────────

REQUIRED_WICKET_FIELDS   = {"id", "label", "description", "evidence_hint"}
REQUIRED_PATH_FIELDS     = {"id", "description", "required_wickets"}
REQUIRED_CATALOG_FIELDS  = {"version", "domain", "description", "wickets", "attack_paths"}

CATALOG_JSON_SCHEMA = {
    "version": str,
    "description": str,
    "wickets": dict,       # id → wicket dict
    "attack_paths": dict,  # id → path dict
}

SCAFFOLD_TEMPLATE = """\
# SKG Attack Precondition Catalog
# Domain: {domain}
# Generated: {ts}
#
# Edit this file, then run:
#   skg catalog compile {domain}.yaml
#
version: "1.0.0"
domain: {domain}
description: >
  Describe what this domain detects and the threat model it covers.

wickets:
  - id: {prefix}-01
    label: example_wicket_one
    description: "The target exhibits condition X."
    evidence_hint: "Evidence rank min: 1 (runtime)"
    # notes: Optional operator notes (not included in compiled output)

  - id: {prefix}-02
    label: example_wicket_two
    description: "The target exhibits condition Y."
    evidence_hint: "Evidence rank min: 3 (config/filesystem)"

  - id: {prefix}-03
    label: example_wicket_three
    description: "The target exhibits condition Z."
    evidence_hint: "Evidence rank min: 4 (network)"

attack_paths:
  - id: {domain}_attack_v1
    description: "Full attack chain via conditions X, Y, Z"
    required_wickets:
      - {prefix}-01
      - {prefix}-02
      - {prefix}-03
    references:
      - https://attack.mitre.org/techniques/TXXXX/
      # - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXX
"""


# ── Validation ────────────────────────────────────────────────────────────────

class ValidationError(Exception):
    pass


def validate_yaml_catalog(data: dict) -> list[str]:
    """
    Validate a parsed YAML catalog dict.
    Returns list of error strings (empty = valid).
    """
    errors = []

    for field in REQUIRED_CATALOG_FIELDS:
        if field not in data:
            errors.append(f"Missing required top-level field: '{field}'")

    if "wickets" not in data:
        return errors  # Can't validate further

    wickets = data["wickets"]
    paths   = data.get("attack_paths", [])

    if not isinstance(wickets, list):
        errors.append("'wickets' must be a list")
        return errors

    wicket_ids = set()
    for i, w in enumerate(wickets):
        if not isinstance(w, dict):
            errors.append(f"wickets[{i}] is not a dict")
            continue
        for field in REQUIRED_WICKET_FIELDS:
            if field not in w:
                errors.append(f"wickets[{i}] missing field '{field}'")
        wid = w.get("id", f"[{i}]")
        if wid in wicket_ids:
            errors.append(f"Duplicate wicket id: '{wid}'")
        wicket_ids.add(wid)

    if not isinstance(paths, list):
        errors.append("'attack_paths' must be a list")
        return errors

    path_ids = set()
    for i, p in enumerate(paths):
        if not isinstance(p, dict):
            errors.append(f"attack_paths[{i}] is not a dict")
            continue
        for field in REQUIRED_PATH_FIELDS:
            if field not in p:
                errors.append(f"attack_paths[{i}] missing field '{field}'")
        pid = p.get("id", f"[{i}]")
        if pid in path_ids:
            errors.append(f"Duplicate path id: '{pid}'")
        path_ids.add(pid)

        # Validate wicket references
        for wid in p.get("required_wickets", []):
            if wid not in wicket_ids:
                errors.append(f"attack_paths[{pid}]: references unknown wicket '{wid}'")

    # Warn on orphaned wickets (not referenced in any path)
    referenced = set(
        wid
        for p in paths
        for wid in p.get("required_wickets", [])
    )
    orphans = wicket_ids - referenced
    if orphans:
        errors.append(f"Warning: orphaned wickets not in any attack path: {sorted(orphans)}")

    return errors


# ── Compilation ───────────────────────────────────────────────────────────────

def compile_yaml_to_json(yaml_path: Path) -> dict:
    """
    Parse and compile a YAML catalog file to catalog JSON dict.
    Raises ValidationError if the source is invalid.
    """
    if not HAS_YAML:
        raise ImportError("PyYAML is required: pip install pyyaml")

    with yaml_path.open() as fh:
        data = yaml.safe_load(fh)

    errors = validate_yaml_catalog(data)
    hard_errors = [e for e in errors if not e.startswith("Warning:")]
    if hard_errors:
        raise ValidationError("\n".join(hard_errors))

    # Build wickets dict (list → keyed by id)
    wickets: dict[str, dict] = {}
    for w in data["wickets"]:
        wid = w["id"]
        wickets[wid] = {
            "id":            wid,
            "label":         w["label"],
            "description":   w["description"],
            "evidence_hint": w["evidence_hint"],
        }

    # Build attack_paths dict
    attack_paths: dict[str, dict] = {}
    for p in data["attack_paths"]:
        pid = p["id"]
        attack_paths[pid] = {
            "id":               pid,
            "description":      p["description"],
            "required_wickets": list(p["required_wickets"]),
            "references":       list(p.get("references", [])),
        }

    catalog = {
        "version":      data["version"],
        "description":  data["description"].strip() if isinstance(data["description"], str) else data["description"],
        "domain":       data.get("domain", yaml_path.stem),
        "compiled_at":  datetime.now(timezone.utc).isoformat(),
        "wickets":      wickets,
        "attack_paths": attack_paths,
    }

    # Surface warnings
    warnings = [e for e in errors if e.startswith("Warning:")]
    if warnings:
        for w in warnings:
            print(f"  {w}", file=sys.stderr)

    return catalog


def compile_file(yaml_path: Path, out_dir: Path | None = None) -> Path:
    """
    Compile a YAML catalog to JSON and write to out_dir (or alongside yaml_path).
    Returns path to written JSON file.
    """
    catalog = compile_yaml_to_json(yaml_path)
    if out_dir is None:
        out_dir = yaml_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    domain   = catalog.get("domain", yaml_path.stem)
    out_path = out_dir / f"attack_preconditions_catalog.v1.{domain}.json"
    out_path.write_text(json.dumps(catalog, indent=2))
    return out_path


def scaffold(domain_name: str) -> str:
    """Generate a YAML scaffold for a new domain."""
    # Derive 2-4 char prefix from domain name
    parts = domain_name.replace("-", "_").split("_")
    prefix = "".join(p[0].upper() for p in parts if p)[:4]
    if len(prefix) < 2:
        prefix = domain_name[:2].upper()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return SCAFFOLD_TEMPLATE.format(domain=domain_name, prefix=prefix, ts=ts)


def lint_json(json_path: Path) -> list[str]:
    """Validate an existing catalog JSON file."""
    data = json.loads(json_path.read_text())
    errors = []
    for field in ("version", "description", "wickets", "attack_paths"):
        if field not in data:
            errors.append(f"Missing field: '{field}'")
    if "wickets" in data and isinstance(data["wickets"], dict):
        wicket_ids = set(data["wickets"].keys())
        for pid, path in (data.get("attack_paths") or {}).items():
            for wid in path.get("required_wickets", []):
                if wid not in wicket_ids:
                    errors.append(f"path '{pid}' references unknown wicket '{wid}'")
    return errors


# ── CLI entry point ───────────────────────────────────────────────────────────

def main(argv: list[str] | None = None):
    import argparse
    parser = argparse.ArgumentParser(
        prog="skg catalog",
        description="Compile YAML catalog definitions to JSON"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_compile = sub.add_parser("compile", help="Compile YAML → JSON")
    p_compile.add_argument("yaml_file")
    p_compile.add_argument("--out", help="Output directory")

    p_validate = sub.add_parser("validate", help="Validate YAML catalog (no output)")
    p_validate.add_argument("yaml_file")

    p_scaffold = sub.add_parser("scaffold", help="Generate YAML template")
    p_scaffold.add_argument("domain")
    p_scaffold.add_argument("--out", help="Output file (default: <domain>.yaml)")

    p_lint = sub.add_parser("lint", help="Lint an existing catalog JSON")
    p_lint.add_argument("catalog_json")

    args = parser.parse_args(argv)

    if args.cmd == "compile":
        yaml_path = Path(args.yaml_file)
        out_dir   = Path(args.out) if args.out else None
        try:
            out = compile_file(yaml_path, out_dir)
            print(f"✓ Compiled: {out}")
        except (ValidationError, ImportError) as exc:
            print(f"✗ {exc}", file=sys.stderr)
            sys.exit(1)

    elif args.cmd == "validate":
        if not HAS_YAML:
            print("PyYAML required", file=sys.stderr)
            sys.exit(1)
        with Path(args.yaml_file).open() as fh:
            data = yaml.safe_load(fh)
        errors = validate_yaml_catalog(data)
        hard = [e for e in errors if not e.startswith("Warning:")]
        for e in errors:
            print(("⚠ " if e.startswith("Warning:") else "✗ ") + e)
        if not hard:
            print("✓ Valid")
        else:
            sys.exit(1)

    elif args.cmd == "scaffold":
        text = scaffold(args.domain)
        out  = Path(args.out) if args.out else Path(f"{args.domain}.yaml")
        out.write_text(text)
        print(f"✓ Scaffold written: {out}")
        print(f"  Edit {out}, then: skg catalog compile {out}")

    elif args.cmd == "lint":
        errors = lint_json(Path(args.catalog_json))
        if errors:
            for e in errors:
                print(f"✗ {e}")
            sys.exit(1)
        else:
            print("✓ Catalog JSON is valid")


if __name__ == "__main__":
    main()

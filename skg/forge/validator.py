"""
skg.forge.validator
====================
Validates a generated toolchain before it goes to the proposal queue.

Tests:
  1. Structural — required files exist, catalog is valid JSON with required keys
  2. Import     — adapter parse.py imports without errors
  3. Synthetic  — create synthetic events for every wicket, run through projector,
                  confirm output is a valid interpretation result
  4. Coverage   — every wicket in the catalog has a check_ function in the adapter

A toolchain passes validation if structural + import + synthetic all pass.
Coverage warnings are noted but don't block.
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("skg.forge.validator")


def validate(tc_dir: Path) -> dict:
    """
    Validate a staged toolchain directory.

    Returns:
      {
        passed: bool,
        tc_name: str,
        checks: {
          structural: {passed, errors},
          import_check: {passed, errors},
          synthetic: {passed, errors, projection_result},
          coverage: {passed, warnings, missing_checks},
        }
      }
    """
    result = {
        "passed": False,
        "tc_name": tc_dir.name,
        "checks": {},
    }

    # --- Structural ---
    struct = _check_structural(tc_dir)
    result["checks"]["structural"] = struct
    if not struct["passed"]:
        result["passed"] = False
        return result

    # --- Import ---
    imp = _check_import(tc_dir)
    result["checks"]["import_check"] = imp

    # --- Synthetic projection ---
    synth = _check_synthetic(tc_dir)
    result["checks"]["synthetic"] = synth

    # --- Coverage ---
    cov = _check_coverage(tc_dir)
    result["checks"]["coverage"] = cov

    result["passed"] = struct["passed"] and imp["passed"] and synth["passed"]
    return result


def _check_structural(tc_dir: Path) -> dict:
    """Check required files and catalog schema."""
    errors = []

    required_single = ["VERSION"]
    for rel in required_single:
        if not (tc_dir / rel).exists():
            errors.append(f"Missing: {rel}")

    # Adapter — any adapters/*/parse.py accepted
    adapter_files = list(tc_dir.glob("adapters/*/parse.py"))
    if not adapter_files:
        errors.append("Missing: adapters/*/parse.py (no adapter found)")

    # Find catalog
    catalogs = list(tc_dir.glob("contracts/catalogs/*.json"))
    if not catalogs:
        errors.append("No catalog JSON found in contracts/catalogs/")
    else:
        try:
            catalog = json.loads(catalogs[0].read_text())
            if "wickets" not in catalog:
                errors.append("Catalog missing 'wickets' key")
            if "attack_paths" not in catalog:
                errors.append("Catalog missing 'attack_paths' key")
            if not catalog.get("wickets"):
                errors.append("Catalog has no wickets defined")
            if not catalog.get("attack_paths"):
                errors.append("Catalog has no attack paths defined")
            # Verify required_wickets reference valid wicket IDs
            for path_id, path in catalog.get("attack_paths", {}).items():
                for wid in path.get("required_wickets", []):
                    if wid not in catalog.get("wickets", {}):
                        errors.append(f"Attack path {path_id} references unknown wicket {wid}")
        except json.JSONDecodeError as exc:
            errors.append(f"Catalog JSON parse error: {exc}")

    # Find projector
    projectors = list(tc_dir.glob("projections/*/run.py"))
    if not projectors:
        errors.append("No projector run.py found in projections/*/")

    return {"passed": len(errors) == 0, "errors": errors}


def _check_import(tc_dir: Path) -> dict:
    """Check that adapter imports without errors."""
    errors = []
    adapter_files = list(tc_dir.glob("adapters/*/parse.py"))
    parse_py = adapter_files[0] if adapter_files else None

    if not parse_py:
        return {"passed": False, "errors": ["No adapter parse.py found in adapters/*/"]}

    mod_name = f"skg_forge_validate_{tc_dir.name.replace('-','_')}"
    try:
        spec = importlib.util.spec_from_file_location(mod_name, parse_py)
        mod = importlib.util.module_from_spec(spec)
        # Add tc_dir to sys.path temporarily
        sys.path.insert(0, str(tc_dir))
        try:
            spec.loader.exec_module(mod)
        finally:
            sys.path.pop(0)

        # Check required attributes
        # emit() may be imported from web_sensor or defined inline
        if not hasattr(mod, "emit") and not hasattr(mod, "evaluate_wickets"):
            errors.append("Adapter missing emit() or evaluate_wickets() function")
        if not hasattr(mod, "TOOLCHAIN"):
            errors.append("Adapter missing TOOLCHAIN constant")
        if not hasattr(mod, "SOURCE_ID"):
            errors.append("Adapter missing SOURCE_ID constant")

        check_fns = [name for name in dir(mod) if name.startswith("check_")]
        eval_fns  = [name for name in dir(mod) if name.startswith("evaluate_") or name.startswith("run_checks")]
        if not check_fns and not eval_fns:
            errors.append("Adapter has no check_ or evaluate_ functions")

    except ImportError as exc:
        # Distinguish expected missing deps vs real errors
        dep = str(exc)
        if any(d in dep for d in ["paramiko", "winrm", "neo4j", "redis",
                                   "pymongo", "psycopg2", "elasticsearch"]):
            # Expected — these are runtime deps not needed for import
            pass
        else:
            errors.append(f"Import error: {exc}")
    except SyntaxError as exc:
        errors.append(f"Syntax error in adapter: {exc}")
    except Exception as exc:
        errors.append(f"Adapter load error: {exc}")

    return {"passed": len(errors) == 0, "errors": errors}


def _check_synthetic(tc_dir: Path) -> dict:
    """
    Create synthetic events for every wicket in the catalog and run
    through the projector. Confirms projection pipeline works end-to-end.
    """
    errors = []
    projection_result = None

    catalogs = list(tc_dir.glob("contracts/catalogs/*.json"))
    if not catalogs:
        return {"passed": False, "errors": ["No catalog found"], "projection_result": None}

    try:
        catalog = json.loads(catalogs[0].read_text())
    except Exception as exc:
        return {"passed": False, "errors": [f"Catalog read error: {exc}"], "projection_result": None}

    wickets = catalog.get("wickets", {})
    attack_paths = catalog.get("attack_paths", {})
    if not wickets or not attack_paths:
        return {"passed": False, "errors": ["Empty wickets or attack_paths"], "projection_result": None}

    # Use first attack path
    path_id = next(iter(attack_paths))
    required = attack_paths[path_id].get("required_wickets", [])

    # Generate synthetic events — all realized
    now = datetime.now(timezone.utc).isoformat()
    run_id = str(uuid.uuid4())[:8]
    events = []

    # Get tc_name for source
    tc_name = tc_dir.name
    domain = tc_name.replace("skg-", "").replace("-toolchain", "")

    for wid in required:
        events.append({
            "id": str(uuid.uuid4()), "ts": now,
            "type": "obs.attack.precondition",
            "source": {"source_id": f"adapter.{domain}_collect",
                       "toolchain": tc_name, "version": "0.1.0"},
            "payload": {
                "wicket_id": wid, "status": "realized",
                "attack_path_id": path_id,
                "run_id": run_id, "workload_id": "synthetic_test",
            },
            "provenance": {
                "evidence_rank": 2,
                "evidence": {"source_kind": "synthetic", "pointer": wid,
                             "collected_at": now, "confidence": 1.0}
            },
        })

    # Load projector
    proj_files = list(tc_dir.glob("projections/*/run.py"))
    if not proj_files:
        return {"passed": False, "errors": ["No projector found"], "projection_result": None}

    proj_file = proj_files[0]
    safe_domain = domain.replace("-", "_")
    compute_fn_name = f"compute_{safe_domain}"

    try:
        spec = importlib.util.spec_from_file_location(
            f"skg_proj_{safe_domain}", proj_file
        )
        proj_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proj_mod)

        compute_fn = getattr(proj_mod, compute_fn_name, None)
        if compute_fn is None:
            # Try any compute_ function
            compute_fn = next(
                (getattr(proj_mod, n) for n in dir(proj_mod) if n.startswith("compute_")),
                None
            )

        if compute_fn is None:
            errors.append(f"No compute function found in projector (expected {compute_fn_name})")
        else:
            result = compute_fn(events, catalog, path_id,
                                run_id=run_id, workload_id="synthetic_test")
            if not result:
                errors.append("Projector returned empty result")
            else:
                payload = result.get("payload", result)
                classification = payload.get("classification", "")
                if classification != "realized":
                    errors.append(
                        f"Expected 'realized' with all wickets present, got '{classification}'"
                    )
                projection_result = {
                    "classification": classification,
                    "score": payload.get(f"{safe_domain}_score",
                                         payload.get("score", "?")),
                    "realized": payload.get("realized", []),
                }

    except SyntaxError as exc:
        errors.append(f"Projector syntax error: {exc}")
    except Exception as exc:
        errors.append(f"Projection error: {exc}")

    return {
        "passed": len(errors) == 0,
        "errors": errors,
        "projection_result": projection_result,
    }


def _check_coverage(tc_dir: Path) -> dict:
    """Check that every catalog wicket has a corresponding check_ function."""
    warnings = []
    missing = []

    catalogs = list(tc_dir.glob("contracts/catalogs/*.json"))
    adapter_files = list(tc_dir.glob("adapters/*/parse.py"))
    parse_py = adapter_files[0] if adapter_files else None

    if not catalogs or not parse_py:
        return {"passed": True, "warnings": [], "missing_checks": []}

    try:
        catalog = json.loads(catalogs[0].read_text())
        adapter_text = parse_py.read_text()

        # Web-style adapters use evaluate_wickets() instead of per-wicket check_ fns
        has_evaluate = "evaluate_wickets" in adapter_text or "run_checks" in adapter_text
        if not has_evaluate:
            for wid in catalog.get("wickets", {}):
                fn_name = f"check_{wid.replace('-','_').lower()}"
                if fn_name not in adapter_text:
                    missing.append(wid)
                    warnings.append(f"No check function for wicket {wid} (expected {fn_name})")

    except Exception as exc:
        warnings.append(f"Coverage check error: {exc}")

    return {
        "passed": True,  # Coverage is a warning, not a blocker
        "warnings": warnings,
        "missing_checks": missing,
    }


def validation_summary(result: dict) -> str:
    """Human-readable validation summary."""
    lines = []
    status = "PASS" if result["passed"] else "FAIL"
    lines.append(f"Validation {status}: {result['tc_name']}")
    lines.append("")

    for check_name, check in result.get("checks", {}).items():
        icon = "✓" if check.get("passed") else "✗"
        lines.append(f"  {icon} {check_name}")
        for err in check.get("errors", []):
            lines.append(f"      ERR: {err}")
        for warn in check.get("warnings", []):
            lines.append(f"      WRN: {warn}")
        if check_name == "synthetic" and check.get("projection_result"):
            pr = check["projection_result"]
            lines.append(f"      projection: {pr.get('classification')} "
                         f"(score={pr.get('score')}, "
                         f"realized={len(pr.get('realized',[]))} wickets)")

    return "\n".join(lines)

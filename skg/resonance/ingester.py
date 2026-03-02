"""
skg.resonance.ingester
======================
Walks existing SKG toolchains and populates the resonance engine
with WicketMemory, AdapterMemory, and DomainMemory records.

Called by the daemon on boot (if memory is empty) and available
as a CLI command to force re-ingestion.

Toolchain discovery is automatic — any directory under SKG_HOME
matching the pattern skg-*-toolchain/ with a contracts/catalogs/
directory is ingested.

Adapter discovery reads the adapters/ subdirectory and extracts
evidence source metadata from the adapter parse.py docstrings.
"""

from __future__ import annotations
import json, logging, re
from pathlib import Path

from skg.resonance.memory import WicketMemory, AdapterMemory, DomainMemory
from skg.resonance.engine import ResonanceEngine

log = logging.getLogger("skg.resonance.ingester")

# Adapter name → human-readable evidence sources
# Maintained here so the ingester doesn't have to parse Python source
ADAPTER_EVIDENCE_SOURCES = {
    # APRS
    "config_effective": [
        "filesystem scan for log4j jar files",
        "log4j2 configuration files (log4j2.xml, log4j2.properties)",
        "classpath and dependency manifests",
    ],
    "net_sandbox": [
        "docker inspect runtime state",
        "iptables egress rules",
        "DNS resolution capability check",
        "running process list",
    ],
    # Container escape
    "container_inspect": [
        "docker inspect JSON output",
        "HostConfig.Privileged flag",
        "HostConfig.CapAdd / CapDrop capability sets",
        "HostConfig.SecurityOpt seccomp/apparmor profiles",
        "HostConfig.PidMode / IpcMode / NetworkMode / UsernsMode",
        "Mounts[] for sensitive host paths",
    ],
    # AD lateral
    "bloodhound": [
        "BloodHound users.json (v4 and v5/CE schema)",
        "BloodHound computers.json",
        "BloodHound groups.json",
        "BloodHound acls.json",
        "BloodHound domains.json",
    ],
    "ldapdomaindump": [
        "ldapdomaindump domain_users.json",
        "ldapdomaindump domain_computers.json",
        "ldapdomaindump domain_policy.json",
    ],
    "manual": [
        "operator-provided structured JSON observations",
    ],
}


def _find_toolchains(skg_home: Path) -> list[Path]:
    return sorted([
        d for d in skg_home.iterdir()
        if d.is_dir() and d.name.startswith("skg-") and d.name.endswith("-toolchain")
        and (d / "contracts" / "catalogs").exists()
    ])


def _domain_from_toolchain(tc_dir: Path) -> str:
    """skg-aprs-toolchain → aprs, skg-ad-lateral-toolchain → ad_lateral"""
    name = tc_dir.name
    name = name.removeprefix("skg-").removesuffix("-toolchain")
    return name.replace("-", "_")


def _find_catalogs(tc_dir: Path) -> list[Path]:
    return sorted((tc_dir / "contracts" / "catalogs").glob("*.json"))


def _find_adapters(tc_dir: Path) -> list[Path]:
    adapter_dir = tc_dir / "adapters"
    if not adapter_dir.exists():
        return []
    return sorted([
        d for d in adapter_dir.iterdir()
        if d.is_dir() and (d / "parse.py").exists()
    ])


def ingest_catalog(engine: ResonanceEngine, domain: str,
                   catalog_path: Path) -> dict[str, int]:
    """
    Extract all wickets and attack paths from a catalog JSON.
    Returns counts of new records stored.
    """
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    wickets_data = catalog.get("wickets", {})
    paths_data   = catalog.get("attack_paths", {})

    # Build wicket → attack_paths mapping
    wicket_paths: dict[str, list[str]] = {}
    for path_id, path_def in paths_data.items():
        for wid in path_def.get("required_wickets", []):
            wicket_paths.setdefault(wid, []).append(path_id)

    new_wickets = 0
    for wid, wdef in wickets_data.items():
        label       = wdef.get("label", wid)
        description = wdef.get("description", "")
        evidence    = wdef.get("evidence_hint", "")
        embed_text  = WicketMemory.make_embed_text(label, description, evidence)

        record = WicketMemory(
            record_id    = f"{domain}::{wid}",
            domain       = domain,
            wicket_id    = wid,
            label        = label,
            description  = description,
            evidence_hint = evidence,
            attack_paths = wicket_paths.get(wid, []),
            embed_text   = embed_text,
        )
        if engine.store_wicket(record):
            new_wickets += 1

    # Store domain memory
    domain_desc = catalog.get("description", domain)
    embed_text  = DomainMemory.make_embed_text(
        domain, domain_desc, list(paths_data.keys()))

    domain_record = DomainMemory(
        record_id       = domain,
        domain          = domain,
        description     = domain_desc,
        wicket_count    = len(wickets_data),
        attack_paths    = list(paths_data.keys()),
        adapters        = [],   # filled in below by ingest_adapters
        catalog_version = catalog.get("version", "unknown"),
        embed_text      = embed_text,
    )
    engine.store_domain(domain_record)

    return {"wickets": new_wickets}


def ingest_adapters(engine: ResonanceEngine, domain: str,
                    adapter_dirs: list[Path],
                    catalog_path: Path) -> int:
    """
    Extract adapter records from discovered adapter directories.
    Returns count of new records stored.
    """
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    wickets_data = catalog.get("wickets", {})

    new_adapters = 0
    for adapter_dir in adapter_dirs:
        adapter_name = adapter_dir.name
        sources = ADAPTER_EVIDENCE_SOURCES.get(adapter_name, [
            f"{adapter_name} data source"
        ])

        # Heuristically determine which wickets this adapter can cover
        # by reading parse.py and finding wicket ID references
        parse_py = adapter_dir / "parse.py"
        covered_wickets = []
        if parse_py.exists():
            src = parse_py.read_text(encoding="utf-8")
            # Match wicket IDs like AP-L4, CE-01, AD-15
            found = re.findall(r'\b([A-Z]{2,3}-[A-Z]?[0-9]{1,2})\b', src)
            covered_wickets = sorted(set(
                w for w in found if w in wickets_data
            ))

        embed_text = AdapterMemory.make_embed_text(domain, adapter_name, sources)
        record = AdapterMemory(
            record_id        = f"{domain}::{adapter_name}",
            domain           = domain,
            adapter_name     = adapter_name,
            evidence_sources = sources,
            wickets_covered  = covered_wickets,
            evidence_ranks   = [],   # could parse from source if needed
            embed_text       = embed_text,
        )
        if engine.store_adapter(record):
            new_adapters += 1

    return new_adapters


def ingest_all(engine: ResonanceEngine, skg_home: Path) -> dict:
    """
    Walk all toolchains under skg_home and ingest everything.
    Safe to call multiple times — skips already-stored records.
    Returns summary of what was ingested.
    """
    toolchains = _find_toolchains(skg_home)
    if not toolchains:
        log.warning(f"No toolchains found under {skg_home}")
        return {"toolchains": 0}

    summary = {"toolchains": len(toolchains), "domains": {}}

    for tc_dir in toolchains:
        domain   = _domain_from_toolchain(tc_dir)
        catalogs = _find_catalogs(tc_dir)
        adapters = _find_adapters(tc_dir)

        if not catalogs:
            log.warning(f"No catalogs found in {tc_dir}, skipping")
            continue

        # Use the first catalog found (there's only one per toolchain currently)
        catalog_path = catalogs[0]
        log.info(f"Ingesting domain: {domain} from {catalog_path.name}")

        wicket_counts = ingest_catalog(engine, domain, catalog_path)
        new_adapters  = ingest_adapters(engine, domain, adapters, catalog_path)

        summary["domains"][domain] = {
            "new_wickets":  wicket_counts["wickets"],
            "new_adapters": new_adapters,
            "catalog":      catalog_path.name,
        }
        log.info(f"  {domain}: +{wicket_counts['wickets']} wickets, "
                 f"+{new_adapters} adapters")

    return summary

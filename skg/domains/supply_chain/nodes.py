"""
Supply chain Node definitions — PKG wicket catalog.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from skg.substrate.node import Node


# Supply chain node catalog
SC_NODES = {
    "PKG-01": Node(
        node_id="PKG-01",
        label="vulnerable_package_in_tree",
        description="A package with a known CVE exists in the dependency tree.",
        domain="supply_chain",
        tags=["sbom", "cve", "dependency"],
    ),
    "PKG-02": Node(
        node_id="PKG-02",
        label="transitive_exposure",
        description="Vulnerable package is reachable via transitive dependency.",
        domain="supply_chain",
        tags=["transitive", "reachability"],
    ),
    "PKG-03": Node(
        node_id="PKG-03",
        label="direct_import",
        description="Target application directly imports the vulnerable package.",
        domain="supply_chain",
        tags=["direct", "import"],
    ),
    "PKG-04": Node(
        node_id="PKG-04",
        label="no_patch_available",
        description="No patched version exists for the vulnerability.",
        domain="supply_chain",
        tags=["patch", "remediation"],
    ),
    "PKG-05": Node(
        node_id="PKG-05",
        label="public_exploit_exists",
        description="A public exploit or PoC exists for the vulnerability.",
        domain="supply_chain",
        tags=["exploit", "weaponized"],
    ),
    "PKG-06": Node(
        node_id="PKG-06",
        label="maintainer_compromise_indicator",
        description="Package maintainer account shows signs of compromise.",
        domain="supply_chain",
        tags=["maintainer", "account", "typosquat"],
    ),
}

# Supply chain path definitions
SC_PATHS = {
    "supply_chain_prototype_injection_v1": {
        "required_nodes": ["PKG-01", "PKG-02", "PKG-03"],
        "description": "Prototype pollution via vulnerable transitive dependency",
    },
    "supply_chain_weaponized_dep_v1": {
        "required_nodes": ["PKG-01", "PKG-03", "PKG-05"],
        "description": "Direct import of package with public exploit",
    },
    "supply_chain_maintainer_takeover_v1": {
        "required_nodes": ["PKG-06", "PKG-01"],
        "description": "Malicious package via maintainer account compromise",
    },
}

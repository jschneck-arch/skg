"""
skg.domains.supply_chain
========================
Supply chain domain skin for SKG.

λ = SBOM ingestion (CycloneDX, SPDX, pip freeze, npm list)
κ = dependency constraints (version ranges, transitive exposure)
π = reachability projection (same substrate engine)

Node types:
  PKG-01: vulnerable package exists in dependency tree
  PKG-02: vulnerable package is transitively reachable
  PKG-03: target application imports vulnerable package directly
  PKG-04: no patch available for vulnerability
  PKG-05: vulnerability has public exploit
  PKG-06: package maintainer account shows compromise indicators
"""

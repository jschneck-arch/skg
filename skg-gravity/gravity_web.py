"""
skg :: gravity_web.py

Gravity web — bond discovery and prior propagation between targets.

Bonds form automatically from observed topology. Priors propagate
across bonds: a realization on target A increases gravitational
pull on the same wicket for bonded target B.

This is the Kuramoto coupling. Realized wickets on one node influence
the phase of coupled nodes through the bond strength.
"""

BOND_STRENGTHS = {
    "same_host": 1.00,
    "docker_host": 0.90,
    "same_compose": 0.80,
    "shared_cred": 0.70,
    "same_domain": 0.60,
    "same_subnet": 0.40,
}


def build_gravity_web(targets):
    """
    Auto-discover bonds between targets from topology.
    Returns dict: {(ip1, ip2): {"type": str, "strength": float}}
    """
    bonds = {}

    def add_bond(ip1, ip2, btype):
        if ip1 == ip2:
            return
        key = tuple(sorted([ip1, ip2]))
        strength = BOND_STRENGTHS.get(btype, 0.3)
        if key not in bonds or bonds[key]["strength"] < strength:
            bonds[key] = {"type": btype, "strength": strength}

    # Group by subnet prefix
    subnet_groups = {}
    for t in targets:
        ip = t["ip"]
        prefix = ".".join(ip.split(".")[:3])
        subnet_groups.setdefault(prefix, []).append(ip)

    # Same-subnet bonds
    for prefix, ips in subnet_groups.items():
        for i, ip1 in enumerate(ips):
            for ip2 in ips[i+1:]:
                add_bond(ip1, ip2, "same_subnet")

    # Gateway detection
    gateways = [t["ip"] for t in targets if t["ip"].endswith(".0.1")]
    for i, gw1 in enumerate(gateways):
        for gw2 in gateways[i+1:]:
            add_bond(gw1, gw2, "same_host")

    # Docker host bonds
    for gw in gateways:
        prefix = ".".join(gw.split(".")[:2])
        for t in targets:
            if t["ip"].startswith(prefix) and t["ip"] != gw and not t["ip"].endswith(".0.1"):
                add_bond(gw, t["ip"], "docker_host")

    # Same compose network
    compose_containers = [t["ip"] for t in targets
                          if t["ip"].startswith("172.18.") and not t["ip"].endswith(".0.1")]
    for i, ip1 in enumerate(compose_containers):
        for ip2 in compose_containers[i+1:]:
            add_bond(ip1, ip2, "same_compose")

    # Same host - LAN hosts with SSH are likely same box as gateways
    lan_ssh = [t["ip"] for t in targets
               if any(s["service"] == "ssh" for s in t.get("services", []))
               and not t["ip"].startswith("172.")]
    for lan_ip in lan_ssh:
        for gw in gateways:
            add_bond(lan_ip, gw, "same_host")

    return bonds


def compute_neighbor_priors(ip, bonds, all_states):
    """
    Compute priors from bonded neighbors' realized wickets.
    Returns dict: {wicket_id: prior_strength}
    """
    priors = {}

    for (ip1, ip2), bond_info in bonds.items():
        if ip1 == ip:
            neighbor_ip = ip2
        elif ip2 == ip:
            neighbor_ip = ip1
        else:
            continue

        strength = bond_info["strength"]
        neighbor_states = all_states.get(neighbor_ip, {})

        for wid, state_info in neighbor_states.items():
            if isinstance(state_info, dict):
                status = state_info.get("status", "unknown")
            elif isinstance(state_info, str):
                status = state_info
            else:
                continue

            if status == "realized":
                prior = strength * 0.5
                if wid not in priors or priors[wid] < prior:
                    priors[wid] = prior

    return priors


def display_web(bonds, all_states=None):
    """Print the gravity web."""
    if not bonds:
        print("  No bonds discovered.")
        return

    print(f"\n  [GRAVITY WEB] {len(bonds)} bonds")
    for (ip1, ip2), info in sorted(bonds.items(), key=lambda x: -x[1]["strength"]):
        print(f"    {ip1:18s} <-{info['type']:14s}-> {ip2:18s}  {info['strength']:.2f}")


def display_priors(landscape, bonds, all_states):
    """Print prior influence from neighbors."""
    prior_targets = []
    for t in landscape:
        priors = compute_neighbor_priors(t["ip"], bonds, all_states)
        if priors:
            prior_targets.append((t["ip"], len(priors), sum(priors.values())))

    if prior_targets:
        print(f"\n  [PRIORS] Neighbor influence:")
        for ip, count, total in sorted(prior_targets, key=lambda x: -x[2]):
            print(f"    {ip:18s} {count} priors, total influence: {total:.2f}")

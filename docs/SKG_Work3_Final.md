# Projection Over Constrained System State: A Formal Substrate for Telemetry-Driven Reasoning

**Jeffrey Michael Schneck**

**March 2026 (Revised)**

---

## Abstract

We present a formal substrate for reasoning about complex system properties grounded in telemetry rather than inference. Prior work established that security-relevant properties are not intrinsic attributes of components but projections over constrained system state, and demonstrated this informally through cross-domain telemetry artifacts. A companion publication presented a spherical oscillator simulation of knowledge dynamics on a coupled graph. This paper provides the formalization both deferred.

We define a system as a tuple (N, T, κ) comprising a node set, a telemetry map, and a constraint surface. We introduce the tri-state encoding Σ ∈ {R, B, U} with formal semantics distinguishing it from Boolean and probabilistic alternatives. We define the projection operator π and a field energy measure E that quantifies observational deficit. We establish that local projections form a sheaf over the node topology and that global attack-path realizability corresponds to the existence of a global section.

Beyond formalization, this paper describes the gravity field: an operational mechanism, motivated by the oscillator dynamics of prior work, through which the substrate directs its own observation. The gravity field follows the energy gradient, selecting instruments that reduce uncertainty and shifting to different instruments when the current one fails. Bonds between targets form from observed topology, creating a gravity web through which prior influence propagates. The oscillator simulation of prior work is recovered as a special case of this inter-target coupling.

We validate the substrate empirically against a live heterogeneous network. The system autonomously discovered 11 hosts, classified 8 targets, auto-discovered 10 inter-target bonds, and realized 10 attack paths across 2 targets without human guidance. These results are presented as a proof of concept demonstrating the substrate's viability, not as a comprehensive evaluation.

This work does not present a finished system. The gravity field is an approximation of continuous field dynamics through a discrete selection mechanism. The confidence model is static. Several toolchain domains remain catalog-only. These limitations are described explicitly. The contribution is a working foundation — formal, operational, and honest about its own boundaries.

---

## 1. Introduction

The question of whether a system is vulnerable is, in practice, almost never answerable by inspection alone. Two systems with identical software inventories may occupy radically different security states. A single system may transition between safe and unsafe states without any change in installed components. These observations are operationally familiar. The representational consequence they imply is not.

If system properties are not intrinsic to components, they must be derived from measured state. The substrate that performs that derivation must represent partial observability without collapsing it. It must distinguish between a condition that has been measured and found absent, a condition that has been suppressed by a constraint, and a condition that simply has not been measured. These are three different states. Treating any two of them as equivalent introduces false certainty.

Prior work in the SKG research direction addressed this through a provenance-first substrate [1] that treats observations as immutable, constraints as physical invariants, and derived properties as projections. That work was deliberately pre-formal. A companion publication [2] demonstrated oscillator dynamics on a spherical graph but did not connect the model to the tri-state substrate.

This paper provides the formalization both deferred. It also describes something neither anticipated: a mechanism by which the substrate directs its own observation. This mechanism — the gravity field — emerged during deployment against a live network rather than from theoretical derivation. The formalism therefore follows the implementation. This ordering is deliberate. The substrate is a working system that reasons about real infrastructure. The mathematics describes what the system does, not what it might do.

The paper is organized as follows. Sections 2–4 establish the formal foundations: state space, projections, energy, and sheaf structure. Section 5 introduces the gravity field as an operational mechanism with theoretical motivation. Section 6 describes the gravity web and its connection to the oscillator model. Section 7 presents empirical results from a live engagement. Section 8 discusses implications, limitations, and open questions.

---

## 2. State Space and Tri-State Encoding

A system is a tuple S = (N, T, κ) where N is a finite set of nodes representing measurable preconditions, T : N → Σ ∪ {⊥} is the telemetry map, and κ ⊆ N × N is the constraint surface encoding dependencies and blocking relationships.

The state space Σ = {R, B, U} is defined as follows:

- Σ(n) = R (realized) if and only if explicit telemetry witnesses the condition.
- Σ(n) = B (blocked) if and only if a constraint in κ prevents the condition from contributing to any projection.
- Σ(n) = U (unknown) if and only if no measurement has been made. T(n) = ⊥.

Several properties distinguish this encoding from alternatives.

Unknown is not a probability. U does not converge toward R or B without new telemetry. It does not carry a prior. It is stable. This separates the encoding from Bayesian frameworks in which unobserved events carry implicit probabilities, and from Boolean frameworks in which absence of positive evidence defaults to negative.

Blocked is not the negation of realized. B records that a constraint currently prevents realization, not that realization is impossible. If the constraint is removed, the node may transition to R without any change in underlying system state. This distinction — between conditional suppression and structural removal — was described informally in prior work. Here it is encoded formally through κ.

These are not abstract distinctions. During the live engagement described in Section 7, the auth scanner initially reported a login form's default credentials as blocked (WB-08 = B). The cause was not that the credentials were wrong — they were correct — but that the scanner's measurement apparatus did not include the CSRF token required by the form. Correcting the apparatus transitioned WB-08 from B to R without any change to the target system. The blocking condition was in the instrument, not in the target. The tri-state encoding preserved this distinction. A Boolean encoding would have lost it.

---

## 3. Projection Operator and Field Energy

### 3.1 Projections

An attack path P ⊆ N defines a set of preconditions whose simultaneous realization constitutes a derived property (e.g., a viable attack chain). The projection operator evaluates:

- π(S, P) = ⊤ (emergent) if ∀n ∈ P, Σ(n) = R
- π(S, P) = ⊥ (collapsed) if ∃n ∈ P such that Σ(n) = B
- π(S, P) = ? (indeterminate) otherwise

Indeterminate is not a failure of the method. It is the correct representation of a system whose state is partially observed. The substrate refuses to resolve indeterminacy through inference. This refusal is the most operationally important property of the projection operator.

### 3.2 Field Energy

The field energy E quantifies the observational deficit for a set of applicable nodes A:

E(S, A) = |{n ∈ A : Σ(n) = U}|

E = 0 when all nodes are resolved (R or B). E is maximized when all nodes are unknown. Each measurement that transitions a node from U reduces E by exactly 1. Minimizing E is therefore equivalent to maximizing observational coverage.

An earlier version of this work defined E as the Shannon entropy H(π | T) of the tri-state distribution. Deployment revealed that Shannon entropy assigns E = 0 when all nodes are in the same state — including the all-unknown case. This contradicts the operational requirement: maximum uncertainty must correspond to maximum field energy. The count-based definition adopted here is less elegant but operationally correct. A more principled information-theoretic formulation that preserves the all-unknown maximum remains an open problem.

### 3.3 Prior Influence

When the gravity web (Section 6) couples targets, the field energy of a node may be augmented by prior influence from neighboring targets:

E*(S, A, P) = |{n ∈ A : Σ(n) = U}| + Σ P(n) for n ∈ A where Σ(n) = U

where P(n) is the prior contribution from coupled neighbors (defined in Section 6.2). Prior influence increases the field energy on unknown nodes that have been realized on bonded targets. This makes those nodes gravitationally more interesting to observe — not because the system assumes they are realized, but because a neighbor's observation suggests the region of state space is worth measuring.

Priors are consumed by measurement. Once a node is observed (U → R or U → B), the prior contribution is replaced by the measurement. This prevents priors from persisting beyond their epistemic warrant.

---

## 4. Sheaf Structure and Global Realizability

An attack path P defines an open cover of the node set. A local section assigns tri-state values to a subset of P. The sheaf condition requires that overlapping local sections agree on shared nodes. Global realizability — π(S, P) = ⊤ — corresponds to the existence of a global section σ : P → {R}.

The cohomological obstruction H¹(X; F) measures irreducible indeterminacy. When H¹ is non-trivial, local realizations exist but cannot be consistently assembled. Operationally, this manifests as mutually conditional preconditions: privilege escalation chains where access to resource A requires privilege B and privilege B requires access to resource A.

This structure was established formally in the prior version of this paper and is retained without modification. The sheaf framework characterizes realizability as a structural property of the node topology, independent of the operational mechanisms that collect telemetry. The gravity field (Section 5) determines how telemetry is collected. The sheaf determines what realizability means given whatever telemetry exists.

---

## 5. The Gravity Field

### 5.1 Motivation

In prior work, the substrate was passive. It accepted telemetry, computed projections, and reported results. The choice of what to observe was external. This is adequate when the operator knows where to look. It is inadequate when the system is deployed against a network of unknown composition and must determine for itself what to measure and how.

The gravity field addresses this. It is an operational mechanism — not a formal result — that directs observation based on the energy landscape. Regions of high E exert gravitational pull. The system follows the gradient, selecting instruments that reduce E and shifting to different instruments when the current one fails.

The motivation is the oscillator model of prior work [2], in which phase coherence evolves under coupling. The gravity field approximates these dynamics through a discrete instrument selection mechanism. This approximation is practical rather than principled: the continuous formulation would require simultaneous evaluation across all instruments and targets, which is computationally and operationally infeasible in a real-time engagement. The discrete mechanism captures the essential behavior — energy-directed observation with failure-driven adaptation — while remaining implementable.

### 5.2 Instruments

An observational instrument I has:

- A wavelength W(I) ⊆ N: the set of nodes it can potentially resolve.
- A cost c(I) ∈ ℝ⁺: the resource expenditure per observation.
- A failure memory M(I, t): whether I failed to reduce E on target t in a prior cycle.

Examples from the deployed system: an HTTP collector (wavelength: web-facing nodes; cost: 1.0), an authenticated scanner with CSRF handling (wavelength: post-authentication nodes; cost: 3.0), an SSH sensor (wavelength: host-level nodes; cost: 2.0), an NVD feed (wavelength: CVE-related nodes; cost: 2.0), Metasploit auxiliary modules (wavelength: broad; cost: 5.0), packet capture (wavelength: wire-level nodes; cost: 2.0), and nmap version detection (wavelength: service identification; cost: 3.0).

Each instrument observes a different slice through state space. Some regions are only visible to certain instruments. The authenticated web surface behind a CSRF-protected login is invisible to the HTTP collector but visible to the authenticated scanner. Kernel version and sudo configuration are invisible to any web instrument but visible to the SSH sensor. This is the operational meaning of wavelength: it defines the observational reach of each instrument.

### 5.3 Selection and Shifting

The entropy reduction potential of instrument I on target t with applicable nodes A(t) is:

Φ(I, t) = |{n ∈ W(I) ∩ A(t) : Σ(n) = U}| / c(I) × penalty(I, t)

where penalty(I, t) = 0.2 if I previously failed to reduce E on t, and 1.0 otherwise.

The gravity field selects argmax_I Φ(I, t) for the highest-energy target.

This is, formally, a greedy algorithm with a penalty term. The paper does not claim otherwise. The physics analogy — that the system follows geodesics through the entropy landscape — describes the behavior, not the mechanism. The mechanism is discrete selection. The behavior is that the system reliably moves toward the highest-uncertainty regions and reliably abandons failed approaches, which is the behavior a continuous field dynamic would produce. Whether a principled continuous formulation exists that recovers this mechanism as a limit is an open question.

### 5.4 Convergence

The gravity field converges when |E_total(cycle n) − E_total(cycle n−1)| < ε. Convergence means no available instrument can further reduce uncertainty. The system has reached the boundary of its observational capability and reports that boundary explicitly rather than filling it with inference.

---

## 6. The Gravity Web

### 6.1 Bond Discovery

Targets in a network are not independent. Relationships between them — shared hosts, container-host coupling, subnet membership, credential reuse, domain trust — create pathways through which information about one target is relevant to another.

The gravity web discovers these relationships from observation:

- **same_host** (coupling 1.00): detected when multiple IP addresses share the same SSH host key or respond on multiple interfaces of the same physical machine.
- **docker_host** (coupling 0.90): detected via Docker API — container to host gateway.
- **same_compose** (coupling 0.80): containers on the same Docker Compose network.
- **shared_cred** (coupling 0.70): the same credential pair succeeds on multiple targets.
- **same_domain** (coupling 0.60): Active Directory domain membership via BloodHound or LDAP.
- **same_subnet** (coupling 0.40): IP address prefix match.

Bonds are discovered, not declared. The operator adds targets to the field. The web emerges from what the instruments observe about those targets.

Runtime note, March 2026: the live `WorkloadGraph` vocabulary has since shifted to `same_identity` (0.85), `credential_overlap` (0.45), `same_domain` (0.35), and `same_subnet` (0.20) for propagation, while manual graph links are also exposed for operator overrides. The list above is the original Work 3 presentation, not the current runtime weight table.

### 6.2 Prior Propagation

When node n is realized on target A, and A is bonded to target B with coupling strength s, the prior influence on node n for target B is:

P_B(n) = s × α

where α = 0.5 is an attenuation factor. This is a heuristic, not a derivation from the Kuramoto equations. The attenuation ensures that priors are weaker than direct observation and decay when measurement does not confirm them.

The effect is that the gravity field pulls harder on nodes where a bonded neighbor has relevant findings. A realized attack path on one target makes the same path more gravitationally interesting on bonded targets — not because the system assumes the condition exists, but because the topology suggests it is worth measuring.

### 6.3 Connection to the Oscillator Model

The prior work [2] simulated coupled oscillators on a graph where nodes carry amplitude-phase pairs and pairwise energy is E_ir = A_i A_r cos(φ_i − φ_r). Phases were abstract; the simulation demonstrated convergence without semantic interpretation.

The gravity web provides the semantic interpretation. Nodes are preconditions. Phases encode tri-state values: φ = 0 for realized, φ = π for blocked, φ = π/2 for unknown. Bond strengths are the coupling constants. The field energy G(S) = Σ_ir A_i A_r cos(φ_i − φ_r) is maximized when all coupled nodes are realized (in phase) and reduced by blocking constraints (phase opposition).

The gravity web extends the model across targets. In [2], coupling was within a single graph. In the gravity web, coupling extends through bonds: a realized node on target A influences the phase of the same node on target B, weighted by bond strength. The Kuramoto order parameter R(t) now measures coherence across the entire web.

This connection is structural, not derived. The prior propagation formula P_B(n) = s × α approximates the coupling effect but is not obtained from the Kuramoto differential equations. A rigorous derivation linking the discrete prior propagation to the continuous oscillator dynamics remains open. The connection is stated as a correspondence, not an equivalence.

---

## 7. Empirical Results

### 7.1 Engagement Environment

The substrate was deployed against a live heterogeneous network:

- archbox: Arch Linux workstation with three network interfaces (192.168.254.5, 172.17.0.1, 172.18.0.1)
- DVWA: intentionally vulnerable web application (Docker, 172.17.0.2)
- BloodHound CE: graph-based AD analysis tool (Docker Compose: application 172.18.0.4, Postgres 172.18.0.2, Neo4j 172.18.0.3)
- Samsung device: IoT, port 8080 (192.168.254.7)
- Beacon device: IoT, nginx/1.17.7, ports 80/443 (192.168.254.254)

### 7.2 Discovery

Network discovery identified 11 live hosts across 3 subnets, classified 8 targets with applicable toolchain domains, and enumerated 4 Docker containers. The gravity web auto-discovered 10 bonds: 3 same_host (archbox interfaces), 3 docker_host (gateways to containers), 1 same_compose (BloodHound components), and 3 same_subnet (LAN).

### 7.3 Realized Attack Paths

Ten attack paths collapsed to realized across two targets:

**DVWA** (4 paths, found through autonomous web collection and authenticated scanning):

| Path | Score | Wickets |
|------|-------|---------|
| web_ssti_to_rce_v1 | 100% | WB-01 (reachable), WB-22 (SSTI confirmed) |
| web_cmdi_to_shell_v1 | 100% | WB-01, WB-14 (command injection via POST) |
| web_default_creds_to_admin_v1 | 100% | WB-01, WB-06 (login form), WB-07 (no rate limit), WB-08 (admin:password) |
| web_source_disclosure_to_foothold_v1 | 100% | WB-01, WB-05 (phpinfo.php exposed) |

**archbox** (6 paths, found through SSH sensor and container inspection):

| Path | Score | Wickets |
|------|-------|---------|
| host_ssh_initial_access_v1 | 100% | HO-01, HO-02, HO-03 |
| host_linux_privesc_sudo_v1 | 100% | HO-03, HO-06 (tshark NOPASSWD) |
| host_credential_access_env_v1 | 100% | HO-03, HO-09 |
| host_lateral_ssh_key_v1 | 100% | HO-03, HO-13 (2 private keys) |
| host_container_escape_docker_v1 | 100% | HO-03, HO-15 |
| container_escape_socket_v1 | 100% | CE-01, CE-03, CE-14 |

Container escape was confirmed independently through two projection paths. Both arrived at the same ground truth from different telemetry. This is expected: the same physical condition observed through different projection lenses produces consistent results. If it did not, the substrate would have a coherence problem.

### 7.4 Gravity Field Behavior

The gravity field demonstrated the following behaviors:

**Instrument shifting.** In cycle 1, the HTTP collector was selected for all targets. It produced no entropy change on BloodHound, Samsung, or Beacon. In cycle 2, the HTTP collector was penalized (potential reduced from 6.0 to 1.2) and the authenticated scanner was selected instead (potential 3.7). The auth scanner successfully penetrated DVWA's CSRF-protected login.

**Prior propagation.** The gravity web increased field energy on 172.18.0.2 (Postgres) from E = 24.0 to E = 26.25. The additional 2.25 arose from realized wickets on bonded neighbors propagating through docker_host and same_compose bonds. This is the prior mechanism operating on live data: the system pulled harder on Postgres because its neighbors had findings.

**Convergence.** After all available instruments had been attempted on all high-entropy targets, the field stabilized at 135 total unknowns. Those unknowns remain reported as unknowns.

### 7.5 NVD Feed Integration

The NVD API v2 feed queried CVEs for Apache HTTP Server 2.4.25 and returned 11 high-severity matches including 4 critical (CVSS ≥ 9.0). Events were emitted at evidence rank 5 (static/database) with confidence 0.7 (version match, not confirmed exploitable). The evidence ranking hierarchy preserves the distinction: a CVE database match is not the same as a runtime observation.

### 7.6 Limitations of the Empirical Results

These results are a proof of concept. DVWA is an intentionally vulnerable application designed to be found. The archbox findings are self-assessment of the operator's own workstation. The Samsung and Beacon devices were observed but not penetrated — 16 unknowns remained on each after all instruments were exhausted. A meaningful validation would require diverse engagement environments, targets not designed to be vulnerable, and repeated measurement across different network topologies.

---

## 8. Discussion

### 8.1 What SKG Is

SKG is a system that treats the attack surface as a physical phenomenon. It measures rather than infers. It preserves uncertainty rather than collapsing it. It directs its own observation based on where uncertainty concentrates. When it reaches the limits of its observational reach, it says so.

This matters because the security industry has a false certainty problem. Severity scores become mandates. Green checkboxes mean safe. Absence of findings means absence of problems. SKG refuses all three. A score of 9.8 does not mean the condition is exploitable in this system. A blocked wicket does not mean the attack surface is eliminated. Sixteen unknowns on a Samsung device do not mean the device is secure.

The boundary between what SKG knows and what it does not know is the most valuable thing it produces. That boundary tells an operator exactly where their ignorance lives. Everything else — the realized paths, the projections, the gravity web — exists to make that boundary as precise as possible.

### 8.2 What SKG Is Not

SKG is not finished. The gravity field approximates continuous dynamics through discrete selection. The confidence weights in the observation memory are static. The inter-target prior propagation uses a fixed attenuation factor rather than a learned coupling. Several toolchain domains (IoT firmware, supply chain) exist only as catalogs without active collection instruments. The daemon does not yet run gravity natively as its primary loop.

These are not apologetic disclaimers. They are the current state of a system that is growing through operation. The substrate's formal properties — tri-state encoding, provenance preservation, deterministic projection, reversible collapse — are stable and proven. The operational mechanisms built on that substrate are developing. The paper captures where the system is, which is the only honest thing a paper can do.

### 8.3 Relationship to Prior Work

The informal substrate of [1] is recovered as the special case in which no gravity field operates. The simulation of [2] is recovered through the phase encoding and gravity web coupling. This paper unifies both and extends them with the operational gravity mechanism.

The tri-state encoding differs from Bayesian networks (U carries no prior), from three-valued logics (U is operationally defined as unmeasured, not truth-functionally undefined), and from probabilistic vulnerability scoring (no likelihoods are assigned). The sheaf structure is related to work on distributed databases and sensor fusion but its application to attack-path realizability appears novel. The gravity field is related to active learning and adaptive sensor selection but differs in its field-theoretic motivation and its refusal to use probabilistic objective functions.

### 8.4 Open Questions

The continuous formulation of the gravity field — whether the discrete instrument selection mechanism can be derived as a limit of a continuous field dynamic — remains open. The complexity-theoretic relationship between sheaf section extension and attack-path realizability from partial telemetry requires formal reduction. The confidence weight model requires calibration data from repeated engagements to become empirically grounded rather than hand-tuned. Behavioral bond discovery (identifying related targets from response patterns rather than topology alone) could enrich the gravity web. Cross-domain projection coupling — how a realized web attack should influence the host privesc projection on the same target — requires formal treatment.

---

## 9. Conclusion

We have presented a formal substrate for telemetry-driven reasoning that is both theoretically grounded and empirically operational. The substrate defines systems as tuples (N, T, κ), encodes preconditions in a tri-state space where unknown is a stable energetic state, and derives properties as projections that refuse premature certainty.

The gravity field directs the substrate's observation, following the energy gradient and shifting instruments when the current one is exhausted. The gravity web couples targets through observed bonds and propagates priors via coupling strengths that correspond to the oscillator dynamics of prior work.

Ten attack paths were realized across two targets on a live network through autonomous observation. The system directed its own instrument selection, shifted approaches when they failed, and converged when no further reduction was achievable. One hundred thirty-five unknowns remain reported as unknowns.

The contribution is not a new vulnerability taxonomy, scoring system, or detection technique. It is a working foundation for a class of reasoning systems that refuse premature certainty, preserve provenance, and remain valid as systems evolve. The foundation is formal. The operation is real. The system is not finished, and does not claim to be.

---

## References

[1] Schneck, J.M. (2026). Telemetry-First Derived System Properties: A Semantic Spherical Multidimensional Substrate Aligned with SKG. Preprint.

[2] Schneck, J.M. (2025). Spherical Knowledge Graph (SKG Core). Zenodo.

[3] Kuramoto, Y. (1984). Chemical Oscillations, Waves, and Turbulence. Springer.

[4] Shannon, C.E. (1948). A Mathematical Theory of Communication. Bell System Technical Journal, 27(3), 379–423.

[5] Curry, J. (2014). Sheaves, Cosheaves and Applications. arXiv:1303.3255.

[6] Ghrist, R. (2014). Elementary Applied Topology. Createspace.

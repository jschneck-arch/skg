# SKG State Transition Model
Defines how observations collapse into node state.

State Σ(n,c,t) ∈ {R, B, U}
R = realized
B = blocked
U = unknown

Observations contribute support vectors φ(o,n,c) → (φ_R, φ_B)

Aggregated support determines state collapse using thresholds.
Nodes never receive state directly from tools.

Pearls record state evolution over time.
Energy measures unknown state.
Gravity prioritizes observations that reduce uncertainty.
# SKG Instrument Support Model
Defines how instruments convert telemetry into support contributions.

Tools do not assign truth.
They emit support vectors used by the state engine.

Examples:
BloodHound → identity topology support
PCAP → network reachability support
Metasploit → exploit validation support
CVE/NVD/IAVA feeds → vulnerability intelligence

Each adapter outputs φ(o,n,c) → (φ_R, φ_B)
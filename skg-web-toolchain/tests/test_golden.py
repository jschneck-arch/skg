"""
skg-web-toolchain :: tests/test_golden.py

Golden test: deterministic projection from known events.
Verifies the invariant: same input always produces same output.

Run:
  cd skg-web-toolchain
  python -m pytest tests/test_golden.py -v
"""

import json
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from projections.run import project


# ── Golden input: known events for web_sqli_to_shell_v1 ──────────────────
# This path requires: WB-01, WB-09, WB-10, WB-20

GOLDEN_EVENTS = [
    {
        "id": "aaaaaaaa-0001-0001-0001-000000000001",
        "ts": "2026-03-08T12:00:00+00:00",
        "type": "obs.attack.precondition",
        "source": {"source_id": "adapter.web_active", "toolchain": "skg-web-toolchain", "version": "1.0.0"},
        "payload": {
            "wicket_id": "WB-01",
            "status": "realized",
            "attack_path_id": "web_sqli_to_shell_v1",
            "run_id": "golden-run-001",
            "workload_id": "testapp",
            "detail": "HTTP 200 in 45ms"
        },
        "provenance": {
            "evidence_rank": 1,
            "evidence": {"source_kind": "runtime", "pointer": "tcp://192.168.1.50:80",
                         "collected_at": "2026-03-08T12:00:00+00:00", "confidence": 1.0}
        }
    },
    {
        "id": "aaaaaaaa-0001-0001-0001-000000000002",
        "ts": "2026-03-08T12:00:01+00:00",
        "type": "obs.attack.precondition",
        "source": {"source_id": "adapter.web_active", "toolchain": "skg-web-toolchain", "version": "1.0.0"},
        "payload": {
            "wicket_id": "WB-09",
            "status": "realized",
            "attack_path_id": "web_sqli_to_shell_v1",
            "run_id": "golden-run-001",
            "workload_id": "testapp",
            "detail": "SQL error on quote injection at /login param=username"
        },
        "provenance": {
            "evidence_rank": 1,
            "evidence": {"source_kind": "runtime", "pointer": "http://192.168.1.50/login",
                         "collected_at": "2026-03-08T12:00:01+00:00", "confidence": 0.9}
        }
    },
    {
        "id": "aaaaaaaa-0001-0001-0001-000000000003",
        "ts": "2026-03-08T12:00:02+00:00",
        "type": "obs.attack.precondition",
        "source": {"source_id": "adapter.web_active", "toolchain": "skg-web-toolchain", "version": "1.0.0"},
        "payload": {
            "wicket_id": "WB-10",
            "status": "realized",
            "attack_path_id": "web_sqli_to_shell_v1",
            "run_id": "golden-run-001",
            "workload_id": "testapp",
            "detail": "UNION SELECT with 5 columns accepted"
        },
        "provenance": {
            "evidence_rank": 1,
            "evidence": {"source_kind": "runtime", "pointer": "http://192.168.1.50/login UNION 5",
                         "collected_at": "2026-03-08T12:00:02+00:00", "confidence": 0.85}
        }
    },
    {
        "id": "aaaaaaaa-0001-0001-0001-000000000004",
        "ts": "2026-03-08T12:00:03+00:00",
        "type": "obs.attack.precondition",
        "source": {"source_id": "adapter.web_active", "toolchain": "skg-web-toolchain", "version": "1.0.0"},
        "payload": {
            "wicket_id": "WB-20",
            "status": "unknown",
            "attack_path_id": "web_sqli_to_shell_v1",
            "run_id": "golden-run-001",
            "workload_id": "testapp",
            "detail": "Requires deeper interaction or exploitation phase"
        },
        "provenance": {
            "evidence_rank": 1,
            "evidence": {"source_kind": "runtime", "pointer": "http://192.168.1.50 (not probed)",
                         "collected_at": "2026-03-08T12:00:03+00:00", "confidence": 0.2}
        }
    },
]

# ── Expected output ──────────────────────────────────────────────────────

EXPECTED = {
    "attack_path_id": "web_sqli_to_shell_v1",
    "realized": ["WB-01", "WB-09", "WB-10"],
    "blocked": [],
    "unknown": ["WB-20"],
    "aprs": 0.75,
    "classification": "indeterminate",
    "wicket_count": 4,
}


def test_golden_sqli_to_shell():
    """Golden test: web_sqli_to_shell_v1 with 3/4 realized = indeterminate at 75%."""
    with tempfile.TemporaryDirectory() as tmpdir:
        events_file = Path(tmpdir) / "events.ndjson"
        interp_file = Path(tmpdir) / "interp.ndjson"

        # Write golden events
        with open(events_file, "w") as f:
            for event in GOLDEN_EVENTS:
                f.write(json.dumps(event) + "\n")

        # Run projection
        result = project(str(events_file), str(interp_file), "web_sqli_to_shell_v1")

        # Verify deterministic output
        assert result["attack_path_id"] == EXPECTED["attack_path_id"]
        assert sorted(result["realized"]) == sorted(EXPECTED["realized"])
        assert sorted(result["blocked"]) == sorted(EXPECTED["blocked"])
        assert sorted(result["unknown"]) == sorted(EXPECTED["unknown"])
        assert result["aprs"] == EXPECTED["aprs"]
        assert result["classification"] == EXPECTED["classification"]
        assert result["wicket_count"] == EXPECTED["wicket_count"]

        # Verify the output file contains the interpretation
        with open(interp_file) as f:
            written = json.loads(f.readline())
        assert written["attack_path_id"] == "web_sqli_to_shell_v1"
        assert written["aprs"] == 0.75


def test_golden_all_realized():
    """When all wickets realized, classification = realized."""
    events = []
    for wid in ["WB-01", "WB-09", "WB-10", "WB-20"]:
        events.append({
            "id": f"bbbbbbbb-0001-0001-0001-{wid.replace('-', '0')}",
            "ts": "2026-03-08T12:00:00+00:00",
            "type": "obs.attack.precondition",
            "source": {"source_id": "test", "toolchain": "test", "version": "1.0.0"},
            "payload": {"wicket_id": wid, "status": "realized",
                        "attack_path_id": "web_sqli_to_shell_v1",
                        "run_id": "golden-002", "workload_id": "test"},
            "provenance": {"evidence_rank": 1,
                           "evidence": {"source_kind": "test", "pointer": "test",
                                        "collected_at": "2026-03-08T12:00:00+00:00",
                                        "confidence": 1.0}},
        })

    with tempfile.TemporaryDirectory() as tmpdir:
        ef = Path(tmpdir) / "events.ndjson"
        of = Path(tmpdir) / "interp.ndjson"
        with open(ef, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        result = project(str(ef), str(of), "web_sqli_to_shell_v1")
        assert result["classification"] == "realized"
        assert result["aprs"] == 1.0


def test_golden_blocked():
    """When any wicket blocked, classification = not_realized."""
    events = [
        {
            "id": "cccccccc-0001-0001-0001-000000000001",
            "ts": "2026-03-08T12:00:00+00:00",
            "type": "obs.attack.precondition",
            "source": {"source_id": "test", "toolchain": "test", "version": "1.0.0"},
            "payload": {"wicket_id": "WB-01", "status": "blocked",
                        "attack_path_id": "web_sqli_to_shell_v1",
                        "run_id": "golden-003", "workload_id": "test"},
            "provenance": {"evidence_rank": 1,
                           "evidence": {"source_kind": "test", "pointer": "test",
                                        "collected_at": "2026-03-08T12:00:00+00:00",
                                        "confidence": 0.95}},
        },
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        ef = Path(tmpdir) / "events.ndjson"
        of = Path(tmpdir) / "interp.ndjson"
        with open(ef, "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

        result = project(str(ef), str(of), "web_sqli_to_shell_v1")
        assert result["classification"] == "not_realized"
        assert "WB-01" in result["blocked"]


if __name__ == "__main__":
    test_golden_sqli_to_shell()
    print("PASS: test_golden_sqli_to_shell")
    test_golden_all_realized()
    print("PASS: test_golden_all_realized")
    test_golden_blocked()
    print("PASS: test_golden_blocked")
    print("\nAll golden tests passed.")

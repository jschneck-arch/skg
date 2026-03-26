"""
Tests for skg.sensors.dark_hypothesis_sensor.

Covers:
  - plan_dark_hypotheses returns empty list when LLM unavailable (no crash)
  - plan_dark_hypotheses correctly filters by min_torque
  - plan_dark_hypotheses parses a valid LLM JSON response into a proposal
  - proposal has required fields and is written to the proposals dir
  - null instrument response (LLM says nothing applicable) is silently skipped
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest import mock

import pytest

# ── Module import (graceful if sensor deps not in path) ──────────────────────
try:
    from skg.sensors.dark_hypothesis_sensor import (
        plan_dark_hypotheses,
        _call_llm,
        _build_prompt,
        _available_instruments,
    )
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False

pytestmark = pytest.mark.skipif(not _IMPORT_OK, reason="dark_hypothesis_sensor not importable")


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _make_landscape(torque: float = 2.0) -> list[dict]:
    return [
        {
            "host": "192.168.1.5",
            "observations": {"os": "Windows Server 2019", "open_ports": [445, 139]},
            "wgraph_dark": [
                {
                    "wicket_id": "SMB-01",
                    "domain":    "smb",
                    "label":     "SMB reachability",
                    "description": "Target exposes SMB but no credential collected",
                    "torque":    torque,
                    "is_dark":   True,
                }
            ],
        }
    ]


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_returns_empty_when_llm_unavailable(tmp_path):
    """When LLM returns None, plan_dark_hypotheses should produce no proposals."""
    landscape = _make_landscape(torque=2.0)
    with mock.patch("skg.sensors.dark_hypothesis_sensor._call_llm", return_value=None), \
         mock.patch("skg.sensors.dark_hypothesis_sensor._PROPOSALS_DIR", tmp_path):
        results = plan_dark_hypotheses(landscape, min_torque=1.0)
    assert results == []


def test_filters_below_min_torque(tmp_path):
    """Hypotheses below min_torque are skipped without calling LLM."""
    landscape = _make_landscape(torque=0.5)
    with mock.patch("skg.sensors.dark_hypothesis_sensor._call_llm") as mock_llm, \
         mock.patch("skg.sensors.dark_hypothesis_sensor._PROPOSALS_DIR", tmp_path):
        results = plan_dark_hypotheses(landscape, min_torque=1.5)
    mock_llm.assert_not_called()
    assert results == []


def test_valid_llm_response_creates_proposal(tmp_path):
    """A valid JSON LLM response should produce a proposal file."""
    llm_output = json.dumps({
        "instrument": "skg-host-toolchain",
        "target":     "192.168.1.5",
        "command":    "smbclient -L 192.168.1.5 -N 2>&1",
        "wicket_id":  "SMB-01",
        "rationale":  "Lists SMB shares without credentials to confirm reachability.",
    })

    landscape = _make_landscape(torque=2.5)
    with mock.patch("skg.sensors.dark_hypothesis_sensor._call_llm", return_value=llm_output), \
         mock.patch("skg.sensors.dark_hypothesis_sensor._available_instruments",
                    return_value=[{"name": "skg-host-toolchain", "domain": "host",
                                   "path": "/tmp", "wicket_count": 5}]), \
         mock.patch("skg.sensors.dark_hypothesis_sensor._PROPOSALS_DIR", tmp_path):
        results = plan_dark_hypotheses(landscape, min_torque=1.0)

    assert len(results) == 1
    p = results[0]
    assert p["proposal_kind"] == "cognitive_action"
    assert p["instrument"]    == "skg-host-toolchain"
    assert p["target"]        == "192.168.1.5"
    assert p["wicket_id"]     == "SMB-01"
    assert "command" in p
    assert p["status"]        == "pending"

    # Proposal file must exist
    proposal_files = list(tmp_path.glob("*.json"))
    assert len(proposal_files) == 1
    on_disk = json.loads(proposal_files[0].read_text())
    assert on_disk["id"] == p["id"]


def test_null_instrument_skipped(tmp_path):
    """If LLM says instrument is null, no proposal is created."""
    llm_output = json.dumps({"instrument": None, "reason": "No applicable instrument."})
    landscape = _make_landscape(torque=2.0)
    with mock.patch("skg.sensors.dark_hypothesis_sensor._call_llm", return_value=llm_output), \
         mock.patch("skg.sensors.dark_hypothesis_sensor._PROPOSALS_DIR", tmp_path):
        results = plan_dark_hypotheses(landscape, min_torque=1.0)
    assert results == []
    assert list(tmp_path.glob("*.json")) == []


def test_invalid_json_skipped(tmp_path):
    """Malformed LLM output is silently skipped without crashing."""
    landscape = _make_landscape(torque=2.0)
    with mock.patch("skg.sensors.dark_hypothesis_sensor._call_llm",
                    return_value="this is not json"), \
         mock.patch("skg.sensors.dark_hypothesis_sensor._PROPOSALS_DIR", tmp_path):
        results = plan_dark_hypotheses(landscape, min_torque=1.0)
    assert results == []


def test_max_proposals_respected(tmp_path):
    """max_proposals caps the number of cognitive_action proposals created."""
    # 5 dark hypotheses at high torque
    landscape = [
        {
            "host": f"192.168.1.{i}",
            "observations": {},
            "wgraph_dark": [
                {"wicket_id": f"SMB-0{i}", "domain": "smb",
                 "label": "SMB", "description": "", "torque": 3.0, "is_dark": True}
            ],
        }
        for i in range(1, 6)
    ]
    llm_output = json.dumps({
        "instrument": "skg-host-toolchain",
        "target":     "192.168.1.1",
        "command":    "echo test",
        "wicket_id":  "SMB-01",
        "rationale":  "test",
    })
    with mock.patch("skg.sensors.dark_hypothesis_sensor._call_llm", return_value=llm_output), \
         mock.patch("skg.sensors.dark_hypothesis_sensor._available_instruments",
                    return_value=[{"name": "skg-host-toolchain", "domain": "host",
                                   "path": "/tmp", "wicket_count": 5}]), \
         mock.patch("skg.sensors.dark_hypothesis_sensor._PROPOSALS_DIR", tmp_path):
        results = plan_dark_hypotheses(landscape, min_torque=1.0, max_proposals=3)

    assert len(results) == 3


def test_build_prompt_contains_wicket_info():
    """The prompt should contain wicket ID, domain, and target."""
    hyp = {"wicket_id": "SMB-01", "domain": "smb", "label": "SMB reachable",
           "description": "SMB exposed", "torque": 2.0}
    instruments = [{"name": "skg-host-toolchain", "domain": "host",
                    "path": "/tmp", "wicket_count": 3}]
    prompt = _build_prompt(hyp, "10.0.0.1", instruments, {"os": "Linux"})
    assert "SMB-01" in prompt
    assert "smb"    in prompt
    assert "10.0.0.1" in prompt
    assert "skg-host-toolchain" in prompt

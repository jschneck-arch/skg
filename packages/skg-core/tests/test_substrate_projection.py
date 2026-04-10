from skg_core.substrate.node import NodeState, TriState
from skg_core.substrate.path import Path
from skg_core.substrate.projection import project_path


def test_project_path_indeterminate_when_unknown_present() -> None:
    path = Path(path_id="host_access", required_nodes=["N1", "N2"])
    states = {
        "N1": NodeState(node_id="N1", state=TriState.REALIZED, confidence=0.9, observed_at="2026-04-01T00:00:00Z"),
    }

    score = project_path(path, states)

    assert score.classification == "indeterminate"
    assert score.realized == ["N1"]
    assert score.unknown == ["N2"]


def test_project_path_not_realized_when_any_blocked() -> None:
    path = Path(path_id="host_access", required_nodes=["N1", "N2"])
    states = {
        "N1": NodeState(node_id="N1", state=TriState.REALIZED, confidence=1.0, observed_at="2026-04-01T00:00:00Z"),
        "N2": NodeState(node_id="N2", state=TriState.BLOCKED, confidence=1.0, observed_at="2026-04-01T00:00:01Z"),
    }

    score = project_path(path, states)

    assert score.classification == "not_realized"
    assert score.blocked == ["N2"]

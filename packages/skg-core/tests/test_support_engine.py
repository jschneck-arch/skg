from datetime import datetime, timedelta, timezone

from skg_core.kernel.observations import Observation
from skg_core.kernel.support import SupportEngine


def test_support_engine_uses_cycle_ids_for_compatibility_span() -> None:
    now = datetime.now(timezone.utc)
    obs1 = Observation(
        instrument="nmap",
        targets=["10.0.0.1"],
        context="HO-01",
        payload={},
        event_time=now - timedelta(minutes=5),
        support_mapping={"10.0.0.1": {"R": 0.8, "B": 0.0, "U": 0.0}},
        cycle_id="run-a",
    )
    obs2 = Observation(
        instrument="nmap",
        targets=["10.0.0.1"],
        context="HO-01",
        payload={},
        event_time=now - timedelta(minutes=4),
        support_mapping={"10.0.0.1": {"R": 0.7, "B": 0.0, "U": 0.0}},
        cycle_id="run-b",
    )

    contribution = SupportEngine().aggregate([obs1, obs2], "10.0.0.1", "HO-01", now)

    assert contribution.realized > 0.0
    assert contribution.compatibility_span == 2

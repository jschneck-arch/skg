from skg_protocol.events import build_event_envelope, build_precondition_payload
from skg_protocol.validation.assistant import classify_assistant_event
from skg_protocol.validation.envelope import validate_event_envelope


def test_build_event_envelope_and_validate() -> None:
    payload = build_precondition_payload(
        wicket_id="HO-01",
        domain="host",
        workload_id="host::10.0.0.5:22",
        realized=True,
    )
    event = build_event_envelope(
        event_type="obs.attack.precondition",
        source_id="sensor.ssh_collect",
        toolchain="host",
        payload=payload,
        evidence_rank=1,
        source_kind="sensor",
        pointer="ssh://10.0.0.5",
        confidence=0.95,
    )

    assert validate_event_envelope(event) == []
    assert event["source"]["toolchain"] == "skg-host-toolchain"


def test_assistant_event_requires_custody_for_observation() -> None:
    event = {
        "source": {"source_id": "assistant.writer"},
        "payload": {"assistant_output_class": "observed_evidence"},
        "provenance": {"evidence": {"source_kind": "assistant"}},
    }

    cls = classify_assistant_event(event)

    assert cls["is_assistant"] is True
    assert cls["observation_admissible"] is False

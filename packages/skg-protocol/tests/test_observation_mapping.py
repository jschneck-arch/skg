from skg_protocol.observation_mapping import map_event_to_observation_mapping


def test_map_event_to_observation_mapping_realized() -> None:
    event = {
        "id": "evt-1",
        "ts": "2026-04-01T12:00:00+00:00",
        "type": "obs.attack.precondition",
        "source": {
            "source_id": "sensor.ssh_collect",
            "toolchain": "skg-host-toolchain",
            "version": "1.0.0",
        },
        "payload": {
            "wicket_id": "HO-01",
            "status": "realized",
            "identity_key": "10.0.0.5",
        },
        "provenance": {
            "evidence_rank": 1,
            "evidence": {
                "source_kind": "sensor",
                "pointer": "ssh://10.0.0.5",
                "collected_at": "2026-04-01T12:00:00+00:00",
                "confidence": 0.95,
            },
        },
    }

    mapped = map_event_to_observation_mapping(event, cycle_id="cycle-123")

    assert mapped is not None
    assert mapped.instrument == "ssh_collect"
    assert mapped.targets == ["10.0.0.5"]
    assert mapped.context == "HO-01"
    assert mapped.decay_class == "operational"
    assert mapped.cycle_id == "cycle-123"
    assert mapped.support_mapping["10.0.0.5"] == {"R": 0.95, "B": 0.0, "U": 0.0}


def test_map_event_to_observation_mapping_prefers_payload_cycle_id() -> None:
    event = {
        "id": "evt-2",
        "ts": "2026-04-01T12:01:00+00:00",
        "type": "obs.attack.precondition",
        "source": {
            "source_id": "sensor.web_active",
            "toolchain": "skg-web-toolchain",
            "version": "1.0.0",
        },
        "payload": {
            "node_id": "WEB-01",
            "status": "unknown",
            "workload_id": "web::https://portal.example.org:443",
            "gravity_cycle_id": "payload-cycle",
        },
        "provenance": {
            "evidence_rank": 2,
            "evidence": {
                "source_kind": "sensor",
                "pointer": "https://portal.example.org",
                "collected_at": "2026-04-01T12:01:00+00:00",
                "confidence": 0.8,
            },
        },
    }

    mapped = map_event_to_observation_mapping(event, cycle_id="arg-cycle")

    assert mapped is not None
    assert mapped.targets == ["portal.example.org"]
    assert mapped.context == "WEB-01"
    assert mapped.decay_class == "structural"
    assert mapped.cycle_id == "payload-cycle"
    assert mapped.support_mapping["portal.example.org"] == {"R": 0.0, "B": 0.0, "U": 0.8}


def test_map_event_to_observation_mapping_drops_inadmissible_assistant_event() -> None:
    event = {
        "source": {"source_id": "assistant.writer"},
        "payload": {
            "wicket_id": "HO-01",
            "status": "realized",
            "assistant_output_class": "observed_evidence",
        },
        "provenance": {
            "evidence": {
                "source_kind": "assistant",
            }
        },
    }

    mapped = map_event_to_observation_mapping(event)

    assert mapped is None

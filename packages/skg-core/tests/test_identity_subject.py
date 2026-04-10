from skg_core.identity.subject import canonical_observation_subject, parse_workload_ref


def test_parse_workload_ref_extracts_domain_and_identity() -> None:
    parsed = parse_workload_ref("web::10.0.0.5:8443")

    assert parsed["domain_hint"] == "web"
    assert parsed["identity_key"] == "10.0.0.5"


def test_canonical_subject_prefers_explicit_target_ip() -> None:
    subject = canonical_observation_subject(
        payload={"workload_id": "host::app.internal:443", "target_ip": "192.0.2.10"}
    )

    assert subject["identity_key"] == "192.0.2.10"
    assert subject["target_ip"] == "192.0.2.10"

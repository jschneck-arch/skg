from __future__ import annotations

import json
from pathlib import Path

import skg_services.gravity.web_runtime as web_runtime


def test_surface_runtime_wrapper_emits_canonical_events(monkeypatch, tmp_path: Path) -> None:
    profile = {
        "base_url": "https://demo.local",
        "scheme": "https",
        "host": "demo.local",
        "port": 443,
        "reachable": True,
        "response_headers": {
            "Server": "nginx/1.24.0",
            "Access-Control-Allow-Origin": "*",
        },
        "cors": {
            "acao": "*",
            "acac": "true",
        },
        "tls": {
            "tls_version": "TLSv1.2",
            "cipher_name": "TLS_AES_128_GCM_SHA256",
            "cipher_bits": 128,
            "issues": [],
        },
        "missing_security_headers": ["content-security-policy"],
        "source_kind": "surface.profile",
    }
    monkeypatch.setattr(web_runtime, "collect_surface_profile", lambda *_args, **_kwargs: profile)

    out_path = tmp_path / "surface.ndjson"
    events = web_runtime.collect_surface_events_to_file(
        "https://demo.local",
        out_path=out_path,
        attack_path_id="web_surface_v1",
        run_id="rid-surface",
        workload_id="web::demo.local",
    )

    assert out_path.exists()
    assert events
    assert all(event["type"] == "obs.attack.precondition" for event in events)
    assert all(event["source"]["toolchain"] == "skg-web-toolchain" for event in events)

    rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert rows
    wicket_ids = {row["payload"]["wicket_id"] for row in rows}
    assert {"WB-01", "WB-02", "WB-18", "WB-19", "WB-17"} <= wicket_ids


def test_nikto_runtime_wrapper_maps_findings_with_canonical_adapter(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        web_runtime,
        "_run_nikto_scan",
        lambda *_args, **_kwargs: [
            {"msg": "SQL injection detected in id parameter", "url": "http://demo.local/item.php?id=1"},
            {"msg": "Server version leak found", "url": "http://demo.local/"},
        ],
    )

    out_path = tmp_path / "nikto.ndjson"
    events = web_runtime.collect_nikto_events_to_file(
        "http://demo.local",
        out_path=out_path,
        out_dir=tmp_path,
        attack_path_id="web_surface_v1",
        run_id="rid-nikto",
        workload_id="web::demo.local",
    )

    assert out_path.exists()
    assert events

    wicket_ids = {event["payload"]["wicket_id"] for event in events}
    assert "WB-41" in wicket_ids
    assert "WB-02" in wicket_ids

    rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == len(events)


def test_auth_runtime_wrapper_emits_default_credential_signal(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        web_runtime,
        "_load_auth_runtime_policy",
        lambda: {
            "max_default_attempts": 2,
            "default_credentials": [
                {"username": "guest", "password": "guest"},
                {"username": "admin", "password": "admin"},
            ],
        },
    )

    admin_auth = "Basic YWRtaW46YWRtaW4="

    def _fake_http_request(_url: str, *, timeout: float, headers: dict[str, str] | None = None):
        hdrs = headers or {}
        auth = str(hdrs.get("Authorization") or "")
        if "Origin" in hdrs:
            return {
                "reachable": True,
                "status": 200,
                "url": "http://demo.local",
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
                "error": "",
            }
        if auth:
            if auth == admin_auth:
                return {
                    "reachable": True,
                    "status": 200,
                    "url": "http://demo.local",
                    "headers": {"Server": "nginx/1.24.0"},
                    "error": "",
                }
            return {
                "reachable": True,
                "status": 401,
                "url": "http://demo.local",
                "headers": {"WWW-Authenticate": "Basic"},
                "error": "",
            }
        return {
            "reachable": True,
            "status": 200,
            "url": "http://demo.local",
            "headers": {"Server": "nginx/1.24.0"},
            "error": "",
        }

    monkeypatch.setattr(web_runtime, "_http_request", _fake_http_request)

    out_path = tmp_path / "auth.ndjson"
    events = web_runtime.collect_auth_surface_events_to_file(
        "http://demo.local",
        out_path=out_path,
        attack_path_id="web_sqli_to_shell_v1",
        run_id="rid-auth",
        workload_id="web::demo.local",
        try_defaults=True,
        timeout=5.0,
    )

    assert out_path.exists()
    assert events
    assert all(event["source"]["toolchain"] == "skg-web-toolchain" for event in events)

    by_wicket = {event["payload"]["wicket_id"]: event for event in events}
    assert "WB-10" in by_wicket
    assert by_wicket["WB-10"]["payload"]["status"] == "realized"


def test_migrated_callsites_do_not_reference_legacy_auth_entrypoints() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    target_py = (repo_root / "skg" / "cli" / "commands" / "target.py").read_text(encoding="utf-8")
    gravity_py = (repo_root / "skg-gravity" / "gravity_field.py").read_text(encoding="utf-8")

    assert "skg-web-toolchain/adapters/web_active/collector.py" not in target_py
    assert "from collector import collect" not in gravity_py
    assert "skg-web-toolchain/adapters/web_active/nikto_adapter.py" not in gravity_py
    assert "skg-web-toolchain/adapters/web_active/auth_scanner.py" not in target_py
    assert "from auth_scanner import auth_scan" not in gravity_py
    assert 'WEB_ADAPTER / "auth_scanner.py"' not in gravity_py

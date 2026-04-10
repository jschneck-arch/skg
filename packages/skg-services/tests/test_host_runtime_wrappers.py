from __future__ import annotations

import json
from pathlib import Path

import skg_services.gravity.host_runtime as host_runtime


class _FakeChan:
    def __init__(self, rc: int):
        self._rc = rc

    def recv_exit_status(self) -> int:
        return self._rc


class _FakeStream:
    def __init__(self, payload: str, rc: int = 0):
        self._payload = payload
        self.channel = _FakeChan(rc)

    def read(self) -> bytes:
        return self._payload.encode("utf-8")


class _FakeSshClient:
    def __init__(self, outputs: dict[str, tuple[str, str, int]]):
        self._outputs = outputs

    def exec_command(self, cmd: str, timeout: int = 15):
        out, err, rc = self._outputs.get(cmd, ("", "", 0))
        return None, _FakeStream(out, rc), _FakeStream(err, rc)


class _FakeWinrmResult:
    def __init__(self, out: str, rc: int = 0):
        self.std_out = out.encode("utf-8")
        self.status_code = rc


class _FakeWinrmSession:
    def __init__(self, outputs: dict[str, tuple[str, int]]):
        self._outputs = outputs

    def run_ps(self, cmd: str):
        out, rc = self._outputs.get(cmd, ("", 0))
        return _FakeWinrmResult(out, rc)


def test_collect_ssh_session_assessment_to_file_emits_canonical_host_events(tmp_path: Path) -> None:
    client = _FakeSshClient(
        {
            "id": ("uid=0(root) gid=0(root) groups=0(root)", "", 0),
            "sudo -l -n 2>&1": ("(ALL) NOPASSWD: ALL", "", 0),
            "uname -r": ("5.10.0-kali9-amd64", "", 0),
        }
    )

    out_path = tmp_path / "host_ssh_runtime.ndjson"
    events = host_runtime.collect_ssh_session_assessment_to_file(
        client,
        host="192.168.56.20",
        out_path=out_path,
        attack_path_id="host_linux_privesc_sudo_v1",
        run_id="run-host-runtime-ssh",
        workload_id="ssh::192.168.56.20",
        username="msfadmin",
        auth_type="password",
        port=22,
    )

    assert out_path.exists()
    assert events

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["HO-01"]["payload"]["status"] == "realized"
    assert by_wicket["HO-03"]["payload"]["status"] == "realized"
    assert by_wicket["HO-10"]["payload"]["status"] == "realized"
    assert by_wicket["HO-06"]["payload"]["status"] == "realized"

    rows = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == len(events)
    assert all(row.get("source", {}).get("toolchain") == "skg-host-toolchain" for row in rows)


def test_collect_winrm_session_assessment_emits_canonical_host_events() -> None:
    session = _FakeWinrmSession(
        {
            "whoami /groups": ("BUILTIN\\\\Administrators\nS-1-5-32-544", 0),
            "Get-ChildItem Env: | ConvertTo-Json -Compress": ("[{\"Name\":\"API_KEY\",\"Value\":\"demo\"}]", 0),
        }
    )

    events = host_runtime.collect_winrm_session_assessment(
        session,
        host="192.168.56.30",
        attack_path_id="host_winrm_initial_access_v1",
        run_id="run-host-runtime-winrm",
        workload_id="winrm::192.168.56.30",
        username="Administrator",
        port=5985,
    )

    by_wicket = {event.get("payload", {}).get("wicket_id"): event for event in events}
    assert by_wicket["HO-04"]["payload"]["status"] == "realized"
    assert by_wicket["HO-05"]["payload"]["status"] == "realized"
    assert by_wicket["HO-10"]["payload"]["status"] == "realized"


def test_ssh_sensor_winrm_runtime_routes_only_through_canonical_host_service(
    monkeypatch, tmp_path: Path
) -> None:
    from skg.sensors.ssh_sensor import SshSensor

    expected_events = [
        {
            "payload": {"wicket_id": "HO-04", "status": "realized"},
            "source": {"source_id": "adapter.host_winrm_assessment"},
        }
    ]
    captured: dict[str, object] = {}

    def _fake_collect(
        host: str,
        *,
        attack_path_id: str,
        run_id: str,
        workload_id: str,
        username: str,
        password: str,
        port: int,
        ssl: bool,
    ) -> list[dict]:
        captured.update(
            {
                "host": host,
                "attack_path_id": attack_path_id,
                "run_id": run_id,
                "workload_id": workload_id,
                "username": username,
                "password": password,
                "port": port,
                "ssl": ssl,
            }
        )
        return expected_events

    monkeypatch.setenv("DEMO_WINRM_PASS", "demo-secret")
    monkeypatch.setattr(host_runtime, "collect_winrm_assessment", _fake_collect)

    sensor = SshSensor({"collect_interval_s": 300}, events_dir=tmp_path)
    events = sensor._collect_winrm(
        {
            "user": "Administrator",
            "password": "${DEMO_WINRM_PASS}",
            "port": 5986,
            "ssl": True,
        },
        "10.10.10.20",
        "winrm::10.10.10.20",
        "host_winrm_initial_access_v1",
        "run-host-convergence-1",
    )

    # Returned events must come only from the canonical host runtime wrapper.
    assert events == expected_events
    assert captured == {
        "host": "10.10.10.20",
        "attack_path_id": "host_winrm_initial_access_v1",
        "run_id": "run-host-convergence-1",
        "workload_id": "winrm::10.10.10.20",
        "username": "Administrator",
        "password": "demo-secret",
        "port": 5986,
        "ssl": True,
    }


def test_migrated_host_callsites_no_longer_require_legacy_host_adapter_parse() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    adapter_runner_py = (repo_root / "skg" / "sensors" / "adapter_runner.py").read_text(encoding="utf-8")
    ssh_sensor_py = (repo_root / "skg" / "sensors" / "ssh_sensor.py").read_text(encoding="utf-8")
    gravity_field_py = (repo_root / "skg-gravity" / "gravity_field.py").read_text(encoding="utf-8")
    legacy_ssh_collect_py = (
        repo_root / "skg-host-toolchain" / "adapters" / "ssh_collect" / "parse.py"
    ).read_text(encoding="utf-8")
    legacy_winrm_collect_py = (
        repo_root / "skg-host-toolchain" / "adapters" / "winrm_collect" / "parse.py"
    ).read_text(encoding="utf-8")

    assert '_adapter_module("skg-host-toolchain", "ssh_collect")' not in adapter_runner_py
    assert "collect_ssh_session_assessment(" in ssh_sensor_py
    assert "collect_winrm_assessment(" in ssh_sensor_py
    assert "run_net_sandbox(" not in ssh_sensor_py
    assert "eval_ho04_winrm_exposed" not in ssh_sensor_py
    assert "eval_ho05_winrm_credential" not in ssh_sensor_py
    assert "from skg.sensors.adapter_runner import run_ssh_host" not in gravity_field_py

    # Legacy entrypoints are now explicit canonical compatibility wrappers.
    assert "Legacy compatibility wrapper for canonical host SSH runtime collection." in legacy_ssh_collect_py
    assert "collect_ssh_assessment_to_file" in legacy_ssh_collect_py
    assert "Legacy compatibility wrapper for canonical host WinRM runtime collection." in legacy_winrm_collect_py
    assert "collect_winrm_assessment_to_file" in legacy_winrm_collect_py

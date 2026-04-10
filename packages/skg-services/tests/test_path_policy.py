from pathlib import Path

from skg_services.gravity.path_policy import (
    build_service_path_policy,
    ensure_runtime_dirs,
)


def test_service_path_policy_uses_core_and_service_overrides() -> None:
    policy = build_service_path_policy(
        env={
            "SKG_HOME": "/tmp/skg-root",
            "SKG_STATE_DIR": "/tmp/skg-state",
            "SKG_CONFIG_DIR": "/tmp/skg-config",
            "SKG_RESONANCE_DIR": "/tmp/skg-resonance",
            "SKG_FORGE_STAGING": "/tmp/skg-forge",
            "SKG_LOG_FILE": "/tmp/skg-logs/custom.log",
            "MSF_DIR": "/tmp/skg-msf",
            "BH_DIR": "/tmp/skg-bh",
        },
        cwd=Path("/tmp/ignored"),
    )

    assert str(policy.root_dir) == "/tmp/skg-root"
    assert str(policy.state_dir) == "/tmp/skg-state"
    assert str(policy.config_dir) == "/tmp/skg-config"
    assert str(policy.events_dir) == "/tmp/skg-state/events"
    assert str(policy.delta_dir) == "/tmp/skg-state/delta"
    assert str(policy.resonance_dir) == "/tmp/skg-resonance"
    assert str(policy.forge_staging_dir) == "/tmp/skg-forge"
    assert str(policy.log_file) == "/tmp/skg-logs/custom.log"
    assert str(policy.msf_dir) == "/tmp/skg-msf"
    assert str(policy.bloodhound_dir) == "/tmp/skg-bh"


def test_service_ensure_runtime_dirs_creates_service_tree(tmp_path: Path) -> None:
    policy = build_service_path_policy(
        env={
            "SKG_HOME": str(tmp_path),
            "SKG_STATE_DIR": str(tmp_path / "state"),
            "SKG_CONFIG_DIR": str(tmp_path / "config"),
        },
        cwd=tmp_path,
    )

    ensure_runtime_dirs(policy)

    assert policy.cve_dir.exists()
    assert policy.resonance_index_dir.exists()
    assert policy.resonance_records_dir.exists()
    assert policy.resonance_drafts_dir.exists()
    assert policy.forge_staging_dir.exists()
    assert policy.log_dir.exists()
    assert policy.brain_dir.exists()
    assert (policy.delta_dir / "snapshots").exists()
    assert (policy.delta_dir / "transitions").exists()


def test_active_runtime_no_longer_imports_legacy_paths_module() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    runtime_root = repo_root / "skg"

    offenders: list[str] = []
    for path in runtime_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "from skg.core.paths import" in text:
            offenders.append(str(path.relative_to(repo_root)))

    assert offenders == []

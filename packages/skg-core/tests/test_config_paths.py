from pathlib import Path

from skg_core.config.paths import ensure_runtime_dirs, resolve_paths


def test_resolve_paths_prefers_skg_home_and_env_overrides() -> None:
    paths = resolve_paths(
        env={
            "SKG_HOME": "/tmp/skg-home",
            "SKG_STATE_DIR": "/tmp/skg-state",
            "SKG_CONFIG_DIR": "/tmp/skg-config",
        },
        cwd=Path("/tmp/ignored"),
    )

    assert str(paths.root_dir) == "/tmp/skg-home"
    assert str(paths.state_dir) == "/tmp/skg-state"
    assert str(paths.config_dir) == "/tmp/skg-config"
    assert str(paths.events_dir) == "/tmp/skg-state/events"
    assert str(paths.delta_dir) == "/tmp/skg-state/delta"


def test_resolve_paths_uses_cwd_without_env() -> None:
    paths = resolve_paths(env={}, cwd=Path("/tmp/skg-cwd"))

    assert str(paths.root_dir) == "/tmp/skg-cwd"
    assert str(paths.state_dir) == "/tmp/skg-cwd/.skg/state"
    assert str(paths.config_dir) == "/tmp/skg-cwd/config"


def test_ensure_runtime_dirs_creates_core_tree(tmp_path: Path) -> None:
    paths = resolve_paths(
        env={
            "SKG_HOME": str(tmp_path),
            "SKG_STATE_DIR": str(tmp_path / "state"),
            "SKG_CONFIG_DIR": str(tmp_path / "config"),
        },
        cwd=tmp_path,
    )

    ensure_runtime_dirs(paths)

    assert paths.state_dir.exists()
    assert paths.events_dir.exists()
    assert paths.interp_dir.exists()
    assert paths.discovery_dir.exists()
    assert paths.graph_dir.exists()
    assert paths.proposals_dir.exists()
    assert (paths.delta_dir / "snapshots").exists()
    assert (paths.delta_dir / "transitions").exists()

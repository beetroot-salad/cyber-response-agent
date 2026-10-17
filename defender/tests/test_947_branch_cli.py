"""#947 — the family launcher's refusals that nothing later could recover from."""
from __future__ import annotations

from defender.run_repository import Run

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests._alert_plant import plant_alert
from defender import _episode_handle as EH


def cli_mod():
    """`defender.learning.branch.cli` — imported per test, so a missing target is one failure
    per test rather than one collection error for the file."""
    return importlib.import_module("defender.learning.branch.cli")


@pytest.fixture
def tenant_paths(tmp_path, monkeypatch):
    """#1078: `episodes_root`'s refused/accepted zones are judged against a TENANT's data root now, not a single configured runs base."""
    from defender.tests._data_root_1078 import set_up_tenant

    root = tmp_path / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    return set_up_tenant(root, "acme")


def _tree(root: Path) -> list[str]:
    """Every path under `root`, sorted — a refusal's no-write claim is compared on this."""
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


@pytest.fixture
def episodes_root(tmp_path, monkeypatch):
    """The CONFIGURED episodes root, through the env var #947 anchors it on."""
    root = tmp_path / "episodes-root"
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(root))
    return root


#: #1078 D4/J52: the two cases pinning the pre-#1078 distant-source pre-check (a source run


@pytest.mark.parametrize("episode_id", ["../escaped", "/tmp/escaped", "nested/episode"])
def test_an_episode_id_that_is_not_one_safe_component_is_refused_before_priming(
        tmp_path, tenant_paths, episodes_root, episode_id):
    """Absolute and traversing episode ids never reach the capture writer."""
    cli = cli_mod()
    # #1120: an accepted tenant's data root exists before the launcher runs, so "created
    # nothing under the data root" is compared on its tree rather than on its absence.
    data_root = tenant_paths.dir.parent
    before = _tree(data_root)

    def primed_too_early(*_args, **_kwargs):
        pytest.fail("prime_base was called before the episode id was validated")

    with pytest.raises(SystemExit, match="episode id"):
        cli.prepare_episode(episode_id, Run(tmp_path / "source", runs_base=None), data_root=tenant_paths.data_root,
                            prime=primed_too_early)

    assert not episodes_root.exists()
    assert _tree(data_root) == before, "the refused priming wrote under the data root"


def test_a_safe_episode_id_resolves_beneath_the_configured_episodes_root(
        tenant_paths, episodes_root):
    """The positive control for the path-component refusal."""
    assert EH.episode_dir(tenant_paths.data_root, "episode-001") == (
        episodes_root / "episode-001")
    assert tenant_paths.dir.parent not in (episodes_root / "episode-001").parents


def test_an_existing_episode_is_refused_even_if_only_stale_world_rows_remain(
        tmp_path, tenant_paths, episodes_root):
    """Reusing an episode id cannot revive old per-world live-base rows."""
    from defender.learning.branch.capture import PrimeReport

    cli = cli_mod()
    episode = episodes_root / "episode-001"
    stale = episode / "served" / "w1.jsonl"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('{"source":"base","world_id":null}\n', encoding="utf-8")
    primed: list[Path] = []

    def prime(_source, claimed):
        primed.append(claimed.dir)
        return PrimeReport()

    plant_alert(tmp_path / "source", {"rule": {"id": "r"}})
    with cli.prepare_episode("episode-001", Run.at(tmp_path / "source"), data_root=tenant_paths.data_root,
                             prime=prime) as fresh:
        assert fresh.dir == episodes_root / "episode-001-r2"
        assert list((fresh.dir / "served").glob("*.jsonl")) == []

    assert primed == [episodes_root / "episode-001-r2"], "the stale episode was primed"
    assert stale.read_text(encoding="utf-8") == '{"source":"base","world_id":null}\n', (
        "the relaunch should not mutate or sanitize the stale episode")


def test_the_launcher_bootstraps_the_package_when_invoked_by_path(tmp_path):
    """The documented ``python3 defender/learning/branch/cli.py`` shape reaches argparse."""
    cli_path = Path(__file__).resolve().parents[1] / "learning" / "branch" / "cli.py"
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)

    proc = subprocess.run(  # noqa: S603 — fixed in-repo launcher and interpreter
        [sys.executable, str(cli_path), "--help"], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert "usage: branch" in proc.stdout


# RETIRED AT #947: `test_an_unknown_world_system_is_refused_before_the_episode_is_primed`.

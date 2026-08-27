"""#947 — the family launcher's one refusal that is not recoverable later.

`learning/branch/cli.py` is what actually runs an episode: it parses the worlds, primes the
capture, and drives each sibling. Almost everything it can get wrong fails loudly on the spot.
One thing does not.

`open_source_store` derives the source run's `runs_base` as `run_dir.parent` — the same
derivation `driver._default_store_factory` made when the store was written — and then checks it
against the path the writer recorded in the run's case pointer. So a source run parked anywhere
but DIRECTLY under the runs base resolves to a database that was never its own: `open_store`
creates-if-missing, so the handle is live and empty, and the failure surfaces later as
`main_session_id` finding no root session, naming neither the run dir nor the launcher.

Refused at the launcher, where the operator's own argument is still in hand.
"""
from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest


def cli_mod():
    """`defender.learning.branch.cli` — imported per test, so a missing target is one failure
    per test rather than one collection error for the file."""
    return importlib.import_module("defender.learning.branch.cli")


@pytest.fixture
def runs_base(tmp_path, monkeypatch):
    """The runs base this process resolves, through the env var that anchors it.

    `setenv`, never `setattr`: the environment IS the seam `resolve_runs_base` reads, and the
    launcher has to consult it at call time rather than at import — a module-level capture would
    make the refusal depend on which order the test files were collected in.
    """
    base = tmp_path / "defender-runs"
    base.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(base))
    return base


@pytest.mark.parametrize("where", ["nested", "elsewhere", "the-base-itself"])
def test_a_source_run_parked_off_the_runs_base_is_refused_at_the_launcher(
        tmp_path, runs_base, where):
    """    A source run dir that does not sit directly under the runs base exits rather than
    branching.

    Each shape derives a `runs_base` one level off from the one the source run was written
    under, and each therefore resolves to a well-formed path holding no database at all. That is
    the worst kind of wrong input here: it does not fail, it succeeds against nothing, and the
    fork then inherits an empty lineage while every message downstream names the store rather
    than the argument that chose it.

    `SystemExit`, because this is an operator's own command line — the launcher's failure mode
    is an exit with a message, not a traceback out of a library frame."""
    source = {
        "nested": runs_base / "batch" / "run-source",
        "elsewhere": tmp_path / "somewhere-else" / "run-source",
        "the-base-itself": runs_base,
    }[where]
    source.mkdir(parents=True, exist_ok=True)

    with pytest.raises(SystemExit):
        cli_mod().refuse_distant_source(Path(source))


def test_a_run_directly_under_the_runs_base_is_accepted(tmp_path, runs_base):
    """    The positive control: the ordinary run dir — `<runs base>/<run id>` — is admitted.

    Without it the refusal above is satisfied by a launcher that refuses every source, which
    would be a batch that can never be run at all."""
    source = runs_base / "20260525T153045Z-canary"
    source.mkdir(parents=True, exist_ok=True)

    cli_mod().refuse_distant_source(Path(source))


@pytest.mark.parametrize("episode_id", ["../escaped", "/tmp/escaped", "nested/episode"])
def test_an_episode_id_that_is_not_one_safe_component_is_refused_before_priming(
        tmp_path, runs_base, episode_id):
    """Absolute and traversing episode ids never reach the capture writer.

    ``prepare_episode`` writes before run-id materialization, so relying on the later run-dir
    validation is too late. A bomb in ``prime_base`` makes the ordering observable: the unsafe
    id must exit while it is still just an argument.

    Handed in through ``prepare_episode``'s own injection seam rather than patched onto the
    module, so the arm drives the production call path instead of a rebound global.
    """
    cli = cli_mod()

    def primed_too_early(*_args, **_kwargs):
        pytest.fail("prime_base was called before the episode id was validated")

    with pytest.raises(SystemExit, match="episode-id"):
        cli.prepare_episode(tmp_path / "source", episode_id, primed_too_early)

    assert not (runs_base / "episodes").exists()


def test_a_safe_episode_id_resolves_beneath_the_episode_root(runs_base):
    """The positive control for the path-component refusal."""
    assert cli_mod().episode_dir_for("episode-001") == runs_base / "episodes" / "episode-001"


def test_an_existing_episode_is_refused_even_if_only_stale_world_rows_remain(
        tmp_path, runs_base):
    """Reusing an episode id cannot revive old per-world live-base rows.

    Checking only ``served/base.jsonl`` misses a partly removed or partly failed episode. Its
    world ledger still participates in ``Ledger._absorb`` and can override live reads for keys
    the new source never captured, so the episode directory itself is the immutable unit.

    Handed in through ``prepare_episode``'s own injection seam rather than patched onto the
    module, so the arm drives the production call path instead of a rebound global.
    """
    cli = cli_mod()
    episode = runs_base / "episodes" / "episode-001"
    stale = episode / "served" / "w1.jsonl"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('{"source":"base","world_id":null}\n', encoding="utf-8")

    def primed_too_early(*_args, **_kwargs):
        pytest.fail("prime_base ran for an episode id that already exists")

    with pytest.raises(cli.LedgerError, match="already exists"):
        cli.prepare_episode(tmp_path / "source", "episode-001", primed_too_early)

    assert stale.is_file(), "the refusal should not mutate or sanitize the stale episode"


def test_the_launcher_bootstraps_the_package_when_invoked_by_path(tmp_path):
    """The documented ``python3 defender/learning/branch/cli.py`` shape reaches argparse.

    The subprocess has no pytest-injected ``PYTHONPATH`` and starts outside the repository, so
    only the launcher's own bootstrap can make ``defender.*`` imports and its branch siblings
    resolvable. ``--help`` stops before any run or external dependency is touched.
    """
    cli_path = Path(__file__).resolve().parents[1] / "learning" / "branch" / "cli.py"
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)

    proc = subprocess.run(  # noqa: S603 — fixed in-repo launcher and interpreter
        [sys.executable, str(cli_path), "--help"], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert "usage: branch" in proc.stdout


def test_an_unknown_world_system_is_refused_before_the_episode_is_primed(
        tmp_path, runs_base):
    """A misspelt touch cannot become a successful all-passthrough sibling."""
    source = runs_base / "source-run"
    source.mkdir()

    with pytest.raises(SystemExit, match="elastc"):
        cli_mod().main([
            str(source), "1", "--episode-id", "episode-001",
            "--world", "w:elastc", "--continuation-prompt", "continue",
        ])

    assert not (runs_base / "episodes").exists()

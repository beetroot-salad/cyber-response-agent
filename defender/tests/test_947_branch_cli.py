"""#947 — the family launcher's refusals that nothing later could recover from.

`learning/branch/cli.py` is what actually runs an episode: it derives the episode id, primes the
capture, has the questioner author the triplet, stages it, reviews it and drives each sibling as
its own process. Almost everything it can get wrong fails loudly on the spot. The ones here do
not, or fail somewhere that names the wrong cause.

RECONCILED AT #947. This file predates the §7 seam and pinned the pre-#947 launcher: an episode
directory under the runs base, `--episode-id` and `--world` as operator arguments, and
`World.touches` as an authored field. All three are retired by decisions recorded in
`spec-flow/specs/spec_graph_947.yaml`'s `handoff.forks` — F5-EPISODE-ROOT (the episodes root is
a CONFIGURED location outside both the runs base and the checkout, never derived from either),
D2 (`touches` is derived from the overlay) and the derived episode id (an episode IS a (source
run, branch point) pair, so an operator-chosen id is a second name for something that already
has one). The assertions below are the same INTENTS against the contract those decisions left;
the two arms whose mechanism #947 deletes outright are retired with a note saying which #947
demand carries their intent now.
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


@pytest.fixture
def episodes_root(tmp_path, monkeypatch):
    """The CONFIGURED episodes root, through the env var #947 anchors it on.

    A second root rather than a derivation, and steered the same way the runs base is: after
    §7 round 2 the two are independent facts, and a test that let one imply the other would
    assert about a layout the launcher refuses to build.
    """
    root = tmp_path / "episodes-root"
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(root))
    return root


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
        tmp_path, runs_base, episodes_root, episode_id):
    """Absolute and traversing episode ids never reach the capture writer.

    ``prepare_episode`` writes before run-id materialization, so relying on the later run-dir
    validation is too late. A bomb in ``prime_base`` makes the ordering observable: the unsafe
    id must exit while it is still just an argument.

    Handed in through ``prepare_episode``'s own injection seam rather than patched onto the
    module, so the arm drives the production call path instead of a rebound global.

    #947: the id is now DERIVED from (source run, branch point) rather than supplied, and the
    episode lands under the CONFIGURED episodes root — but `prepare_episode` is still reachable
    programmatically, and it is still the frame that writes first, so the component rule is
    still its own to enforce.
    """
    cli = cli_mod()

    def primed_too_early(*_args, **_kwargs):
        pytest.fail("prime_base was called before the episode id was validated")

    with pytest.raises(SystemExit, match="episode id"):
        cli.prepare_episode(episode_id, tmp_path / "source", primed_too_early)

    assert not episodes_root.exists()
    assert not (runs_base / "episodes").exists()


def test_a_safe_episode_id_resolves_beneath_the_configured_episodes_root(
        runs_base, episodes_root):
    """The positive control for the path-component refusal.

    #947 (F5-EPISODE-ROOT): the root is READ FROM CONFIGURATION and is never derived from the
    runs base — deriving it is what put `episodes/` back inside the tree every runs-base walker
    descends and inside the checkout a sibling's own stamp is taken over."""
    assert cli_mod().episode_dir_for("episode-001") == episodes_root / "episode-001"
    assert runs_base not in (episodes_root / "episode-001").parents


def test_an_existing_episode_is_refused_even_if_only_stale_world_rows_remain(
        tmp_path, runs_base, episodes_root):
    """Reusing an episode id cannot revive old per-world live-base rows.

    Checking only ``served/base.jsonl`` misses a partly removed or partly failed episode. Its
    world ledger still participates in ``Ledger._absorb`` and can override live reads for keys
    the new source never captured, so a directory holding per-world rows is not adoptable.

    #947 (FORK-2) narrows what "already exists" means without weakening this: an episode
    directory that got no further than being MADE is adopted, because a mid-prime death would
    otherwise leave that source and branch point permanently unbranchable. A directory holding
    rows is a different state, and it is still refused.

    Handed in through ``prepare_episode``'s own injection seam rather than patched onto the
    module, so the arm drives the production call path instead of a rebound global.
    """
    cli = cli_mod()
    episode = episodes_root / "episode-001"
    stale = episode / "served" / "w1.jsonl"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('{"source":"base","world_id":null}\n', encoding="utf-8")

    def primed_too_early(*_args, **_kwargs):
        pytest.fail("prime_base ran for an episode id that already holds rows")

    with pytest.raises(cli.LedgerError, match="per-world rows"):
        cli.prepare_episode("episode-001", tmp_path / "source", primed_too_early)

    assert stale.is_file(), "the refusal should not mutate or sanitize the stale episode"


def test_the_launcher_bootstraps_the_package_when_invoked_by_path(tmp_path):
    """The documented ``python3 defender/learning/branch/cli.py`` shape reaches argparse.

    The subprocess has no pytest-injected ``PYTHONPATH`` and starts outside the repository, so
    only the launcher's own bootstrap can make ``defender.*`` imports and its branch siblings
    resolvable. ``--help`` stops before any run or external dependency is touched — which is
    also why the launcher defers its heavyweight collaborators to the frames that use them.
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


# RETIRED AT #947: `test_an_unknown_world_system_is_refused_before_the_episode_is_primed`.
#
# It drove `--episode-id ... --world w:elastc`, and #947 deletes both arguments: the episode id
# is derived from (source run, branch point), and the worlds are authored by the questioner
# rather than declared on the command line, with `World.touches` retired as an authored field
# (D2). Its INTENT — a misspelt system cannot become a successful all-passthrough sibling — is
# carried by two #947 demands against the mechanism that replaced it:
#   * `test_947_triplet_manifest.py::test_947_a_patch_naming_a_system_outside_the_six_is_refused_by_field`
#     — the loader refuses the overlay key by name, before any world is staged;
#   * `test_947_triplet_manifest.py::test_947_validate_world_touches_takes_the_derived_set`
#     — the estate's own validator still refuses an unknown name, now over the derived set.

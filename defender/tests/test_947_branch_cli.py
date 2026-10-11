"""#947 — the family launcher's refusals that nothing later could recover from.

`learning/branch/cli.py` is what actually runs an episode: it derives the episode id, primes the
capture, has the questioner author the triplet, has pre-flight calibrate each world's oracle
(#1224) and drives each sibling as its own process. Almost everything it can get wrong fails loudly on the spot. The ones here do
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

from defender import _episode_handle as EH


def cli_mod():
    """`defender.learning.branch.cli` — imported per test, so a missing target is one failure
    per test rather than one collection error for the file."""
    return importlib.import_module("defender.learning.branch.cli")


@pytest.fixture
def tenant_paths(tmp_path, monkeypatch):
    """#1078: `episodes_root`'s refused/accepted zones are judged against a TENANT's data root
    now, not a single configured runs base. `setenv`, never `setattr`: the environment is the
    seam `resolve_data_root` reads. #1120: the launcher takes an ACCEPTED `Tenant`, so the
    tenant is set up under that root the way an operator does (`set_up_tenant`)."""
    from defender.tests._data_root_1078 import set_up_tenant

    root = tmp_path / "data"
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    return set_up_tenant(root, "acme")


def _tree(root: Path) -> list[str]:
    """Every path under `root`, sorted — a refusal's no-write claim is compared on this."""
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


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


#: #1078 D4/J52: the two cases pinning the pre-#1078 distant-source pre-check (a source run
#: parked off a single configured runs base; the positive control admitting an ordinary run dir)
#: are RETIRED — that function is deleted (see #1078's pass-A launcher spec, J52). Its
#: intent is carried by `tenant_of_run_dir`'s location check on the launch path
#: (`test_1078_launcher.py::test_d4_launch_location_check` and its neighbors), which this file
#: predates.


@pytest.mark.parametrize("episode_id", ["../escaped", "/tmp/escaped", "nested/episode"])
def test_an_episode_id_that_is_not_one_safe_component_is_refused_before_priming(
        tmp_path, tenant_paths, episodes_root, episode_id):
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
    # #1120: an accepted tenant's data root exists before the launcher runs, so "created
    # nothing under the data root" is compared on its tree rather than on its absence.
    data_root = tenant_paths.dir.parent
    before = _tree(data_root)

    def primed_too_early(*_args, **_kwargs):
        pytest.fail("prime_base was called before the episode id was validated")

    with pytest.raises(SystemExit, match="episode id"):
        cli.prepare_episode(episode_id, tmp_path / "source", data_root=tenant_paths.data_root,
                            prime=primed_too_early)

    assert not episodes_root.exists()
    assert _tree(data_root) == before, "the refused priming wrote under the data root"


def test_a_safe_episode_id_resolves_beneath_the_configured_episodes_root(
        tenant_paths, episodes_root):
    """The positive control for the path-component refusal.

    #947 (F5-EPISODE-ROOT): the root is READ FROM CONFIGURATION and is never derived from the
    data root — deriving it is what put `episodes/` back inside the tree every tenant-tree
    walker descends and inside the checkout a sibling's own stamp is taken over."""
    assert EH.episode_dir(tenant_paths.data_root, "episode-001") == (
        episodes_root / "episode-001")
    assert tenant_paths.dir.parent not in (episodes_root / "episode-001").parents


def test_an_existing_episode_is_refused_even_if_only_stale_world_rows_remain(
        tmp_path, tenant_paths, episodes_root):
    """Reusing an episode id cannot revive old per-world live-base rows.

    Checking only ``served/base.jsonl`` misses a partly removed or partly failed episode. Its
    world ledger still participates in ``Ledger._absorb`` and can override live reads for keys
    the new source never captured, so a directory holding per-world rows is never adopted.

    #1224 (N17) made the rule total: a launch never reuses an episode directory at all — the
    taken id moves on to ``<id>-r2`` — so the stale directory is left exactly as it was, and
    the episode that IS primed is a fresh one holding no row the old one left.

    Handed in through ``prepare_episode``'s own injection seam rather than patched onto the
    module, so the arm drives the production call path instead of a rebound global.
    """
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

    with cli.prepare_episode("episode-001", tmp_path / "source", data_root=tenant_paths.data_root,
                             prime=prime) as fresh:
        assert fresh.dir == episodes_root / "episode-001-r2"
        assert list((fresh.dir / "served").glob("*.jsonl")) == []

    assert primed == [episodes_root / "episode-001-r2"], "the stale episode was primed"
    assert stale.read_text(encoding="utf-8") == '{"source":"base","world_id":null}\n', (
        "the relaunch should not mutate or sanitize the stale episode")


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
# (D2). Its INTENT — a misspelt system cannot become a successful all-passthrough sibling — was
# carried by #947's overlay-key refusals, which #1224 retired with the overlay itself: a world is
# now natural-language `facts` that name no system, and the manifest's `served_systems` is the
# launcher's own derivation from the tenant's gather grant (`cli.served_systems`), overwriting
# whatever the questioner returned — so no authored system name reaches a sibling at all.

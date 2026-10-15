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

    #1187 declared changes 1, 3 and 5: the launcher no longer takes an episode id to claim —
    `runs.create_episode()` mints a UUID (`episode_id_for` and `prepare_episode`'s id argument
    and `-r<n>` loop are gone) — so an unsafe id now meets the episode-id rule wherever an id
    IS read: `episode_id_fault` refuses it, and the repository's door `runs.episode(<id>)`
    refuses it before any path is built, writing nothing under the data root or the configured
    root. Positive control through the same door: the UUID `create_episode` claimed opens.
    (Name kept.)
    """
    from defender._run_id import episode_id_fault

    # #1120: an accepted tenant's data root exists before the launcher runs, so "created
    # nothing under the data root" is compared on its tree rather than on its absence.
    data_root = tenant_paths.dir.parent
    before = _tree(data_root)
    runs = tenant_paths.runs_repository()

    assert episode_id_fault(episode_id), f"the episode-id rule admits {episode_id!r}"
    try:
        with runs.episode(episode_id):
            refused = None
    except Exception as exc:  # noqa: BLE001 — the refusal is the observation
        refused = exc
    assert refused is not None, f"the episode door opened {episode_id!r}"
    assert not isinstance(refused, OSError), (
        f"the door built a path from {episode_id!r} and let the OS answer: {refused!r}")
    assert not episodes_root.exists()
    assert _tree(data_root) == before, "the refused id wrote under the data root"

    with runs.create_episode() as view:
        claimed = view.episode_id
    with runs.episode(claimed) as opened:
        assert opened is not None, "positive control: the claimed episode does not open"


def test_a_safe_episode_id_resolves_beneath_the_configured_episodes_root(
        tenant_paths, episodes_root):
    """The positive control for the path-component refusal: a claimed episode is one safe
    component, a real folder where the tenant's episodes live.

    #1187 declared change 5: that place is no longer READ FROM CONFIGURATION outside the data
    root (F5-EPISODE-ROOT is superseded by Layout A). `runs.create_episode()` claims
    `<data root>/<T>/episodes/<uuid>/` — inside the tenant's own folder — and the configured
    episodes root is neither read nor created. (Name kept.)"""
    from defender.tests.ids_1187 import _spec1187 as S

    with tenant_paths.runs_repository().create_episode() as view:
        episode_id = view.episode_id
    claimed = S.episodes_dir(tenant_paths.data_root, str(tenant_paths.id)) / episode_id
    assert S.is_canonical_uuid(episode_id), f"{episode_id!r} is not a canonical uuid"
    assert claimed.is_dir(), claimed
    assert not claimed.is_symlink(), claimed
    assert tenant_paths.dir in claimed.parents, f"{claimed} is not under the tenant's folder"
    assert not episodes_root.exists(), "the configured episodes root was created"


def test_an_existing_episode_is_refused_even_if_only_stale_world_rows_remain(
        tmp_path, tenant_paths, episodes_root):
    """Reusing an episode cannot revive old per-world live-base rows.

    Checking only ``served/base.jsonl`` misses a partly removed or partly failed episode. Its
    world ledger still participates in ``Ledger._absorb`` and can override live reads for keys
    the new source never captured, so a directory holding per-world rows is never adopted:
    the stale directory is left exactly as it was, and the episode that IS claimed is a fresh
    one holding no row the old one left.

    #1187 declared change 3: a launch claims a fresh UUID episode (`runs.create_episode()`)
    under `<T>/episodes/`, never `<id>-r2` beside a taken derived id. A stale episode folder
    already there — at its own UUID — is never the one handed out. (An exclusive-create
    collision at the minted name refuses with no retry; no seam forces one, see
    `ids_1187/test_1187_layout_isolation.py::test_two_episodes_get_two_fresh_uuid_folders_and_never_a_retry_suffix`.)
    """
    from defender.tests.ids_1187 import _spec1187 as S

    episodes = S.episodes_dir(tenant_paths.data_root, str(tenant_paths.id))
    stale_id = S.new_id()
    stale = episodes / stale_id / "served" / "w1.jsonl"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('{"source":"base","world_id":null}\n', encoding="utf-8")

    with tenant_paths.runs_repository().create_episode() as view:
        fresh = view.episode_id
        assert fresh != stale_id, "the stale episode was handed out"
        assert not fresh.endswith("-r2"), f"{fresh!r} is a retry name"
        assert S.is_canonical_uuid(fresh), f"{fresh!r} is not a canonical uuid"
        assert list((episodes / fresh).rglob("*.jsonl")) == [], "the fresh episode holds rows"

    assert sorted(os.listdir(episodes)) == sorted([stale_id, fresh])
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

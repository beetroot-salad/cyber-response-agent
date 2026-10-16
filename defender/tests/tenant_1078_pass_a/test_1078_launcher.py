"""#1078 pass (A) — a fork keeps its tenant: the branch launcher (O5, D1, D2, D3, D4's
launch-path and episodes-root rows, J26, J44, J52).

#1105 PR 2 (declared change 1): the launcher takes `--tenant T <source_run_id>` — the tenant from
the request, the source by its id — and opens the source through T's runs repository at
`<root>/<T>/runs/<id>` (`tenant_of_run_dir`'s derivation from the source's folder is deleted,
F-13). A source that does not sit at T's tenant location cannot be named at all: the
repository refuses the id. Every scenario drives the REAL `learning/branch/cli.main` (through
`_spec1078.drive_launch` / `_launch_id`, the role preflight neutralised) or the replacement owner
directly, over sources written to disk here.

"Refused at the source" is observed as: the launcher's `LauncherRefused` text CONTAINS the
repository's own refusal verbatim (F0/J29; `_repository_refusal`), and nothing was written — no
episode dir under the episodes root and the data root's census unchanged.
"""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

from defender.tests._spec1077 import fixture_run

from datetime import datetime

import json
import shutil
from pathlib import Path
from defender.run_repository import RunPaths
from typing import Any

import pytest

from defender._episode_handle import Episode
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import current_data_root
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests.tenant_1078_pass_a import _spec1078 as H
from defender.tests import _state1135

TID = H.VALID_ID
#: The family's branch-point clock pre-flight's context carries.
_AS_OF = datetime.fromisoformat(T.AS_OF)


# ======================================================================================
# Cluster helpers
# ======================================================================================

def _episodes_root(tmp_path: Path, monkeypatch) -> Path:
    """A configured episodes root OUTSIDE the data root (the only place pass A accepts one)."""
    root = tmp_path / "episodes-root"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(root))
    return root


def _seams(**over):
    """Every launcher seam a scenario is not about, faked: nothing here decides a refusal."""
    seams = {
        "spawn": T.FakeSpawn(),
        "questioner": T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c")),
        "live_tree": T.source_capture(), **H.serving_oracle(),
    }
    seams.update(over)
    return seams


def _launch(source: Path, *, tenant_id: str = TID, **over):
    """The REAL launcher over `--tenant tenant_id <source's run id>` (`_spec1078.launch_argv`)."""
    seams = _seams(**over)
    spawn = seams.pop("spawn")
    return (H.drive_launch(source, spawn=spawn, tenant_id=tenant_id, **seams), spawn,
            seams["questioner"])


def _launch_id(source_run_id: str, *, tenant_id: str = TID, **over):
    """The REAL launcher over `--tenant tenant_id <source_run_id>` verbatim (#1105 PR 2,
    declared change 1) — for a source argument that is not a run folder's name (a path where
    the id belongs, a sidecar's name)."""
    seams = _seams(**over)
    spawn = seams.pop("spawn")
    seams.setdefault("preflight", H.no_preflight)
    H.place_knowledge_for_rows()
    argv = ["--tenant", tenant_id, source_run_id, str(T.BRANCH_MESSAGE_ID),
            "--continuation-prompt", H.CONTINUATION]
    try:
        result = H.branch_cli().main(argv, spawn=spawn, **seams)
    except SystemExit as refused:
        result = refused
    return result, spawn, seams["questioner"]


def _repository_refusal(root: Path, run_id: str, tenant_id: str = TID) -> BaseException:
    """The refusal tenant `tenant_id`'s runs repository (accepted under `root`) gives for the
    source `run_id` — what the launcher opens its source through and passes through verbatim
    (#1105 PR 2). The replacement for `tenant_of_run_dir`'s location refusal (F-13): a run that
    is not at `<root>/<T>/runs/<run_id>` is not T's to fork."""
    from defender._tenant import TenantRefused
    from defender.run_repository import RunId, RunRefused

    with pytest.raises((RunRefused, TenantRefused)) as refused:
        H.accept(root, tenant_id).runs_repository().open(RunId.parse(run_id))
    return refused.value


def _opens_as(root: Path, run_id: str, tenant_id: str = TID) -> str:
    """The tenant a run opened by id through `tenant_id`'s repository under `root` is addressed
    to — the replacement for `tenant_of_run_dir(...) == T` (F-13)."""
    from defender.run_repository import RunId

    return H.accept(root, tenant_id).runs_repository().open(RunId.parse(run_id)).tenant_id


def _assert_refused_writing_nothing(result, *, owner: BaseException | None, episodes: Path,
                                    roots: dict[Path, dict], agent) -> str:
    """The launcher REFUSED (a LauncherRefused, not a crash), passed `owner`'s message through
    verbatim when one is given, spent nothing and wrote nothing."""
    assert isinstance(result, H.branch_cli().LauncherRefused), (
        f"the launcher did not refuse with LauncherRefused: {result!r}")
    text = H.refusal_text(result)
    if owner is not None:
        H.assert_verbatim(text, owner, entry="the branch launcher")
    assert agent.calls == 0, "the questioner was paid for before the refusal"
    assert H.entries(episodes) == [], f"an episode dir was written: {H.entries(episodes)}"
    for root, before in roots.items():
        assert H.census(root) == before, f"the refused launch wrote under {root}"
    return text


def _old_layout_source(tmp_path: Path, tenant_id: str = TID) -> tuple[Path, Path]:
    """A runs base OUTSIDE `<root>/<T>/runs` whose `_tenant.json` names `tenant_id` — N4's old
    layout, carrying a record that names the EXISTING tenant."""
    base = tmp_path / "defender-runs"
    base.mkdir(parents=True)
    H.plant_record(base, tenant_id)
    return base, H.source_run(base)


def _pass_a_sibling(tmp_path: Path, root: Path, episodes: Path) -> tuple[Path, Path, Path]:
    """A pass-A sibling run dir, hand-built the way a pass-A sibling's materialize leaves it:
    under `<episode>/runs/` (the old episodes base, not a tenant location), beside a runs-base
    record naming T (the sibling arm of D2 mints one), with a case pointer naming its SOURCE's
    store under `<root>/<T>/sessions/` (C67). Returns (source, episode dir, sibling run dir)."""
    _base, src = H.tenant_source(root, TID)
    ep = episodes / T.EPISODE_ID
    T.write_family(ep, T.family_doc(source_run_dir=str(src)))
    sib_base = ep / "runs"
    # #1187 declared change 1: the arm's id is a uuid, so the launcher's refusal of it is the
    # location check's (T's repository does not hold it), never the id rule's.
    sib = sib_base / fixture_uuid("pass-a-sibling-b")
    (sib / "gather_raw").mkdir(parents=True)
    H.plant_record(sib_base, TID)
    shutil.copytree(src / "alert_input", sib / "alert_input")
    shutil.copy(src / "investigation.md", sib / "investigation.md")
    (sib / "provenance.json").write_text(json.dumps(T.provenance_record()), encoding="utf-8")
    # #1235: the case pointer is a host-only sidecar beside each run dir, not a file in it.
    from defender.run_repository import RunPaths

    shutil.copy(RunPaths(src).session_pointer(), RunPaths(sib).session_pointer())
    return src, ep, sib


def _materialize_sibling(root: Path, episodes: Path | None = None,
                         label: str = "b") -> tuple[Path, Path, Any]:
    """A REAL sibling materialize: a source at `<root>/<T>/runs/`, an episode at
    `<root>/<T>/episodes/<ep>` (#1187 Layout A — `episodes`, a configured root, is no longer
    where an episode lives and is ignored), and `materialize_run(..., world=<that world>,
    episode_runs=<its view>)` as the sibling process calls it (#1105 PR 2: the arm is made in
    its episode's container, which the launcher's RUNS step makes with the arm roster before
    the first sibling — `_triplet_947.episode_view` does that when it is absent). Returns
    (episode dir, sibling run dir, world)."""
    del episodes
    src = root / TID / "runs" / T.SOURCE_RUN_ID
    if not src.exists():
        H.tenant_source(root, TID)
    episodes = root / TID / "episodes"
    ep = episodes / T.EPISODE_ID
    if not (ep / "family.yaml").exists():
        T.episode(episodes.parent, doc=T.family_doc(source_run_dir=str(src)), root=episodes)
    accepted = H.accept(root, TID)
    with Episode.open(ep) as episode:
        world = H.run_py().resume_world(
            episode, label, tenant=lambda: H.T1106.run_tenant(accepted))
        view = T.episode_view(episode, tenant=accepted)
        # #1187 (review-4 F42): the arm's id is the one the roster holds for its label, never the
        # world's composed `run_id` (design: `ResumeWorld.run_id` is deleted or the roster's).
        run_dir = H.run_common().materialize_run(
            RunPaths(src).alert, T.roster_arm_id(ep, label), tenant=accepted, world=world,
            episode_runs=view).run_dir
    return ep, Path(run_dir), world


# ======================================================================================
# O5 — the derivation's own refusals (owner, then the fork-source entry)
# ======================================================================================

def test_o5_old_layout_refused_by_location(tmp_path, monkeypatch, data_root):
    """A run dir in a runs base outside <root>/T/runs whose _tenant.json names the existing T is
    refused as a fork source: `--tenant T <its id>` opens `<root>/T/runs/<id>` through T's
    repository (#1105 PR 2), which does not hold it, and the launcher passes that refusal
    through. Positive control: the same id at `<root>/T/runs/` opens as T's."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    H.make_tenant(data_root, TID)
    _base, src = _old_layout_source(tmp_path)
    before = {data_root: H.census(data_root), src.parent: H.census(src.parent)}
    owner = _repository_refusal(data_root, src.name)
    result, _spawn, agent = _launch(src)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)
    good_base = H.runs_dir(data_root, TID)
    good_id = fixture_uuid("o5-old-layout-control")  # #1187 dc1: a uuid; R1: no record
    (good_base / good_id).mkdir(parents=True)
    assert _opens_as(data_root, good_id) == TID


def test_o5_no_record_refused_never_minted(tmp_path, monkeypatch, data_root):
    """A run dir at <root>/T/runs/r1 whose base has no _tenant.json is refused, and no
    _tenant.json is created.

    Driven at the owner (T's runs repository, #1105 PR 2) and through the launcher; the positive
    control is the same run dir once its base carries the record.

    #1187 declared change 6 (R1): a base with no `_tenant.json` is the only kind of base there
    is — the record is neither written nor required — so the run at T's tenant location opens
    through T's repository as T's, and still nothing mints a record (the "never minted" half
    stands). The launch from it is the ordinary launch the launcher suites drive. (Name kept.)"""
    base, src = H.tenant_source(data_root, TID)
    before = H.census(data_root)
    assert not (base / H.RECORD_NAME).exists(), "precondition: the base holds no record"
    assert _opens_as(data_root, src.name) == TID, "T's run at T's location did not open as T's"
    assert not (base / H.RECORD_NAME).exists(), "the open minted a record"
    assert H.census(data_root) == before, "opening the source wrote under the data root"


def test_o5_requires_row(tmp_path, data_root):
    """A run dir at a tenant location whose record names T is refused when T has no row: the
    tenant is not accepted, so its runs are not opened (#1105 PR 2: the source is opened through
    the accepted tenant's repository).

    Positive control: the same run dir once T's row exists."""
    base, src = H.tenant_source(data_root, TID, row=False)
    assert not H.row_path(data_root, TID).exists()
    H.place_knowledge(data_root, TID)
    before = H.census(data_root)
    H.owner_refusal(H.accept, data_root, TID)
    assert H.census(data_root) == before, "the refused acceptance wrote under the data root"
    H.plant_row(data_root, TID)
    assert _opens_as(data_root, src.name) == TID


def test_def6_sibling_source_refused_by_tenant_check(tmp_path, monkeypatch, data_root):
    """In pass (A), launching a fork from a sibling run dir (under an episode's runs/) is refused
    by the tenant location check, before the source-store check is reached.

    The sibling carries everything the store check needs to refuse it on its own (a case
    pointer naming its source's store, which `open_source_store` re-derives beside the
    episode's runs base, C67); the launcher's refusal must be the tenant check's, not that one —
    since #1105 PR 2, T's runs repository refusing the sibling's id, which is not at
    `<root>/T/runs/`."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    old_episodes = tmp_path / "old-episodes-base"
    _src, ep, sib = _pass_a_sibling(tmp_path, data_root, old_episodes)
    before = {data_root: H.census(data_root), ep: H.census(ep)}
    owner = _repository_refusal(data_root, sib.name)
    result, _spawn, agent = _launch(sib)
    text = _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                           agent=agent)
    assert "records its store at" not in text, (
        "the source-store check was reached before the tenant location check")


def test_pass_a_episode_sibling_bases_carry_a_record_naming_the_tenant(
        tmp_path, monkeypatch, data_root):
    """In (A), a fork from a pass-A sibling, whose base record names T at a non-tenant location,
    is refused by the location check (#1105 PR 2: T's runs repository, which holds only
    `<root>/T/runs/`) and by C67's store check. N14's 'three independent' count failing for
    (A)-era episodes after (B) adopts them is a (B)-chain correction (Red flag 5).

    Both refusals are observed independently: the launcher's (the repository's message,
    verbatim) and `open_source_store`'s own `BranchError` on the same sibling."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    _src, ep, sib = _pass_a_sibling(tmp_path, data_root, tmp_path / "old-episodes-base")
    record = json.loads((ep / "runs" / H.RECORD_NAME).read_text(encoding="utf-8"))
    assert record["tenant_id"] == TID
    assert data_root / TID not in (ep / "runs").parents
    store_check = H.mod("runtime.branch")
    with pytest.raises(store_check.BranchError, match="records its store at"):
        store_check.open_source_store(sib, source_run=_run_handle_1165(sib))
    before = {data_root: H.census(data_root), ep: H.census(ep)}
    owner = _repository_refusal(data_root, sib.name)
    result, _spawn, agent = _launch(sib)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)


# ======================================================================================
# D4 — the launch-path location check, and refuse_distant_source's deletion (J52)
# ======================================================================================

def test_d4_launch_location_check(tmp_path, monkeypatch, data_root):
    """cli.py launched on a source outside <root>/T/runs is refused (#1105 PR 2: by T's runs
    repository, which the source is opened through by id) before any episode dir is written;
    refuse_distant_source is not on the launch path.

    Positive control (and s7_j52's pair): the same source at `<root>/T/runs/` gets past the
    location check — the launch goes on to start its siblings."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    H.make_tenant(data_root, TID)
    _base, src = _old_layout_source(tmp_path)
    before = {data_root: H.census(data_root)}
    owner = _repository_refusal(data_root, src.name)
    result, _spawn, agent = _launch(src)
    text = _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                           agent=agent)
    assert "does not live directly under" not in text, (
        "the launch path still answers through refuse_distant_source")

    good_base = H.runs_dir(data_root, TID)
    good_base.mkdir(parents=True)
    good = H.source_run(good_base)  # #1187 (R1): no runs-base record
    _result, spawn, agent = _launch(good)
    assert agent.calls > 0, f"a tenant-location source was refused: {_result!r}"
    assert spawn.launches, f"a tenant-location source started no sibling: {_result!r}"


def _graded_launch(tmp_path: Path, monkeypatch, root: Path, *, collide: bool):
    """ONE whole episode through the real launcher, judge included (`_judge_921`'s own drive:
    `J.FakeSibling` leaves finished, archivable siblings, so the family is accepted and the
    JUDGE step actually runs). The source sits at `<root>/<T>/runs/`; with `collide`, a finished
    run named for graded world `b` stands beside it there. Returns (status, episode dir)."""
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)  # the retired knob: nothing may read it
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
    episodes = _episodes_root(tmp_path, monkeypatch)
    del episodes  # #1187 (O9): the episode is `<root>/<T>/episodes/<uuid>`, the variable a decoy
    _base, src = H.tenant_source(root, TID)
    if collide:
        (H.runs_dir(root, TID) / "b").mkdir()
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    result = H.drive_launch(src, spawn=J.FakeSibling(data_root=root), judge=judge,
                            questioner=T.FakeAgent(T.family_doc(), T.world_doc("b"),
                                                   T.world_doc("c")),
                            live_tree=T.source_capture(), **H.serving_oracle())
    made = sorted((root / TID / "episodes").glob("*"))
    assert len(made) <= 1, f"one launch made {made}"
    return result, made[0] if made else root / TID / "episodes" / "<none made>"


def test_d4_launcher_derives_once(tmp_path, monkeypatch, data_root, capfd):
    """The launcher takes T once, from the request, before it places the episode dir, and hands
    T's repository to every consumer it drives; no consumer re-derives T or reads the manifest
    for it.

    Driven end to end through the REAL `cli.main` with its `judge=` seam: the grade the launcher
    runs at the tail of `_run_episode` (`_grade` -> `grade_episode(runs, episode_id)`).

    #1105 PR 2, declared change 3 (J3, G17): the judge reads only the episode it is handed, and
    its world-label collision probe over `<root>/<T>/runs` is removed — so a finished run named
    for graded world `b` standing in `<root>/<T>/runs/` no longer refuses the grade: the episode
    is graded (`judge.yaml` written) and F-5's non-fatal print channel carries no judge failure —
    in particular no `TypeError` (a keyword the new signature does not take), `ImportError` or
    `resolve_runs_base` fault (a leftover import of the deleted resolver), any of which
    `_grade`'s broad `except` would otherwise print and swallow. The retired
    `DEFENDER_RUNS_BASE` is unset.

    Control, same drive: without the colliding run the episode is graded too."""
    result, episode_dir = _graded_launch(tmp_path / "collide", monkeypatch, data_root,
                                         collide=True)
    err = capfd.readouterr().err
    assert not isinstance(result, BaseException), f"the launch itself was refused: {result!r}"
    assert "the judge pass failed" not in err, (
        f"the grade failed over a world label equal to a natural run id:\n{err[-2000:]}")
    for wrong in ("TypeError", "ImportError", "resolve_runs_base", "FatalConfigError"):
        assert wrong not in err, f"the launcher's grade failed for the wrong reason ({wrong})"
    assert (episode_dir / "judge.yaml").is_file(), (
        "an episode whose world label equals a natural run id was not graded")

    clean_root = tmp_path / "clean-data"
    H.set_data_root(monkeypatch, clean_root)
    result, clean_episode = _graded_launch(tmp_path / "clean", monkeypatch, clean_root,
                                           collide=False)
    err = capfd.readouterr().err
    assert not isinstance(result, BaseException), f"the control launch was refused: {result!r}"
    assert "the judge pass failed" not in err, f"the control's grade failed:\n{err[-2000:]}"
    assert (clean_episode / "judge.yaml").is_file(), "the control episode was never graded"


def test_s7_j52_refuse_distant_source_deleted():
    """refuse_distant_source no longer exists: learning.branch.cli defines no such name and its
    __all__ does not list it, and test_947_branch_cli.py's cases for it are gone. Its launch-path
    role is the source open through T's runs repository (#1105 PR 2; positive control:
    d4_launch_location_check)."""
    cli = H.branch_cli()
    assert not hasattr(cli, "refuse_distant_source"), "refuse_distant_source still exists"
    assert "refuse_distant_source" not in getattr(cli, "__all__", ()), (
        "refuse_distant_source is still exported")
    tests = H.DEFENDER / "tests" / "test_947_branch_cli.py"
    assert "refuse_distant_source" not in tests.read_text(encoding="utf-8"), (
        f"{tests.name} still exercises the deleted pre-check")
    production = [
        p for p in H.DEFENDER.rglob("*.py")
        if "tests" not in p.relative_to(H.DEFENDER).parts and ".venv" not in p.parts
        and "refuse_distant_source" in p.read_text(encoding="utf-8", errors="replace")]
    assert production == [], f"production still names refuse_distant_source: {production}"


def test_s7_j26_symlinked_tenant_folder_accepted(tmp_path, monkeypatch, data_root):
    """With <root>/T (or <root>/T/runs) a symlink to another directory, a launch from a run
    there is refused, nothing spent and nothing written.

    SHAPE 2 FLIPS (#1105 PR 2, declared changes 1 and 11): the launcher opens its source by id
    through T's runs repository, which holds `<root>/T/runs` no-follow — a link there is refused
    with the repository's own message, passed through verbatim. (Before PR 2 the source's
    folder was resolved and compared, so a linked `<root>/T/runs` got past the location check
    and the siblings were started.) The old-layout control went with `tenant_of_run_dir`
    (F-13): `test_o5_old_layout_refused_by_location` drives it through the launcher.

    SHAPE 1's LAUNCH IS SUPERSEDED by #1120 (human, PR #1157; spec_graph_1120-piece1.yaml
    x1078_s7_j26_symlinked_tenant_folder): the launcher accepts the source's tenant through
    accept_tenant, which refuses a `<root>/T` linked elsewhere because its knowledge/ does not
    resolve to `<root>/T/knowledge` (accept_refuses_knowledge_not_real); the launch is refused
    with the owner's message verbatim, nothing spent and nothing written.

    KNOWN LIMIT, not pinned and not fixed here: a fork of a run MATERIALIZED through a symlinked
    <root>/T/runs still fails the pre-existing C67 store check — its case pointer names the store
    beside the unresolved base, while open_source_store re-derives it beside the resolved one —
    so that shape stays unbranchable. Shape 2 below therefore builds its source at the resolved
    base, which keeps the location check the only question this test asks.

    Two data roots, one per shape: `<root>/T` linked, and `<root>/T/runs` linked. Shape 2's
    launch is refused at the source open (no sibling is started)."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    # shape 1: <root>/T is a symlink to a real tenant folder elsewhere
    real_tenant = tmp_path / "real-tenant-folder"
    real_tenant.mkdir()
    (data_root / TID).symlink_to(real_tenant, target_is_directory=True)
    H.place_knowledge(data_root, TID)  # #1120 DC2: the operator's clone, before the row
    H.plant_row(data_root, TID)
    _base, src = H.tenant_source(data_root, TID, row=False)
    owner = H.owner_refusal(H.accept, data_root, TID)
    assert str(data_root / TID / "knowledge") in str(owner), owner
    before = {data_root: H.census(data_root), real_tenant: H.census(real_tenant)}
    result, spawn, agent = _launch(src)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)
    assert not spawn.launches, f"<root>/T as a symlink started a sibling: {result!r}"

    # shape 2: <root>/T is real, <root>/T/runs is a symlink
    root2 = tmp_path / "data-2"
    H.set_data_root(monkeypatch, root2)
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root-2"))
    H.make_tenant(root2, TID)
    # One level down, so its store (`<real>/sessions/`) is not the old-layout control's below
    # (`<tmp>/sessions/`): two sources seeded into one store never reach their branch point.
    real_runs = tmp_path / "real-tenant-2" / "runs"
    real_runs.mkdir(parents=True)
    (root2 / TID / "runs").symlink_to(real_runs, target_is_directory=True)
    # Built AT THE RESOLVED base, so the source's case pointer names the store beside
    # `real-runs` — the one C67's own derive-and-compare (unchanged by #1078, it resolves the
    # run dir first) re-derives. That keeps the location check the only question asked here.
    H.source_run(real_runs)
    src2 = root2 / TID / "runs" / T.SOURCE_RUN_ID
    owner2 = _repository_refusal(root2, src2.name)
    # An open answers a container fault as `RunUnreachable` from it (#1105 PR 2 review).
    assert isinstance(owner2.__cause__, H.tenant().TenantRefused), (
        f"T's runs repository did not refuse a linked <root>/T/runs as a container: {owner2!r}")
    before2 = {root2: H.census(root2), real_runs: H.census(real_runs)}
    result, spawn, agent = _launch(src2)
    _assert_refused_writing_nothing(result, owner=owner2,
                                    episodes=tmp_path / "episodes-root-2", roots=before2,
                                    agent=agent)
    assert not spawn.launches, f"<root>/T/runs as a symlink started a sibling: {result!r}"


def test_branch_launch_after_the_data_root_changes_underneath_a_valid_run(
        tmp_path, monkeypatch, data_root):
    """A launch from a run materialized under a data root the environment no longer names is
    refused at the source (#1105 PR 2: T's runs repository under the environment's root does not
    hold its id), with nothing written. Whether its message differs from an old-layout refusal
    is not pinned.

    The run is materialized for real under the OLD root; T exists under the new one too, so
    the location is the only thing wrong with the source."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    old_root = tmp_path / "old-data-root"
    H.set_data_root(monkeypatch, old_root)
    H.make_tenant(old_root, TID)
    alert = H.plant_alert(tmp_path / "in")
    run_id = fixture_uuid("1078-moved-root-run")  # #1187 dc1: a uuid
    run_dir = H.run_common().materialize_run(alert, run_id, tenant=H.accept(old_root, TID)).run_dir
    assert run_dir == old_root / TID / "runs" / run_id
    H.set_data_root(monkeypatch, data_root)
    H.make_tenant(data_root, TID)
    before = {data_root: H.census(data_root), old_root: H.census(old_root)}
    owner = _repository_refusal(data_root, run_dir.name)
    result, _spawn, agent = _launch(run_dir)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)


def test_launch_from_a_source_under_another_data_root(tmp_path, monkeypatch, data_root):
    """A launch from a source under another data root is refused by location (#1105 PR 2: the
    source is opened by id through T's repository under the environment's root, which does not
    hold it); nothing is written.

    The other root is a complete tenant layout of its own (row, record, branchable run); only
    the environment's root decides."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    H.make_tenant(data_root, TID)
    other = tmp_path / "another-data-root"
    _base, src = H.tenant_source(other, TID)
    before = {data_root: H.census(data_root), other: H.census(other)}
    owner = _repository_refusal(data_root, src.name)
    result, _spawn, agent = _launch(src)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)


# ======================================================================================
# Past the tenant check, into the launcher's existing source checks
# ======================================================================================

def test_launch_from_a_nonexistent_run_dir_at_a_tenant_location(tmp_path, monkeypatch, data_root):
    """(a) A nonexistent run id at T's runs base (with a valid record) is refused by the
    launcher's source open; (b) an arbitrary nonexistent path where the id belongs is refused
    (#1105 PR 2: the source is named by its run id, never a path). Nothing is written in either
    case."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    base, _src = H.tenant_source(data_root, TID)
    ghost = base / fixture_uuid("no-such-run")  # #1187 dc1: refused as absent, not by shape
    before = {data_root: H.census(data_root)}
    result, _spawn, agent = _launch(ghost)
    _assert_refused_writing_nothing(result, owner=None, episodes=episodes, roots=before,
                                    agent=agent)
    assert not ghost.exists()

    nowhere = tmp_path / "nowhere" / "r1"
    result, _spawn, agent = _launch_id(str(nowhere))
    _assert_refused_writing_nothing(result, owner=None, episodes=episodes, roots=before,
                                    agent=agent)
    assert not (tmp_path / "nowhere").exists(), "(b) the refusal minted a record or a dir"


@pytest.mark.parametrize("entry", [H.RECORD_NAME, "r1.run-end.json"])
def test_launch_from_a_non_run_entry_of_the_runs_base(tmp_path, monkeypatch, data_root, entry):
    """A non-run entry of T's runs base (_tenant.json, a run-end sidecar) given as the source
    id is refused by the launcher's source open; nothing is written."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    base, _src = H.tenant_source(data_root, TID)
    source = base / entry
    if not source.exists():
        source.write_text('{"exit_class": "completed"}\n', encoding="utf-8")
    before = {data_root: H.census(data_root)}
    result, _spawn, agent = _launch_id(source.name)
    _assert_refused_writing_nothing(result, owner=None, episodes=episodes, roots=before,
                                    agent=agent)


def test_tenant_of_run_dir_given_a_run_dir_that_is_a_file_not_a_directory(
        tmp_path, monkeypatch, data_root):
    """A run id naming a regular file inside T's runs base is refused by the launcher's source
    open (a run is only ever a real directory); nothing is written."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    base, _src = H.tenant_source(data_root, TID)
    as_file = base / fixture_uuid("1078-as-file")  # #1187 dc1: refused as a file, not by shape
    as_file.write_text("not a directory\n", encoding="utf-8")
    before = {data_root: H.census(data_root)}
    result, _spawn, agent = _launch(as_file)
    _assert_refused_writing_nothing(result, owner=None, episodes=episodes, roots=before,
                                    agent=agent)


# ======================================================================================
# Episodes made before (A). (#1187 R1 retired the pass-A sibling record a never-adopted
# episodes base kept: no `_tenant.json` is minted in an arm container any more.)
# ======================================================================================

def test_episode_made_between_1077_and_pass_a(tmp_path, monkeypatch, data_root):
    """A launch from a sibling of an episode made between #1077 and (A) (its record names
    `default`), or a by-hand sibling start of that episode (whose source is an old-layout run
    with no record, C74/C75), is refused, never minted, and nothing is written. Its (B) adoption
    is outside this pass.

    #1105 PR 2: the launch names the sibling by id under T (declared change 1), refused by T's
    runs repository, which does not hold it; the sibling is started by id
    (`run.py --tenant T --episode <id> --world L`, declared change 6 — `--resume` is gone) and
    is refused at its episode container, whose record names `default`, before the manifest or
    its source is read.

    #1187 declared changes 5, 6 and 10: the by-hand sibling start no longer reaches a container
    record or reads `DEFENDER_EPISODES_BASE` (still set here to the old base, as a decoy): the
    episode is looked for only under `<root>/T/episodes/`, where this pre-A episode is not, so
    it is refused with nothing spent and nothing written, and the
    refusal does not speak of the retired variable. (Name kept.)"""
    episodes = _episodes_root(tmp_path, monkeypatch)
    H.make_tenant(data_root, TID)
    old_base = tmp_path / "defender-runs"
    old_base.mkdir()
    old_src = H.source_run(old_base)
    assert not (old_base / H.RECORD_NAME).exists()
    old_ep = tmp_path / "old-episodes-base" / T.EPISODE_ID
    manifest = T.write_family(old_ep, T.family_doc(source_run_dir=str(old_src)))
    (old_ep / "served").mkdir()
    (old_ep / "served" / "base.jsonl").write_text("", encoding="utf-8")
    sib_base = old_ep / "runs"
    sib = sib_base / fixture_uuid("pre-a-sibling-b")  # #1187 dc1: refused by place, not shape
    (sib / "gather_raw").mkdir(parents=True)
    H.plant_record(sib_base, "default")
    shutil.copytree(old_src / "alert_input", sib / "alert_input")
    (sib / "provenance.json").write_text(json.dumps(T.provenance_record()), encoding="utf-8")
    record_before = (sib_base / H.RECORD_NAME).read_bytes()
    roots = {data_root: H.census(data_root), old_base: H.census(old_base)}

    owner = _repository_refusal(data_root, sib.name)
    result, _spawn, agent = _launch(sib)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=roots,
                                    agent=agent)
    assert (sib_base / H.RECORD_NAME).read_bytes() == record_before, "the record was rewritten"

    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(manifest.parent.parent))
    rec = H.Recorder(tmp_path / "never")
    rc, refused = H.drive_main(
        ["--tenant", TID, "--episode", T.EPISODE_ID, "--world", "b"], rec)
    assert rc is None, "the by-hand sibling start of a pre-A episode ran"
    assert refused is not None
    assert T.EPISODES_BASE_ENV not in H.refusal_text(refused), (
        f"the refusal reads the retired variable: {H.refusal_text(refused)}")
    assert not rec.spent, f"the refused resume spent: {rec.order}"
    assert not (old_base / H.RECORD_NAME).exists(), "the refused resume minted a record"
    for root, before in roots.items():
        assert H.census(root) == before, f"the refused resume wrote under {root}"


# ======================================================================================
# D2 — the launcher stops exporting DEFENDER_RUNS_BASE (C9, J46), and the #947 pins (s104)
# ======================================================================================

def test_d2_launcher_no_runs_base_export(tmp_path, monkeypatch):
    """The environment the launcher hands each sibling run.py carries no DEFENDER_RUNS_BASE.

    Under a clean parent environment the variable is ABSENT from every child's env; under a
    stale operator shell it is the PARENT's value, inherited, never one the launcher composed
    (J46). The positive control on the same channel: the child env does carry the parent's
    DEFENDER_DATA_ROOT, so the observation can see an inherited variable."""
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    ep = T.episode(tmp_path)
    spawn = T.FakeSpawn()
    with Episode.open(ep) as episode:
        H.branch_cli().start_family(episode, ["a", "b", "c"], spawn=spawn, tenant_id=H.VALID_ID)
    assert len(spawn.launches) == 3, "not every sibling was started"
    for launch in spawn.launches:
        assert T.RUNS_BASE_ENV not in launch["env"], (
            f"the launcher composed a runs base for {launch['argv']}: "
            f"{launch['env'].get(T.RUNS_BASE_ENV)}")
        assert launch["env"].get(H.DATA_ROOT_ENV) == str(current_data_root())

    stale = tmp_path / "stale-operator-runs"
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(stale))
    spawn = T.FakeSpawn()
    with Episode.open(ep) as episode:
        H.branch_cli().start_family(episode, ["b"], spawn=spawn, tenant_id=H.VALID_ID)
    assert [la["env"].get(T.RUNS_BASE_ENV) for la in spawn.launches] == [str(stale)]


def test_947_pins_under_a_clean_environment(tmp_path, monkeypatch, d9_tenant):
    """The two #947 pins are rewritten: test_947_triplet_archive.py asserts the launcher sets no
    DEFENDER_RUNS_BASE of its own; the replay context's env value (#947's review replay, now
    pre-flight's `_preflight_context`, #1224) is runs_base_for(T) from the tenant fixture.

    Pinned here under the CLEAN environment the old pins could not survive (brief R2): no
    DEFENDER_RUNS_BASE in the parent at all. The sibling's env then carries none (a `KeyError`
    for the old `launch["env"]["DEFENDER_RUNS_BASE"]`), and the replay env's value is the
    threaded tenant runs base, composed without any environment read."""
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    ep = T.episode(tmp_path)
    spawn = T.FakeSpawn()
    with Episode.open(ep) as episode:
        H.branch_cli().start_family(episode, ["a", "b"], spawn=spawn, tenant_id=d9_tenant)
    assert spawn.launches
    assert all(T.RUNS_BASE_ENV not in la["env"] for la in spawn.launches)

    runs_base = H.runs_base_for(d9_tenant)
    # #1105 PR 2: the context's runs base is the opened source run's own hand-out
    # (`Run.runs_base_export`), the source at T's tenant location.
    _base, src = H.tenant_source(current_data_root(), d9_tenant, row=False)
    ctx = H.branch_cli()._preflight_context(
        ep, T.open_source(src), H.T1106.run_tenant(H.accept(current_data_root(), d9_tenant)),
        _AS_OF)
    assert ctx.env[T.RUNS_BASE_ENV] == str(runs_base)
    assert runs_base == current_data_root().resolve() / d9_tenant / "runs"
    assert ctx.env[T.RUNS_BASE_ENV] != str(ep.parent)


# ======================================================================================
# D4 — the episodes root re-keyed onto the tenant (A), J44's pass-A refusal
# ======================================================================================

def _accepted(root: Path):
    """T created in `root` over its placed knowledge (when it is not there yet) and accepted
    through the real `accept_tenant` — what the launcher hands `episodes_root`."""
    if not H.row_path(root, TID).exists():
        H.make_tenant(root, TID)
    return H.accept(root, TID)


def test_g_r7_episode_dir_reader_coherence(tmp_path, monkeypatch, data_root):
    """visualize_episode — the existing reader of episode_dir left unmoved while
    materialize_run's sibling arm (EpisodePaths(world.episode_dir).runs, C8) newly reads it this
    pass — resolves the same path materialize_run now threads; driving a sibling run and then
    the reader over the same episode_dir observes agreement, not a stale copy. (The third
    reader, the claimed-episode refusal, went with episode adoption in #1224.)

    #1187 declared change 5: the second reader, `episodes_root`, is retired — the episode
    folder is the tenant's own `<T>/episodes/<ep>`, reached through the repository's walk, and
    no resolver reads `DEFENDER_EPISODES_BASE` (pinned by
    `ids_1187/test_1187_layout_isolation.py::test_the_episodes_variable_changes_nothing_and_no_episodes_root_refusal_fires`).
    (Name kept.)"""
    episodes = _episodes_root(tmp_path, monkeypatch)
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    ep, run_dir, world = _materialize_sibling(data_root, episodes, "b")
    assert run_dir.parent == H.mod("_episode_paths").EpisodePaths(world.episode_dir).runs
    assert run_dir.parent == ep / "runs"
    # #1105 PR 2 (declared change 4): the page's loader reads the episode view it is handed,
    # opened by id through the tenant's repository (#1187: under `<T>/episodes/`).
    module = H.mod("scripts.visualize.visualize_episode")
    with module.open_episode_view(_accepted(data_root).runs_repository(), ep.name) as view:
        page = module.load_episode(view)
    assert page.entries["b"].run_dir_name == run_dir.name, (
        "the episode page does not see the run dir the sibling's materialize made")


# ======================================================================================
# O4 — a fork's session rows land in its source's store under <root>/T/sessions/ (C67)
# ======================================================================================

def _sibling_state(sib: Path):  # noqa: ANN202 — a `RunState` (#1235: not imported at top)
    """A fresh run state for the sibling at `sib`, which seeding takes as its third argument
    (#1235 round 2, where it was the sibling's run dir)."""
    from defender.runtime.run_state import RunState

    return RunState(sib, sib.name)


def test_o4_fork_store_location(tmp_path, data_root):
    """A sibling forked from <root>/T/runs/r1 records a session pointer naming
    <root>/T/sessions/<case>.db, its source's store.

    Driven through the resume's own store seam (`store_factory_for`, `open_main_session`,
    `attach_case_pointer`) — the path `run_investigation` takes for a sibling. The mechanism is
    C67/C11's and unchanged by #1078; what pass A adds is that the source sits at a tenant
    location, so the store it forks into is the tenant's."""
    base = H.runs_dir(data_root, TID)
    base.mkdir(parents=True)
    src = H.source_run(base)  # #1187: a uuid id (dc1), no runs-base record (R1)
    br = H.mod("runtime.branch")
    store = br.open_source_store(src, source_run=_run_handle_1165(src))
    try:
        as_of = br.branch_point_time(store, src, T.BRANCH_MESSAGE_ID, source_run=_run_handle_1165(src))
    finally:
        store.close()
    spec = br.BranchSpec(source_run_dir=src, branch_message_id=T.BRANCH_MESSAGE_ID,
                         continuation_prompt=H.CONTINUATION, as_of=as_of)
    sib = (data_root / TID / "episodes" / T.EPISODE_ID / "runs"
           / fixture_uuid("o4-fork-sibling-b"))  # #1187: Layout A, the arm's id a uuid
    sib.mkdir(parents=True)
    store = br.store_factory_for(spec, source_run=fixture_run(spec.source_run_dir))("minted-case", sib)
    try:
        session_id, _history = br.open_main_session(store, spec, _sibling_state(sib), run=fixture_run(sib), source_run=fixture_run(spec.source_run_dir))
        br.attach_case_pointer(store, spec, _run_handle_1165(sib), case_id="minted-case", session_id=session_id)
    finally:
        store.close()
    from defender.run_repository import RunPaths

    pointer = json.loads(RunPaths(sib).session_pointer().read_text(encoding="utf-8"))
    assert not (sib / "session_store_pointer.json").exists(), (
        "the fork wrote its case pointer inside the box-writable run dir")
    expected = H.sessions_dir(data_root, TID) / f"{T.SOURCE_CASE_ID}.db"
    assert Path(pointer["store_path"]).resolve() == expected.resolve()
    assert not (sib.parent.parent / "sessions").exists(), "the fork opened a store of its own"

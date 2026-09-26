"""#1078 pass (A) — a fork keeps its tenant: `tenant_of_run_dir` and the branch launcher (O5, D1,
D2, D3, D4's launch-path and episodes-root rows, J26, J44, J52).

The launcher derives T ONCE, from the source's HOST-ONLY runs-base record, before it builds an
episode dir, and refuses a source that does not sit at a tenant location (`<root>/<T>/runs/`).
Every scenario drives the REAL `learning/branch/cli.main` (through `_spec1078.drive_launch`,
the role preflight neutralised) or the owner directly, over sources written to disk here.

"Refused by tenant_of_run_dir" is observed as: the launcher's `LauncherRefused` text CONTAINS
the owner's own refusal verbatim (F0/J29), and nothing was written — no episode dir under the
episodes root and the data root's census unchanged. Where a scenario must get PAST the tenant
check to the launcher's existing source checks, the test asserts the derivation itself
answers T, and that the launcher still refuses, writing nothing.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests._data_root_1078 import current_data_root
from defender.tests.tenant_1078_pass_a import _spec1078 as H

TID = H.VALID_ID


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
        "spawn": T.FakeSpawn(), "door": T.FakeDoor(),
        "questioner": T.FakeAgent(T.family_doc(), T.world_doc("b"), T.world_doc("c")),
        "adapters": T.FakeAdapters(), "invoke": T.FakeAgent(*["same"] * 24),
        "live_tree": T.source_capture(),
    }
    seams.update(over)
    return seams


def _launch(source: Path, **over):
    seams = _seams(**over)
    spawn = seams.pop("spawn")
    return H.drive_launch(source, spawn=spawn, **seams), spawn, seams["questioner"]


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
    sib = sib_base / f"{T.EPISODE_ID}-b"
    (sib / "gather_raw").mkdir(parents=True)
    H.plant_record(sib_base, TID)
    shutil.copy(src / "alert.json", sib / "alert.json")
    shutil.copy(src / "investigation.md", sib / "investigation.md")
    (sib / "provenance.json").write_text(json.dumps(T.provenance_record()), encoding="utf-8")
    shutil.copy(src / "session_store_pointer.json", sib / "session_store_pointer.json")
    return src, ep, sib


def _materialize_sibling(root: Path, episodes: Path, label: str = "b") -> tuple[Path, Path, Any]:
    """A REAL pass-A sibling materialize: a source at `<root>/<T>/runs/`, an episode under the
    configured episodes root, and `materialize_run_dir(..., world=<that world>)` as the sibling
    process calls it. Returns (episode dir, sibling run dir, world)."""
    src = root / TID / "runs" / T.SOURCE_RUN_ID
    if not src.exists():
        H.tenant_source(root, TID)
    ep = episodes / T.EPISODE_ID
    if not (ep / "family.yaml").exists():
        T.episode(episodes.parent, doc=T.family_doc(source_run_dir=str(src)), root=episodes)
    world = H.run_py().resume_world(ep / "family.yaml", label)
    run_dir = H.run_common().materialize_run_dir(
        src / "alert.json", world.run_id, tenant_id=TID, world=world)
    return ep, Path(run_dir), world



# ======================================================================================
# O5 — the derivation's own refusals (owner, then the fork-source entry)
# ======================================================================================

def test_o5_old_layout_refused_by_location(tmp_path, monkeypatch, data_root):
    """A run dir in a runs base outside <root>/T/runs whose _tenant.json names the existing T is
    refused by tenant_of_run_dir, so it is refused as a fork source and as a lead-author item.

    The fork-source entry is driven (the launcher). The lead-author entry derives through the
    SAME owner call (D6: `tenant_of_run_dir` is the single derivation every deriver uses), and
    its own `--tenant`/derivation rows land with pass (C), so it is observed here as the owner's
    refusal. Positive control: the same run at `<root>/T/runs/` derives T."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    H.make_tenant(data_root, TID)
    _base, src = _old_layout_source(tmp_path)
    before = {data_root: H.census(data_root), src.parent: H.census(src.parent)}
    owner = H.owner_refusal(H.tenant_of_run_dir, src)
    result, _spawn, agent = _launch(src)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)
    good_base = H.runs_dir(data_root, TID)
    H.plant_record(good_base, TID)
    (good_base / "r1").mkdir()
    assert H.tenant_of_run_dir(good_base / "r1") == TID


def test_o5_no_record_refused_never_minted(tmp_path, monkeypatch, data_root):
    """A run dir at <root>/T/runs/r1 whose base has no _tenant.json is refused, and no
    _tenant.json is created.

    Driven at the owner and through the launcher; the positive control is the same run dir once
    its base carries the record."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    base, src = H.tenant_source(data_root, TID, record=None)
    before = {data_root: H.census(data_root)}
    owner = H.owner_refusal(H.tenant_of_run_dir, src)
    assert not (base / H.RECORD_NAME).exists(), "the refusing derivation minted a record"
    result, _spawn, agent = _launch(src)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)
    assert not (base / H.RECORD_NAME).exists(), "the refused launch minted a record"
    H.plant_record(base, TID)
    assert H.tenant_of_run_dir(src) == TID


def test_o5_requires_row(tmp_path, data_root):
    """A run dir at a tenant location whose record names T is refused when T has no row.

    Positive control: the same run dir once T's row exists."""
    base, src = H.tenant_source(data_root, TID, row=False)
    assert not H.row_path(data_root, TID).exists()
    before = H.census(data_root)
    H.owner_refusal(H.tenant_of_run_dir, src)
    assert H.census(data_root) == before, "the refused derivation wrote under the data root"
    H.plant_row(data_root, TID)
    assert H.tenant_of_run_dir(src) == TID


def test_def6_sibling_source_refused_by_tenant_check(tmp_path, monkeypatch, data_root):
    """In pass (A), launching a fork from a sibling run dir (under an episode's runs/) is refused
    by the tenant location check, before the source-store check is reached.

    The sibling carries everything the store check needs to refuse it on its own (a case
    pointer naming its source's store, which `open_source_store` re-derives beside the
    episode's runs base, C67); the launcher's refusal must be the tenant check's, not that one."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    old_episodes = tmp_path / "old-episodes-base"
    _src, ep, sib = _pass_a_sibling(tmp_path, data_root, old_episodes)
    before = {data_root: H.census(data_root), ep: H.census(ep)}
    owner = H.owner_refusal(H.tenant_of_run_dir, sib)
    result, _spawn, agent = _launch(sib)
    text = _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                           agent=agent)
    assert "records its store at" not in text, (
        "the source-store check was reached before the tenant location check")


def test_pass_a_episode_sibling_bases_carry_a_record_naming_the_tenant(
        tmp_path, monkeypatch, data_root):
    """In (A), a fork from a pass-A sibling, whose base record names T at a non-tenant location,
    is refused by tenant_of_run_dir's location check and by C67's store check. N14's 'three
    independent' count failing for (A)-era episodes after (B) adopts them is a (B)-chain
    correction (Red flag 5).

    Both refusals are observed independently: the launcher's (the location check's message,
    verbatim) and `open_source_store`'s own `BranchError` on the same sibling."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    _src, ep, sib = _pass_a_sibling(tmp_path, data_root, tmp_path / "old-episodes-base")
    record = json.loads((ep / "runs" / H.RECORD_NAME).read_text(encoding="utf-8"))
    assert record["tenant_id"] == TID
    assert data_root / TID not in (ep / "runs").parents
    store_check = H.mod("runtime.branch")
    with pytest.raises(store_check.BranchError, match="records its store at"):
        store_check.open_source_store(sib)
    before = {data_root: H.census(data_root), ep: H.census(ep)}
    owner = H.owner_refusal(H.tenant_of_run_dir, sib)
    result, _spawn, agent = _launch(sib)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)


# ======================================================================================
# D4 — the launch-path location check, and refuse_distant_source's deletion (J52)
# ======================================================================================

def test_d4_launch_location_check(tmp_path, monkeypatch, data_root):
    """cli.py launched on a source outside <root>/T/runs is refused by tenant_of_run_dir before
    any episode dir is written; refuse_distant_source is not on the launch path.

    Positive control (and s7_j52's pair): the same source at `<root>/T/runs/` gets past the
    location check — the launch goes on to start its siblings."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    H.make_tenant(data_root, TID)
    _base, src = _old_layout_source(tmp_path)
    before = {data_root: H.census(data_root)}
    owner = H.owner_refusal(H.tenant_of_run_dir, src)
    result, _spawn, agent = _launch(src)
    text = _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                           agent=agent)
    assert "does not live directly under" not in text, (
        "the launch path still answers through refuse_distant_source")

    good_base = H.runs_dir(data_root, TID)
    good_base.mkdir(parents=True)
    H.plant_record(good_base, TID)
    good = H.source_run(good_base)
    _result, spawn, agent = _launch(good)
    assert agent.calls > 0, f"a tenant-location source was refused: {_result!r}"
    assert spawn.launches, f"a tenant-location source started no sibling: {_result!r}"


def _graded_launch(tmp_path: Path, monkeypatch, root: Path, *, collide: bool):
    """ONE whole episode through the real launcher, judge included (`_judge_921`'s own drive:
    `J.FakeSibling` leaves finished, archivable siblings, so the family is accepted and the
    JUDGE step actually runs). The source sits at `<root>/<T>/runs/`; with `collide`, a finished
    run named for graded world `b` stands beside it there. Returns (status, episode dir)."""
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)  # the retired knob: nothing may read it
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))
    episodes = _episodes_root(tmp_path, monkeypatch)
    _base, src = H.tenant_source(root, TID)
    if collide:
        (H.runs_dir(root, TID) / "b").mkdir()
    episode_dir = episodes.resolve() / T.EPISODE_ID
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    result = H.drive_launch(src, spawn=J.FakeSibling(episode_dir), judge=judge,
                            door=T.FakeDoor(),
                            questioner=T.FakeAgent(T.family_doc(), T.world_doc("b"),
                                                   T.world_doc("c")),
                            adapters=T.FakeAdapters(), invoke=T.FakeAgent(*["same"] * 24),
                            live_tree=T.source_capture())
    return result, episode_dir


def test_d4_launcher_derives_once(tmp_path, monkeypatch, data_root, capfd):
    """The launcher derives T once, before episode_dir_for, and threads runs_base_for(T) to every
    consumer it drives; no consumer re-derives T or reads the manifest for it.

    Driven end to end through the REAL `cli.main` with its `judge=` seam: the grade the launcher
    runs at the tail of `_run_episode` (`_grade` -> `grade_episode`) probes the THREADED base.
    A finished run named for graded world `b` in `<root>/<T>/runs/` must be refused by the
    label-collision probe, and that refusal is what F-5's non-fatal print channel carries —
    not a `TypeError` (the now-required keyword left out), not an `ImportError` or a
    `resolve_runs_base` fault (a leftover import of the deleted resolver), both of which
    `_grade`'s broad `except` would otherwise print and swallow exactly like the collision.
    The retired `DEFENDER_RUNS_BASE` is unset, so a consumer that re-derives its base from
    anything but T finds nothing to collide with.

    Positive control, same drive: without the colliding run the episode is graded
    (`judge.yaml` written), so the refusal above is the probe firing on the threaded base."""
    result, episode_dir = _graded_launch(tmp_path / "collide", monkeypatch, data_root,
                                         collide=True)
    err = capfd.readouterr().err
    assert not isinstance(result, BaseException), f"the launch itself was refused: {result!r}"
    failed = [ln for ln in err.splitlines() if "the judge pass failed" in ln]
    assert failed, f"the judge pass did not fail on the colliding world label:\n{err[-2000:]}"
    collision = H.runs_dir(data_root, TID) / "b"
    assert any("collides" in ln and str(collision) in ln for ln in failed), (
        f"the grade failed, but not on the label-collision probe over <root>/<T>/runs:\n{failed}")
    for wrong in ("TypeError", "ImportError", "resolve_runs_base", "FatalConfigError"):
        assert wrong not in err, f"the launcher's grade failed for the wrong reason ({wrong})"
    assert not (episode_dir / "judge.yaml").exists(), "a colliding episode was graded anyway"

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
    role is tenant_of_run_dir's location check (positive control: d4_launch_location_check)."""
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
    """With <root>/T (or <root>/T/runs) a symlink to another directory, a run dir there passes
    tenant_of_run_dir's location check, because both sides of the comparison are resolved
    (base == TenantPaths(root, T).runs.resolve()), and a launch from it gets past that check; an
    old-layout base still resolves outside <root>/T/runs and is refused.

    KNOWN LIMIT, not pinned and not fixed here: a fork of a run MATERIALIZED through a symlinked
    <root>/T/runs still fails the pre-existing C67 store check — its case pointer names the store
    beside the unresolved base, while open_source_store re-derives it beside the resolved one —
    so that shape stays unbranchable. Shape 2 below therefore builds its source at the resolved
    base, which keeps the location check the only question this test asks.

    Two data roots, one per shape: `<root>/T` linked, and `<root>/T/runs` linked. Each launch
    must get past the location check (the siblings are started)."""
    _episodes_root(tmp_path, monkeypatch)
    # shape 1: <root>/T is a symlink to a real tenant folder elsewhere
    real_tenant = tmp_path / "real-tenant-folder"
    real_tenant.mkdir()
    (data_root / TID).symlink_to(real_tenant, target_is_directory=True)
    H.plant_row(data_root, TID)
    _base, src = H.tenant_source(data_root, TID, row=False)
    assert H.tenant_of_run_dir(src) == TID
    assert H.tenant_of_run_dir(src.resolve()) == TID
    result, spawn, agent = _launch(src)
    assert agent.calls > 0, f"<root>/T as a symlink was refused: {result!r}"
    assert spawn.launches, f"<root>/T as a symlink started no sibling: {result!r}"

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
    H.plant_record(root2 / TID / "runs", TID)
    # Built AT THE RESOLVED base, so the source's case pointer names the store beside
    # `real-runs` — the one C67's own derive-and-compare (unchanged by #1078, it resolves the
    # run dir first) re-derives. That keeps the location check the only question asked here.
    H.source_run(real_runs)
    src2 = root2 / TID / "runs" / T.SOURCE_RUN_ID
    assert H.tenant_of_run_dir(src2) == TID
    assert H.tenant_of_run_dir(src2.resolve()) == TID
    result, spawn, agent = _launch(src2)
    assert agent.calls > 0, f"<root>/T/runs as a symlink was refused: {result!r}"
    assert spawn.launches, f"<root>/T/runs as a symlink started no sibling: {result!r}"

    # the control: an old-layout base is still refused by location
    _old, old_src = _old_layout_source(tmp_path)
    H.owner_refusal(H.tenant_of_run_dir, old_src)


def test_branch_launch_after_the_data_root_changes_underneath_a_valid_run(
        tmp_path, monkeypatch, data_root):
    """A launch from a run materialized under a data root the environment no longer names is
    refused by tenant_of_run_dir's location check, with nothing written. Whether its message
    differs from an old-layout refusal is not pinned.

    The run is materialized for real under the OLD root; T exists under the new one too, so
    the location is the only thing wrong with the source."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    old_root = tmp_path / "old-data-root"
    H.set_data_root(monkeypatch, old_root)
    H.make_tenant(old_root, TID)
    alert = H.plant_alert(tmp_path / "in")
    run_dir = Path(H.run_common().materialize_run_dir(alert, "r1", tenant_id=TID))
    assert run_dir == old_root / TID / "runs" / "r1"
    H.set_data_root(monkeypatch, data_root)
    H.make_tenant(data_root, TID)
    before = {data_root: H.census(data_root), old_root: H.census(old_root)}
    owner = H.owner_refusal(H.tenant_of_run_dir, run_dir)
    result, _spawn, agent = _launch(run_dir)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)


def test_launch_from_a_source_under_another_data_root(tmp_path, monkeypatch, data_root):
    """A launch from a source under another data root is refused by location (its base is not
    TenantPaths(resolved root, T).runs); nothing is written.

    The other root is a complete tenant layout of its own (row, record, branchable run); only
    the environment's root decides."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    H.make_tenant(data_root, TID)
    other = tmp_path / "another-data-root"
    _base, src = H.tenant_source(other, TID)
    before = {data_root: H.census(data_root), other: H.census(other)}
    owner = H.owner_refusal(H.tenant_of_run_dir, src)
    result, _spawn, agent = _launch(src)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)


# ======================================================================================
# Past the tenant check, into the launcher's existing source checks
# ======================================================================================

def test_launch_from_a_nonexistent_run_dir_at_a_tenant_location(tmp_path, monkeypatch, data_root):
    """(a) A nonexistent run dir whose parent is T's runs base with a valid record passes
    tenant_of_run_dir (step 1's resolve() is non-strict) and is refused later by the launcher's
    existing source checks; (b) an arbitrary nonexistent path is refused as an absent record.
    Nothing is written in either case."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    base, _src = H.tenant_source(data_root, TID)
    ghost = base / "no-such-run"
    assert H.tenant_of_run_dir(ghost) == TID, "(a) the derivation refused a tenant location"
    before = {data_root: H.census(data_root)}
    result, _spawn, agent = _launch(ghost)
    _assert_refused_writing_nothing(result, owner=None, episodes=episodes, roots=before,
                                    agent=agent)
    assert not ghost.exists()

    nowhere = tmp_path / "nowhere" / "r1"
    owner = H.owner_refusal(H.tenant_of_run_dir, nowhere)
    result, _spawn, agent = _launch(nowhere)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=before,
                                    agent=agent)
    assert not (tmp_path / "nowhere").exists(), "(b) the refusal minted a record or a dir"


@pytest.mark.parametrize("entry", [H.RECORD_NAME, "r1.run-end.json"])
def test_launch_from_a_non_run_entry_of_the_runs_base(tmp_path, monkeypatch, data_root, entry):
    """A non-run entry of T's runs base (_tenant.json, a run-end sidecar) given as the source
    passes tenant_of_run_dir (its parent is T's runs base) and is refused by the existing source
    checks; nothing is written."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    base, _src = H.tenant_source(data_root, TID)
    source = base / entry
    if not source.exists():
        source.write_text('{"exit_class": "completed"}\n', encoding="utf-8")
    assert H.tenant_of_run_dir(source) == TID
    before = {data_root: H.census(data_root)}
    result, _spawn, agent = _launch(source)
    _assert_refused_writing_nothing(result, owner=None, episodes=episodes, roots=before,
                                    agent=agent)


def test_tenant_of_run_dir_given_a_run_dir_that_is_a_file_not_a_directory(
        tmp_path, monkeypatch, data_root):
    """A run_dir that is a regular file inside T's runs base passes tenant_of_run_dir and is
    refused by the existing source checks; nothing is written."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    base, _src = H.tenant_source(data_root, TID)
    as_file = base / "r2"
    as_file.write_text("not a directory\n", encoding="utf-8")
    assert H.tenant_of_run_dir(as_file) == TID
    before = {data_root: H.census(data_root)}
    result, _spawn, agent = _launch(as_file)
    _assert_refused_writing_nothing(result, owner=None, episodes=episodes, roots=before,
                                    agent=agent)


# ======================================================================================
# Episodes made before (A), and pass-A episodes setup never adopts
# ======================================================================================

def test_episode_made_between_1077_and_pass_a(tmp_path, monkeypatch, data_root):
    """A launch from a sibling of an episode made between #1077 and (A) (its record names
    `default`), or a by-hand resume of its manifest (whose source is an old-layout run with no
    record, C74/C75), is refused, by location or as an absent record, never minted, and nothing
    is written. Its (B) adoption is outside this pass."""
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
    sib = sib_base / f"{T.EPISODE_ID}-b"
    (sib / "gather_raw").mkdir(parents=True)
    H.plant_record(sib_base, "default")
    shutil.copy(old_src / "alert.json", sib / "alert.json")
    (sib / "provenance.json").write_text(json.dumps(T.provenance_record()), encoding="utf-8")
    record_before = (sib_base / H.RECORD_NAME).read_bytes()
    roots = {data_root: H.census(data_root), old_base: H.census(old_base)}

    owner = H.owner_refusal(H.tenant_of_run_dir, sib)
    result, _spawn, agent = _launch(sib)
    _assert_refused_writing_nothing(result, owner=owner, episodes=episodes, roots=roots,
                                    agent=agent)
    assert (sib_base / H.RECORD_NAME).read_bytes() == record_before, "the record was rewritten"

    resume_owner = H.owner_refusal(H.tenant_of_run_dir, old_src)
    rec = H.Recorder(tmp_path / "never")
    rc, refused = H.drive_main(H.resume_argv(manifest), rec)
    assert rc is None, "the by-hand resume of a pre-A manifest ran"
    assert refused is not None
    H.assert_verbatim(H.refusal_text(refused), resume_owner, entry="run.py --resume")
    assert not rec.spent, f"the refused resume spent: {rec.order}"
    assert not (old_base / H.RECORD_NAME).exists(), "the refused resume minted a record"
    for root, before in roots.items():
        assert H.census(root) == before, f"the refused resume wrote under {root}"


def test_unadopted_base_keeps_tenant_named_records_forever(tmp_path, monkeypatch, data_root):
    """A pass-A episodes base that setup never adopts keeps sibling records naming T outside
    <root>/T/ (N14 residual); nothing refuses or cleans them.

    Two siblings of one episode materialize for real under the old episodes base; the record
    the first mints names T, sits outside `<root>/T/`, is read (never rewritten) by the second,
    and survives a setup re-run for T untouched."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    ep, _run_b, _world = _materialize_sibling(data_root, episodes, "b")
    record = ep / "runs" / H.RECORD_NAME
    body = record.read_bytes()
    assert json.loads(body)["tenant_id"] == TID
    assert (data_root / TID) not in record.parents, "the sibling record sits inside <root>/T/"
    _ep, run_c, _world = _materialize_sibling(data_root, episodes, "c")
    assert run_c.parent == ep / "runs"
    assert record.read_bytes() == body, "the second sibling rewrote the record"
    proc = H.run_setup(data_root, TID)
    H.assert_setup_ran(proc)
    assert proc.returncode == 0, H.setup_output(proc)
    assert record.read_bytes() == body, "setup touched a record outside the data root"


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
    H.branch_cli().start_family(ep, ["a", "b", "c"], spawn=spawn)
    assert len(spawn.launches) == 3, "not every sibling was started"
    for launch in spawn.launches:
        assert T.RUNS_BASE_ENV not in launch["env"], (
            f"the launcher composed a runs base for {launch['argv']}: "
            f"{launch['env'].get(T.RUNS_BASE_ENV)}")
        assert launch["env"].get(H.DATA_ROOT_ENV) == str(current_data_root())

    stale = tmp_path / "stale-operator-runs"
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(stale))
    spawn = T.FakeSpawn()
    H.branch_cli().start_family(ep, ["b"], spawn=spawn)
    assert [la["env"].get(T.RUNS_BASE_ENV) for la in spawn.launches] == [str(stale)]


def test_947_pins_under_a_clean_environment(tmp_path, monkeypatch, d9_tenant):
    """The two #947 pins are rewritten: test_947_triplet_archive.py asserts the launcher sets no
    DEFENDER_RUNS_BASE of its own; test_947_triplet_review.py's ctx.env value is runs_base_for(T)
    from the tenant fixture.

    Pinned here under the CLEAN environment the old pins could not survive (brief R2): no
    DEFENDER_RUNS_BASE in the parent at all. The sibling's env then carries none (a `KeyError`
    for the old `launch["env"]["DEFENDER_RUNS_BASE"]`), and the replay env's value is the
    threaded tenant runs base, composed without any environment read."""
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    ep = T.episode(tmp_path)
    spawn = T.FakeSpawn()
    H.branch_cli().start_family(ep, ["a", "b"], spawn=spawn)
    assert spawn.launches
    assert all(T.RUNS_BASE_ENV not in la["env"] for la in spawn.launches)

    runs_base = H.runs_base_for(d9_tenant)
    ctx = H.mod("learning.branch.review").verb_context(ep, runs_base=runs_base)
    assert ctx.env[T.RUNS_BASE_ENV] == str(runs_base)
    assert runs_base == current_data_root().resolve() / d9_tenant / "runs"
    assert ctx.env[T.RUNS_BASE_ENV] != str(ep.parent)


# ======================================================================================
# D4 — the episodes root re-keyed onto the tenant (A), J44's pass-A refusal
# ======================================================================================

def _episodes_root_for(tenant_paths):
    return H.branch_cli().episodes_root(tenant=tenant_paths)


@pytest.mark.parametrize("member", [
    "inside-tenant-runs", "equal-data-root", "containing-data-root", "inside-data-root-other",
    "tenant-folder", "tenant-episodes", "outside-data-root",
])
def test_d4_episodes_root_rekeyed(tmp_path, monkeypatch, member):
    """episodes_root, handed TenantPaths(root, T) as its tenant, refuses a base inside
    <T>/runs, a base equal to or containing the data root, and ANY base inside the data root,
    <T>/episodes and its subdirectories included (so /tmp/defender-data,
    /tmp/defender-data/playground, <root>/T/episodes and /tmp are refused for root
    /tmp/defender-data), and accepts a base outside the data root.

    The root is a tmp stand-in for /tmp/defender-data (nothing is created at the real path);
    `containing-data-root` is its parent, as /tmp is for /tmp/defender-data. The old runs base
    is unset, so the re-keyed check is the only one that can refuse."""
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    root = tmp_path / "defender-data"
    H.set_data_root(monkeypatch, root)
    base = {
        "inside-tenant-runs": root / TID / "runs" / "x",
        "equal-data-root": root,
        "containing-data-root": tmp_path,
        "inside-data-root-other": root / "other",
        "tenant-folder": root / TID,
        "tenant-episodes": root / TID / "episodes",
        "outside-data-root": tmp_path / "elsewhere" / "episodes",
    }[member]
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(base))
    tenant_paths = H.TenantPaths(root, TID)
    if member == "outside-data-root":
        assert _episodes_root_for(tenant_paths) == base.resolve()
    else:
        with pytest.raises(H.branch_cli().LauncherRefused) as refused:
            _episodes_root_for(tenant_paths)
        assert T.EPISODES_BASE_ENV in H.refusal_text(refused.value)
    assert not root.exists(), "the episodes-root check created something under the data root"


def test_s7_j44_episodes_base_inside_data_root_refused(tmp_path, monkeypatch, data_root):
    """In pass (A), DEFENDER_EPISODES_BASE=<root>/T/episodes and <root>/T/episodes/sub are
    refused by episodes_root, naming the variable, and nothing is written; a base outside the
    data root is accepted (the control)."""
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    H.make_tenant(data_root, TID)
    before = H.census(data_root)
    tenant_paths = H.TenantPaths(data_root, TID)
    for base in (data_root / TID / "episodes", data_root / TID / "episodes" / "sub"):
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(base))
        with pytest.raises(H.branch_cli().LauncherRefused) as refused:
            _episodes_root_for(tenant_paths)
        assert T.EPISODES_BASE_ENV in H.refusal_text(refused.value)
    assert H.census(data_root) == before, "the refusal wrote under the data root"
    outside = tmp_path / "episodes-outside"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(outside))
    assert _episodes_root_for(tenant_paths) == outside.resolve()


def test_episodes_base_inside_an_old_runs_base(tmp_path, monkeypatch, data_root):
    """DEFENDER_EPISODES_BASE=/tmp/defender-runs/episodes in (A) is accepted by the re-keyed
    check, which refuses only a base inside tenant.runs or at or around the data root; N9's
    walkers of the old base still descend into it.

    Asked twice: with the literal path (resolved, never created) and with a tmp stand-in old
    base that an operator shell still exports as DEFENDER_RUNS_BASE — the base today's check
    keys on. The walker is the orientation corpus's recursive `load_corpus`, pointed at the old
    base as N9's directory tools are."""
    tenant_paths = H.TenantPaths(data_root, TID)
    literal = Path("/tmp/defender-runs/episodes")
    existed = literal.exists()
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(literal))
    assert _episodes_root_for(tenant_paths) == literal.resolve()
    assert literal.exists() == existed, "the check created the literal episodes base"

    old_base = tmp_path / "defender-runs"
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(old_base))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(old_base / "episodes"))
    assert _episodes_root_for(tenant_paths) == (old_base / "episodes").resolve()
    T.corpus_document(old_base / "episodes" / T.EPISODE_ID / "runs" / "sib-b")
    _companions, report = H.mod("skills.invlang.corpus").load_corpus(old_base)
    assert report.loaded == 1, "the old base's walker no longer descends into its episodes"


def test_episodes_base_reached_through_a_symlink_into_the_data_root(
        tmp_path, monkeypatch, data_root):
    """An episodes base reached through a symlink is judged on its resolved path, so a link to
    <root>/T/runs/x or to <root>/other is refused by D4's overlap refusal.

    Control: a link to a directory outside the data root is accepted, as its resolved target."""
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    tenant_paths = H.TenantPaths(data_root, TID)
    for target in (data_root / TID / "runs" / "x", data_root / "other"):
        target.mkdir(parents=True)
        link = tmp_path / f"link-{target.name}"
        link.symlink_to(target, target_is_directory=True)
        monkeypatch.setenv(T.EPISODES_BASE_ENV, str(link))
        with pytest.raises(H.branch_cli().LauncherRefused):
            _episodes_root_for(tenant_paths)
    outside = tmp_path / "outside-episodes"
    outside.mkdir()
    ok_link = tmp_path / "ok-link"
    ok_link.symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(ok_link))
    assert _episodes_root_for(tenant_paths) == outside.resolve()


def test_g_r7_episode_dir_reader_coherence(tmp_path, monkeypatch, data_root):
    """episodes_root, refuse_claimed_episode and visualize_episode — the three existing readers of
    episode_dir left unmoved while materialize_run_dir's sibling arm
    (EpisodePaths(world.episode_dir).runs, C8) newly reads it this pass — resolve the same path
    materialize_run_dir now threads; driving a sibling run and then each of the three readers
    over the same episode_dir observes agreement, not a stale copy."""
    episodes = _episodes_root(tmp_path, monkeypatch)
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)
    ep, run_dir, world = _materialize_sibling(data_root, episodes, "b")
    assert run_dir.parent == H.mod("_episode_paths").EpisodePaths(world.episode_dir).runs
    assert run_dir.parent == ep / "runs"
    cli = H.branch_cli()
    assert _episodes_root_for(H.TenantPaths(data_root, TID)) / T.EPISODE_ID == ep.resolve()
    with pytest.raises(H.mod("learning.branch.ledger").LedgerError) as claimed:
        cli.refuse_claimed_episode(ep, T.EPISODE_ID)
    assert str(ep / "family.yaml") in str(claimed.value)
    page = H.mod("scripts.visualize.visualize_episode").load_episode(ep)
    assert page.entries["b"].run_dir_name == run_dir.name, (
        "the episode page does not see the run dir the sibling's materialize made")


# ======================================================================================
# O4 — a fork's session rows land in its source's store under <root>/T/sessions/ (C67)
# ======================================================================================

def test_o4_fork_store_location(tmp_path, data_root):
    """A sibling forked from <root>/T/runs/r1 records a session pointer naming
    <root>/T/sessions/<case>.db, its source's store.

    Driven through the resume's own store seam (`store_factory_for`, `open_main_session`,
    `attach_case_pointer`) — the path `run_investigation` takes for a sibling. The mechanism is
    C67/C11's and unchanged by #1078; what pass A adds is that the source sits at a tenant
    location, so the store it forks into is the tenant's."""
    base = H.runs_dir(data_root, TID)
    base.mkdir(parents=True)
    H.plant_record(base, TID)
    src = H.source_run(base, "r1")
    br = H.mod("runtime.branch")
    store = br.open_source_store(src)
    try:
        as_of = br.branch_point_time(store, src, T.BRANCH_MESSAGE_ID)
    finally:
        store.close()
    spec = br.BranchSpec(source_run_dir=src, branch_message_id=T.BRANCH_MESSAGE_ID,
                         continuation_prompt=H.CONTINUATION, as_of=as_of)
    sib = tmp_path / "episodes-root" / T.EPISODE_ID / "runs" / f"{T.EPISODE_ID}-b"
    sib.mkdir(parents=True)
    store = br.store_factory_for(spec)("minted-case", sib)
    try:
        session_id, _history = br.open_main_session(store, spec, sib)
        br.attach_case_pointer(store, spec, sib, case_id="minted-case", session_id=session_id)
    finally:
        store.close()
    pointer = json.loads((sib / "session_store_pointer.json").read_text(encoding="utf-8"))
    expected = H.sessions_dir(data_root, TID) / f"{T.SOURCE_CASE_ID}.db"
    assert Path(pointer["store_path"]).resolve() == expected.resolve()
    assert not (sib.parent.parent / "sessions").exists(), "the fork opened a store of its own"

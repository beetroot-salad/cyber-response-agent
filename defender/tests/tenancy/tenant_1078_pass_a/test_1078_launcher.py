"""Branch launcher keeps a fork's tenant: source opened through the tenant's runs repository, refusals write nothing, episodes-root placement refusals."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from defender.tests.support.learning.branch import _branch_947 as B947

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

from defender.tests.support.shared.contracts._spec1077 import fixture_run


import json
from pathlib import Path
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.records import RunPaths

import pytest

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H
from defender.tests.support.learning.core import _state1135

TID = H.VALID_ID


def _episodes_root(tmp_path: Path, monkeypatch) -> Path:
    """A configured episodes root OUTSIDE the data root (the only place pass A accepts one)."""
    root = tmp_path / "episodes-root"
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(root))
    return root


def _seams(**over):
    """Every launcher seam a scenario is not about, faked: nothing here decides a refusal."""
    seams = {
        "spawn": T.FakeSpawn(),
        "questioner": T.FakeAgent(T.declaration(T.family_doc()), T.declaration(T.world_doc("b")), T.declaration(T.world_doc("c"))),
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
            *T.retired_continuation_argv()]
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
    from defender.records._tenant_id import TenantRefused
    from defender.records import RunId, RunRefused

    with pytest.raises((RunRefused, TenantRefused)) as refused:
        H.accept(root, tenant_id).runs_repository().open(RunId.parse(run_id))
    return refused.value


def _opens_as(root: Path, run_id: str, tenant_id: str = TID) -> str:
    """The tenant a run opened by id through `tenant_id`'s repository under `root` is addressed
    to — the replacement for `tenant_of_run_dir(...) == T` (F-13)."""
    from defender.records import RunId

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


def test_o5_no_record_refused_never_minted(tmp_path, monkeypatch, data_root):
    'A run dir at <root>/T/runs/r1 whose base has no _tenant.json is refused, and no\n_tenant.json is created.'
    base, src = H.tenant_source(data_root, TID)
    before = H.census(data_root)
    assert not (base / H.RECORD_NAME).exists(), "precondition: the base holds no record"
    assert _opens_as(data_root, src.name) == TID, "T's run at T's location did not open as T's"
    assert not (base / H.RECORD_NAME).exists(), "the open minted a record"
    assert H.census(data_root) == before, "opening the source wrote under the data root"



def test_o5_requires_row(tmp_path, data_root):
    base, src = H.tenant_source(data_root, TID, row=False)
    assert not location_path(H.row_path)(data_root, TID).exists()
    H.place_knowledge(data_root, TID)
    before = H.census(data_root)
    H.owner_refusal(H.accept, data_root, TID)
    assert H.census(data_root) == before, "the refused acceptance wrote under the data root"
    H.plant_row(data_root, TID)
    assert _opens_as(data_root, src.name) == TID


def test_d4_launch_location_check(tmp_path, monkeypatch, data_root):
    episodes = _episodes_root(tmp_path, monkeypatch)
    # #1108 P4: the good half launches a branch, which needs a published tenant (flow 7).
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    set_up_tenant(data_root, TID, published=True)
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
    "ONE whole episode through the real launcher, judge included (`_judge_921`'s own drive:\n`J.FakeSibling` leaves finished, archivable siblings, so the family is accepted and the\nJUDGE step actually runs). The source sits at `<root>/<T>/runs/`; with `collide`, a finished\nrun named for graded world `b` stands beside it there. Returns (status, episode dir)."
    monkeypatch.delenv(T.RUNS_BASE_ENV, raising=False)  # the retired knob: nothing may read it
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
    episodes = _episodes_root(tmp_path, monkeypatch)
    del episodes  # #1187 (O9): the episode is `<root>/<T>/episodes/<uuid>`, the variable a decoy
    _base, src = H.tenant_source(root, TID, published=True)  # #1108 P4: a branch launch needs a published tenant (flow 7 pins its commit)
    if collide:
        (H.runs_dir(root, TID) / "b").mkdir()
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    result = H.drive_launch(src, spawn=J.FakeSibling(data_root=root), judge=judge,
                            questioner=T.FakeAgent(T.declaration(T.family_doc()), T.declaration(T.world_doc("b")),
                                                   T.declaration(T.world_doc("c"))),
                            live_tree=T.source_capture(), **H.serving_oracle())
    made = sorted((root / TID / "episodes").glob("*"))
    assert len(made) <= 1, f"one launch made {made}"
    return result, made[0] if made else root / TID / "episodes" / "<none made>"



def test_d4_launcher_derives_once(tmp_path, monkeypatch, data_root, capfd):
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


def test_s7_j26_symlinked_tenant_folder_accepted(tmp_path, monkeypatch, data_root):
    'With <root>/T (or <root>/T/runs) a symlink to another directory, a launch from a run\nthere is refused, nothing spent and nothing written.'
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



def test_launch_from_a_nonexistent_run_dir_at_a_tenant_location(tmp_path, monkeypatch, data_root):
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
    "A run id naming a regular file inside T's runs base is refused by the launcher's source\nopen (a run is only ever a real directory); nothing is written."
    episodes = _episodes_root(tmp_path, monkeypatch)
    base, _src = H.tenant_source(data_root, TID)
    as_file = base / fixture_uuid("1078-as-file")  # #1187 dc1: refused as a file, not by shape
    as_file.write_text("not a directory\n", encoding="utf-8")
    before = {data_root: H.census(data_root)}
    result, _spawn, agent = _launch(as_file)
    _assert_refused_writing_nothing(result, owner=None, episodes=episodes, roots=before,
                                    agent=agent)





def _accepted(root: Path):
    """T created in `root` over its placed knowledge (when it is not there yet) and accepted
    through the real `accept_tenant` — what the launcher hands `episodes_root`."""
    if not location_path(H.row_path)(root, TID).exists():
        H.make_tenant(root, TID)
    return H.accept(root, TID)










def _sibling_state(sib: Path):  # noqa: ANN202 — a `RunState` (#1235: not imported at top)
    """A fresh run state for the sibling at `sib`, which seeding takes as its third argument
    (#1235 round 2, where it was the sibling's run dir)."""
    from defender.investigation.run_state import RunState

    return RunState(sib, sib.name)


def test_o4_fork_store_location(tmp_path, data_root):
    """A sibling forked from <root>/T/runs/r1 records a session pointer naming
    <root>/T/sessions/<case>.db, its source's store."""
    base = H.runs_dir(data_root, TID)
    base.mkdir(parents=True)
    src = H.source_run(base)
    br = H.mod("investigation.branch")
    store = br.open_source_store(src, source_run=_run_handle_1165(src))
    try:
        as_of = br.branch_point_time(store, src, T.BRANCH_MESSAGE_ID, source_run=_run_handle_1165(src))
    finally:
        store.close()
    # #1255 (D1, P4) COMPAT: the prompt reaches the spec only while the spec declares it.
    retired = ({B947.RETIRED_PROMPT_FIELD: H.CONTINUATION}
               if B947.declares_retired_prompt() else {})
    spec = br.BranchSpec(source_run_dir=src, branch_message_id=T.BRANCH_MESSAGE_ID,
                         as_of=as_of, **retired)
    sib = (data_root / TID / "episodes" / T.EPISODE_ID / "runs"
           / fixture_uuid("o4-fork-sibling-b"))
    sib.mkdir(parents=True)
    store = br.store_factory_for(spec, source_run=fixture_run(spec.source_run_dir))("minted-case", sib)
    try:
        session_id, _history = br.open_main_session(store, spec, _sibling_state(sib), run=fixture_run(sib), source_run=fixture_run(spec.source_run_dir))
        br.attach_case_pointer(store, spec, _run_handle_1165(sib), case_id="minted-case", session_id=session_id)
    finally:
        store.close()

    pointer = json.loads(RunPaths(sib).session_pointer().read_text(encoding="utf-8"))
    assert not (sib / "session_store_pointer.json").exists(), (
        "the fork wrote its case pointer inside the box-writable run dir")
    expected = H.sessions_dir(data_root, TID) / f"{T.SOURCE_CASE_ID}.db"
    assert Path(pointer["store_path"]).resolve() == expected.resolve()
    assert not (sib.parent.parent / "sessions").exists(), "the fork opened a store of its own"

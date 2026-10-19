"""The tenant-scoped run repository: open/create/list, RunAddress, episode views and their refusals."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender import _tenant
from defender._tenant import TenantRecordMismatch, TenantRefused
from defender.tests.tenant_1105_run_repository import _spec1105 as H

EP = "20260728t161845z-src-n59"
LABEL = "a"


@pytest.fixture
def episodes(tmp_path, monkeypatch) -> Path:
    """The configured episodes root, outside the data root and the checkout."""
    root = tmp_path / "episodes"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(root))
    return root


def _good(tmp_path: Path, *run_ids: str, tenant_id: str = H.T_ID):
    """A data root holding `tenant_id`, its natural runs folder made as run setup leaves it
    (`_tenant.json` naming it) and a real run folder per id."""
    root = tmp_path / "data"
    root.mkdir(parents=True, exist_ok=True)
    t = H.tenant(root, tenant_id)
    H.runs_folder(t)
    for rid in run_ids:
        H.make_run(t.runs, rid)
    return root, t


def _rid(text: str):
    from defender.run_repository import RunId

    return RunId.parse(text)


def _ids(listed) -> list[str]:
    """A `Listed`'s run ids, as text, in its order (the one place its spelling is read)."""
    return [str(i) for i in listed]


def _refusal_classes():
    from defender.run_repository import RunRefused

    return (RunRefused, TenantRefused)


def _episode(episodes: Path, *, container: str | None = None, arms: tuple[str, ...] = (),
             raw_record: str | None = None) -> Path:
    """`<episodes>/<EP>/` with a manifest-shaped file and, when asked, its container `runs/`:
    `container` names the tenant its `_tenant.json` names (written by the real writer);
    `raw_record` plants that file's bytes verbatim instead; arms are real folders inside."""
    ep = episodes / EP
    ep.mkdir()
    (ep / "family.yaml").write_text("episode_id: x\n", encoding="utf-8")
    if container is not None or raw_record is not None or arms:
        (ep / "runs").mkdir()
    if container is not None:
        _tenant.ensure_runs_base_record(ep / "runs", container)
    if raw_record is not None:
        (ep / "runs" / "_tenant.json").write_text(raw_record, encoding="utf-8")
    for label in arms:
        H.make_run(ep / "runs", f"{EP}-{label}", alert=f'{{"arm": "{label}"}}\n')
    return ep


def test_the_accepted_tenant_hands_out_a_repository_that_opens_its_own_runs_by_id(tmp_path):
    _root, t = _good(tmp_path, "r1", "r2")
    runs = t.runs_repository()

    run = runs.open(_rid("r1"))
    assert Path(run.run_dir) == Path(t.runs) / "r1"
    assert str(run.tenant_id) == H.T_ID
    assert "seed" in (run.facts.alert.read() or "")
    assert Path(runs.open(_rid("r2")).run_dir) == Path(t.runs) / "r2"
    assert isinstance(H.raised(runs.open, t, _rid("r1")), TypeError), (
        "the repository's open took a Tenant beside the id")


def test_run_absent_tells_an_absent_run_from_a_refused_entry(tmp_path):
    from defender.run_repository import RunAbsent, RunRefused

    _root, t = _good(tmp_path, "r1")
    (Path(t.runs) / "afile").write_text("x\n", encoding="utf-8")
    os.symlink(Path(t.runs) / "r1", Path(t.runs) / "alink")
    runs = t.runs_repository()

    absent = H.raised(runs.open, _rid("nope"))
    assert isinstance(absent, RunAbsent), f"an absent run raised {absent!r}"
    assert isinstance(absent, RunRefused)
    assert issubclass(RunAbsent, RunRefused)
    for name in ("afile", "alink"):
        err = H.raised(runs.open, _rid(name))
        assert isinstance(err, RunRefused), (
            f"{name}: {err!r} — a present non-run must not read as absent")
        assert not isinstance(err, RunAbsent), (
            f"{name}: {err!r} — a present non-run must not read as absent")
        assert name in str(err)
    with pytest.raises(RunRefused) as caught:  # the handler every existing caller has
        runs.open(_rid("nope"))
    assert isinstance(caught.value, RunAbsent)
    assert Path(runs.open(_rid("r1")).run_dir) == Path(t.runs) / "r1"


def test_a_container_fault_is_the_tenants_refusal_not_an_absent_run(tmp_path):  # name kept; the owner changed the class (#1105 PR 2 review)
    from defender.run_repository import RunAbsent, RunUnreachable

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()
    absent = H.raised(runs.open, _rid("r1"))
    assert isinstance(absent, RunAbsent), repr(absent)

    elsewhere = tmp_path / "elsewhere-runs"
    H.plant_tenant_record(elsewhere, H.T_ID)
    H.make_run(elsewhere, "r1")
    os.symlink(elsewhere, t.runs)
    linked = H.raised(runs.open, _rid("r1"))
    assert isinstance(linked, RunUnreachable), f"a linked runs folder was followed: {linked!r}"
    assert isinstance(linked.__cause__, TenantRefused), repr(linked.__cause__)
    os.unlink(t.runs)

    H.plant_tenant_record(t.runs, H.U_ID)
    H.make_run(t.runs, "r1")
    foreign = H.raised(runs.open, _rid("r1"))
    assert isinstance(foreign, RunUnreachable), repr(foreign)
    assert isinstance(foreign.__cause__, TenantRecordMismatch), repr(foreign.__cause__)

    (Path(t.runs) / "_tenant.json").unlink()
    recordless = H.raised(runs.open, _rid("r1"))
    assert isinstance(recordless, RunUnreachable), repr(recordless)
    assert isinstance(recordless.__cause__, TenantRefused), repr(recordless.__cause__)
    assert not isinstance(recordless, RunAbsent), repr(recordless)

    H.plant_tenant_record(t.runs, H.T_ID)
    assert Path(runs.open(_rid("r1")).run_dir) == Path(t.runs) / "r1"


def test_list_tells_an_absent_container_from_an_empty_one_and_judges_every_entry(tmp_path):
    from defender.run_repository import RunRefused

    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()

    none_yet = runs.list()
    assert none_yet.absent is True
    assert _ids(none_yet) == []

    H.runs_folder(t)
    empty = runs.list()
    assert empty.absent is False
    assert _ids(empty) == []

    for rid in ("r2", "r1"):
        H.make_run(t.runs, rid)
    H.plant_sidecars(t.runs, "r1")
    listed = runs.list()
    assert listed.absent is False
    assert _ids(listed) == ["r1", "r2"]

    (Path(t.runs) / "stray.txt").write_text("x\n", encoding="utf-8")
    stray = H.raised(runs.list)
    assert isinstance(stray, RunRefused), repr(stray)
    assert "stray.txt" in str(stray), repr(stray)


def test_create_holds_the_container_writes_its_record_and_hands_out_the_run(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    t = H.tenant(root, H.T_ID)
    runs = t.runs_repository()

    run = runs.create(_rid("r9"))
    assert Path(run.run_dir) == Path(t.runs) / "r9"
    assert str(run.tenant_id) == H.T_ID
    assert Path(t.runs).is_dir()
    assert not Path(t.runs).is_symlink()
    assert _tenant.read_tenant(Path(t.runs)).tenant_id == H.T_ID

    other_root = tmp_path / "data2"
    other_root.mkdir()
    u = H.tenant(other_root, H.T_ID)
    target = tmp_path / "link-target"
    target.mkdir()
    os.symlink(target, u.runs)
    linked = H.raised(u.runs_repository().create, _rid("r9"))
    assert isinstance(linked, TenantRefused), repr(linked)
    assert list(target.iterdir()) == [], "the create wrote through a linked runs folder"

    third_root = tmp_path / "data3"
    third_root.mkdir()
    w = H.tenant(third_root, H.T_ID)
    record = H.plant_tenant_record(w.runs, H.U_ID)
    foreign_bytes = record.read_bytes()
    foreign = H.raised(w.runs_repository().create, _rid("r9"))
    assert isinstance(foreign, TenantRefused), repr(foreign)
    assert record.read_bytes() == foreign_bytes
    assert not (Path(w.runs) / "r9").exists()


def test_a_run_address_round_trips_and_rehydrates_only_in_its_own_tenant(tmp_path):
    from defender.run_repository import RunAddress, RunId

    root, t = _good(tmp_path, "r1")
    u = H.tenant(root, H.U_ID)
    H.runs_folder(u)
    H.make_run(u.runs, "r1")

    addr = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse("r1"),
                      episode_id=None)
    stored = {"tenant_id": str(addr.tenant_id), "run_id": str(addr.run_id)}
    back = RunAddress(tenant_id=_tenant.TenantId(stored["tenant_id"]),
                      run_id=RunId.parse(stored["run_id"]), episode_id=None)
    assert back == addr

    accepted = H.tenant(root, stored["tenant_id"])
    resolved = accepted.runs_repository().resolve(back)
    assert Path(resolved.run_dir) == Path(t.runs) / "r1"
    assert str(resolved.tenant_id) == H.T_ID

    beta_addr = RunAddress(tenant_id=_tenant.TenantId(H.U_ID), run_id=RunId.parse("r1"),
                           episode_id=None)
    crossed = H.raised(t.runs_repository().resolve, beta_addr)
    assert isinstance(crossed, _refusal_classes()), f"another tenant's address: {crossed!r}"
    assert Path(u.runs_repository().resolve(beta_addr).run_dir) == Path(u.runs) / "r1"


def test_a_run_address_checks_its_fields_at_construction_and_is_frozen():
    from defender.run_repository import RunAddress, RunId

    good = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse("r1"),
                      episode_id=None)
    arm = RunAddress(tenant_id=_tenant.TenantId(H.T_ID), run_id=RunId.parse(f"{EP}-a"),
                     episode_id=EP)
    assert arm.episode_id == EP
    assert good.episode_id is None

    for bad in ({"tenant_id": "Not A Tenant", "run_id": RunId.parse("r1"), "episode_id": None},
                {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": "../r1", "episode_id": None},
                {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse("r1"),
                 "episode_id": "a/b"}):
        assert H.raised(RunAddress, **bad) is not None, f"RunAddress accepted {bad!r}"
    assert H.raised(setattr, good, "tenant_id", _tenant.TenantId(H.U_ID)) is not None
    assert str(good.tenant_id) == H.T_ID


@pytest.mark.parametrize("episode_id", [
    "..", ".", "a/b", "Upper-Case", "", "x" * 300, "-leading", "a\x00b", b"ep", 7,
], ids=["dotdot", "dot", "slash", "upper", "empty", "over-long", "dash-first", "nul", "bytes",
        "int"])
def test_a_run_address_holds_its_episode_id_to_the_owners_episode_grammar(episode_id):
    from defender.run_repository import RunAddress, RunId

    fields = {"tenant_id": _tenant.TenantId(H.T_ID), "run_id": RunId.parse(f"{EP}-a")}
    assert RunAddress(**fields, episode_id=EP).episode_id == EP
    assert H.raised(RunAddress, **fields, episode_id=episode_id) is not None, (
        f"RunAddress accepted the episode id {episode_id!r}")


def test_an_arm_created_for_t_opens_for_t_through_its_episode_and_never_as_a_natural_run(
        tmp_path, episodes):
    from defender.run_repository import RunAbsent, RunId

    _root, t = _good(tmp_path, "r1")
    ep = _episode(episodes, container=H.T_ID, arms=(LABEL,))
    runs = t.runs_repository()

    view = runs.episode(EP)
    arm_id = view.arm_id(LABEL)
    assert isinstance(arm_id, RunId)
    assert str(arm_id) == f"{EP}-{LABEL}"
    arm = view.open(arm_id)
    assert Path(arm.run_dir) == ep / "runs" / f"{EP}-{LABEL}"
    assert str(arm.tenant_id) == H.T_ID
    assert Path(view.episode.dir) == ep
    assert view.base_world_id() == _tenant.read_tenant(ep / "runs").base_world_id
    assert isinstance(H.raised(runs.open, arm_id), RunAbsent)


def test_the_view_refuses_a_container_naming_another_tenant_or_none_at_once(tmp_path, episodes):
    _root, t = _good(tmp_path)
    ep = _episode(episodes, container=H.U_ID, arms=(LABEL,))
    runs = t.runs_repository()

    foreign = H.raised(runs.episode, EP)
    assert isinstance(foreign, TenantRecordMismatch), repr(foreign)

    (ep / "runs" / "_tenant.json").unlink()
    recordless = H.raised(runs.episode, EP)
    assert isinstance(recordless, TenantRefused), f"a recordless container opened: {recordless!r}"

    _tenant.ensure_runs_base_record(ep / "runs", H.T_ID)
    view = runs.episode(EP)
    assert Path(view.open(view.arm_id(LABEL)).run_dir) == ep / "runs" / f"{EP}-{LABEL}"


def test_an_absent_container_opens_the_view_but_no_arm_until_the_launcher_creates_it(
        tmp_path, episodes):
    _root, t = _good(tmp_path)
    ep = _episode(episodes)
    view = t.runs_repository().episode(EP)
    arm_id = view.arm_id(LABEL)

    assert view.state == "absent"
    assert not view.present
    assert isinstance(H.raised(view.open, arm_id), _refusal_classes())
    assert isinstance(H.raised(view.create, arm_id), _refusal_classes())
    assert not (ep / "runs").exists(), "a create over an absent container made it"

    view.create_container()
    assert _tenant.read_tenant(ep / "runs").tenant_id == H.T_ID
    arm = view.create(arm_id)
    assert Path(arm.run_dir) == ep / "runs" / f"{EP}-{LABEL}"
    assert str(arm.tenant_id) == H.T_ID

    H.make_run(ep / "runs", f"{EP}-{LABEL}")
    record = (ep / "runs" / "_tenant.json").read_bytes()
    t.runs_repository().episode(EP).create_container()
    assert (ep / "runs" / "_tenant.json").read_bytes() == record
    assert (ep / "runs" / f"{EP}-{LABEL}" / "alert_input" / "alert.json").is_file()


def test_an_unreadable_container_is_recorded_not_raised_and_never_written_through(
        tmp_path, episodes):
    _root, t = _good(tmp_path)
    ep = _episode(episodes)
    target = tmp_path / "elsewhere"
    target.mkdir()
    H.make_run(target, f"{EP}-{LABEL}")
    os.symlink(target, ep / "runs")
    before = H.tree_state(target)

    view = t.runs_repository().episode(EP)
    assert view.state == "unreadable", f"a linked container read as {view.state}"
    assert view.unreadable_reason, "a linked container's reason was not recorded"
    assert isinstance(H.raised(view.open, view.arm_id(LABEL)), _refusal_classes())
    assert isinstance(H.raised(view.create_container), _refusal_classes())
    assert H.tree_state(target) == before
    assert (ep / "runs").is_symlink()


def test_episode_files_is_the_owners_handle_alone_and_creates_nothing(tmp_path, episodes):
    from defender._tenant import TenantRecordMismatch

    _root, t = _good(tmp_path)
    ep = _episode(episodes, container=H.U_ID)
    runs = t.runs_repository()

    before = H.tree_state(episodes)
    assert isinstance(H.raised(runs.episode_files, EP), TenantRecordMismatch)
    assert H.tree_state(episodes) == before, "a refused door changed the episode"
    (ep / "runs" / "_tenant.json").write_text(H.tenant_record_text(H.T_ID), encoding="utf-8")
    handle = runs.episode_files(EP)
    try:
        assert Path(handle.dir) == ep
    finally:
        handle.close()

    before = H.tree_state(episodes)
    assert H.raised(runs.episode_files, "20260728t161845z-missing-n1") is not None
    assert H.tree_state(episodes) == before, "a missing episode was created"
    (episodes / "20260728t161845z-afile-n1").write_text("x\n", encoding="utf-8")
    with_file = H.tree_state(episodes)
    assert H.raised(runs.episode_files, "20260728t161845z-afile-n1") is not None
    assert H.tree_state(episodes) == with_file, "a file at the episode's name was changed"


def test_a_bad_episode_id_or_an_unset_episodes_base_is_refused_before_anything_is_read(
        tmp_path, episodes, monkeypatch):
    _root, t = _good(tmp_path)
    _episode(episodes, container=H.T_ID)
    runs = t.runs_repository()
    before = H.tree_state(tmp_path)

    for bad in ("../x", "a/b", "Upper-Case", ""):
        assert H.raised(runs.episode, bad) is not None, f"episode({bad!r}) opened"
        assert H.raised(runs.episode_files, bad) is not None, f"episode_files({bad!r}) opened"
    assert H.tree_state(tmp_path) == before

    monkeypatch.delenv("DEFENDER_EPISODES_BASE")
    assert H.raised(runs.episode, EP) is not None
    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(episodes))
    assert runs.episode(EP).present

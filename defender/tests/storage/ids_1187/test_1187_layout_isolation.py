"""Tenant-scoped episode walks refuse aliases and preserve filesystem isolation."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

import os
import shutil
import stat
from pathlib import Path, PurePosixPath

import pytest

from defender import _yaml
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.storage.ids_1187 import _spec1187 as S

A_ID = S.H5.T_ID
B_ID = S.H5.U_ID
DEFENDER = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _no_episodes_variable(monkeypatch):
    """Clear the retired episodes-root variable except in tests that explicitly exercise it."""
    monkeypatch.delenv(S.EPISODES_BASE_ENV, raising=False)
# Local builders (pure filesystem over `_spec1187`) and observation helpers.

def _rid(text: str):
    from defender.records import RunId

    return RunId.parse(text)


def _refusals():
    """The repository's two refusal classes (S-iso: a link refuses with either, naming the level)."""
    from defender.tenancy._tenant import TenantRefused
    from defender.records import RunRefused

    return (TenantRefused, RunRefused)


def _is_refusal(err: BaseException | None) -> bool:
    return err is not None and isinstance(err, _refusals())


def _manifest(episode_id: str) -> str:
    """Build a loadable three-world manifest for the requested episode ID."""
    return _yaml.safe_dump(T.family_doc(episode_id=episode_id, source_run_id=S.new_id()))


def _tenant_scene(root: Path, tenant_id: str) -> dict:
    """Accept a tenant and create one natural run and one episode with rostered arms."""
    t = S.tenant(root, tenant_id)
    run_id = S.new_id()
    S.make_run(S.natural_runs(root, tenant_id), run_id, alert=f'{{"alert": "{tenant_id}"}}\n')
    ep_id = S.new_id()
    roster = {T.fixture_world_id(label): S.new_id() for label in ("a", "b", "c")}
    ep = S.make_episode(root, tenant_id, ep_id, manifest=_manifest(ep_id), roster=roster,
                        arms=True)
    return {"tenant": t, "run_id": run_id, "episode_id": ep_id, "episode": ep,
            "roster": roster}


def _two_tenants(root: Path) -> tuple[dict, dict]:
    """Create two accepted tenants, each with distinct runs, episodes, and arms."""
    return _tenant_scene(root, A_ID), _tenant_scene(root, B_ID)


def _aside(path: Path, scratch: Path) -> Path:
    """Move the real `path` out of the way (to `scratch`), so a link can stand at its name."""
    scratch.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), str(scratch))
    return scratch


def _restore(link: Path, aside: Path) -> None:
    """Remove the link at `link` and put the real folder back."""
    os.unlink(link)
    shutil.move(str(aside), str(link))


def _real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False


def _records_under(folder: Path) -> list[str]:
    """Every `_tenant.json` under `folder`, links not followed."""
    return sorted(str(p) for p in Path(folder).rglob("_tenant.json"))
# The natural container: no record written, read or required (R1; O10; flow 1).

def test_create_makes_the_runs_folder_and_writes_no_tenant_record(data_root):
    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    assert not os.path.lexists(runs_dir)
    runs = t.runs_repository()

    run = runs.create()
    assert _real_dir(runs_dir), "create did not make <T>/runs as a real directory"
    assert Path(run.run_dir).parent == runs_dir
    assert S.is_canonical_uuid(Path(run.run_dir).name), run.run_dir
    assert str(run.tenant_id) == A_ID
    assert os.listdir(runs_dir) == [], (
        f"create wrote into <T>/runs beyond making it: {sorted(os.listdir(runs_dir))}")

    again = runs.create()
    assert Path(again.run_dir).parent == runs_dir
    assert Path(again.run_dir) != Path(run.run_dir), "create minted the same id twice"
    assert os.listdir(runs_dir) == []
    assert _records_under(S.tenant_dir(data_root, A_ID)) == []


def test_run_setup_writes_no_tenant_record_for_a_minted_run(
        tmp_path, data_root):
    from defender import run_common
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    alert = H5.alert_file(tmp_path / "in")

    first = run_common.materialize_run(alert, tenant=t)
    assert Path(first.run_dir).parent == runs_dir
    assert _records_under(runs_dir) == [], "run setup wrote a _tenant.json"

    second = run_common.materialize_run(alert, tenant=t)
    assert Path(second.run_dir).parent == runs_dir
    assert _records_under(S.tenant_dir(data_root, A_ID)) == [], "run setup wrote a _tenant.json"
    assert sorted(p.name for p in runs_dir.iterdir() if p.is_dir()) == sorted(
        [Path(first.run_dir).name, Path(second.run_dir).name])


def test_a_container_with_no_record_opens_lists_and_hands_out_every_run(data_root):
    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    first, second = sorted([S.new_id(), S.new_id()])
    S.make_run(runs_dir, first, sidecars=True)
    S.make_run(runs_dir, second)
    runs = t.runs_repository()

    assert Path(runs.open(_rid(first)).run_dir) == runs_dir / first
    assert [str(i) for i in runs.list()] == [first, second]
    assert [Path(r.run_dir).name for r in runs.all_runs()] == [first, second]
    assert not os.path.lexists(runs_dir / "_tenant.json"), "a read wrote a record"


@pytest.mark.parametrize("entry", ["_tenant.json", "_episodes"])
def test_the_listing_refuses_a_tenant_record_or_an_episodes_folder(data_root, entry):
    from defender.records import RunRefused
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    run_id = S.new_id()
    S.make_run(runs_dir, run_id)
    if entry == "_tenant.json":
        planted = H5.plant_tenant_record(runs_dir, A_ID)
    else:
        planted = runs_dir / "_episodes"
        planted.mkdir()
        (planted / "placeholder.json").write_text("{}\n", encoding="utf-8")
    runs = t.runs_repository()

    for call in (runs.list, runs.all_runs):
        err = S.raised(call)
        assert isinstance(err, RunRefused), (
            f"{call.__name__}() over a container holding {entry} gave {err!r}")
    assert os.path.lexists(planted), "the refused listing removed the entry"

    if planted.is_dir():
        shutil.rmtree(planted)
    else:
        planted.unlink()
    assert [str(i) for i in runs.list()] == [run_id]
    assert [Path(r.run_dir).name for r in runs.all_runs()] == [run_id]


def test_an_arm_id_is_absent_from_the_natural_container_and_opens_through_its_episode(
        data_root):
    from defender.records import RunAbsent

    a = _tenant_scene(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    before = S.tree(runs_dir)
    runs = a["tenant"].runs_repository()
    arm = a["roster"][T.fixture_world_id("b")]

    err = S.raised(runs.open, _rid(arm))
    assert isinstance(err, RunAbsent), f"runs.open(<arm id>) gave {err!r}"
    assert arm not in [str(i) for i in runs.list()]
    assert S.tree(runs_dir) == before, "the natural container changed"

    assert Path(runs.open(_rid(a["run_id"])).run_dir) == runs_dir / a["run_id"]
    with runs.episode(a["episode_id"]) as view:
        assert Path(view.open(_rid(arm)).run_dir) == a["episode"] / "runs" / arm
# O8 / S-iso: a link at every level below <T> refuses — with the link aimed at ANOTHER
# tenant's real folder holding real entries — and the real folder opens.

def _held_arm(view, arm, operation="open"):
    if operation != "arms":
        return getattr(view, operation)(_rid(arm))
    with view.arms([_rid(arm)]) as handout:
        answer = handout[_rid(arm)]
    if isinstance(answer, BaseException):
        raise answer
    return answer


def _arm_door(runs, episode_id, arm, operation="open"):
    with runs.episode(episode_id) as view:
        return _held_arm(view, arm, operation)


def _episode_door(runs, episode_id, door="episode"):
    with getattr(runs, door)(episode_id):
        pass


def _link_paths(root, scene):
    natural = S.natural_runs(root, scene["tenant"].id)
    episode = scene["episode"]
    return {"runs": natural, "episodes": episode.parent, "episode": episode,
            "arms": episode / "runs", "run": natural / scene["run_id"],
            "arm": episode / "runs" / scene["roster"][T.fixture_world_id("b")]}


@pytest.mark.parametrize("level", ["runs", "episodes", "episode", "arms", "run", "arm"])
def test_linked_repository_levels_refuse_and_restore(tmp_path, data_root, level):
    from defender.records import RunAbsent, RunRefused

    a, b = _two_tenants(data_root)
    link, target = (_link_paths(data_root, scene)[level] for scene in (a, b))
    aside = _aside(link, tmp_path / "aside" / level)
    S.replace_with_link(link, target)
    before = S.tree(S.tenant_dir(data_root, B_ID))
    runs = a["tenant"].runs_repository()
    if level in ("runs", "run"):
        opened_id = b["run_id"] if level == "runs" else a["run_id"]
        probes = {"list": runs.list, "all_runs": runs.all_runs,
                  "open": lambda: runs.open(_rid(opened_id))}
        if level == "runs":
            probes["create"] = lambda: runs.create()
    elif level in ("episodes", "episode"):
        ep_id = b["episode_id"] if level == "episodes" else a["episode_id"]
        probes = {door: lambda door=door: _episode_door(runs, ep_id, door)
                  for door in ("episode", "episode_files")}
        if level == "episodes":
            probes["create_episode"] = runs.create_episode
    else:
        if level == "arm":
            _episode_door(runs, a["episode_id"])  # A bad leaf must not refuse the episode.
        arm = b["roster"][T.fixture_world_id("a")] if level == "arms" else a["roster"][T.fixture_world_id("b")]
        probes = {operation: lambda operation=operation: _arm_door(
            runs, a["episode_id"], a["roster"][T.fixture_world_id("a")] if operation == "create" else arm, operation)
            for operation in (("open", "arms", "create") if level == "arms" else ("open",))}
    for name, probe in probes.items():
        err = S.raised(probe)
        assert _is_refusal(err), (level, name, err)
        assert str(link) in S.message(err), (level, name, err)
        if level in ("run", "arm") and name == "open":
            assert isinstance(err, RunRefused)
            assert not isinstance(err, RunAbsent), "a linked run must not read as absent"
    assert link.is_symlink(), "the refused door replaced the link"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == before, "A's calls changed B's tree"

    _restore(link, aside)
    if level in ("runs", "run"):
        assert Path(runs.open(_rid(a["run_id"])).run_dir) == S.natural_runs(data_root, A_ID) / a["run_id"]
        assert [str(rid) for rid in runs.list()] == [a["run_id"]]
    else:
        arm = a["roster"][T.fixture_world_id("b")]
        assert Path(_arm_door(runs, a["episode_id"], arm).run_dir) == a["episode"] / "runs" / arm
        with runs.episode_files(a["episode_id"]) as handle:
            assert Path(handle.dir) == a["episode"]

# Refusals must not reveal another tenant's record identities.

def _b_ids(b: dict) -> dict[str, str]:
    """B's ids that none of A's refusals may show: its natural run, its episode, its arms."""
    return {"B's run": b["run_id"], "B's episode": b["episode_id"],
            **{f"B's arm {label}": arm for label, arm in b["roster"].items()}}


def test_a_link_at_the_tenant_folder_is_refused_at_acceptance_and_the_real_folder_accepts(
        tmp_path, data_root):
    from defender.tenancy import _tenant
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    _two_tenants(data_root)
    link = S.tenant_dir(data_root, A_ID)
    aside = _aside(link, tmp_path / "aside" / "tenant")
    S.replace_with_link(link, S.tenant_dir(data_root, B_ID))
    b_before = S.tree(S.tenant_dir(data_root, B_ID))

    err = S.raised(_tenant.accept_tenant, fixture_data_root(data_root), A_ID, defender_dir=H5.DEFENDER)
    assert isinstance(err, _tenant.TenantRefused), f"acceptance through a linked <A> gave {err!r}"
    assert str(link) in S.message(err), f"the refusal does not name <A>: {S.message(err)!r}"
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "acceptance changed B's tree"

    _restore(link, aside)
    accepted = _tenant.accept_tenant(fixture_data_root(data_root), A_ID, defender_dir=H5.DEFENDER)
    assert str(accepted.id) == A_ID
    assert Path(location_path(accepted.tenant_root)) == link


def test_a_tenant_folder_swapped_for_a_link_after_acceptance_refuses_every_repository_door(
        tmp_path, data_root):
    from defender.records import RunAbsent

    a, b = _two_tenants(data_root)
    link = S.tenant_dir(data_root, A_ID)
    b_dir = S.tenant_dir(data_root, B_ID)
    aside = _aside(link, tmp_path / "aside" / "tenant")
    S.replace_with_link(link, b_dir)
    b_ids = _b_ids(b)
    faults: list[str] = []
    refusals: dict[str, tuple[BaseException | None, str | None]] = {}

    taken: list = []
    b_before = S.tree(b_dir)
    at_take = S.raised(lambda: taken.append(a["tenant"].runs_repository()))
    if at_take is not None:
        refusals["runs_repository()"] = (at_take, None)
    else:
        runs = taken[0]
        probes = {
            "list()": (lambda: runs.list(), None),
            "all_runs()": (lambda: runs.all_runs(), None),
            "open(B's run)": (lambda: runs.open(_rid(b["run_id"])), b["run_id"]),
            "create()": (lambda: runs.create(), None),
            "create_episode()": (lambda: runs.create_episode(), None),
            "episode(B's episode)": (lambda: runs.episode(b["episode_id"]), b["episode_id"]),
            "episode_files(B's episode)": (
                lambda: runs.episode_files(b["episode_id"]), b["episode_id"]),
        }
        for what, (probe, asked) in probes.items():
            before = S.tree(b_dir)
            refusals[what] = (S.raised(probe), asked)
            if S.tree(b_dir) != before:
                faults.append(f"{what} through a linked <A> changed B's tree")
    for what, (err, asked) in refusals.items():
        if not _is_refusal(err):
            faults.append(f"{what} through a linked <A> gave {err!r}")
            continue
        said = S.message(err)
        if str(link) not in said:
            faults.append(f"{what}'s refusal does not name <A> ({link}): {said!r}")
        faults.extend(f"{what}'s refusal shows {name} {value}: {said!r}"
                      for name, value in b_ids.items() if value != asked and value in said)
    if S.tree(b_dir) != b_before:
        faults.append("A's calls through the link changed B's tree")
    if not link.is_symlink():
        faults.append("the link at <A> was replaced")
    assert faults == [], "a linked <A> was followed or refused wrongly:\n  " + "\n  ".join(faults)

    _restore(link, aside)
    runs = taken[0] if taken else a["tenant"].runs_repository()
    a_runs = S.natural_runs(data_root, A_ID)
    b_before = S.tree(b_dir)
    assert [str(i) for i in runs.list()] == [a["run_id"]]
    assert [Path(r.run_dir).name for r in runs.all_runs()] == [a["run_id"]]
    assert Path(runs.open(_rid(a["run_id"])).run_dir) == a_runs / a["run_id"]
    assert Path(runs.create().run_dir).parent == a_runs
    with runs.create_episode() as claimed:
        claimed_id = claimed.episode_id
    assert _real_dir(S.episodes_dir(data_root, A_ID) / claimed_id)
    with runs.episode(a["episode_id"]) as view:
        got = {label: str(arm) for label, arm in (view.arm_ids() or {}).items()}
    assert got == a["roster"], f"A's episode answered another roster: {got}"
    handle = runs.episode_files(a["episode_id"])
    try:
        assert Path(handle.dir) == a["episode"]
    finally:
        handle.close()
    absent = S.raised(runs.open, _rid(b["run_id"]))
    assert isinstance(absent, RunAbsent), f"A's open(<B's run id>) gave {absent!r}"
    assert S.raised(runs.episode, b["episode_id"]) is not None, "A's episode(<B's ep>) opened"
    assert S.tree(b_dir) == b_before, "A's calls through its real folder changed B's tree"
# A level swapped AFTER the check (adversary F10: every link test above plants its link before
# the call, so a walk that `lstat`s each level and then opens it by path passes them all).

def _decoy_episode(a: dict, root: Path, stranger: str) -> Path:
    """Copy tenant A's episode outside its tenant tree as a cross-tenant decoy."""
    decoy = root / a["episode_id"]
    shutil.copytree(a["episode"], decoy, symlinks=True)
    S.write_roster(decoy, {T.fixture_world_id("a"): stranger, T.fixture_world_id("b"): S.new_id(), T.fixture_world_id("c"): S.new_id()})
    S.make_run(decoy / "runs", stranger, alert='{"alert": "decoy"}\n')
    return decoy


@pytest.mark.parametrize("level", ["episode", "arm_container"])
def test_a_level_swapped_for_a_link_after_the_view_opened_is_never_followed(
        tmp_path, data_root, level):
    a = _tenant_scene(data_root, A_ID)
    stranger = a["roster"][T.fixture_world_id("a")]
    shutil.rmtree(a["episode"] / "runs" / stranger)
    decoy = _decoy_episode(a, tmp_path / "decoy", stranger)
    decoy_before = S.tree(decoy)
    swapped = a["episode"] if level == "episode" else a["episode"] / "runs"
    target = decoy if level == "episode" else decoy / "runs"
    aside = data_root / f"aside-{level}"
    runs = a["tenant"].runs_repository()

    faults: list[str] = []
    with runs.episode(a["episode_id"]) as view:
        os.rename(swapped, aside)
        os.symlink(target, swapped)
        opened = S.raised(view.open, _rid(stranger))
        if opened is None:
            faults.append("open(stranger) after the swap handed out the decoy's arm")
        elif not _is_refusal(opened):
            faults.append(f"open(stranger) after the swap gave {opened!r}")
        answer = S.raised(_held_arm, view, stranger, "arms")
        if not _is_refusal(answer):
            faults.append(f"arms([stranger]) after the swap handed out {answer!r}")
        ids: list = []
        read = S.raised(lambda: ids.append(view.arm_ids()))
        if read is None:
            got = {label: str(arm) for label, arm in (ids[0] or {}).items()}
            if got != a["roster"]:
                faults.append(f"arm_ids() after the swap answered {got}, not A's roster")
        elif not _is_refusal(read):
            faults.append(f"arm_ids() after the swap gave {read!r}")
    assert faults == [], f"a level swapped for a link ({level}) was followed:\n  " + (
        "\n  ".join(faults))
    assert S.tree(decoy) == decoy_before, "A's view changed the decoy's tree"

    os.unlink(swapped)
    os.rename(aside, swapped)
    S.make_run(a["episode"] / "runs", stranger)
    with runs.episode(a["episode_id"]) as view:
        assert Path(view.open(_rid(stranger)).run_dir) == a["episode"] / "runs" / stranger
        assert {k: str(v) for k, v in view.arm_ids().items()} == a["roster"]


def _episode_doors(a: dict, bare_id: str) -> dict:
    """Pair each repository episode door with the paths its walk may open."""
    arm = a["episode"] / "runs" / a["roster"][T.fixture_world_id("b")]

    def episode(runs) -> None:
        with runs.episode(a["episode_id"]) as view:
            view.arm_ids()
            view.arm_id(T.fixture_world_id("b"))
            view.open(_rid(a["roster"][T.fixture_world_id("b")]))

    def arms(runs) -> None:
        with runs.episode(a["episode_id"]) as view, view.arms(
                [_rid(a["roster"][T.fixture_world_id("b")])]) as handout:
            handout[_rid(a["roster"][T.fixture_world_id("b")])]

    def sibling(runs) -> None:
        with runs.episode(a["episode_id"], require_roster=True) as view:
            view.arm_id(T.fixture_world_id("b"))

    def start_runs(runs) -> None:
        with runs.episode(bare_id) as view:
            view.start_runs([T.fixture_world_id(label) for label in ("a", "b", "c")])

    def episode_files(runs) -> None:
        runs.episode_files(a["episode_id"]).close()

    def create_episode(runs) -> None:
        with runs.create_episode():
            pass

    allow = {"episode": [arm], "arms": [arm]}
    return {fn.__name__: (fn, allow.get(fn.__name__, ()))
            for fn in (episode, arms, sibling, start_runs, episode_files, create_episode)}


def test_no_episode_door_opens_a_level_below_the_tenant_by_its_path(data_root):
    a = _tenant_scene(data_root, A_ID)
    tenant_dir = S.tenant_dir(data_root, A_ID)
    bare_id = S.new_id()
    S.make_episode(data_root, A_ID, bare_id, manifest=_manifest(bare_id), roster=False)
    runs = a["tenant"].runs_repository()

    faults = []
    for name, (door, allow) in _episode_doors(a, bare_id).items():
        with S.PathOpens() as audit:
            err = S.raised(door, runs)
        if err is not None:
            faults.append(f"{name}: raised {err!r}")
            continue
        faults.extend(f"{name}: opened {path} by its path"
                      for path in audit.below(tenant_dir, allow))
    assert faults == [], "an episode door reached a level below <T> by its path:\n  " + (
        "\n  ".join(faults))


def test_the_path_open_recorder_sees_a_path_walk_and_not_a_handle_walk(tmp_path):
    from defender import _io

    tenant_dir = tmp_path / A_ID
    ep = tenant_dir / "episodes" / "ep"
    (ep / "runs").mkdir(parents=True)
    (ep / "family.yaml").write_text("episode_id: ep\n", encoding="utf-8")

    def handle_walk() -> None:
        with _io.hold(tenant_dir, follow=False) as held:
            held.mkdir("episodes/ep2")
            held.view().read("episodes/ep/family.yaml")

    def by_hold() -> None:
        with _io.hold(ep / "runs", follow=False):
            pass

    def by_bind() -> None:
        with _io.bind(ep):
            pass

    def lstat_then_open() -> None:
        for level in (tenant_dir / "episodes", ep):
            os.lstat(level)
        with _io.hold(ep, follow=False):
            pass

    with S.PathOpens() as clean:
        handle_walk()
    assert clean.below(tenant_dir) == [], f"a handle walk was reported: {clean.below(tenant_dir)}"
    for name, walk in {"hold": by_hold, "bind": by_bind, "lstat-then-open": lstat_then_open}.items():
        with S.PathOpens() as audit:
            walk()
        assert audit.below(tenant_dir), f"a {name} path walk was not reported: {audit.seen}"
    with S.PathOpens() as audit:
        by_hold()
    assert audit.below(tenant_dir, allow=[ep / "runs"]) == [], "an allowed folder was reported"
    with S.PathOpens() as audit, _io.hold(tenant_dir, follow=False):
        pass
    assert audit.below(tenant_dir) == [], "opening <T> itself was reported as below <T>"
# Episodes: claimed under <T>/episodes by one exclusive create; no environment (O9, dc 3, 5).

@pytest.mark.parametrize("variable", ["unset", "bogus", "existing-elsewhere"])
def test_create_episode_claims_a_uuid_folder_under_the_tenant_and_reads_no_environment(
        tmp_path, data_root, monkeypatch, variable):
    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    S.make_run(runs_dir, S.new_id())
    elsewhere = tmp_path / "elsewhere-episodes"
    if variable == "existing-elsewhere":
        elsewhere.mkdir()
        (elsewhere / "keep.txt").write_text("not an episode\n", encoding="utf-8")
    if variable != "unset":
        monkeypatch.setenv(S.EPISODES_BASE_ENV, str(elsewhere))
    elsewhere_before = S.tree(elsewhere)
    runs_before = S.tree(runs_dir)
    episodes = S.episodes_dir(data_root, A_ID)
    assert not os.path.lexists(episodes)

    with t.runs_repository().create_episode() as view:
        episode_id = view.episode_id

    assert S.is_canonical_uuid(episode_id), f"the claimed id is not a uuid: {episode_id!r}"
    assert _real_dir(episodes), "<T>/episodes was not made as a real directory"
    assert os.listdir(episodes) == [episode_id]
    assert _real_dir(episodes / episode_id)
    assert S.tree(elsewhere) == elsewhere_before, "the episodes variable's folder was touched"
    assert os.path.lexists(elsewhere) == (variable == "existing-elsewhere")
    assert S.tree(runs_dir) == runs_before, "claiming an episode changed <T>/runs"
    assert _records_under(S.tenant_dir(data_root, A_ID)) == []


def test_two_episodes_get_two_fresh_uuid_folders_and_never_a_retry_suffix(data_root):
    t = S.tenant(data_root, A_ID)
    runs = t.runs_repository()

    with runs.create_episode() as first:
        one = first.episode_id
    with runs.create_episode() as second:
        two = second.episode_id

    assert one != two
    for episode_id in (one, two):
        assert S.is_canonical_uuid(episode_id), f"{episode_id!r} is not a canonical uuid"
        assert not episode_id.endswith("-r2"), f"{episode_id!r} is a retry name"
    assert sorted(os.listdir(S.episodes_dir(data_root, A_ID))) == sorted([one, two])


_CLAIM_CHILD = """
import os, sys, uuid
from pathlib import Path
from defender.records import RunRefused
from defender.tests.storage.ids_1187 import _spec1187 as S
root, tenant_id, collide = Path(sys.argv[1]), sys.argv[2], sys.argv[3] == "collision"
runs = S.tenant(root, tenant_id).runs_repository()
real_mkdir, attempts = os.mkdir, []
def claim_mkdir(path, *args, **kwargs):
    name = os.path.basename(os.fsdecode(path))
    try:
        is_uuid = str(uuid.UUID(name)) == name
    except ValueError:
        is_uuid = False
    if is_uuid:
        attempts.append(name)
        if len(attempts) > 1:
            raise RuntimeError("episode claim retried")
        if collide:
            real_mkdir(path, *args, **kwargs)
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY, dir_fd=kwargs.get("dir_fd"))
            try:
                marker = os.open("PLANTED", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                                 dir_fd=fd)
                try:
                    os.write(marker, b"someone else's episode\\n")
                finally:
                    os.close(marker)
            finally:
                os.close(fd)
            print("PLANTED", name, flush=True)
    return real_mkdir(path, *args, **kwargs)
os.mkdir = claim_mkdir
try:
    with runs.create_episode() as view:
        print("CLAIMED", view.episode_id)
except RunRefused:
    print("REFUSED")
except BaseException as exc:
    print("UNEXPECTED", type(exc).__name__)
print("ATTEMPTS", len(attempts))
"""


def _claim_in_a_child(data_root: Path, *, collide: bool):
    import subprocess
    import sys

    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", S.DATA_ROOT_ENV: str(data_root),
           "PYTHONPATH": os.pathsep.join(filter(None, [str(H5.WORKTREE),
                                                       os.environ.get("PYTHONPATH")]))}
    return subprocess.run(  # noqa: S603 — this interpreter, a fixed script
        [sys.executable, "-c", _CLAIM_CHILD, str(data_root), A_ID,
         "collision" if collide else "control"],
        capture_output=True, text=True, encoding="utf-8", check=False, env=env,
        cwd=str(H5.WORKTREE), timeout=300)


def test_create_episode_refuses_a_folder_already_at_the_minted_name(data_root):
    S.tenant(data_root, A_ID)
    refused = _claim_in_a_child(data_root, collide=True)
    out = refused.stdout.splitlines()
    assert refused.returncode == 0, refused.stderr[-1500:]
    assert "REFUSED" in out, f"the collision was not refused: {refused.stdout!r}"
    assert "ATTEMPTS 1" in out, f"the claim retried or never reached mkdir: {refused.stdout!r}"
    planted = [line.split()[1] for line in out if line.startswith("PLANTED ")]
    assert len(planted) == 1, refused.stdout
    episodes = S.episodes_dir(data_root, A_ID)
    folder = episodes / planted[0]
    assert os.listdir(episodes) == planted, "the failed claim made another episode"
    assert os.listdir(folder) == ["PLANTED"], "the claim adopted or changed the planted folder"
    assert (folder / "PLANTED").read_text(encoding="utf-8") == "someone else's episode\n"

    shutil.rmtree(folder)
    claimed = _claim_in_a_child(data_root, collide=False)
    out = claimed.stdout.splitlines()
    assert claimed.returncode == 0, claimed.stderr[-1500:]
    assert "ATTEMPTS 1" in out, claimed.stdout
    made = [line.split()[1] for line in out if line.startswith("CLAIMED ")]
    assert len(made) == 1, f"control: the claim failed: {claimed.stdout!r} {claimed.stderr[-800:]}"
    assert os.listdir(episodes) == made
    assert _real_dir(episodes / made[0])


@pytest.mark.parametrize("variable", [
    "unset", "inside-data-root", "containing-data-root", "the-tenants-episodes", "decoy"])
def test_the_episodes_variable_changes_nothing_and_no_episodes_root_refusal_fires(
        tmp_path, data_root, monkeypatch, variable):
    a = _tenant_scene(data_root, A_ID)
    decoy = tmp_path / "decoy-episodes"
    decoy_roster = {T.fixture_world_id(label): S.new_id() for label in ("a", "b", "c")}
    S.make_episode(decoy.parent, decoy.name, a["episode_id"],
                   manifest=_manifest(a["episode_id"]), roster=decoy_roster)
    decoy = decoy / "episodes"
    decoy_before = S.tree(decoy)
    places = {
        "inside-data-root": data_root / "inside",
        "containing-data-root": data_root.parent,
        "the-tenants-episodes": S.episodes_dir(data_root, A_ID),
        "decoy": decoy,
    }
    if variable in places:
        monkeypatch.setenv(S.EPISODES_BASE_ENV, str(places[variable]))
    runs = a["tenant"].runs_repository()

    opened = S.raised(runs.episode, a["episode_id"])
    assert opened is None, f"runs.episode refused with the variable {variable}: {opened!r}"
    assert S.EPISODES_BASE_ENV not in S.message(opened)
    handle = runs.episode_files(a["episode_id"])
    try:
        assert Path(handle.dir) == a["episode"], f"episode_files handed out {handle.dir}"
    finally:
        handle.close()
    with runs.episode(a["episode_id"]) as view:
        got = {label: str(arm) for label, arm in (view.arm_ids() or {}).items()}
    assert got == a["roster"], f"the view read another roster: {got}"
    assert S.tree(decoy) == decoy_before, "the decoy episodes folder was touched"
# O8: A's repository, asked for B's episode by id, reads nothing of B's (the page's and the
# judge's doors are `runs.episode` and `runs.episode_files`).

def test_another_tenants_episode_is_absent_to_this_tenants_repository(data_root):
    a, b = _two_tenants(data_root)
    b_before = S.tree(S.tenant_dir(data_root, B_ID))
    runs_a = a["tenant"].runs_repository()

    for what, probe in {"episode": runs_a.episode, "episode_files": runs_a.episode_files}.items():
        err = S.raised(probe, b["episode_id"])
        assert err is not None, f"A's {what}(epB) opened B's episode"
        assert isinstance(err, (FileNotFoundError, *_refusals())), (
            f"A's {what}(epB) gave {err!r}, not an absent episode")
        assert S.EPISODES_BASE_ENV not in S.message(err), (
            f"A's {what}(epB) refused for the retired variable: {S.message(err)!r}")
    assert S.tree(S.tenant_dir(data_root, B_ID)) == b_before, "A's calls changed B's tree"
    assert not os.path.lexists(S.episodes_dir(data_root, A_ID) / b["episode_id"])

    runs_b = b["tenant"].runs_repository()
    with runs_b.episode(b["episode_id"]) as view:
        got = {label: str(arm) for label, arm in (view.arm_ids() or {}).items()}
    assert got == b["roster"]
    handle = runs_b.episode_files(b["episode_id"])
    try:
        assert Path(handle.dir) == b["episode"]
    finally:
        handle.close()
    with runs_a.episode(a["episode_id"]) as view:
        assert Path(view.open(_rid(a["roster"][T.fixture_world_id("a")])).run_dir) == (
            a["episode"] / "runs" / a["roster"][T.fixture_world_id("a")])
# R6 / declared change 13: no `_episodes` claim is read by `create`.

def test_create_is_not_refused_by_an_episodes_claim_and_the_listing_refuses(data_root):
    from defender.records import RunRefused
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    t = S.tenant(data_root, A_ID)
    runs_dir = S.natural_runs(data_root, A_ID)
    record = H5.plant_record(runs_dir, "e1", A_ID, S.new_id(), {"a": S.new_id()})
    record_bytes = record.read_bytes()
    runs = t.runs_repository()

    run = runs.create()
    assert Path(run.run_dir).parent == runs_dir
    assert record.read_bytes() == record_bytes, "create touched the _episodes record"
    assert not os.path.lexists(runs_dir / "_tenant.json"), "create wrote a _tenant.json"
    assert isinstance(S.raised(runs.all_runs), RunRefused), (
        "the listing accepted a container holding _episodes")
# The roster name belongs to the layout owner and appears in the kinds registry.

#: The kinds registry the design's docs step edits (`defender/docs/run-records-kinds.tsv`).
KINDS_TSV = DEFENDER / "docs" / "run-records-kinds.tsv"


def _kinds_rows() -> list[dict[str, str]]:
    """The kinds table as dicts keyed by its header, read off the file itself."""
    lines = KINDS_TSV.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"), strict=False)) for line in lines[1:]
            if line.strip()]


def test_the_arm_rosters_name_is_owned_by_the_episode_layout(tmp_path):
    from defender.records import _episode_paths as P

    episode_dir = tmp_path / "episodes" / S.new_id()
    assert P.FAMILY_NAME == S.MANIFEST_NAME, "control: not the episode layout's owner"
    assert P.LAYOUT.family == PurePosixPath(S.MANIFEST_NAME)
    assert P.EpisodePaths(episode_dir).family == episode_dir / S.MANIFEST_NAME

    assert P.ARM_ROSTER_NAME == S.ROSTER_NAME == "arms.json"
    assert P.LAYOUT.arm_roster == PurePosixPath(S.ROSTER_NAME)
    assert P.EpisodePaths(episode_dir).arm_roster == episode_dir / S.ROSTER_NAME


def test_the_kinds_table_has_the_roster_row_and_drops_the_record_rows():
    table = _kinds_rows()
    rows = {row["kind"]: row for row in table}
    assert rows["family"]["path"] == S.MANIFEST_NAME, f"control: not the kinds table: {KINDS_TSV}"
    assert rows["family"]["table"] == "4"

    at_roster = [row["kind"] for row in table if row.get("path") == S.ROSTER_NAME]
    assert at_roster == ["arm_roster"], f"rows at {S.ROSTER_NAME}: {at_roster}"
    assert rows["arm_roster"]["table"] == "4", rows["arm_roster"]
    assert rows["episode_runs"]["path"] == "runs/<uuid>/", rows["episode_runs"]
    gone = sorted({"tenant", "episode_runs_record"} & set(rows))
    assert gone == [], f"rows #1187 retires are still in the table: {gone}"

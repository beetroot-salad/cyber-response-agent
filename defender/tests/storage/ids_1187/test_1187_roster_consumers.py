"""Episode readers, launchers, and siblings use host-written arm rosters."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
import os
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.storage.ids_1187 import _spec1187 as R
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P

#: The tenant every page / VERIFY / door scene is planted under (`_spec1187.tenant`'s default).
TENANT = R.H5.T_ID
#: The manifest's worlds: `a` the control, `b` and `c` the siblings (`_triplet_947.family_doc`).
LABELS = ("a", "b", "c")
#: The source run every manifest names (a UUID, as every run id after #1187).
SOURCE_ID = "5d0c3f7e-2a91-4b6e-8f14-9c7a2e5b3d60"
#: World `b`'s axis: manifest text the page renders whatever the arms' state.
AXIS_B = "AXIS-1187-B whether a second login to web-1 came from 10.0.0.9"
#: The outcome record's reason: an episode-level record the page renders whatever the arms'.
OUTCOME_REASON = "OUTCOME-1187 pre-flight calibrated every world against the live estate"
#: The redaction filter's marker (`_redaction._TOKEN_MARK`).
MARK = "[a run id]"
#: An id no family knows: the filter's positive control.
UNRELATED_UUID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"


@pytest.fixture(autouse=True)
def _decoy_episodes_base(tmp_path, monkeypatch):
    """Point the retired episodes-root variable at an empty decoy that must stay untouched."""
    decoy = tmp_path / "decoy-episodes-base"
    decoy.mkdir()
    monkeypatch.setenv(R.EPISODES_BASE_ENV, str(decoy))
# Scene builders (new layout, loadable manifest, roster, arms named by roster id)

def _worlds(*, null_world: bool = False) -> list[dict]:
    """Build three worlds with a control and optionally a fourth null world."""
    worlds = [T.base_world(),
              T.world_doc("b", axis=AXIS_B, facts=[T.fact("f-b")]),
              T.world_doc("c", role="C", axis="axis of c", facts=[T.fact("f-c")])]
    if null_world:
        worlds.append(T.world_doc("d", role=None, axis="axis of d", facts=[T.fact("f-d")]))
    return worlds


def _doc(episode_id: str, *, null_world: bool = False) -> dict:
    """A loadable manifest (`_triplet_947.family_doc`) naming `episode_id` and `SOURCE_ID`."""
    return T.family_doc(worlds=_worlds(null_world=null_world), episode_id=episode_id,
                        source_run_id=SOURCE_ID)


def _labels(doc: dict) -> list[str]:
    return [w["label"] for w in doc["worlds"]]


def _episode(data_root: Path, *, roster: Any = True,
             null_world: bool = False) -> tuple[Path, str, dict | None]:
    """A fresh UUID episode under `TENANT` (`_episode_at`), its manifest `_doc`."""
    episode_id = R.new_id()
    return _episode_at(data_root, episode_id, _doc(episode_id, null_world=null_world), roster)


def _episode_at(data_root: Path, episode_id: str, doc: dict,
                roster: Any) -> tuple[Path, str, dict | None]:
    """Create a tenant-scoped episode containing the supplied loadable manifest."""
    R.tenant(data_root)
    mapping = {world["world_id"]: R.new_id() for world in doc["worlds"]} if roster is True else roster
    ep = R.make_episode(data_root, TENANT, episode_id, labels=_labels(doc),
                        roster=mapping if mapping is not None else False)
    T.write_family(ep, doc)
    return ep, episode_id, mapping


def _arm(ep: Path, name: str) -> Path:
    """Create a finished arm with an alert and terminal result event."""
    rd = R.make_run(ep / "runs", name)
    E.write_tool_trace(rd, [E.result_event()])
    (rd / "runtime.html").write_text("<!doctype html><title>arm</title>", encoding="utf-8")
    return rd


def _outcome(ep: Path) -> None:
    """Pre-flight's `accepted` outcome record, through the production writer."""
    E.write_outcome(ep, "accepted", reason=OUTCOME_REASON, family_stamp=False)


def _page(episode_id: str, tenant_id: str = TENANT) -> P.CliResult:
    """The episode page CLI, `visualize_episode.py --tenant T <episode_id>`."""
    return P.drive_cli(P.page_main(), P.new_page_argv(tenant_id, episode_id))


def _arm_hrefs(page: E.Page) -> list[str]:
    return [h for h in page.hrefs if h.endswith("runtime.html")]
# R5 — the manifest's episode_id is its folder's name, checked in the one loader

def _loadable(which: str, episode_id: str) -> dict:
    """A real loadable manifest from an existing fixture, rewritten to `episode_id`."""
    if which == "triplet_947":
        return T.family_doc(episode_id=episode_id, source_run_id=SOURCE_ID)
    return S.family_v2(episode_id=episode_id, source_run_id=SOURCE_ID)


@pytest.mark.parametrize("which", ["triplet_947", "spec1224"])
@pytest.mark.parametrize("named", ["same", "another_uuid", "old_id", *range(R.UUID_HEX_DIGITS)])
@pytest.mark.parametrize("door", ["load_family", "load_manifest_document"])
def test_manifest_loaders_require_the_complete_folder_identity(tmp_path, which, named, door):
    from defender._io import bind
    from defender.records import _family

    folder_id = R.new_id()
    manifest_id = (folder_id if named == "same" else R.new_id() if named == "another_uuid"
                   else R.OLD_MINTED_ID if named == "old_id" else R.near_miss_id(folder_id, named))
    ep = tmp_path / "episodes" / folder_id
    T.write_family(ep, _loadable(which, manifest_id))
    with bind(ep) as view:
        if named == "same":
            result = getattr(_family, door)(view, expected_episode_id=folder_id)
            assert (result.episode_id if door == "load_family" else result["episode_id"]) == folder_id
        else:
            err = R.raised(getattr(_family, door), view, expected_episode_id=folder_id)
            assert R.is_a(err, _family.FamilyError), err
            assert manifest_id in R.message(err), err
            assert folder_id in R.message(err), err


def test_r5_the_expected_episode_id_is_a_required_keyword(tmp_path):
    from defender._io import bind
    from defender.records._family import load_family, load_manifest_document

    episode_id = R.new_id()
    ep = tmp_path / "episodes" / episode_id
    T.write_family(ep, _loadable("triplet_947", episode_id))
    for door in (load_family, load_manifest_document):
        with bind(ep) as view:
            bare = R.raised(door, view)
            positional = R.raised(door, view, episode_id)
            keyword = R.raised(door, view, expected_episode_id=episode_id)
        assert isinstance(bare, TypeError), f"{door.__name__}(view) was accepted: {bare!r}"
        assert isinstance(positional, TypeError), (
            f"{door.__name__}(view, <id>) was accepted positionally: {positional!r}")
        assert keyword is None, f"{door.__name__}(view, expected_episode_id=) refused: {keyword!r}"


def test_r5_pre_flight_refuses_a_manifest_naming_another_episode(tmp_path, monkeypatch,
                                                                  data_root):
    from defender.learning.branch import cli

    P.roots(tmp_path, monkeypatch)
    monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    est, src = P.launch_source(tmp_path, source_run_id=R.new_id())
    source = T.open_source(src)
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    rows = [S.captured(c.system, c.verb, c.params, c.payload) for c in P.source_calls()]
    episode_id = R.new_id()
    other = R.near_miss_id(episode_id)

    def doc(named: str) -> dict:
        return S.family_v2(episode_id=named, source_run_id=src.name, source_run_dir=str(src))

    ep = S.episode_v2(tmp_path, doc=doc(episode_id), root=R.episodes_dir(data_root,
                                                                          P.LAUNCH_TENANT),
                      episode_id=episode_id, base_rows=rows)
    T.write_family(ep, doc(other))
    runs = R.tenant(data_root, P.LAUNCH_TENANT).runs_repository()

    def preflight(oracle) -> BaseException | None:
        with runs.episode(episode_id) as view:
            return R.raised(cli.preflight_replay, view.episode, source=source,
                            roster=est.roster(), tenant=est.run_tenant(), oracle=oracle.model,
                            verifier=S.passing_verifier().model)

    unasked = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))
    err = preflight(unasked)
    assert err is not None, "pre-flight calibrated an episode whose manifest names another"
    assert not isinstance(err, (TypeError, AttributeError, NameError)), f"machinery: {err!r}"
    text = R.message(err)
    assert other in text, f"the refusal does not name the manifest's id {other}: {text}"
    assert episode_id in text, f"the refusal does not name the folder's id {episode_id}: {text}"
    assert unasked.requests == 0, "pre-flight asked its oracle over a mismatched manifest"
    assert not (ep / "outcome.yaml").exists(), "pre-flight recorded an outcome for it"

    T.write_family(ep, doc(episode_id))
    asked = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))
    assert preflight(asked) is None, "control: pre-flight over its own manifest refused"
    assert asked.requests > 0, "control: pre-flight never asked its oracle"
    assert (ep / "outcome.yaml").is_file(), "control: pre-flight wrote no outcome record"


@pytest.mark.parametrize("consumer", ["page", "verify", "judge"])
def test_manifest_consumers_refuse_other_episode_ids_before_side_effects(
        tmp_path, data_root, consumer):
    from defender.learning.branch import cli
    from defender.learning.judge import JudgeRefused, grade_episode
    from defender.records import Run
    from defender.tests.support.learning.core import _state1135

    ep, episode_id, roster = _episode(data_root)
    if consumer == "verify":
        _arm(ep, roster[T.world_id(ep, "a")])
    runs = R.tenant(data_root).runs_repository()
    judge = P.quiet_judge()
    state = _state1135.state_over(tmp_path / "judge-state")

    def exercise(refused):
        if consumer == "page":
            got = _page(episode_id)
            assert got.rc == (1 if refused else 0), got.said
            assert (ep / E.PAGE_NAME).is_file() is not refused
            return got.said
        if consumer == "judge":
            err = R.raised(grade_episode, runs, episode_id, judge=judge, state=state)
            assert judge.prompts == [], "a mismatched or outcome-less episode asked the judge"
            assert (ep / "judge.yaml").is_file() is not refused
            assert R.is_a(err, JudgeRefused) if refused else err is None, err
            return R.message(err)
        with runs.episode(episode_id) as view:
            if refused:
                err = R.raised(cli._finished_arms, view, ["a"])
                assert err is not None, "VERIFY opened arms under another episode's manifest"
                assert not isinstance(err, (TypeError, AttributeError, NameError)), err
                return R.message(err)
            opened = cli._finished_arms(view, [T.world_id(ep, "a")])
            assert isinstance(opened[T.world_id(ep, "a")], Run), opened
            assert Path(opened[T.world_id(ep, "a")].run_dir) == ep / "runs" / roster[T.world_id(ep, "a")]
            return ""

    other = R.near_miss_id(episode_id)
    T.write_family(ep, _doc(other))
    text = exercise(True)
    assert other in text, text
    assert episode_id in text, text
    T.write_family(ep, _doc(episode_id))
    exercise(False)
# Flow 4 — the episode page reads its arms from the roster

def test_page_links_each_arm_by_its_roster_id_never_a_composed_name(data_root):
    ep, episode_id, roster = _episode(data_root, null_world=True)
    for label in ("a", "c", "d"):
        _arm(ep, roster[T.world_id(ep, label)])
    for label in ("a", "b"):
        _arm(ep, f"{episode_id}-{label}")

    got = _page(episode_id)
    assert got.rc == 0, f"the page was not rendered: {got.said}"
    page = E.read_page(ep)
    for label in ("a", "c", "d"):
        expected = f"runs/{roster[T.world_id(ep, label)]}/runtime.html"
        assert expected in page.anchors_in(f"world-{label}"), (
            f"world {label}'s arm is not linked by its roster id: {page.anchors_in(f'world-{label}')}")
    composed = [h for h in page.hrefs if f"{episode_id}-" in h]
    assert composed == [], f"the page linked a composed <ep>-<label> folder: {composed}"
    assert "run directory absent" in page.text_of("world-b"), page.text_of("world-b")


@pytest.mark.parametrize("runs_folder", ["none", "empty", "with_arms"],
                         ids=["no_runs", "empty_runs_without_roster", "runs_without_roster"])
def test_page_without_a_roster_renders_no_world_section_and_no_arm_link(data_root, runs_folder):
    ep, episode_id, _none = _episode(data_root, roster=None)
    mapping = {T.fixture_world_id(label): R.new_id() for label in LABELS}
    if runs_folder == "empty":
        (ep / "runs").mkdir()
    elif runs_folder == "with_arms":
        for arm_id in mapping.values():
            _arm(ep, arm_id)
    _outcome(ep)

    got = _page(episode_id)
    assert got.rc == 0, f"a pre-RUNS episode did not render: {got.said}"
    page = E.read_page(ep)
    assert page.ids_with("world-") == [], f"world sections without a roster: {page.ids_with('world-')}"
    assert _arm_hrefs(page) == [], f"arm links without a roster: {_arm_hrefs(page)}"
    assert AXIS_B in page.text, "the manifest's worlds guide did not render"
    assert OUTCOME_REASON in page.text, "the outcome record did not render"

    R.write_roster(ep, mapping)
    again = _page(episode_id)
    assert again.rc == 0, again.said
    assert "world-b" in E.read_page(ep).by_id, "the control failed: a roster gave no world section"


def _refused_roster(kind: str, ep: Path, good: dict[str, str], tmp_path: Path) -> None:
    """Plant the refused roster `kind` at `<ep>/arms.json`, derived from the good one."""
    text = json.dumps(good, indent=2, sort_keys=True)
    if kind == "torn":
        R.write_roster(ep, raw=R.torn(text))
    elif kind == "missing_label":
        R.write_roster(ep, {k: v for k, v in good.items() if k != T.world_id(ep, "c")})
    elif kind == "extra_label":
        R.write_roster(ep, {**good, R.new_id(): R.new_id()})
    elif kind == "shared_id":
        R.write_roster(ep, {**good, T.world_id(ep, "b"): good[T.world_id(ep, "c")]})
    elif kind == "old_id":
        R.write_roster(ep, {**good, T.world_id(ep, "b"): R.OLD_MINTED_ID})
    elif kind == "link":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir(exist_ok=True)
        R.write_roster(elsewhere, good)
        (ep / R.ROSTER_NAME).unlink(missing_ok=True)
        os.symlink(elsewhere / R.ROSTER_NAME, ep / R.ROSTER_NAME)
    else:
        raise AssertionError(kind)


REFUSED_ROSTERS = ["torn", "missing_label", "extra_label", "shared_id", "old_id", "link"]


@pytest.mark.parametrize("kind", REFUSED_ROSTERS)
def test_page_shows_a_refused_roster_as_the_arms_state_and_renders_the_rest(data_root, tmp_path,
                                                                           kind):
    ep, episode_id, good = _episode(data_root)
    for arm_id in good.values():
        _arm(ep, arm_id)
    _outcome(ep)
    _refused_roster(kind, ep, good, tmp_path)

    got = _page(episode_id)
    assert got.rc == 0, f"a refused roster failed the whole page: {got.said}"
    page = E.read_page(ep)
    assert R.ROSTER_NAME in page.text, f"no reason naming {R.ROSTER_NAME}: {page.text[:2000]}"
    assert "refused" in page.text, f"no refused state for the arms: {page.text[:2000]}"
    assert _arm_hrefs(page) == [], f"arms linked through a refused roster: {_arm_hrefs(page)}"
    assert AXIS_B in page.text, "the manifest's worlds guide did not render"
    assert OUTCOME_REASON in page.text, "the outcome record did not render"

    (ep / R.ROSTER_NAME).unlink()
    R.write_roster(ep, good)
    control = _page(episode_id)
    assert control.rc == 0, control.said
    page = E.read_page(ep)
    assert R.ROSTER_NAME not in page.text, "the control still shows a roster refusal"
    for wid, arm_id in good.items():
        label = T.mod("records._family").label_for_world_id(_manifest_of(ep), wid)
        assert f"runs/{arm_id}/runtime.html" in page.anchors_in(f"world-{label}"), label


@pytest.mark.parametrize("asked", ["latest_link", "old_id_folder"])
def test_page_refuses_latest_and_any_non_uuid_episode_id(data_root, asked):
    ep, episode_id, roster = _episode(data_root)
    if asked == "latest_link":
        bad = "latest"
        os.symlink(ep, R.episodes_dir(data_root, TENANT) / bad, target_is_directory=True)
        target = ep
    else:
        bad = R.OLD_MINTED_ID
        target, _id, _roster = _episode_at(data_root, bad, _doc(bad), roster)
    os.symlink(target, Path(os.environ[R.EPISODES_BASE_ENV]) / bad, target_is_directory=True)

    refused = _page(bad)
    assert refused.rc == 1, f"{bad!r} was accepted as an episode id: {refused.said}"
    assert bad in refused.said, refused.said
    assert not (target / E.PAGE_NAME).exists(), "a page was written through a bad id"

    ok = _page(episode_id)
    assert ok.rc == 0, f"the control did not render: {ok.said}"
    assert (ep / E.PAGE_NAME).is_file()


def test_the_page_for_one_tenant_never_renders_another_tenants_episode(data_root):
    other = R.H5.U_ID
    R.tenant(data_root)
    R.tenant(data_root, other)
    episode_id = R.new_id()
    roster = {T.fixture_world_id(label): R.new_id() for label in LABELS}
    ep = R.make_episode(data_root, other, episode_id, labels=LABELS, roster=roster)
    T.write_family(ep, _doc(episode_id))
    for arm_id in roster.values():
        _arm(ep, arm_id)
    os.symlink(ep, Path(os.environ[R.EPISODES_BASE_ENV]) / episode_id, target_is_directory=True)

    refused = _page(episode_id, TENANT)
    assert refused.rc == 1, f"tenant {TENANT} rendered {other}'s episode: {refused.said}"
    assert not (ep / E.PAGE_NAME).exists(), "a page was written into another tenant's episode"

    ok = _page(episode_id, other)
    assert ok.rc == 0, f"the control did not render: {ok.said}"
    assert (ep / E.PAGE_NAME).is_file()
# Flow 2 steps 7-9 — VERIFY, the archive, the judge and the page after RUNS

def test_verify_opens_each_finished_arm_by_its_roster_id(data_root):
    from defender.learning.branch import cli
    from defender.records import Run, RunAbsent

    ep, episode_id, roster = _episode(data_root)
    _arm(ep, roster[T.world_id(ep, "a")])
    _arm(ep, f"{episode_id}-b")
    _arm(ep, roster[T.world_id(ep, "c")])
    runs = R.tenant(data_root).runs_repository()
    with runs.episode(episode_id) as view:
        arms = cli._finished_arms(view, [T.world_id(ep, label) for label in ("a", "b")])
    assert set(arms) == {T.world_id(ep, label) for label in ("a", "b")}, f"VERIFY opened {sorted(arms)}"
    assert isinstance(arms[T.world_id(ep, "a")], Run), f"a: {arms[T.world_id(ep, 'a')]!r}"
    assert Path(arms[T.world_id(ep, "a")].run_dir) == ep / "runs" / roster[T.world_id(ep, "a")]
    assert isinstance(arms[T.world_id(ep, "b")], RunAbsent), (
        f"b, whose roster id has no folder, was answered {arms[T.world_id(ep, 'b')]!r} (the decoy composed?)")


def test_verify_refuses_outright_on_a_refused_roster(data_root):
    from defender.learning.branch import cli
    from defender.records import Run

    ep, episode_id, good = _episode(data_root)
    _arm(ep, good[T.world_id(ep, "a")])
    runs = R.tenant(data_root).runs_repository()

    def verify() -> dict:
        with runs.episode(episode_id) as view:
            return cli._finished_arms(view, [T.world_id(ep, "a")])

    R.write_roster(ep, raw=R.torn(json.dumps(good)))
    err = R.raised(verify)
    assert err is not None, "VERIFY read a torn roster"
    assert not isinstance(err, (TypeError, AttributeError, NameError)), f"machinery: {err!r}"
    assert R.ROSTER_NAME in R.message(err), f"the refusal does not name the roster: {err!r}"

    R.write_roster(ep, good)
    assert isinstance(verify()[T.world_id(ep, "a")], Run), "the control failed: a good roster did not open a"


def test_r8_the_archive_writes_no_run_dir_pointer(data_root):
    archive = T.mod("learning.branch.archive")
    ep, episode_id, roster = _episode(data_root)
    # The finished arm and its scrub-verdict sidecar, at the roster's id for `b`.
    T.sibling_run_dir(ep / "runs", "b", arm_id=roster[T.world_id(ep, "b")])
    runs = R.tenant(data_root).runs_repository()
    with runs.episode(episode_id) as view:
        archive.archive_episode(view.episode, {T.world_id(ep, "b"): ep / "runs" / roster[T.world_id(ep, "b")]})
    world = ep / "worlds" / T.world_id(ep, "b")
    assert (world / "report.md").is_file(), "the control failed: nothing was archived"
    assert not os.path.lexists(world / "run_dir"), "the archive wrote the run_dir pointer"


def _spawn_worlds(spawn: J.FakeSibling) -> list[str]:
    """Check every launch's three required flags, then expose the labels for flow assertions."""
    worlds = []
    for call in spawn.launches:
        argv = call["argv"]
        assert all(flag in argv for flag in ("--tenant", "--episode", "--world")), argv
        worlds.append(argv[argv.index("--world") + 1])
    return worlds


def test_a_launch_verifies_finished_arms_by_roster_id_archives_no_pointer_and_pages_by_id(
        tmp_path, monkeypatch, data_root):
    P.roots(tmp_path, monkeypatch)
    source_id = R.new_id()
    est, src = P.launch_source(tmp_path, source_run_id=source_id)
    # The natural container in #1187's shape: no `_tenant.json` (R1).
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    spawn = J.FakeSibling(data_root=data_root, exits={"c": 3})

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, source_id), spawn=spawn)
    assert spawn.launches, f"no sibling was started: rc={got.rc} {got.message!r}"
    assert spawn.faults == [], spawn.faults
    assert "c" in _spawn_worlds(spawn), _spawn_worlds(spawn)
    assert len(_spawn_worlds(spawn)) >= 2, _spawn_worlds(spawn)
    episodes = [p for p in R.episodes_dir(data_root, P.LAUNCH_TENANT).iterdir() if p.is_dir()]
    assert len(episodes) == 1, f"expected one episode under <T>/episodes: {episodes}"
    ep = episodes[0]
    roster = R.read_roster(ep)
    finished = [label for label in _spawn_worlds(spawn) if label != "c"]
    for label in finished:
        world = ep / "worlds" / T.world_id(ep, label)
        assert (world / "report.md").is_file(), f"finished world {label} was not archived"
        assert not os.path.lexists(world / "run_dir"), f"world {label}: a run_dir pointer"
    assert (ep / "runs" / roster[T.world_id(ep, "c")]).is_dir(), "the control failed: c left no arm"
    assert not (ep / "worlds" / T.world_id(ep, "c") / "report.md").exists(), "VERIFY opened an unfinished arm"

    page = ep / E.PAGE_NAME
    assert page.is_file(), "the launcher rendered no page"
    parsed = E.Page.parse(page.read_text(encoding="utf-8"))
    for label in finished:
        assert f"runs/{roster[T.world_id(ep, label)]}/runtime.html" in parsed.anchors_in(f"world-{label}"), label
# Launch the arm family through the real entrypoint.

#: The manifest's poison (`test_1187_roster_sibling`'s technique): a top-level field the family
#: loader refuses BY NAME, so it reaches a refusal's text exactly when the manifest was read.
SENTINEL = "zz_spec1187_never_read_before_the_gate"
#: World `c`'s fact statement in the unservable scene: the marker its pre-flight requests carry.
MARK_C = "MARK-1187-C carol read the vault from 10.0.0.9"


def _launch_scene(tmp_path: Path, monkeypatch: Any) -> tuple[Any, Path]:
    """The launch fixture tenant (`_spec1105_pr2.launch_source`) with one branchable source run."""
    P.roots(tmp_path, monkeypatch)
    est, src = P.launch_source(tmp_path, source_run_id=R.new_id())
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    return est, src


def _episodes_made(data_root: Path) -> list[Path]:
    """Every entry under the launch tenant's `<T>/episodes` (none when it does not exist)."""
    root = R.episodes_dir(data_root, P.LAUNCH_TENANT)
    return sorted(root.iterdir()) if root.is_dir() else []


def _manifest_of(ep: Path) -> dict:
    """The manifest the launcher wrote, read back as plain YAML."""
    from defender import _yaml

    return _yaml.safe_load((ep / R.MANIFEST_NAME).read_text(encoding="utf-8"))


def _hand_sibling(episode_id: str, label: str) -> tuple[int | None, Any, str, Any]:
    """Drive the real sibling entrypoint and capture its refusal and recorder."""
    rec = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(P.LAUNCH_TENANT, episode_id, label), rec)
    return rc, refused, f"{P.refusal_text(refused)}\n{err}", rec


class OracleFailingC:
    """Fail preflight oracle requests for world c and serve the other worlds."""

    __name__ = "OracleFailingC"

    def __init__(self) -> None:
        self.failing = S.oracle(then=S.text_only("no served answer fits this world"))
        self.passing = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))
        self.hits = {"c": 0, "other": 0}
        self._model: Any = None

    @property
    def model(self) -> Any:
        if self._model is None:
            from pydantic_ai.models.function import FunctionModel

            self._model = FunctionModel(self, model_name=S.double_model_name("oracle"))
        return self._model

    def __call__(self, messages: list[Any], info: Any) -> Any:
        text = S._messages_text(messages) + "\n" + (getattr(info, "instructions", None) or "")
        route = "c" if MARK_C in text else "other"
        self.hits[route] += 1
        return (self.failing if route == "c" else self.passing)(messages, info)


@pytest.mark.parametrize("verdict", ["unusable", "refused"])
def test_a_launch_whose_preflight_does_not_accept_writes_no_roster_and_its_sibling_is_refused(
        tmp_path, monkeypatch, data_root, verdict):
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est, src = _launch_scene(tmp_path, monkeypatch)
    spawn = J.FakeSibling(data_root=data_root, exits={})
    if verdict == "unusable":
        seams: dict[str, Any] = {"verifier": S.failing_verifier().model}
    else:
        factless = S.family_v2(worlds=[S.control_world("a"), S.world_v2("b", facts=[]),
                                       S.world_v2("c", role="C", facts=[])])
        seams = {"questioner": P.CountingQuestioner(S.questioner_for(factless))}

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=spawn, **seams)
    made = _episodes_made(data_root)
    assert len(made) == 1, (
        f"expected one episode under <T>/episodes, found {made}: rc={got.rc} {got.message!r}")
    ep = made[0]
    assert R.is_canonical_uuid(ep.name), f"the episode folder is not a uuid: {ep.name!r}"
    assert (ep / R.MANIFEST_NAME).is_file(), "the manifest (written at QUESTIONER) is missing"
    outcome = S.read_outcome(ep)
    assert outcome is not None, "control: pre-flight wrote no outcome record"
    assert outcome["outcome"] == verdict, (
        f"control: pre-flight should have ruled the family {verdict}: {outcome!r}")
    assert not os.path.lexists(ep / R.ROSTER_NAME), "a roster was written before RUNS"
    assert not os.path.lexists(ep / "runs"), "runs/ was made for an episode that never ran"
    assert spawn.launches == [], f"a sibling was started: {spawn.launches}"

    doc = _manifest_of(ep)
    T.write_family(ep, {**doc, SENTINEL: "read"})
    before = R.tree(data_root)
    rc, refused, said, rec = _hand_sibling(ep.name, "b")
    assert refused is not None, f"the hand-run sibling ran: rc {rc}"
    assert rc is None, f"the hand-run sibling ran: rc {rc}"
    assert SENTINEL not in said, f"the manifest was read before the gate: {said!r}"
    assert R.EPISODES_BASE_ENV not in said, f"refused for the retired variable: {said!r}"
    assert rec.order == [], f"the sibling spent before refusing: {rec.order}"
    assert R.tree(data_root) == before, "the refused sibling wrote under the data root"

    (ep / "runs").mkdir()
    R.write_roster(ep, {w["world_id"]: R.new_id() for w in doc["worlds"]})
    rc, refused, said, rec = _hand_sibling(ep.name, "b")
    assert refused is not None, f"the poisoned manifest was not read past the gate: rc {rc}"
    assert SENTINEL in said, f"past the gate the refusal should name {SENTINEL}: {said!r}"
    assert rec.order == [], f"the manifest refusal came after a spend: {rec.order}"


def test_a_launch_rosters_every_manifest_world_and_starts_only_the_servable_ones(
        tmp_path, monkeypatch, data_root):
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est, src = _launch_scene(tmp_path, monkeypatch)
    doc = S.family_v2(worlds=[
        S.control_world("a"), S.world_v2("b", facts=[S.fact("f1")]),
        S.world_v2("c", role="C", facts=[S.fact("f2", MARK_C, ("carol", "vault", "10.0.0.9"))])])
    oracle = OracleFailingC()
    spawn = J.FakeSibling(data_root=data_root, exits={})

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=spawn,
                         questioner=P.CountingQuestioner(S.questioner_for(doc)),
                         oracle=oracle.model)
    made = _episodes_made(data_root)
    assert len(made) == 1, (
        f"expected one episode under <T>/episodes, found {made}: rc={got.rc} {got.message!r}")
    ep = made[0]
    outcome = S.read_outcome(ep)
    assert outcome is not None, "control: pre-flight wrote no outcome record"
    assert outcome["outcome"] == "accepted", outcome
    assert [u["world"] for u in outcome["unservable_worlds"]] == ["c"], (
        f"control: c should be unservable: {outcome['unservable_worlds']}")
    assert oracle.hits["c"] > 0, "control: c's pre-flight never asked its oracle"
    assert spawn.faults == [], spawn.faults

    labels = {w["label"] for w in _manifest_of(ep)["worlds"]}
    assert labels == {"a", "b", "c"}, labels
    roster = R.read_roster(ep)
    assert set(roster) == {world["world_id"] for world in _manifest_of(ep)["worlds"]}, f"the roster names {sorted(roster)}, the manifest {sorted(labels)}"
    assert all(R.is_canonical_uuid(v) for v in roster.values()), roster
    assert len(set(roster.values())) == len(roster), f"two labels share an id: {roster}"
    assert sorted(_spawn_worlds(spawn)) == ["a", "b"], f"started {_spawn_worlds(spawn)}"
    for label in ("a", "b"):
        assert (ep / "worlds" / T.world_id(ep, label) / "report.md").is_file(), f"{label} was not archived"
    assert not (ep / "worlds" / T.world_id(ep, "c") / "report.md").exists(), "the unservable world was archived"


@pytest.mark.parametrize("variable", ["unset", "decoy"])
def test_a_launch_lands_its_episode_under_its_tenant_whatever_the_episodes_variable_says(
        tmp_path, monkeypatch, data_root, variable):
    est, src = _launch_scene(tmp_path, monkeypatch)
    decoy: Path | None = None
    if variable == "unset":
        monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    else:
        decoy = R.plant_old_episodes_root(tmp_path / "decoy-episodes")
        monkeypatch.setenv(R.EPISODES_BASE_ENV, str(decoy))
    decoy_before = R.tree(decoy) if decoy is not None else None
    episodes = R.episodes_dir(data_root, P.LAUNCH_TENANT)
    if episodes.is_dir() and not any(episodes.iterdir()):
        episodes.rmdir()
    assert not os.path.lexists(episodes), "the scene must start with no <T>/episodes"
    natural_before = sorted(os.listdir(src.parent))
    spawn = J.FakeSibling(data_root=data_root, exits={})

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=spawn)
    assert got.rc == 0, f"the launch did not complete: rc={got.rc} {got.message!r} {got.raised!r}"
    made = _episodes_made(data_root)
    assert len(made) == 1, f"expected one episode under <T>/episodes: {made}"
    ep = made[0]
    assert R.is_canonical_uuid(ep.name), f"the episode folder is not a uuid: {ep.name!r}"
    assert (ep / R.MANIFEST_NAME).is_file(), "the launched episode holds no manifest"
    assert (ep / R.ROSTER_NAME).is_file(), "the launched episode holds no roster"
    assert spawn.faults == [], spawn.faults
    assert sorted(_spawn_worlds(spawn)) == ["a", "b", "c"], f"control: the siblings ran: {_spawn_worlds(spawn)}"
    if decoy is not None:
        assert R.tree(decoy) == decoy_before, "the launch touched the decoy episodes base"
    assert sorted(os.listdir(src.parent)) == natural_before, (
        f"the launch changed <T>/runs (O10): {sorted(os.listdir(src.parent))}")


def test_the_launcher_refuses_an_old_source_id_before_anything_is_spent(
        tmp_path, monkeypatch, data_root):
    P.roots(tmp_path, monkeypatch)
    est, _old_src = P.launch_source(tmp_path, source_run_id=R.OLD_MINTED_ID)
    asked = P.CountingQuestioner()

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, R.OLD_MINTED_ID),
                         spawn=J.FakeSibling(data_root=data_root, exits={}), questioner=asked)
    assert R.OLD_MINTED_ID in got.message, f"the refusal does not name the id: {got.message!r}"
    assert asked.calls == 0, "the questioner was called for an old source id"
    assert _episodes_made(data_root) == [], "an episode was claimed for an old source id"

    # The control's source lives under a data root of its own: a second fixture source in the
    # SAME root shares `_triplet_947.seed_source_session`'s one store and case, whose row loop
    # then never reaches the branch point (it spins). Same tenant id, same launcher, same channel.
    control_root = tmp_path / "control-data-root"
    control_root.mkdir()
    monkeypatch.setenv(R.DATA_ROOT_ENV, str(control_root))
    est, src = P.launch_source(tmp_path / "control", source_run_id=R.new_id())
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    control = P.CountingQuestioner()
    ok = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name),
                        spawn=J.FakeSibling(data_root=control_root, exits={}), questioner=control)
    assert control.calls > 0, f"control: a UUID source was refused: {ok.message!r}"


class RolePreflight:
    """Record role-model preflight calls and return the configured verdict."""

    def __init__(self) -> None:
        self.calls: list[str | None] = []

    def __call__(self, model: str | None = None, *_args: Any, **_kw: Any) -> int:
        self.calls.append(model)
        return 0


def _sans_paths(text: str) -> str:
    """Remove absolute path tokens so refusals can be compared across tenant roots."""
    import re

    return re.sub(r"/\S*", "<path>", text)


def test_the_launcher_refuses_a_settings_half_inside_its_episodes_folder(
        tmp_path, monkeypatch, data_root):
    est, src = _launch_scene(tmp_path, monkeypatch)
    monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    tenant_dir = R.tenant_dir(data_root, P.LAUNCH_TENANT)
    episodes = tenant_dir / "episodes"
    if episodes.is_dir() and not any(episodes.iterdir()):
        episodes.rmdir()
    os.symlink(tenant_dir / "knowledge", episodes, target_is_directory=True)
    knowledge_before = R.tree(tenant_dir / "knowledge")
    listed_before = sorted(os.listdir(episodes))
    asked = P.CountingQuestioner()
    role = RolePreflight()
    spawn = J.FakeSibling(data_root=data_root, exits={})

    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=spawn,
                         questioner=asked, preflight=role)
    assert got.rc != 0, f"the launch was not refused: rc={got.rc}"
    assert "settings" in got.message, f"not acceptance's settings refusal: {got.message!r}"
    assert "a box mounts" in got.message, f"not acceptance's settings refusal: {got.message!r}"
    assert P.LAUNCH_TENANT in _sans_paths(got.message), (
        f"the refusal does not name the tenant {P.LAUNCH_TENANT!r}: {got.message!r}")
    assert R.EPISODES_BASE_ENV not in got.message, got.message
    assert role.calls == [], f"the role preflight was spent before acceptance refused: {role.calls}"
    assert asked.calls == 0, "the questioner was called before acceptance refused"
    assert spawn.launches == [], spawn.launches
    assert sorted(os.listdir(episodes)) == listed_before, (
        f"an episode folder appeared under <T>/episodes: {sorted(os.listdir(episodes))}")
    assert [n for n in os.listdir(episodes) if R.is_canonical_uuid(n)] == [], (
        "an episode folder exists under <T>/episodes")
    assert R.tree(tenant_dir / "knowledge") == knowledge_before, "the knowledge folder changed"

    os.unlink(episodes)
    control = P.CountingQuestioner()
    control_role = RolePreflight()
    ok = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name),
                        spawn=J.FakeSibling(data_root=data_root, exits={}), questioner=control,
                        preflight=control_role)
    assert control_role.calls != [], f"control: the role preflight was never reached: {ok.message!r}"
    assert control.calls > 0, f"the control launch was refused at acceptance: {ok.message!r}"
    assert ok.rc == 0, f"the control launch did not complete: {ok.message!r} {ok.raised!r}"
    assert len(_episodes_made(data_root)) == 1, (
        f"control: the launch made no one episode under <T>/episodes: {_episodes_made(data_root)}")


def test_the_judge_gate_holds_a_label_to_its_own_rule_not_its_composed_name(tmp_path):
    from defender import _io
    from defender.learning.judge import JudgeRefused, family

    episode_id = R.new_id()
    ep = tmp_path / episode_id
    good = ("w" * 200, "w" * 220, "w" * 230, "w" * 1000, "b")
    bad = ("-a", "_a", ".a", "", "../x", "a/b", "..", "a\x00b")
    for label in (*good, *bad):
        T.write_family(ep, T.family_doc(episode_id=episode_id,
                                       worlds=[T.base_world(), T.world_doc(label)]))
        with _io.bind(ep) as view:
            err = R.raised(family.read_manifest, view, expected_episode_id=episode_id)
        assert (err is None) is (label in good), (label, err)
        if label in bad:
            assert isinstance(err, JudgeRefused), err


# S-red — the redaction set is the roster's

def _family(episode_id: str) -> Any:
    return T.sym("records._family", "parse_family")(_doc(episode_id))


def _arm_ids(roster: dict[str, str]) -> dict[str, Any]:
    from defender.records import RunId

    return {label: RunId.parse(text) for label, text in roster.items()}


def test_family_identities_is_the_episode_its_tokens_and_every_roster_arm_id():
    from defender.records._family import family_identities

    episode_id = R.new_id()
    roster = {T.fixture_world_id(label): R.new_id() for label in LABELS}
    family = _family(episode_id)
    expected = {episode_id, *(world.world_id for world in family.worlds), *roster.values()}
    known = {str(member) for member in family_identities(family, _arm_ids(roster))}
    assert known == expected, (
        f"missing {sorted(expected - known)}; unexpected {sorted(known - expected)}")


def test_family_identities_requires_the_arm_ids():
    from defender.records._family import family_identities

    family = _family(R.new_id())
    assert isinstance(R.raised(family_identities, family), TypeError), (
        "family_identities(family) was accepted without the roster's arm ids")


def test_a_roster_arm_id_is_redacted_and_an_unrelated_uuid_is_not():
    from defender._redaction import redact_model_visible
    from defender.records._family import family_identities

    episode_id = R.new_id()
    roster = {T.fixture_world_id(label): R.new_id() for label in LABELS}
    known = family_identities(_family(episode_id), _arm_ids(roster))
    detail = (f"run {roster[T.fixture_world_id('c')]} refused; sibling {roster[T.fixture_world_id('b')].upper()} served; "
              f"index {UNRELATED_UUID} unavailable")
    assert redact_model_visible(detail, known) == (
        f"run {MARK} refused; sibling {MARK} served; index {UNRELATED_UUID} unavailable")


def test_the_comparator_prompt_never_carries_a_roster_arm_id(data_root):
    from defender.records._family import FamilyError

    ep, episode_id, roster = _episode(data_root)
    _outcome(ep)
    J.comparable_family_stamp(ep)
    for label in LABELS:
        T.archived_world(ep, label)
    T.base_capture(ep, [T.captured_row(key="k1")])
    leaked = {"hits": [{"_id": "x", "note": f"seen by {roster[T.world_id(ep, 'c')]} near {UNRELATED_UUID}"}]}
    (ep / "served" / f"{T.world_id(ep, 'b')}.jsonl").write_text(
        json.dumps(T.captured_row(key="k1", payload=leaked)) + "\n", encoding="utf-8")
    delta_o = T.sym("learning.branch.episode", "delta_o")
    runs = R.tenant(data_root).runs_repository()

    agent = T.FakeAgent("mutation")
    with runs.episode(episode_id) as view:
        out = delta_o(view, invoke=agent)
    assert out["b"]["k1"] == "mutation"
    assert agent.prompts, "the comparator was never asked"
    assert roster[T.world_id(ep, "c")] not in agent.prompts[0], "a roster arm id reached the comparator prompt"
    assert MARK in agent.prompts[0]
    assert UNRELATED_UUID in agent.prompts[0], "the payload never reached the prompt"

    T.write_family(ep, _doc(R.near_miss_id(episode_id)))
    unasked = T.FakeAgent("mutation")
    with runs.episode(episode_id) as view:
        err = R.raised(delta_o, view, invoke=unasked)
    assert R.is_a(err, FamilyError), f"delta_o over a mismatched manifest: {err!r}"
    assert unasked.prompts == [], "the comparator was asked over a mismatched manifest"


def test_the_episode_readers_take_the_walked_view_and_no_path(data_root):
    ep, episode_id, _roster = _episode(data_root)
    _outcome(ep)
    J.comparable_family_stamp(ep)
    want = {"a": "benign", "b": "malicious", "c": "false-positive"}
    for label, disposition in want.items():
        T.archived_world(ep, label, disposition=disposition)
    T.base_capture(ep, [T.captured_row(key="k1")])
    episode_mod = T.mod("learning.branch.episode")
    runs = R.tenant(data_root).runs_repository()

    with runs.episode(episode_id) as view:
        got = episode_mod.verdicts(view)
    assert got == want, f"verdicts through the walked view: {got!r}"

    assert R.raised(episode_mod.verdicts, ep) is not None, "verdicts answered through a bare path"
    asked = T.FakeAgent("mutation")
    assert R.raised(episode_mod.delta_o, ep, invoke=asked) is not None, (
        "delta_o answered through a bare path")
    assert asked.prompts == [], "the comparator was asked through a bare path"


class RegistryProbe:
    """The sibling's `lifecycle=` seam: runs the REAL drive function `run._drive_investigation`."""

    def __init__(self) -> None:
        self.known: frozenset[str] | None = None

    def __call__(self, **kw: Any) -> dict[str, Any]:
        from defender import run as run_py
        from defender.records import RunPaths

        seen: dict[str, Any] = {}
        inner = dict(kw)
        inner["model_name"] = inner.pop("model")
        run_py._drive_investigation(
            alert_path=RunPaths(kw["run"].run_dir).alert, box=None,
            investigate=lambda **got: seen.update(got) or {}, **inner)
        self.known = frozenset(str(m) for m in seen["verbs"].branch_identities())
        return {"output": "probe", "requests": 0, "truncated_by": None}


def test_the_siblings_query_tool_knows_every_roster_arm_id(tmp_path, monkeypatch, data_root):
    P.roots(tmp_path, monkeypatch)
    source_id = R.new_id()
    _base, src = location_path(T.runs_base)(tmp_path, source_run_id=source_id)
    tenant_id = src.parent.parent.name
    episode_id = R.new_id()
    doc = P.family_doc(src, episode_id=episode_id, source_run_id=source_id)
    ep = T.episode(tmp_path, doc=doc, root=R.episodes_dir(data_root, tenant_id),
                   episode_id=episode_id)
    # The natural container in #1187's shape: no `_tenant.json` (R1).
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    roster = {w["world_id"]: R.new_id() for w in doc["worlds"]}
    (ep / "runs").mkdir()
    R.write_roster(ep, roster)

    probe = RegistryProbe()
    rec = P.SiblingRecorder()
    rc, refused, err = P.drive_run_py(P.new_sibling_argv(tenant_id, episode_id, "b"), rec,
                                      lifecycle=probe)
    assert probe.known is not None, (
        f"the sibling never built its registry: rc={rc} {P.refusal_text(refused)} {err[-2000:]}")
    expected = {episode_id, *(world["world_id"] for world in doc["worlds"]), *roster.values()}
    assert probe.known == expected, (
        f"missing {sorted(expected - probe.known)}; unexpected {sorted(probe.known - expected)}")
    assert f"{episode_id}-c" not in probe.known

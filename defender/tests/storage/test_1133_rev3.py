from __future__ import annotations

from defender.run_repository import Run

import errno
import json
import logging
import os
import stat
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.episodes._episode_paths import LAYOUT
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.storage import _spec1133 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.branch.test_947_capture_prime import append_call, call_row, source_run
from defender.tests.support.learning.core import _state1135
from defender.run_repository import RunPaths

EPISODE_ID = "ep-1133"
#: Bytes that are not UTF-8: a plain file holding them is a refused text read.
UNDECODABLE = b"\xff\xfe record bytes, not text\n"
#: A string no UTF-8 encoder accepts (a lone surrogate).
UNENCODABLE = "a row \udcff that cannot be encoded\n"


@pytest.fixture
def roots(tmp_path, monkeypatch):
    """The configured roots inside `tmp_path` (environment steering, the resolvers' own seam):
    the runs base, the episodes root and the learning state root the judge's queue lands in."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


@pytest.fixture
def host(tmp_path: Path) -> Path:
    """A host folder outside every episode: where an outside link points."""
    h = tmp_path / "host"
    h.mkdir()
    return h


def bare_episode(tmp_path: Path) -> Path:
    ep = tmp_path / "episodes" / EPISODE_ID
    ep.mkdir(parents=True)
    return ep


def view_reason(ep: Path, rel: PurePosixPath) -> str:
    """What the view says of `rel` right now (its refusal reason), read through a fresh `bind`
    so the expectation comes from the reader itself, not a hand-copied sentence."""
    with _io.bind(ep) as view:
        rec = view.read(rel)
    assert rec.text is None, f"the fixture's {rel} reads as text: {rec!r}"
    assert not rec.absent, f"the fixture's {rel} reads as absent: {rec!r}"
    assert rec.reason, f"the fixture's {rel} is refused with no reason: {rec!r}"
    return rec.reason


def plant_record(at: Path, kind: str, *, host: Path) -> S.Planted:
    """`kind` at a record's own name: a leaf plant, or `undecodable` (a plain, single-linked
    file whose bytes are not UTF-8 — refused by a text read)."""
    if kind == "undecodable":
        at.parent.mkdir(parents=True, exist_ok=True)
        at.write_bytes(UNDECODABLE)
        return S.Planted("file", at)
    return S.plant_leaf(at, kind, host=host, body=b"host: bytes\n")


def link_folder(at: Path, *, reach: str, ep: Path, host: Path, keep: dict[str, bytes]) -> Path:
    """Replace the folder at `at` (or nothing) with a symlink to a real folder, outside the
    episode or elsewhere inside it, holding `keep`. Answers the folder the link reaches."""
    target = (host if reach == "outside" else ep) / f"elsewhere-{at.name}"
    target.mkdir()
    for name, body in keep.items():
        (target / name).write_bytes(body)
    if at.is_dir() and not at.is_symlink():
        for child in at.iterdir():
            child.unlink()
        at.rmdir()
    at.symlink_to(target, target_is_directory=True)
    return target


def mod(dotted: str) -> Any:
    return T.mod(dotted)


@pytest.mark.parametrize("key", ["family", "review"])
@pytest.mark.parametrize("kind", S.LEAF_PLANTS)
def test_r1_a_record_is_read_through_the_view_present_absent_or_refused(tmp_path, key, kind):
    ep = bare_episode(tmp_path)
    host = tmp_path / "host"
    host.mkdir()
    rel = S.expected_record_rel(key)
    with S.open_episode(ep) as episode:
        planted = S.plant_leaf(ep / rel, kind, host=host)
        before = S.census(tmp_path)
        got = S.in_time(lambda: episode.view().read(rel), fifo=planted.fifo)
        assert got.text is None, f"the view read through a {kind} at {rel}: {got!r}"
        assert not got.absent, f"a {kind} at {rel} read as absent: {got!r}"
        assert got.reason, f"a {kind} at {rel} was refused with no reason: {got!r}"
        assert S.census(tmp_path) == before, f"reading a {kind} at {rel} changed the tree"

        planted.remove()
        assert episode.view().read(rel).absent, "control: an absent record did not read absent"
        getattr(getattr(episode, key), "create" if key == "family" else "write")(f"{key}: plain\n")
        assert episode.view().read(rel).text == f"{key}: plain\n"
        assert not hasattr(getattr(episode, key), "read"), (
            f"the {key} record still answers `read`: records are write-only (R1)")


def _view_matrix():
    rec = PurePosixPath("fa/fb/rec.jsonl")
    for kind in S.LEAF_PLANTS:
        yield pytest.param(kind, None, id=f"read-{kind}")
    for site in S.holding_folders(rec):
        for kind in S.FOLDER_PLANTS:
            yield pytest.param(kind, site, id=f"read-{kind}@{site}")


@pytest.mark.parametrize(("kind", "site"), list(_view_matrix()))
def test_r1_the_views_read_of_a_plant_is_refused_promptly_and_changes_nothing(
        tmp_path, kind, site):
    root = tmp_path / "root"
    root.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    rel = PurePosixPath("fa/fb/rec.jsonl")
    with S.hold(root) as held:
        view = held.view()
        planted = S.plant(root, rel, site, kind, host=host)
        before = S.census(tmp_path)
        got = S.in_time(lambda: view.read(rel), fifo=planted.fifo)
        assert got.text is None, f"the view read through a {kind}: {got!r}"
        assert not got.absent, f"a {kind} read as absent: {got!r}"
        assert got.reason, f"a {kind} is refused with no reason: {got!r}"
        rows, _bad, rec = S.in_time(lambda: view.read_jsonl(rel), fifo=planted.fifo)
        assert rows == [], f"read_jsonl through a {kind} answered rows: {rows!r}"
        assert rec.reason, f"read_jsonl through a {kind} is not refused: {rec!r}"
        assert S.census(tmp_path) == before

        planted.remove()
        assert view.read(rel).absent
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text('{"k": 1}\n', encoding="utf-8")
        assert view.read(rel).text == '{"k": 1}\n'
        assert view.read_jsonl(rel)[0] == [{"k": 1}]


# ---- the view under a close race (the E-race shape) --------------------------------------

_RACE_OPS = ("read-top", "read-deep", "read_jsonl", "entries-root", "entries-under")


def _race_trees(tmp_path: Path) -> tuple[Path, Path]:
    """A root and a DECOY of the same shape, each marking its own bytes and names."""
    trees = []
    for who in ("root", "decoy"):
        top = tmp_path / who
        (top / "fa").mkdir(parents=True)
        (top / "rec.txt").write_text(f"{who.upper()}\n", encoding="utf-8")
        (top / "fa" / "rec.jsonl").write_text(json.dumps({"who": who}) + "\n", encoding="utf-8")
        (top / f"{who}-marker").write_text("", encoding="utf-8")
        (top / "fa" / f"{who}-only").write_text("", encoding="utf-8")
        trees.append(top)
    return trees[0], trees[1]


def _race_op(view: Any, op: str) -> Any:
    return {
        "read-top": lambda: view.read("rec.txt"),
        "read-deep": lambda: view.read("fa/rec.jsonl"),
        "read_jsonl": lambda: view.read_jsonl("fa/rec.jsonl"),
        "entries-root": lambda: view.entries(),
        "entries-under": lambda: view.under("fa").entries(),
    }[op]()


def _answered_root(op: str, got: Any) -> None:
    if op == "read-top":
        assert got.text == "ROOT\n", f"the in-flight read answered {got!r}, not the root's bytes"
    elif op == "read-deep":
        assert got.text == json.dumps({"who": "root"}) + "\n", f"the in-flight read: {got!r}"
    elif op == "read_jsonl":
        assert got[0] == [{"who": "root"}], f"the in-flight read_jsonl answered {got!r}"
    elif op == "entries-root":
        assert got.entries is not None, f"the in-flight listing was refused: {got!r}"
        assert "root-marker" in got.entries, f"the in-flight listing is not the root's: {got!r}"
        assert "decoy-marker" not in got.entries, f"the listing is the decoy's: {got!r}"
    else:
        assert got.files() == ["rec.jsonl", "root-only"], (
            f"the in-flight listing of fa/ is not the root's: {got!r}")


def _refused_as_closed(op: str, got: Any) -> None:
    rec = got[2] if op == "read_jsonl" else got
    payload = rec.entries if op.startswith("entries") else rec.text
    assert payload is None, f"a {op} after close answered {got!r}"
    assert rec.reason == os.strerror(errno.EBADF), (
        f"a {op} after close is not refused as a closed descriptor: {got!r}")


@pytest.mark.parametrize("op", _RACE_OPS)
def test_r1_a_view_read_in_flight_when_close_lands_answers_the_root_never_the_reused_number(
        tmp_path, op):
    root, decoy = _race_trees(tmp_path)
    spy = S.OsSpy()
    held = S.hold(root, os_=spy)
    view = held.view()
    [root_fd] = S.open_fds_on(root)
    state: dict[str, Any] = {}

    def close_mid_read(_op: str, _args: tuple, _kwargs: dict) -> None:
        spy.hook = None
        state["closed_promptly"] = S.run_in_thread(held.close, timeout=1.0)
        if not state["closed_promptly"]:
            return
        state["open_after_close"] = S.open_fds_on(root)
        if root_fd not in state["open_after_close"]:
            fd = os.open(decoy, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            if fd != root_fd:
                os.dup2(fd, root_fd, inheritable=False)
                os.close(fd)
            state["decoy_on"] = root_fd

    spy.hook = close_mid_read
    try:
        got = _race_op(view, op)
        assert "closed_promptly" in state, f"the view's {op} made no relative operation"
        assert state["closed_promptly"], "close() waited for the read in flight"
        assert "decoy_on" in state, (
            f"close() released nothing while a read ran: {state.get('open_after_close')}")
        _answered_root(op, got)
        assert S.inode(decoy) == (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino), (
            "something closed or replaced the reused descriptor number")

        _refused_as_closed(op, S.in_time(lambda: _race_op(view, op)))
    finally:
        if "decoy_on" in state:
            os.close(state["decoy_on"])
        held.close()


@pytest.mark.parametrize("op", _RACE_OPS)
def test_r1_a_close_landing_as_the_view_takes_its_dup_never_redirects_the_read(tmp_path, op):
    root, decoy = _race_trees(tmp_path)
    spy = S.OsSpy()
    held = S.hold(root, os_=spy)
    view = held.view()
    state: dict[str, Any] = {}

    def close_at_dup(fd: int) -> None:
        closer = threading.Thread(target=held.close, daemon=True)
        closer.start()
        closer.join(0.5)
        state["closer"] = closer
        if not closer.is_alive():
            taken = os.open(decoy, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            if taken != fd:
                os.dup2(taken, fd, inheritable=False)
                os.close(taken)
            state["decoy_on"] = fd

    spy.before_dup = close_at_dup
    try:
        got = _race_op(view, op)
        assert "closer" in state, f"the view's {op} took no dup of the root through its os_ seam"
        state["closer"].join(S.DEADLINE)
        assert not state["closer"].is_alive(), "close() never completed once the read had its dup"
        _answered_root(op, got)
    finally:
        if "decoy_on" in state:
            os.close(state["decoy_on"])
        held.close()


# ---- delta_o: one bind for the pass ------------------------------------------------------

def _delta_episode(tmp_path: Path) -> Path:
    """An accepted episode (pre-flight's `outcome.yaml`) with a base world `a` and a world `b`,
    both archived; the base captures k1 and k2, and `b` served k1 the same and k2 differently."""
    doc = T.family_doc(worlds=[T.base_world(), T.world_doc("b")])
    ep = T.episode(tmp_path, doc=doc)
    J.outcome_record(ep)
    for label in ("a", "b"):
        T.archived_world(ep, label)
    T.base_capture(ep, [T.captured_row(key="k1"), T.captured_row(key="k2")])
    _world_file(ep, "b").write_text(
        json.dumps(T.captured_row(key="k1")) + "\n"
        + json.dumps(T.captured_row(key="k2", payload={"hits": [{"_id": "other"}]})) + "\n",
        encoding="utf-8")
    return ep


def _world_file(ep: Path, label: str) -> Path:
    return ep / LAYOUT.served_world(T.world_id(ep, label))


def episode_mod() -> Any:
    return mod("learning.branch.episode")


@pytest.mark.parametrize("base", ["absent", "symlink", "fifo"])
def test_r1_delta_o_with_no_archived_worlds_is_empty_before_the_base_is_read(tmp_path, host,
                                                                             base):
    ep = T.episode(tmp_path)
    J.outcome_record(ep)
    at = ep / LAYOUT.served_base
    at.unlink()
    fifo = None
    if base != "absent":
        fifo = S.plant_leaf(at, base, host=host).fifo
    assert S.in_time(lambda: J.through_view(ep, episode_mod().delta_o), fifo=fifo) == {}


@pytest.mark.parametrize("kind", ["absent", "symlink", "dangling", "hardlink", "fifo",
                                  "directory"])
def test_r1_delta_o_refuses_an_absent_or_refused_base_as_no_primed_base(tmp_path, host, kind):
    ledger = mod("learning.branch.ledger")
    ep = _delta_episode(tmp_path)
    at = ep / LAYOUT.served_base
    good = at.read_bytes()
    at.unlink()
    planted = None if kind == "absent" else S.plant_leaf(at, kind, host=host, body=good)
    before = S.census(ep)

    raised = S.raised_by(lambda: J.through_view(ep, episode_mod().delta_o),
                         fifo=planted.fifo if planted else None)
    assert isinstance(raised, ledger.LedgerError), f"delta_o over a {kind} base: {raised!r}"
    assert "no primed base" in str(raised), raised
    assert S.census(ep) == before

    if planted is not None:
        planted.remove()
    at.write_bytes(good)
    out = J.through_view(ep, episode_mod().delta_o)
    assert out["b"]["k1"] == "same", out
    assert "k2" in out["b"], out


@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "fifo", "directory"])
def test_r1_delta_o_refuses_a_refused_world_file_naming_it(tmp_path, host, kind):
    ep = _delta_episode(tmp_path)
    at = _world_file(ep, "b")
    good = at.read_bytes()
    at.unlink()
    planted = S.plant_leaf(at, kind, host=host, body=good)

    raised = S.raised_by(lambda: J.through_view(ep, episode_mod().delta_o), fifo=planted.fifo)
    assert isinstance(raised, episode_mod().EpisodeError), (
        f"delta_o over a {kind} world file: {raised!r}")
    assert at.name in str(raised), f"the refusal does not name {at.name}: {raised}"


@pytest.mark.parametrize("state", ["absent", "undecodable", "plain"])
def test_r1_delta_o_reads_an_absent_world_file_as_serving_nothing(tmp_path, state):
    ep = _delta_episode(tmp_path)
    at = _world_file(ep, "b")
    if state == "absent":
        at.unlink()
    elif state == "undecodable":
        at.write_bytes(b"\xff\xfe not a row\n" + json.dumps(T.captured_row(key="k1")).encode()
                       + b"\n")
    out = J.through_view(ep, episode_mod().delta_o)
    if state == "absent":
        assert out["b"] == {}, out
    else:
        assert out["b"]["k1"] == "same", out


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "undecodable"])
def test_r1_delta_os_outcome_gate_refuses_a_refused_outcome_record(tmp_path, host, kind):
    ep = _delta_episode(tmp_path)
    record = ep / LAYOUT.outcome
    good = record.read_bytes()
    record.unlink()
    planted = plant_record(record, kind, host=host)

    raised = S.raised_by(lambda: J.through_view(ep, episode_mod().delta_o), fifo=planted.fifo)
    assert isinstance(raised, episode_mod().EpisodeError), (
        f"delta_o past a {kind} outcome record: {raised!r}")

    planted.remove()
    record.write_bytes(good)
    assert J.through_view(ep, episode_mod().delta_o)["b"]["k1"] == "same"
    record.write_text("outcome: [unclosed\n", encoding="utf-8")
    with pytest.raises(episode_mod().EpisodeError):
        J.through_view(ep, episode_mod().delta_o)
    J.outcome_record(ep, "unusable", reason="r")
    with pytest.raises(episode_mod().EpisodeError):
        J.through_view(ep, episode_mod().delta_o)


@pytest.mark.parametrize("via", ["bind", "episode-view", "delta_o"])
@pytest.mark.parametrize("state", ["absent", "symlink", "undecodable"])
def test_r1_load_family_through_a_view_names_family_yaml_never_a_path(tmp_path, host, via,
                                                                      state):
    fam = mod("runtime.branch._family")
    ep = _delta_episode(tmp_path)
    manifest = ep / LAYOUT.family
    good = manifest.read_bytes()
    manifest.unlink()
    planted = None if state == "absent" else plant_record(manifest, state, host=host)

    def load() -> Any:
        if via == "delta_o":
            return J.through_view(ep, episode_mod().delta_o)
        # #1187 (R5, declared change 10): the loader is told the episode's id (its folder's
        # name) and refuses a manifest naming another; `expected_episode_id=` is required.
        if via == "bind":
            with _io.bind(ep) as view:
                return fam.load_family(view, expected_episode_id=ep.name)
        with S.open_episode(ep) as episode:
            return fam.load_family(episode.view(), expected_episode_id=ep.name)

    raised = S.raised_by(load)
    assert isinstance(raised, fam.FamilyError), f"{via} over a {state} manifest: {raised!r}"
    assert str(LAYOUT.family) in str(raised), f"the refusal does not name family.yaml: {raised}"
    assert str(tmp_path) not in str(raised), f"the refusal names an absolute path: {raised}"

    if planted is not None:
        planted.remove()
    manifest.write_bytes(good)
    got = load()
    if via == "delta_o":
        assert got["b"]["k1"] == "same"
    else:
        assert got.episode_id == T.EPISODE_ID


@pytest.mark.parametrize("lane", ["held", "rooted_write", "write_guarded"])
@pytest.mark.parametrize("kind", S.LEAF_PLANTS)
def test_r2_a_plant_at_the_name_is_not_plain_entry_keeping_its_errno_and_mark(
        tmp_path, lane, kind):
    root = tmp_path / "root"
    (root / "fa").mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    rel = "fa/rec.txt"
    planted = S.plant_leaf(root / rel, kind, host=host)

    def write(text: str) -> None:
        if lane == "held":
            with S.hold(root) as held:
                held.write(rel, text, mode="replace")
        elif lane == "rooted_write":
            _io.rooted_write(root, rel, text, mode="replace")
        else:
            _io.write_guarded(root / rel, text, mode="replace")

    raised = S.raised_by(lambda: write("refused\n"), fifo=planted.fifo)
    S.assert_refusal(raised, "symlink" if kind == "dangling" else kind,
                     where=f"{lane} into a {kind}")
    planted.remove()
    write("landed\n")
    assert (root / rel).read_text(encoding="utf-8") == "landed\n"


@pytest.mark.parametrize("kind", ["folder_link_outside", "folder_link_inside", "folder_file",
                                  "folder_fifo"])
def test_r2_a_linked_or_non_directory_folder_on_the_way_is_not_the_leaf_class(tmp_path, kind):
    cls = S.not_plain_entry()
    root = tmp_path / "root"
    root.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    rel = PurePosixPath("fa/rec.txt")
    planted = S.plant_folder(root, rel, PurePosixPath("fa"), kind, host=host)
    with S.hold(root) as held:
        raised = S.raised_by(lambda: held.write(str(rel), "x\n", mode="replace"),
                             fifo=planted.fifo)
        assert raised is not None, f"a {kind} on the way was not refused"
        assert not isinstance(raised, cls), f"a {kind} on the way raised the leaf class: {raised!r}"
        S.assert_refusal(raised, kind, where=f"Held.write through a {kind}")
        planted.remove()
        held.write(str(rel), "x\n", mode="replace")
    assert (root / rel).read_text(encoding="utf-8") == "x\n"


# ---- R2 at the judge's stale-draw removal (S1) -------------------------------------------

def _draw0_asks() -> list[str]:
    """Every ask of world `b`'s draw 0: the first and its re-asks after a refused reply (N22,
    `judge._REPLY_ATTEMPTS` asks per draw)."""
    attempts = J.mod("learning.judge")._REPLY_ATTEMPTS
    return [f"judge:{T.fixture_world_id('b')}:0", *(f"judge:{T.fixture_world_id('b')}:0:{a}" for a in range(1, attempts))]


class SwappingJudge:
    """The judge seam: a malformed reply for every ask of world `b`'s draw 0 (after `act()`
    runs once, on the first, a plant made mid-pass), a good reply for every other call; each
    agent id recorded."""

    def __init__(self, act: Any = None) -> None:
        self.good = J.as_reply_text(J.reply_doc())
        self.bad = J.as_reply_text(J.reply_doc(), malformed="lookalike-bucket")
        self.act = act
        self.agent_ids: list[str] = []

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        self.agent_ids.append(agent_id)
        if agent_id in _draw0_asks():
            if self.act is not None:
                act, self.act = self.act, None
                act()
            return self.bad
        return self.good

    def called_for(self, label: str) -> list[str]:
        return [a for a in self.agent_ids if a.startswith(f"judge:{T.fixture_world_id(label)}:")]


def _grade(tmp_path: Path, ep: Path, judge: Any) -> Any:
    try:
        return J.grade_at(
            ep, judge=judge, draws=2,
            state=_state1135.env_state())
    except Exception as refused:  # noqa: BLE001 — the refusal is the observation
        return refused


@pytest.mark.parametrize("reach", ["outside", "inside"])
def test_r2_a_judge_folder_linked_after_its_ensure_stops_the_pass_at_the_stale_draw_removal(
        tmp_path, roots, host, reach):
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.oracle_row("b")], "c": []})
    judge_dir = ep / "worlds" / T.world_id(ep, "b") / "judge"
    stale = b"findings: [{bucket: stale}]\n"
    reached: dict[str, Path] = {}

    def swap() -> None:
        reached["dir"] = link_folder(judge_dir, reach=reach, ep=ep, host=host,
                                     keep={"0.yaml": stale})

    judge = SwappingJudge(act=swap)
    got = _grade(tmp_path, ep, judge)

    assert "dir" in reached, "the pass never reached world b's first draw"
    assert isinstance(got, J.mod("learning.judge").JudgeRefused), (
        f"a judge/ folder linked mid-pass did not stop the pass: {got!r}")
    S.assert_refusal(S.refusal_in(got), f"folder_link_{reach}",
                     where="the stale-draw removal through a linked judge/")
    assert judge.called_for("b") == _draw0_asks(), (
        f"the pass went on past a linked judge/ folder: {judge.called_for('b')}")
    assert (reached["dir"] / "0.yaml").read_bytes() == stale, "a draw was removed through the link"
    assert judge_dir.is_symlink(), "the link at judge/ was removed"

    judge_dir.unlink()
    (ep / LAYOUT.judge).unlink(missing_ok=True)
    judge = SwappingJudge()
    got = _grade(tmp_path, ep, judge)
    assert not isinstance(got, BaseException), f"the control pass was refused: {got!r}"
    assert judge.called_for("b") == [*_draw0_asks(), f"judge:{T.fixture_world_id('b')}:1"]
    assert sorted(p.name for p in judge_dir.iterdir()) == ["1.yaml"]


# ---- R2 at the priming claim and the primed base -----------------------------------------

def _swap_served_before(ep: Path, rel: PurePosixPath, *, reach: str, host: Path,
                        state: dict[str, Any]) -> Any:
    """A `RecordingHeld` `before` hook: just before the held root delegates the `write` of
    `rel`, `served/` (real, made by the `ensure` or present for the listing) is swapped for a
    link to a real folder elsewhere."""
    def before(method: str, args: tuple, kwargs: dict) -> None:
        name = args[0] if args else kwargs.get("name")
        if method == "write" and S.as_rel(name) == rel and "reached" not in state:
            state["reached"] = link_folder(ep / "served", reach=reach, ep=ep, host=host,
                                           keep={})
    return before


@pytest.mark.parametrize("reach", ["outside", "inside"])
def test_r2_a_served_folder_linked_after_its_ensure_is_the_folder_refusal_at_the_claim(
        tmp_path, host, reach):
    cli = mod("learning.branch.cli")
    ledger = mod("learning.branch.ledger")
    ep = bare_episode(tmp_path)
    state: dict[str, Any] = {}
    ran: list[Any] = []

    def prime(_source: Path, _episode: Any) -> Any:
        ran.append(True)
        return mod("learning.branch.capture").PrimeReport(primed=1)

    io = S.RecordingIo(before=_swap_served_before(ep, LAYOUT.priming_lock, reach=reach,
                                                  host=host, state=state))
    with S.open_episode(ep, io=io) as episode:
        raised = S.raised_by(lambda: cli._prime_once(episode, EPISODE_ID, tmp_path / "src",
                                                     prime))
    assert "reached" in state, "the claim was never created through the held root"
    assert not isinstance(raised, ledger.LedgerError), (
        f"a served/ linked after its ensure was read as an occupied claim: {raised!r}")
    S.assert_refusal(raised, f"folder_link_{reach}", where="the claim through a linked served/")
    assert ran == [], "the primer ran past a refused claim"
    assert list(state["reached"].iterdir()) == [], "the claim was made through the link"

    (ep / "served").unlink()
    (ep / "served").mkdir()
    (ep / LAYOUT.priming_lock).symlink_to(host / "claim-target")
    with S.open_episode(ep) as episode, pytest.raises(
            ledger.LedgerError, match="another launcher is priming"):
        cli._prime_once(episode, EPISODE_ID, tmp_path / "src", prime)
    (ep / LAYOUT.priming_lock).unlink()
    with S.open_episode(ep) as episode:
        cli._prime_once(episode, EPISODE_ID, tmp_path / "src", prime)
    assert ran == [True]
    assert not os.path.lexists(ep / LAYOUT.priming_lock)


@pytest.mark.parametrize("reach", ["outside", "inside"])
def test_r2_a_served_folder_linked_after_the_listing_is_the_folder_refusal_at_the_base(
        tmp_path, host, reach):
    capture = mod("learning.branch.capture")
    ledger = mod("learning.branch.ledger")
    run_dir = _one_call_source(tmp_path)
    ep = bare_episode(tmp_path)
    (ep / "served").mkdir()
    state: dict[str, Any] = {}

    io = S.RecordingIo(before=_swap_served_before(ep, LAYOUT.served_base, reach=reach,
                                                  host=host, state=state))
    with S.open_episode(ep, io=io) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode))
    assert "reached" in state, "the base was never created through the held root"
    assert not isinstance(raised, ledger.LedgerError), (
        f"a served/ linked after the listing was read as an existing base: {raised!r}")
    S.assert_refusal(raised, f"folder_link_{reach}", where="the base through a linked served/")
    assert list(state["reached"].iterdir()) == [], "the base was written through the link"

    (ep / "served").unlink()
    (ep / "served").mkdir()
    with S.open_episode(ep) as episode:
        assert capture.prime_base(run_dir, episode).primed == 1


def _one_call_source(tmp_path: Path) -> Path:
    run_dir = source_run(tmp_path)
    append_call(run_dir, call_row("l-001", 0, "cmdb", "get-host", {"host": "canary-1"}),
                json.dumps({"owner": "estate", "role": "canary"}))
    return run_dir


def _empty_source(tmp_path: Path) -> Path:
    run_dir = source_run(tmp_path)
    (run_dir / "executed_queries.jsonl").write_text("", encoding="utf-8")
    return run_dir


def fifo_sidecar(run_dir: Path) -> tuple[Path, bytes]:
    """Turn the one captured call's payload sidecar into a FIFO, which the capture read opens
    (`_captured_call` -> `read_text_soft` blocks on it). Answers the FIFO and the payload it
    stood for."""
    sidecar = run_dir / "gather_raw" / "l-001" / "0.json"
    payload = sidecar.read_bytes()
    sidecar.unlink()
    os.mkfifo(sidecar)
    return sidecar, payload


class CaptureRead:
    """Makes reading the capture observable, over `fifo_sidecar`'s FIFO: a watcher sees a
    reader arrive (its non-blocking write-open stops failing `ENXIO`), records it, and hands the
    reader the payload, so a read completes as it would have. Used as a context manager, once
    per call under observation."""

    def __init__(self, sidecar: Path, payload: bytes) -> None:
        self.sidecar = sidecar
        self.payload = payload
        self.read = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._watch, daemon=True)

    def __enter__(self) -> CaptureRead:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(S.DEADLINE)

    def _watch(self) -> None:
        while not self._stop.is_set():
            try:
                fd = os.open(self.sidecar, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as e:
                if e.errno != errno.ENXIO:
                    return
                time.sleep(0.002)
                continue
            self.read.set()
            try:
                os.write(fd, self.payload)
            finally:
                os.close(fd)
            return


BASE_KINDS = ("plain", "empty", "symlink", "dangling", "hardlink", "fifo", "directory")


def _plant_base(ep: Path, kind: str, host: Path) -> S.Planted:
    at = ep / LAYOUT.served_base
    at.parent.mkdir(parents=True, exist_ok=True)
    if kind in ("plain", "empty"):
        at.write_bytes(b'{"an": "earlier prime"}\n' if kind == "plain" else b"")
        return S.Planted("file", at)
    return S.plant_leaf(at, kind, host=host)


@pytest.mark.parametrize("kind", BASE_KINDS)
def test_r3_anything_at_the_base_is_already_primed_before_the_capture_is_read(tmp_path, host,
                                                                              kind):
    capture = mod("learning.branch.capture")
    ledger = mod("learning.branch.ledger")
    run_dir = _one_call_source(tmp_path)
    sidecar, payload = fifo_sidecar(run_dir)
    ep = bare_episode(tmp_path)
    planted = _plant_base(ep, kind, host)
    before = S.census(ep.parent)
    spy = S.OsSpy()
    io = S.RecordingIo(os_=spy)

    with CaptureRead(sidecar, payload) as watch, S.open_episode(ep, io=io) as episode:
        raised = S.raised_by(lambda: capture.prime_base(run_dir, episode), fifo=planted.fifo)
    assert isinstance(raised, ledger.LedgerError), f"a {kind} at the base: {raised!r}"
    assert "already holds a primed base" in str(raised), raised
    assert not watch.read.is_set(), "the capture was read before the already-primed check"
    opened = [o for o in spy.opens if PurePosixPath(o.path).name == LAYOUT.served_base.name]
    assert opened == [], f"the base was opened: {opened}"
    assert [c for c in io.calls if c.method == "write"] == [], "the held root was written"
    assert S.census(ep.parent) == before, f"priming over a {kind} changed the tree"

    planted.remove()
    io = S.RecordingIo()
    with CaptureRead(sidecar, payload) as watch, S.open_episode(ep, io=io) as episode:
        report = S.in_time(lambda: capture.prime_base(run_dir, episode), fifo=sidecar)
    assert watch.read.is_set(), "control: the capture read is not observable"
    assert report.primed == 1
    writes = [c for c in io.calls if c.method == "write"]
    assert [(c.name, c.kwargs.get("mode")) for c in writes] == [(LAYOUT.served_base, "create")]


def test_r3_zero_rows_are_refused_by_default_and_primed_empty_with_allow_empty(tmp_path):
    capture = mod("learning.branch.capture")
    ledger = mod("learning.branch.ledger")
    run_dir = _empty_source(tmp_path)
    ep = bare_episode(tmp_path)
    base = ep / LAYOUT.served_base

    io = S.RecordingIo()
    with S.open_episode(ep, io=io) as episode, pytest.raises(
            ledger.LedgerError, match="primed no base rows"):
        capture.prime_base(run_dir, episode)
    assert not os.path.lexists(base)
    assert [c for c in io.calls if c.method == "write"] == []

    io = S.RecordingIo()
    with S.open_episode(ep, io=io) as episode:
        report = capture.prime_base(run_dir, episode, allow_empty=True)
    assert report.primed == 0
    assert base.read_bytes() == b""
    assert stat.S_ISREG(os.lstat(base).st_mode)
    assert os.lstat(base).st_nlink == 1
    writes = [c for c in io.calls if c.method == "write"]
    assert [(c.name, c.kwargs.get("mode"), c.text) for c in writes] == [
        (LAYOUT.served_base, "create", "")], writes


def _launcher(tmp_path: Path) -> tuple[Any, Path, Any]:
    """`(cli, the source run dir, T's runs repository)` — the launcher's entry
    `cli.prepare_episode(runs, source, *, prime=)` (#1187 declared change 3, review-4 F37: the
    episode is claimed by `runs.create_episode()`, a fresh UUID under `<T>/episodes/`; the
    retired `episode_dir` resolver names nothing)."""
    cli = mod("learning.branch.cli")
    _base, src = T.runs_base(tmp_path)
    return cli, src, T.current_tenant().runs_repository()


def test_r3_the_launchers_default_primer_primes_an_empty_capture_once_and_warns(
        tmp_path, roots, caplog):
    """The launcher's default primer is `prime_base(..., allow_empty=True)`: a source whose
    capture yields no row gets an EMPTY base (a plain file), with a warning that every key
    reaches the live estate; there is no message-matched downgrade left to create it a second
    time (`_is_empty_capture` is removed). Through `prepare_episode(runs, source)` with no
    `prime=` (review-4 F37), the episode it claimed is under `<T>/episodes/`."""
    cli, src, runs = _launcher(tmp_path)
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    caplog.set_level(logging.WARNING)
    with cli.prepare_episode(runs, Run.at(src)) as view:
        ep = Path(view.episode.dir)
        assert ep.name == view.episode_id
    assert ep.parent == Path(T.current_tenant().episodes), (
        f"the launcher claimed {ep}, not an episode under <T>/episodes/")
    base = ep / LAYOUT.served_base
    assert base.read_bytes() == b""
    assert stat.S_ISREG(os.lstat(base).st_mode)
    assert os.lstat(base).st_nlink == 1
    # The warning's wording is the implementer's: any WARNING that speaks of the base, the
    # prime, the capture or its emptiness counts.
    assert S.warned(caplog, "base", "primed", "prime", "capture", "empty", "EMPTY", "rows"), (
        "an empty prime was not warned about")
    assert not hasattr(cli, "_is_empty_capture"), (
        "the message-matched downgrade `_is_empty_capture` is still there (R3: one primer)")


@pytest.mark.parametrize("lane", ["held", "rooted_write"])
def test_r4_a_durable_append_that_cannot_encode_its_text_leaves_no_descriptor_open(
        tmp_path, lane):
    root = tmp_path / "episodes" / EPISODE_ID
    root.mkdir(parents=True)
    rel = "rec.jsonl"
    leaf = root / rel
    leaf.write_text("prior\n", encoding="utf-8")

    def append(text: str, *, durable: bool = True) -> None:
        if lane == "held":
            with S.hold(root) as held:
                held.write(rel, text, mode="append", durable=durable)
        else:
            _io.rooted_write(root, rel, text, mode="append", durable=durable)

    try:
        raised = S.raised_by(lambda: append(UNENCODABLE))
        assert isinstance(raised, UnicodeError), f"an unencodable durable append: {raised!r}"
        assert S.open_fds_on(leaf) == [], "the durable append left the leaf's descriptor open"
        assert leaf.read_text(encoding="utf-8") == "prior\n"
        assert isinstance(S.raised_by(lambda: append(UNENCODABLE, durable=False)),
                          UnicodeError)
        assert S.open_fds_on(leaf) == []
        append("landed\n")
        assert leaf.read_text(encoding="utf-8") == "prior\nlanded\n"
    finally:
        for fd in S.open_fds_on(leaf):
            os.close(fd)


def test_r4_a_durable_append_into_a_missing_holding_folder_makes_nothing(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    spy = S.OsSpy()
    with S.hold(root, os_=spy) as held:
        before = S.census(root)
        raised = S.raised_by(lambda: held.write("fa/rec.jsonl", "row\n", mode="append",
                                                durable=True))
        assert isinstance(raised, FileNotFoundError), f"a durable append into fa/: {raised!r}"
        assert S.census(root) == before, "a durable append made a folder"
        assert spy.mkdirs == [], f"a durable append made folders: {spy.mkdirs}"
        assert spy.fsyncs == [], f"a refused durable append synced: {spy.fsyncs}"

        held.write("fa/rec.jsonl", "plain\n", mode="append")
        held.write("fa/rec.jsonl", "durable\n", mode="append", durable=True)
    assert (root / "fa" / "rec.jsonl").read_text(encoding="utf-8") == "plain\ndurable\n"


@pytest.mark.parametrize(("token", "minted"), [
    pytest.param("Control", False, id="dotless-not-case-stable"),
    pytest.param("E1133.b", False, id="head-not-case-stable"),
    pytest.param("e1133.B", False, id="label-not-case-stable"),
    pytest.param("control", False, id="dotless-case-stable"),
    pytest.param("e1133.b", False, id="a-world-token"),
    pytest.param(T.fixture_world_id("b"), True, id="world-uuid"),
])
def test_patch_the_minting_check_judges_the_whole_token(tmp_path, token, minted):
    from defender.episodes._episode_paths import EpisodePaths

    paths = EpisodePaths(tmp_path)
    if minted:
        assert paths.served_world(token).name == f"{token}.jsonl"
    else:
        with pytest.raises(ValueError, match="not a valid world id"):
            paths.served_world(token)


def test_patch_resume_with_no_held_episode_is_refused_never_an_ordinary_run(tmp_path):
    run = mod("run")
    _base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    ns = run.parse_args(["--tenant", T.SOURCE_TENANT, "--episode", ep.name, "--world", "b"])

    def settings() -> Path:
        raise AssertionError("the tenant's record was resolved for a manifest that names them")

    with pytest.raises(SystemExit):
        run._resume_target(ns, episode=None, tenant=settings)

    ordinary = run.parse_args([str(RunPaths(src).alert), "--tenant", T.SOURCE_TENANT])
    assert run._resume_target(ordinary, episode=None, tenant=settings) is None
    with S.open_episode(ep) as episode:
        world = run._resume_target(ns, episode=episode, tenant=settings)
    assert world is not None, "a held episode's --episode answered no world"
    assert world.label == "b", world

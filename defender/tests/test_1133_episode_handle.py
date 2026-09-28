"""#1133 — the `Episode` handle owns every write into an episode tree, and writes only through
the rooted core (O1, O2, D1, D7, N-g).

The handle this suite builds against (the names are gathered in `_spec1133`, which the
implementation must match):

* `defender._episode_handle.Episode(episode_dir, *, io=_io)`: `.dir`, `.create_dir()`;
* records (`.path` plus only the verbs their row grants): `family`, `family_stamp`, `review`,
  `samples`, `judge`, `timing`, `staged`, `learning_html`, `served_base`, `priming_lock`
  (properties); `served_world(token)`, `wire_log(name)` (methods); `world(label).draw(n)`,
  `world(label).run_dir_pointer`;
* folders (`.path`, `.ensure()`): `served`, `runs`, `worlds`, `world(label).dir`,
  `world(label).draws`;
* the tables `RECORD_VERBS` (address -> verbs) and `FOLDERS` (addresses), keyed as
  `_spec1133`'s docstring defines;
* the owner addition `_episode_paths.LAYOUT.wire_log(name)` (`wire_logs/<name>`).

What each section pins:

- The tables: the shipped `RECORD_VERBS` / `FOLDERS` hold every row of D1's table with exactly
  its verbs (this file's copy is `_spec1133.RECORD_VERBS`), so the matrices cannot shrink. Each
  record's `.path` is the episode dir joined with its `LAYOUT` name.
- Verb absence: a record answers only the verbs its row grants; every other verb is absent.
- D7 matrix 1 (O2), records x granted verbs x plant site: a symlink (live or dangling), a hard
  link, a FIFO or a directory at the name; a symlink (outside or inside the episode), a file
  or a FIFO at each holding folder below the episode dir. A write verb raises the core's
  refusal row (`_spec1133.ROWS`); a read answers `(None, reason)`; either way, promptly, and
  the whole temp tree is unchanged: the plant, a link's target, a hard link's other name, the
  folder a link points at. Paired positive control on the same address: the plant removed,
  the verb lands (and on a plain file already there, too).
- D7 matrix 2, folders x `ensure` x plant site: a link or a non-directory at the folder and at
  each folder above it below the episode dir; refused, tree unchanged (the link's target folder
  gains nothing); control: absent or already real, `ensure` leaves a real directory.
- D7 matrix 3 / N-g, `create_dir`: a link or a non-directory at the episode dir's own name is
  refused, and nothing appears in the link's target; every other access follows the episode
  dir's own spelling.
- D1 addressing through the `io=` seam: each verb crosses the seam as one `rooted_*` call on
  the episode dir and the record's `LAYOUT` name, carrying the payload and mode; write verbs
  first `rooted_mkdir` the holding folder; `append_durable` passes `durable=True`.
- D1 name checks: a non-case-stable label or token, a multi-component wire-log name and a bad
  draw index are `ValueError` before any I/O (the `io=` seam sees no call, the tree is
  unchanged).

Red before #1133: `defender._episode_handle` does not exist (every case fails importing it);
`LAYOUT.wire_log` does not exist.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender._episode_paths import LAYOUT
from defender.tests import _spec1077
from defender.tests import _spec1133 as S

EPISODE_ID = "ep-1133"


def payload(key: str, tag: str) -> str | bytes:
    """What a write verb is handed: text, or bytes for the rendered page (D1: `learning_html`
    writes bytes)."""
    text = f"{key} {tag}\n"
    return text.encode("utf-8") if key == "learning_html" else text


def as_bytes(p: str | bytes) -> bytes:
    return p if isinstance(p, bytes) else p.encode("utf-8")


class Tree:
    """An episodes root holding one episode dir, and a host folder outside the episode where a
    planted link points and a hard link's other name lives."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.episodes = tmp / "episodes"
        self.ep = self.episodes / EPISODE_ID
        self.ep.mkdir(parents=True)
        self.host = tmp / "host"
        self.host.mkdir()

    def episode(self, io: Any = _io) -> Any:
        return S.handle().Episode(self.ep, io=io)


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


def verb_call(rec: Any, verb: str, key: str, tag: str) -> Any:
    if verb == "read":
        return lambda: rec.read()
    if verb == "delete":
        return lambda: rec.delete()
    return lambda: getattr(rec, verb)(payload(key, tag))


# =======================================================================================
# The tables
# =======================================================================================

def test_d1_the_shipped_tables_hold_every_row_of_the_designs_table_with_exactly_its_verbs():
    """`RECORD_VERBS` holds each of D1's fourteen records with exactly the verbs its row grants,
    and `FOLDERS` each of D1's five folders. Extra rows are allowed (they join every matrix);
    a missing row or a changed verb set is not."""
    mod = S.handle()
    shipped = mod.RECORD_VERBS
    for key, verbs in S.RECORD_VERBS.items():
        assert key in shipped, f"the handle's RECORD_VERBS lost D1's row {key!r}"
        assert set(shipped[key]) == set(verbs), (
            f"{key}: the handle grants {sorted(shipped[key])}, D1 grants {sorted(verbs)}")
    for key, verbs in shipped.items():
        assert set(verbs) <= set(S.ALL_VERBS), f"{key}: unknown verb in {verbs}"
    assert set(S.FOLDERS) <= set(mod.FOLDERS), (
        f"the handle's FOLDERS {mod.FOLDERS} lost one of D1's {S.FOLDERS}")


@pytest.mark.parametrize("key", list(S.record_cases()))
def test_d1_each_record_is_addressed_by_its_layout_name_under_the_episode_dir(tree, key):
    """A record's `.path` is `episode_dir / LAYOUT.<name>` (no containment resolve, no second
    spelling), and asking for it creates nothing."""
    before = S.census(tree.tmp)
    rec = S.resolve(tree.episode(), key)
    want = S.expected_record_rel(key)
    if want is not None:
        assert Path(rec.path) == tree.ep / want, f"{key}: .path is {rec.path}"
    else:
        assert Path(rec.path).is_relative_to(tree.ep), f"{key}: .path {rec.path} is outside"
    assert S.census(tree.tmp) == before, f"{key}: asking for .path touched the tree"


@pytest.mark.parametrize("key", list(S.folder_cases()))
def test_d1_each_folder_is_addressed_by_its_layout_name_under_the_episode_dir(tree, key):
    before = S.census(tree.tmp)
    folder = S.resolve(tree.episode(), key)
    want = S.expected_folder_rel(key)
    if want is not None:
        assert Path(folder.path) == tree.ep / want, f"{key}: .path is {folder.path}"
    assert S.census(tree.tmp) == before, f"{key}: asking for .path touched the tree"


def test_d1_the_runs_folder_is_the_siblings_runs_base():
    """`episode.runs.path` is what the launcher hands siblings as their runs base: the same
    path `cli.sibling_runs_base` answers today."""
    from defender.learning.branch import cli

    ep = Path("/nonexistent-1133/episodes/ep-1133")
    assert Path(S.handle().Episode(ep).runs.path) == cli.sibling_runs_base(ep) == ep / "runs"


def test_d1_the_owner_spells_the_wire_log_name_under_wire_logs():
    """D1's one owner addition: `LAYOUT.wire_log(name)` is `wire_logs/<name>`, the directory
    the wire-log read deny keys on, and `name` is one component."""
    assert LAYOUT.wire_log(S.WIRE_NAME) == PurePosixPath("wire_logs") / S.WIRE_NAME
    for bad in ("a/b.jsonl", "..", ".", ""):
        with pytest.raises(ValueError, match=S.NAME_REFUSAL):
            LAYOUT.wire_log(bad)


# =======================================================================================
# Verb absence
# =======================================================================================

@pytest.mark.parametrize(("key", "granted"), list(S.record_cases().items()))
def test_d1_a_record_answers_only_the_verbs_its_row_grants(tree, key, granted):
    """As on `RecordHandle`: a verb the row does not grant is ABSENT (not a raising stub), and
    every granted verb is callable. So `samples` has no `read`, `priming_lock` no `write`,
    `served_base` no `write` (only the exclusive `create`)."""
    rec = S.resolve(tree.episode(), key)
    for verb in S.ALL_VERBS:
        if verb in granted:
            assert callable(getattr(rec, verb, None)), f"{key} lacks its granted verb {verb}"
        else:
            assert not hasattr(rec, verb), f"{key} answers {verb!r}, which its row does not grant"


@pytest.mark.parametrize("key", list(S.folder_cases()))
def test_d1_a_folder_answers_ensure_and_no_record_verb(tree, key):
    folder = S.resolve(tree.episode(), key)
    assert callable(getattr(folder, "ensure", None)), f"{key} has no ensure()"
    for verb in S.ALL_VERBS:
        assert not hasattr(folder, verb), f"folder {key} answers the record verb {verb!r}"


# =======================================================================================
# D7 matrix 1 — records x granted verbs x plant site
# =======================================================================================

def _record_matrix():
    for key, verbs in S.record_cases().items():
        rel = S.collection_rel(key)
        for verb in verbs:
            for kind in S.LEAF_PLANTS:
                yield pytest.param(key, verb, kind, None, id=f"{key}.{verb}-{kind}")
            for folder in S.holding_folders(rel) if rel is not None else ():
                for kind in S.FOLDER_PLANTS:
                    yield pytest.param(key, verb, kind, folder,
                                       id=f"{key}.{verb}-{kind}@{folder}")


def _assert_landed(path: Path, key: str, verb: str, tag: str, *, prior: bytes = b"") -> None:
    assert not path.is_symlink(), f"{key}.{verb}: a link stands at {path}"
    assert path.is_file(), f"{key}.{verb}: nothing plain at {path}"
    got = path.read_bytes()
    if verb in ("append", "append_durable"):
        assert got == prior + as_bytes(payload(key, tag)), f"{key}.{verb} did not append"
    else:
        assert got == as_bytes(payload(key, tag)), f"{key}.{verb} did not land whole"
    assert os.lstat(path).st_nlink == 1, f"{key}.{verb} left a file with two names"


def _positive_controls(tree: Tree, rec: Any, key: str, verb: str, path: Path) -> None:
    """The same verb on the same address: with nothing there, then with a plain file there."""
    if verb == "read":
        assert rec.read()[0] is None, f"control: {key}.read of nothing returned text"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{key} plain\n", encoding="utf-8")
        assert rec.read() == (f"{key} plain\n", None), f"control: {key}.read of a plain file"
        return
    if verb == "delete":
        assert rec.delete() is False, f"control: {key}.delete of nothing did not answer False"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("plain\n", encoding="utf-8")
        assert rec.delete() is True, f"control: {key}.delete of a plain file did not answer True"
        assert not os.path.lexists(path), f"control: {key}.delete left the plain file"
        return
    verb_call(rec, verb, key, "landed")()
    _assert_landed(path, key, verb, "landed")
    if verb == "create":
        before = path.read_bytes()
        with pytest.raises(FileExistsError) as taken:
            verb_call(rec, verb, key, "again")()
        assert not getattr(taken.value, "write_guarded_alias", False), (
            f"{key}.create over a plain file is the ordinary write-once collision, unmarked")
        assert path.read_bytes() == before, f"{key}.create over a plain file changed it"
        return
    prior = path.read_bytes()
    verb_call(rec, verb, key, "again")()
    _assert_landed(path, key, verb, "again", prior=prior)


@pytest.mark.parametrize(("key", "verb", "kind", "site"), list(_record_matrix()))
def test_o2_d7_a_record_verb_into_a_plant_is_refused_and_changes_nothing(
        tree, key, verb, kind, site):
    """O2: no handle write lands outside the episode dir or through a non-plain entry, and no
    handle read follows a link. A write verb (`write`, `create`, `append`, `append_durable`,
    `delete`) raises the core's refusal row for the plant; `read` answers `(None, reason)`.
    Neither blocks on a FIFO. The whole temp tree is unchanged: the plant is left in place,
    a link's target (live, or a dangling link's absent one) is untouched or still absent, a hard
    link's other name keeps its bytes and link count, and a linked folder's target gains
    nothing. Then, on the same address, the verb succeeds with nothing there and with a plain
    file there (`create` over a plain file is the unmarked `FileExistsError`)."""
    rec = S.resolve(tree.episode(), key)
    rel = S.rel_of(tree.ep, key, rec)
    path = tree.ep / rel
    planted = S.plant(tree.ep, rel, site, kind, host=tree.host)
    before = S.census(tree.tmp)

    if verb == "read":
        got = S.in_time(rec.read, fifo=planted.fifo)
        assert isinstance(got, tuple), f"{key}.read answered {got!r}, not (text, reason)"
        assert got[0] is None, (
            f"{key}.read of a {kind} plant{f' at {site}/' if site else ''} returned {got!r} — "
            "a read followed the plant")
        assert isinstance(got[1], str), f"{key}.read of a {kind} gave no reason"
        assert got[1], f"{key}.read of a {kind} gave an empty reason"
    else:
        raised = S.raised_by(verb_call(rec, verb, key, "refused"), fifo=planted.fifo)
        S.assert_refusal(raised, "symlink" if kind == "dangling" else kind,
                         where=f"{key}.{verb}{f' @{site}' if site else ''}")
    assert S.census(tree.tmp) == before, f"{key}.{verb} into a {kind} plant changed the tree"

    planted.remove()
    _positive_controls(tree, rec, key, verb, path)


# =======================================================================================
# D7 matrix 2 — folders x ensure x plant site
# =======================================================================================

def _folder_matrix():
    for key in S.folder_cases():
        rel = S.collection_rel(key, folder=True)
        for site in S.folder_and_parents(rel) if rel is not None else ():
            for kind in S.FOLDER_PLANTS:
                yield pytest.param(key, kind, site, id=f"{key}-{kind}@{site}")


@pytest.mark.parametrize(("key", "kind", "site"), list(_folder_matrix()))
def test_o2_d7_a_folders_ensure_through_a_plant_is_refused_and_changes_nothing(
        tree, key, kind, site):
    """`ensure()` makes the folder with `rooted_mkdir(episode_dir, rel)`: a symlink (to a
    folder outside the episode or inside it), a file or a FIFO at the folder itself or at any
    folder above it below the episode dir is refused in the core's row, and the tree is
    unchanged — in particular the link's target folder gains no subfolder. Control on the same
    address: the plant removed, `ensure` leaves a real directory there, and a second `ensure`
    over the real directory is a no-op."""
    folder = S.resolve(tree.episode(), key)
    rel = S.rel_of(tree.ep, key, folder, folder=True)
    planted = S.plant_folder(tree.ep, rel, site, kind, host=tree.host)
    before = S.census(tree.tmp)

    raised = S.raised_by(folder.ensure, fifo=planted.fifo)
    S.assert_refusal(raised, kind, where=f"{key}.ensure @{site}")
    assert S.census(tree.tmp) == before, f"{key}.ensure through a {kind} changed the tree"

    planted.remove()
    folder.ensure()
    target = tree.ep / rel
    assert stat.S_ISDIR(os.lstat(target).st_mode), f"control: {key}.ensure made no real folder"
    marker = target / "marker"
    marker.write_text("kept\n", encoding="utf-8")
    folder.ensure()
    assert marker.read_text(encoding="utf-8") == "kept\n", "a second ensure disturbed the folder"


# =======================================================================================
# D7 matrix 3 / N-g — the episode dir's own creation
# =======================================================================================

@pytest.mark.parametrize("kind", ["folder_link_outside", "folder_link_inside", "folder_file",
                                  "folder_fifo", "dangling_dir_link"])
def test_n_g_d7_create_dir_refuses_a_plant_at_the_episode_dirs_own_name(tmp_path, kind):
    """`create_dir()` judges the episode dir from its parent (`rooted_mkdir(dir.parent,
    dir.name)`), so a link at the episode dir's name (to a real folder outside the episodes
    root or beside the episode, or dangling) and a file or FIFO there are refused in the core's
    folder rows, left in place, and nothing is created in the link's target. Control: the plant
    removed, `create_dir` makes a real directory; over an existing real one it is a no-op; with
    the episodes root itself missing, it makes both (the root following its spelling)."""
    episodes = tmp_path / "episodes"
    episodes.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    ep = episodes / EPISODE_ID
    if kind == "dangling_dir_link":
        ep.symlink_to(host / "not-yet", target_is_directory=True)
        planted = S.Planted("folder_link_outside", ep)
        row = "folder_link_outside"
    else:
        planted = S.plant_folder(episodes, PurePosixPath(EPISODE_ID), PurePosixPath(EPISODE_ID),
                                 kind, host=host)
        row = kind
    before = S.census(tmp_path)

    raised = S.raised_by(S.handle().Episode(ep).create_dir, fifo=planted.fifo)
    S.assert_refusal(raised, row, where=f"create_dir over a {kind}")
    assert S.census(tmp_path) == before, f"create_dir over a {kind} changed the tree"

    planted.remove()
    S.handle().Episode(ep).create_dir()
    assert stat.S_ISDIR(os.lstat(ep).st_mode), "control: create_dir made no real directory"
    (ep / "family.yaml").write_text("kept\n", encoding="utf-8")
    S.handle().Episode(ep).create_dir()
    assert (ep / "family.yaml").read_text(encoding="utf-8") == "kept\n"

    fresh = tmp_path / "fresh-root" / EPISODE_ID
    S.handle().Episode(fresh).create_dir()
    assert fresh.is_dir()
    assert not fresh.is_symlink()


def test_n_g_every_other_access_follows_the_episode_dirs_own_spelling(tmp_path):
    """N-g: only the creation door judges the episode dir's name. A handle built over a symlink
    to a real episode dir (the operator's spelling) writes, reads and ensures THROUGH it, as
    `base=episode_dir` does today — while `create_dir()` on the same spelling is refused."""
    real = tmp_path / "real" / EPISODE_ID
    real.mkdir(parents=True)
    alias = tmp_path / "alias-ep"
    alias.symlink_to(real, target_is_directory=True)
    ep = S.handle().Episode(alias)

    ep.family.write("family: through the root's spelling\n")
    assert (real / "family.yaml").read_text(encoding="utf-8") == (
        "family: through the root's spelling\n")
    assert ep.family.read() == ("family: through the root's spelling\n", None)
    ep.served.ensure()
    assert (real / "served").is_dir()
    assert alias.is_symlink(), "the episode dir's own link was replaced"

    with pytest.raises(OSError, match=S.CORE_REFUSAL):
        ep.create_dir()


# =======================================================================================
# D1 — addressing through the io= seam
# =======================================================================================

_MODE_OF = {"write": "replace", "create": "create", "append": "append",
            "append_durable": "append"}


@pytest.mark.parametrize(("key", "verb"), [
    pytest.param(k, v, id=f"{k}.{v}") for k, vs in S.record_cases().items() for v in vs])
def test_d1_each_verb_crosses_the_io_seam_as_rooted_calls_on_the_episode_dir_and_layout_name(
        tree, key, verb):
    """D1: the handle calls `io.rooted_*(episode_dir, LAYOUT.<x>)` directly. A pass-through
    recorder on `io=` (never `monkeypatch.setattr`) sees every call the verb makes: each is a
    `rooted_*` op; the verb's own op names the episode dir as its trust root and the record's
    LAYOUT name relative to it, with the payload handed in and the mode D1 maps the verb to
    (`write` -> replace, `create` -> create, `append` / `append_durable` -> append, the latter
    with `durable=True`); a write verb first `rooted_mkdir`s its holding folder under the
    episode dir; `read` is `rooted_read` and `delete` is `rooted_unlink`."""
    rec_io = _spec1077.RecordingIo()
    rec = S.resolve(tree.episode(io=rec_io), key)
    rel = S.rel_of(tree.ep, key, rec)
    if verb in ("read", "delete"):
        (tree.ep / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree.ep / rel).write_text("plain\n", encoding="utf-8")
    mark = len(rec_io.invocations)

    verb_call(rec, verb, key, "seam")()

    calls = [(op, _spec1077.bound_arguments(op, a, kw))
             for op, a, kw in rec_io.invocations[mark:]]
    ops = [op for op, _ in calls]
    assert ops, f"{key}.{verb} made no io call at all"
    assert all(op.startswith("rooted_") for op in ops), (
        f"{key}.{verb} made a non-rooted io call: {ops}")
    op, args = calls[-1]
    want_op = {"read": "rooted_read", "delete": "rooted_unlink"}.get(verb, "rooted_write")
    assert op == want_op, f"{key}.{verb}'s own op is {op}, not {want_op}: {ops}"
    assert Path(args["root"]) == tree.ep, f"{key}.{verb} is rooted at {args['root']}"
    assert PurePosixPath(str(args["name"])) == rel, f"{key}.{verb} names {args['name']}"
    if want_op == "rooted_write":
        assert args["mode"] == _MODE_OF[verb], f"{key}.{verb} wrote in mode {args['mode']}"
        assert args["text"] == payload(key, "seam"), f"{key}.{verb} changed the payload"
        assert bool(args.get("durable", False)) is (verb == "append_durable"), (
            f"{key}.{verb}: durable={args.get('durable')!r}")
        mkdirs = [a for o, a in calls[:-1] if o == "rooted_mkdir"]
        assert mkdirs, f"{key}.{verb} did not make its holding folder first: {ops}"
        assert Path(mkdirs[-1]["root"]) == tree.ep
        assert PurePosixPath(str(mkdirs[-1]["folder_name"]) or ".") == rel.parent, (
            f"{key}.{verb} made {mkdirs[-1]['folder_name']}, not its holding folder "
            f"{rel.parent}")


@pytest.mark.parametrize("key", list(S.folder_cases()))
def test_d1_ensure_and_create_dir_cross_the_io_seam_as_one_rooted_mkdir(tree, key):
    """`ensure()` is `rooted_mkdir(episode_dir, LAYOUT.<folder>)`; `create_dir()` is
    `rooted_mkdir(episode_dir.parent, episode_dir.name)`."""
    rec_io = _spec1077.RecordingIo()
    ep = tree.episode(io=rec_io)
    folder = S.resolve(ep, key)
    mark = len(rec_io.invocations)
    folder.ensure()
    calls = [(op, _spec1077.bound_arguments(op, a, kw))
             for op, a, kw in rec_io.invocations[mark:]]
    assert [op for op, _ in calls] == ["rooted_mkdir"], calls
    assert Path(calls[0][1]["root"]) == tree.ep
    assert PurePosixPath(str(calls[0][1]["folder_name"])) == S.rel_of(tree.ep, key, folder,
                                                                       folder=True)

    mark = len(rec_io.invocations)
    ep.create_dir()
    calls = [(op, _spec1077.bound_arguments(op, a, kw))
             for op, a, kw in rec_io.invocations[mark:]]
    assert [op for op, _ in calls] == ["rooted_mkdir"], calls
    assert Path(calls[0][1]["root"]) == tree.episodes
    assert str(calls[0][1]["folder_name"]) == EPISODE_ID


# =======================================================================================
# D1 — name checks run before any I/O
# =======================================================================================

_BAD_NAMES = [
    pytest.param(lambda ep: ep.world("B").draw(0).write("x"), id="label-not-case-stable-draw"),
    pytest.param(lambda ep: ep.world("B").run_dir_pointer.write("x"), id="label-pointer"),
    pytest.param(lambda ep: ep.world("B").dir.ensure(), id="label-dir-ensure"),
    pytest.param(lambda ep: ep.world("B").draws.ensure(), id="label-draws-ensure"),
    pytest.param(lambda ep: ep.world("a/b").draw(0).write("x"), id="label-two-components"),
    pytest.param(lambda ep: ep.world("..").dir.ensure(), id="label-dotdot"),
    pytest.param(lambda ep: ep.served_world("e1133.B").append(""), id="token-not-case-stable"),
    pytest.param(lambda ep: ep.served_world("e1133/b").append(""), id="token-two-components"),
    pytest.param(lambda ep: ep.served_world("..").append(""), id="token-dotdot"),
    pytest.param(lambda ep: ep.wire_log("a/b.jsonl").write("x"), id="wire-log-two-components"),
    pytest.param(lambda ep: ep.wire_log("../escape.jsonl").write("x"), id="wire-log-climbs"),
    pytest.param(lambda ep: ep.wire_log("..").write("x"), id="wire-log-dotdot"),
    pytest.param(lambda ep: ep.world("b").draw(-1).write("x"), id="draw-negative"),
    pytest.param(lambda ep: ep.world("b").draw("0").write("x"), id="draw-string"),
    pytest.param(lambda ep: ep.world("b").draw(True).write("x"), id="draw-bool"),
    pytest.param(lambda ep: ep.world("b").draw(-1).delete(), id="draw-negative-delete"),
]


@pytest.mark.parametrize("call", _BAD_NAMES)
def test_d1_a_bad_component_is_a_value_error_before_any_io(tree, call):
    """D1: writers use the owner's MINTING checks (a case-stable label as `EpisodePaths.world`
    requires; a case-stable token label as `EpisodePaths.served_world` requires), `wire_log`
    takes one component, and a draw index is a non-negative int. Each is a `ValueError` raised
    before any I/O: the `io=` seam records no call at all and the tree is unchanged, whether the
    check fires at the accessor or at the verb.

    Control: the same calls with good components land (the matrix above)."""
    rec_io = _spec1077.RecordingIo()
    ep = tree.episode(io=rec_io)
    before = S.census(tree.tmp)
    with pytest.raises(ValueError, match=S.NAME_REFUSAL):
        call(ep)
    assert rec_io.invocations == [], f"io was touched before the name check: {rec_io.ops}"
    assert S.census(tree.tmp) == before

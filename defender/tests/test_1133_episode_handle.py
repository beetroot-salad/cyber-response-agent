"""#1133 — the `Episode` handle holds the episode dir open, and every verb works relative to it
(rev 2: O2, O3, O6, N-g, N-h, D1', D2', D7').

The handle this suite builds against (every name is gathered in `_spec1133`'s docstring):

* `defender._episode_handle.Episode.open(episode_dir, *, io=_io)` — one `io.hold(episode_dir)`;
  `Episode.create(episode_dir, *, io=_io)` — one `io.hold_new(episode_dir.parent,
  episode_dir.name)`. Each returns the `Episode`, which is its own context manager (`.dir`,
  `.view()`, `.close()`); `Episode(<path>)` is a `TypeError`.
* records (`.path` plus exactly the verbs their row grants, as CLASS attributes): `family`,
  `family_stamp`, `review`, `samples`, `judge`, `timing`, `staged`, `learning_html`,
  `served_base`, `priming_lock` (properties); `served_world(token)`, `wire_log(name)`
  (methods); `world(label).draw(n)`, `world(label).run_dir_pointer`;
* folders (`.path`, `.ensure()`): `served`, `runs`, `worlds`, `world(label).dir`,
  `world(label).draws`;
* `RECORD_VERBS` / `FOLDERS`, exactly the spec's tables; `LAYOUT.wire_log(name)`.

What each section pins:

- Tables and typed classes: the shipped tables equal the spec's, row for row; each record's
  CLASS grants exactly its row's verbs (so no class can grant a verb the matrices never
  exercise), and each instance answers exactly those.
- Doors: `open` / `create` return the `Episode` itself, a context manager that releases the
  held root on exit; there is no public bare constructor.
- The `io=` seam (a recorder offering ONLY `hold` / `hold_new`): opening is exactly one `hold`
  (creating exactly one `hold_new`), and every verb is exactly ONE call on the held root — the
  record's `LAYOUT` name, the payload, the mode (`write` -> replace, `create` -> create,
  `append` / `append_durable` -> append, the latter `durable=True`); `read` -> `Held.read`,
  `delete` -> `Held.unlink`, `ensure` -> `Held.mkdir`. No holding-folder `mkdir` before a
  write (the write's own walk makes it), no second `hold`.
- D7' matrix 1 (O2), records x granted verbs x plant site, on an OPENED episode: refused in the
  core's row, the whole tree unchanged, promptly; control on the same address.
- D7' matrix 2, folders x `ensure` x plant site.
- `Episode.create` (N-g, O6): a link, file or FIFO at the episode dir's own name is the core's
  folder refusal, left in place; a real directory is adopted; a missing parent is made.
  `Episode.open` follows the dir's own spelling.
- O6: `open` of a missing dir is `FileNotFoundError`, of a non-directory `NotADirectoryError`;
  a handle whose dir was removed refuses every write verb and every `ensure` with `OSError` and
  never recreates it; one whose dir was renamed writes into the moved folder.
- O3: `view()` is a `Bound` (readers and `close` only) reading through the same handle.
- Lifetime: after `close()`, a write raises `EBADF` and lands nowhere.
- The durable chain: `Episode.create` fsyncs the episodes root, and `staged.append_durable`
  fsyncs `staged.yaml` then the episode dir (the `os_` seam, reached through the `io=` seam).
- No iterable text: a record's write verb refuses anything but `str` / `bytes`.
- Name checks run before any held call.

Red before rev 2: `Episode.open` / `Episode.create` do not exist, the rev-1 bare constructor
does, rev-1 verbs are bound per instance, and `_io` has no `hold` / `hold_new`.
"""
from __future__ import annotations

import errno
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender._episode_paths import LAYOUT
from defender.tests import _spec1133 as S

EPISODE_ID = "ep-1133"


def payload(key: str, tag: str) -> str | bytes:
    """What a write verb is handed: text, or bytes for the rendered page (`learning_html`
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


@pytest.fixture
def tree(tmp_path: Path) -> Tree:
    return Tree(tmp_path)


@pytest.fixture
def opened(tree: Tree):
    """The tree's episode, opened with the real core; closed after the test."""
    episode = S.open_episode(tree.ep)
    try:
        yield episode
    finally:
        episode.close()


def verb_call(rec: Any, verb: str, key: str, tag: str) -> Any:
    if verb == "read":
        return lambda: rec.read()
    if verb == "delete":
        return lambda: rec.delete()
    return lambda: getattr(rec, verb)(payload(key, tag))


# =======================================================================================
# The tables and the typed record classes
# =======================================================================================

def test_d2_the_shipped_tables_are_the_designs_row_for_row():
    """Rev 2 keeps rev 1's records and folders unchanged in name and verbs: the shipped
    `RECORD_VERBS` equals the spec's copy key for key and verb set for verb set, and `FOLDERS`
    names exactly the spec's five folders. A record added or dropped is a change to this spec."""
    mod = S.handle()
    shipped = {k: set(v) for k, v in mod.RECORD_VERBS.items()}
    assert shipped == {k: set(v) for k, v in S.RECORD_VERBS.items()}, shipped
    assert sorted(mod.FOLDERS) == sorted(S.FOLDERS), mod.FOLDERS
    assert len(set(mod.FOLDERS)) == len(mod.FOLDERS)


@pytest.mark.parametrize(("key", "granted"), list(S.RECORD_VERBS.items()))
def test_d2_each_records_class_grants_exactly_its_rows_verbs(opened, key, granted):
    """Records are statically typed: one class per verb set, composed from verb mixins. The
    record's CLASS grants exactly the verbs of its `RECORD_VERBS` row — a verb bound per
    instance (rev 1's `setattr`) or inherited beyond the row is not — so no class grants a verb
    the matrices never exercise. The instance answers the same set."""
    rec = S.resolve(opened, key)
    by_class = {v for v in S.ALL_VERBS if callable(getattr(type(rec), v, None))}
    assert by_class == set(granted), (
        f"{key}: its class {type(rec).__name__} grants {sorted(by_class)}, the row grants "
        f"{sorted(granted)}")
    for verb in S.ALL_VERBS:
        assert hasattr(rec, verb) is (verb in granted), (
            f"{key}: the instance {'lacks' if verb in granted else 'answers'} {verb!r}")


def test_d2_records_sharing_a_verb_set_share_their_class_and_others_do_not(opened):
    """One class per verb set: two records with the same row are the same class, and records
    with different rows are different classes."""
    by_verbs: dict[frozenset[str], set[type]] = {}
    for key, verbs in S.RECORD_VERBS.items():
        by_verbs.setdefault(frozenset(verbs), set()).add(type(S.resolve(opened, key)))
    for verbs, classes in by_verbs.items():
        assert len(classes) == 1, f"the verb set {sorted(verbs)} is spread over {classes}"
    all_classes = [next(iter(c)) for c in by_verbs.values()]
    assert len(set(all_classes)) == len(all_classes), "two verb sets share one class"


@pytest.mark.parametrize("key", list(S.RECORD_VERBS))
def test_d2_each_record_is_addressed_by_its_layout_name_under_the_episode_dir(tree, key):
    """A record's `.path` is `episode_dir / LAYOUT.<name>`, and asking for it touches neither
    the tree nor the held root."""
    rec_io = S.RecordingIo()
    with S.open_episode(tree.ep, io=rec_io) as episode:
        before = S.census(tree.tmp)
        rec = S.resolve(episode, key)
        assert Path(rec.path) == tree.ep / S.expected_record_rel(key), f"{key}: {rec.path}"
        assert S.census(tree.tmp) == before, f"{key}: asking for .path touched the tree"
        assert rec_io.calls == [], f"{key}: asking for .path called the held root"


@pytest.mark.parametrize("key", list(S.FOLDERS))
def test_d2_each_folder_is_addressed_by_its_layout_name_and_answers_no_record_verb(tree, key):
    with S.open_episode(tree.ep) as episode:
        folder = S.resolve(episode, key)
        assert Path(folder.path) == tree.ep / S.expected_folder_rel(key)
        assert callable(getattr(folder, "ensure", None)), f"{key} has no ensure()"
        for verb in S.ALL_VERBS:
            assert not hasattr(folder, verb), f"folder {key} answers the record verb {verb!r}"


def test_d2_the_runs_folder_is_the_siblings_runs_base(tree):
    """`episode.runs.path` is what the launcher hands siblings as their runs base: the same
    path `cli.sibling_runs_base` answers."""
    cli = S.mod("learning.branch.cli")
    with S.open_episode(tree.ep) as episode:
        assert Path(episode.runs.path) == cli.sibling_runs_base(tree.ep) == tree.ep / "runs"


def test_d2_the_owner_spells_the_wire_log_name_under_wire_logs():
    """`LAYOUT.wire_log(name)` is `wire_logs/<name>`, and `name` is one component."""
    assert LAYOUT.wire_log(S.WIRE_NAME) == PurePosixPath("wire_logs") / S.WIRE_NAME
    for bad in ("a/b.jsonl", "..", ".", ""):
        with pytest.raises(ValueError, match=S.NAME_REFUSAL):
            LAYOUT.wire_log(bad)


# =======================================================================================
# The doors: open / create; no bare constructor
# =======================================================================================

@pytest.mark.parametrize("door", ["open", "create"])
def test_d2_open_and_create_return_the_episode_which_is_its_own_context_manager(tree, door):
    """`Episode.open` / `Episode.create` return an `Episode`; `with` binds that same object,
    holds one descriptor on the episode dir while inside, and releases it on exit. `.dir` is
    the episode dir, for messages and argv."""
    cls = S.Episode()
    episode = getattr(cls, door)(tree.ep)
    assert isinstance(episode, cls), f"Episode.{door} answered {type(episode).__name__}"
    with episode as same:
        assert same is episode, f"`with Episode.{door}(...)` bound a different object"
        assert Path(same.dir) == tree.ep
        assert len(S.open_fds_on(tree.ep)) == 1, "the episode is not held open exactly once"
    assert S.open_fds_on(tree.ep) == [], "leaving the `with` did not release the episode dir"


@pytest.mark.parametrize("call", [
    pytest.param(lambda cls, ep: cls(ep), id="positional"),
    pytest.param(lambda cls, ep: cls(ep, io=_io), id="rev1-io-keyword"),
])
def test_d2_there_is_no_public_bare_constructor(tree, call):
    """An `Episode` is only had from a door. Rev 1's `Episode(episode_dir, io=)` — a remembered
    path, re-opened by every verb — is gone: calling the class with a path is a `TypeError`, and
    it touches nothing."""
    before = S.census(tree.tmp)
    with pytest.raises(TypeError):
        call(S.Episode(), tree.ep)
    assert S.census(tree.tmp) == before


def test_d2_open_is_one_hold_and_create_one_hold_new_through_the_io_seam(tree):
    """Through the `io=` seam (a recorder that offers ONLY `hold` and `hold_new`, so a handle
    reaching for `rooted_*` or `bind` fails): `Episode.open(dir)` is exactly one
    `io.hold(dir)`, `Episode.create(dir)` exactly one `io.hold_new(dir.parent, dir.name)`, and
    neither calls the held root."""
    rec_io = S.RecordingIo()
    with S.open_episode(tree.ep, io=rec_io):
        assert rec_io.opened == [("hold", (tree.ep,))], rec_io.opened
    assert [c.method for c in rec_io.calls] == ["close"], rec_io.calls

    fresh = tree.episodes / "ep-fresh"
    rec_io = S.RecordingIo()
    with S.create_episode(fresh, io=rec_io):
        assert rec_io.opened == [("hold_new", (tree.episodes, "ep-fresh"))], rec_io.opened
    assert [c.method for c in rec_io.calls] == ["close"], rec_io.calls
    assert fresh.is_dir()


# =======================================================================================
# Each verb is ONE call on the held root
# =======================================================================================

@pytest.mark.parametrize(("key", "verb"), [
    pytest.param(k, v, id=f"{k}.{v}") for k, vs in S.RECORD_VERBS.items() for v in vs])
def test_d2_each_verb_is_one_call_on_the_held_root_with_its_name_payload_and_mode(
        tree, key, verb):
    """D2': each write verb is one `held.write(LAYOUT name, payload, mode=..., durable=...)`
    whose own walk makes the holding folders (no `mkdir` first); `read` is one `held.read(name)`
    answering what the held root answered; `delete` one `held.unlink(name)`. No second `hold`,
    and the episode is not closed by a verb."""
    rec_io = S.RecordingIo()
    rel = S.expected_record_rel(key)
    if verb in ("read", "delete"):
        (tree.ep / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree.ep / rel).write_text("plain\n", encoding="utf-8")
    with S.open_episode(tree.ep, io=rec_io) as episode:
        rec = S.resolve(episode, key)
        mark = len(rec_io.calls)
        got = verb_call(rec, verb, key, "seam")()
        calls = rec_io.calls[mark:]
        assert len(calls) == 1, f"{key}.{verb} made {len(calls)} held calls: {calls}"
        [call] = calls
        assert call.name == rel, f"{key}.{verb} named {call.name}, not {rel}"
        if verb == "read":
            assert call.method == "read", calls
            assert got == ("plain\n", None), f"{key}.read answered {got!r}"
        elif verb == "delete":
            assert call.method == "unlink", calls
            assert got is True
        else:
            assert call.method == "write", calls
            assert call.text == payload(key, "seam"), f"{key}.{verb} changed the payload"
            assert call.kwargs.get("mode") == S.WRITE_MODE[verb], (
                f"{key}.{verb} wrote in mode {call.kwargs.get('mode')!r}")
            assert bool(call.kwargs.get("durable", False)) is (verb == "append_durable"), (
                f"{key}.{verb}: durable={call.kwargs.get('durable')!r}")
        assert rec_io.opened == [("hold", (tree.ep,))], "a verb re-opened the episode"


@pytest.mark.parametrize("key", list(S.FOLDERS))
def test_d2_ensure_is_one_mkdir_on_the_held_root(tree, key):
    rec_io = S.RecordingIo()
    with S.open_episode(tree.ep, io=rec_io) as episode:
        folder = S.resolve(episode, key)
        mark = len(rec_io.calls)
        folder.ensure()
        calls = rec_io.calls[mark:]
    assert [c.method for c in calls] == ["mkdir"], calls
    assert calls[0].name == S.expected_folder_rel(key)
    assert stat.S_ISDIR(os.lstat(tree.ep / S.expected_folder_rel(key)).st_mode)


# =======================================================================================
# D7' matrix 1 — records x granted verbs x plant site, on an opened episode
# =======================================================================================

def _record_matrix():
    for key, verbs in S.RECORD_VERBS.items():
        rel = S.expected_record_rel(key)
        for verb in verbs:
            for kind in S.LEAF_PLANTS:
                yield pytest.param(key, verb, kind, None, id=f"{key}.{verb}-{kind}")
            for folder in S.holding_folders(rel):
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


def _positive_controls(rec: Any, key: str, verb: str, path: Path) -> None:
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
        tree, opened, key, verb, kind, site):
    """O2: no handle write lands outside the episode dir or through a non-plain entry, and no
    handle read follows a link. A write verb raises the core's refusal row for the plant;
    `read` answers `(None, reason)`; neither blocks on a FIFO. The whole temp tree is unchanged.
    Then, on the same address, the verb succeeds with nothing there and with a plain file there
    (`create` over a plain file is the unmarked `FileExistsError`)."""
    rec = S.resolve(opened, key)
    rel = S.expected_record_rel(key)
    path = tree.ep / rel
    planted = S.plant(tree.ep, rel, site, kind, host=tree.host)
    before = S.census(tree.tmp)

    if verb == "read":
        got = S.in_time(rec.read, fifo=planted.fifo)
        assert isinstance(got, tuple), f"{key}.read answered {got!r}, not (text, reason)"
        assert got[0] is None, f"{key}.read of a {kind} plant returned {got!r}"
        assert isinstance(got[1], str), f"{key}.read of a {kind} gave no reason"
        assert got[1], f"{key}.read of a {kind} gave an empty reason"
    else:
        raised = S.raised_by(verb_call(rec, verb, key, "refused"), fifo=planted.fifo)
        S.assert_refusal(raised, "symlink" if kind == "dangling" else kind,
                         where=f"{key}.{verb}{f' @{site}' if site else ''}")
    assert S.census(tree.tmp) == before, f"{key}.{verb} into a {kind} plant changed the tree"

    planted.remove()
    _positive_controls(rec, key, verb, path)


# =======================================================================================
# D7' matrix 2 — folders x ensure x plant site
# =======================================================================================

def _folder_matrix():
    for key in S.FOLDERS:
        for site in S.folder_and_parents(S.expected_folder_rel(key)):
            for kind in S.FOLDER_PLANTS:
                yield pytest.param(key, kind, site, id=f"{key}-{kind}@{site}")


@pytest.mark.parametrize(("key", "kind", "site"), list(_folder_matrix()))
def test_o2_d7_a_folders_ensure_through_a_plant_is_refused_and_changes_nothing(
        tree, opened, key, kind, site):
    """`ensure()` is `held.mkdir(rel)`: a link (outside or inside), a file or a FIFO at the
    folder or at any folder above it below the episode dir is refused in the core's row and the
    tree is unchanged. Control: the plant removed, `ensure` leaves a real directory, and a
    second `ensure` over it is a no-op."""
    folder = S.resolve(opened, key)
    rel = S.expected_folder_rel(key)
    planted = S.plant_folder(tree.ep, rel, site, kind, host=tree.host)
    before = S.census(tree.tmp)

    S.assert_refusal(S.raised_by(folder.ensure, fifo=planted.fifo), kind,
                     where=f"{key}.ensure @{site}")
    assert S.census(tree.tmp) == before, f"{key}.ensure through a {kind} changed the tree"

    planted.remove()
    folder.ensure()
    target = tree.ep / rel
    assert stat.S_ISDIR(os.lstat(target).st_mode), f"control: {key}.ensure made no real folder"
    (target / "marker").write_text("kept\n", encoding="utf-8")
    folder.ensure()
    assert (target / "marker").read_text(encoding="utf-8") == "kept\n"


# =======================================================================================
# Episode.create (N-g, O6) and Episode.open's spelling
# =======================================================================================

@pytest.mark.parametrize("kind", ["folder_link_outside", "folder_link_inside", "folder_file",
                                  "folder_fifo", "dangling_dir_link"])
def test_n_g_create_refuses_a_plant_at_the_episode_dirs_own_name(tmp_path, kind):
    """`Episode.create(dir)` judges `dir` from its parent (`hold_new`): a link at its name (to a
    real folder outside the episodes root or beside the episode, or dangling), a file or a FIFO
    is the core's folder refusal, left in place, and nothing is created where a link points.
    Control on the same address: the plant removed, `create` makes a real directory and holds
    it; over an existing real directory it adopts it (its records kept); with the episodes root
    itself missing, it makes both."""
    episodes = tmp_path / "episodes"
    episodes.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    ep = episodes / EPISODE_ID
    if kind == "dangling_dir_link":
        ep.symlink_to(host / "not-yet", target_is_directory=True)
        planted, row = S.Planted("folder_link_outside", ep), "folder_link_outside"
    else:
        planted = S.plant_folder(episodes, PurePosixPath(EPISODE_ID), PurePosixPath(EPISODE_ID),
                                 kind, host=host)
        row = kind
    before = S.census(tmp_path)

    raised = S.raised_by(lambda: S.create_episode(ep).close(), fifo=planted.fifo)
    S.assert_refusal(raised, row, where=f"Episode.create over a {kind}")
    assert S.census(tmp_path) == before, f"Episode.create over a {kind} changed the tree"

    planted.remove()
    with S.create_episode(ep) as episode:
        episode.family.write("family: made\n")
    assert stat.S_ISDIR(os.lstat(ep).st_mode)
    with S.create_episode(ep) as episode:
        assert episode.family.read() == ("family: made\n", None), "a real dir was not adopted"

    fresh = tmp_path / "fresh-root" / EPISODE_ID
    with S.create_episode(fresh) as episode:
        episode.family.write("family: fresh\n")
    assert (fresh / "family.yaml").read_text(encoding="utf-8") == "family: fresh\n"
    assert not fresh.is_symlink()


def test_n_g_open_follows_the_episode_dirs_own_spelling_and_create_does_not(tmp_path):
    """N-g: only the creation door judges the episode dir's name. A handle opened over a
    symlink to a real episode dir (the operator's spelling) writes, reads and ensures THROUGH
    it — while `Episode.create` on the same spelling is refused."""
    real = tmp_path / "real" / EPISODE_ID
    real.mkdir(parents=True)
    alias = tmp_path / "alias-ep"
    alias.symlink_to(real, target_is_directory=True)
    with S.open_episode(alias) as episode:
        episode.family.write("family: through the root's spelling\n")
        assert episode.family.read() == ("family: through the root's spelling\n", None)
        episode.served.ensure()
    assert (real / "family.yaml").read_text(encoding="utf-8") == (
        "family: through the root's spelling\n")
    assert (real / "served").is_dir()
    assert alias.is_symlink(), "the episode dir's own link was replaced"

    with pytest.raises(OSError, match=S.CORE_REFUSAL):
        S.create_episode(alias)


# =======================================================================================
# O6 — a handle verb never makes the episode dir
# =======================================================================================

@pytest.mark.parametrize(("kind", "exc"), [
    ("missing", FileNotFoundError), ("missing-parent", FileNotFoundError),
    ("dangling-link", FileNotFoundError), ("file", NotADirectoryError),
    ("fifo", NotADirectoryError)])
def test_o6_open_refuses_a_missing_dir_or_a_non_directory_and_makes_nothing(
        tmp_path, kind, exc):
    """`Episode.open(dir)` on a missing dir (or a missing episodes root, or a link to nothing)
    is `FileNotFoundError`; on a file or a FIFO it is `NotADirectoryError`, without blocking.
    Nothing is created. Control: a real directory at the same spelling opens."""
    ep = tmp_path / "episodes" / EPISODE_ID
    fifo = None
    if kind != "missing-parent":
        ep.parent.mkdir()
    if kind == "dangling-link":
        ep.symlink_to(tmp_path / "nowhere", target_is_directory=True)
    elif kind == "file":
        ep.write_bytes(S.HOST_BYTES)
    elif kind == "fifo":
        os.mkfifo(ep)
        fifo = ep
    before = S.census(tmp_path)

    raised = S.raised_by(lambda: S.open_episode(ep).close(), fifo=fifo)

    assert isinstance(raised, exc), f"Episode.open over a {kind}: {raised!r}"
    assert S.census(tmp_path) == before, f"Episode.open over a {kind} created something"
    if os.path.lexists(ep):
        ep.unlink()
    ep.mkdir(parents=True, exist_ok=True)
    with S.open_episode(ep) as episode:
        episode.family.write("family: control\n")


def _write_verbs():
    for key, verbs in S.RECORD_VERBS.items():
        for verb in verbs:
            if verb in S.WRITE_MODE:
                yield pytest.param(key, verb, id=f"{key}.{verb}")


@pytest.mark.parametrize(("key", "verb"), list(_write_verbs()))
def test_o6_a_handle_whose_dir_was_removed_refuses_every_write_verb_and_never_recreates_it(
        tree, key, verb):
    """C14's fix: a held episode whose dir was removed refuses each write verb with `OSError`,
    and the episode dir's name stays absent (rev 1's `rooted_mkdir` made it again). Control:
    the same verb on a present episode lands."""
    episode = S.open_episode(tree.ep)
    try:
        rec = S.resolve(episode, key)
        tree.ep.rmdir()
        raised = S.raised_by(verb_call(rec, verb, key, "removed"))
        assert isinstance(raised, OSError), f"{key}.{verb} on a removed episode: {raised!r}"
        assert not os.path.lexists(tree.ep), f"{key}.{verb} recreated the removed episode dir"
    finally:
        episode.close()
    tree.ep.mkdir()
    with S.open_episode(tree.ep) as episode:
        verb_call(S.resolve(episode, key), verb, key, "control")()


@pytest.mark.parametrize("key", list(S.FOLDERS))
def test_o6_a_handle_whose_dir_was_removed_refuses_every_ensure(tree, key):
    episode = S.open_episode(tree.ep)
    try:
        folder = S.resolve(episode, key)
        tree.ep.rmdir()
        raised = S.raised_by(folder.ensure)
        assert isinstance(raised, OSError), f"{key}.ensure on a removed episode: {raised!r}"
        assert not os.path.lexists(tree.ep), f"{key}.ensure recreated the removed episode dir"
    finally:
        episode.close()


@pytest.mark.parametrize(("key", "verb"), list(_write_verbs()))
def test_o6_a_handle_whose_dir_was_renamed_writes_into_the_moved_folder(tree, key, verb):
    """The episode is held, not remembered: after its dir is renamed, a write verb lands in the
    moved folder at the record's name, and nothing appears at the old spelling."""
    moved = tree.episodes / "moved"
    with S.open_episode(tree.ep) as episode:
        rec = S.resolve(episode, key)
        tree.ep.rename(moved)
        verb_call(rec, verb, key, "moved")()
    assert not os.path.lexists(tree.ep), f"{key}.{verb} wrote at the old spelling"
    assert (moved / S.expected_record_rel(key)).read_bytes() == as_bytes(payload(key, "moved"))


# =======================================================================================
# O3 — the view
# =======================================================================================

def test_o3_the_view_is_a_bound_with_the_readers_surface_reading_through_the_same_handle(tree):
    """`episode.view()` is a `Bound` whose public surface is exactly `read`, `read_jsonl`,
    `entries`, `under`, `close` — write-free by type. It reads through the episode's own held
    handle: after the episode dir is renamed it still reads the record the episode just wrote.
    Its `close()` releases nothing (the episode still writes)."""
    moved = tree.episodes / "moved"
    with S.open_episode(tree.ep) as episode:
        view = episode.view()
        assert isinstance(view, _io.Bound), f"view() is {type(view).__name__}"
        public = {n for n in dir(view) if not n.startswith("_")}
        assert public == {"read", "read_jsonl", "entries", "under", "close"}, sorted(public)
        tree.ep.rename(moved)
        episode.review.write("review: after the rename\n")
        assert view.read(LAYOUT.review).text == "review: after the rename\n"
        view.close()
        episode.samples.write("samples: still held\n")
    assert (moved / LAYOUT.samples).read_text(encoding="utf-8") == "samples: still held\n"


# =======================================================================================
# Lifetime, the durable chain, text types, name checks
# =======================================================================================

def test_d1_a_write_after_close_raises_ebadf_and_lands_nowhere(tree):
    """Once the episode is closed its records do not reopen it: a write raises
    `OSError(EBADF)` and nothing is written anywhere."""
    episode = S.open_episode(tree.ep)
    family = episode.family
    episode.close()
    before = S.census(tree.tmp)
    closed = S.raised_by(lambda: family.write("family: after close\n"))
    assert isinstance(closed, OSError), f"a write after close raised {closed!r}"
    assert closed.errno == errno.EBADF, closed
    assert S.census(tree.tmp) == before


def test_d1_the_staging_records_durable_chain_is_leaf_then_episode_dir_then_episodes_root(tree):
    """`staged.yaml`'s whole chain is durable when `append_durable` returns: `Episode.create`
    fsyncs the episodes root (the episode dir's own entry), and the durable append fsyncs the
    leaf (every byte on it) and then the episode dir holding it, on a directory handle that is
    not `O_PATH`. Observed through the `os_` seam, reached through the `io=` seam."""
    fresh = tree.episodes / "ep-durable"
    staged = fresh / LAYOUT.staged
    spy = S.OsSpy(watch=staged)
    rec_io = S.RecordingIo(os_=spy)
    with S.create_episode(fresh, io=rec_io) as episode:
        at_create = list(spy.fsyncs)
        assert any(s.ino == S.inode(tree.episodes) and s.is_dir and not s.getfl & S.O_PATH
                   for s in at_create), (
            f"Episode.create did not fsync the episodes root on a directory handle: {at_create}")
        episode.staged.create("# header\n")
        mark = len(spy.fsyncs)
        episode.staged.append_durable("- name: wv-x\n")
        syncs = spy.fsyncs[mark:]
    leaf = [i for i, s in enumerate(syncs) if s.ino == S.inode(staged)]
    folder = [i for i, s in enumerate(syncs) if s.ino == S.inode(fresh)]
    assert leaf, f"staged.yaml was not fsynced: {syncs}"
    assert syncs[leaf[0]].watched_bytes == b"# header\n- name: wv-x\n"
    assert folder, "the episode dir holding staged.yaml was not fsynced"
    assert folder[-1] > leaf[0], "the episode dir was fsynced before the leaf"
    assert not syncs[folder[-1]].getfl & S.O_PATH


@pytest.mark.parametrize(("key", "verb"), list(_write_verbs()))
def test_d1_a_records_write_verb_takes_str_or_bytes_only(tree, opened, key, verb):
    """No iterable text: a list or a generator handed to a write verb is a `TypeError` before
    anything is written or made."""
    rec = S.resolve(opened, key)
    for value in (["a line\n"], (line for line in ["a line\n"])):
        before = S.census(tree.tmp)
        with pytest.raises(TypeError):
            getattr(rec, verb)(value)
        assert S.census(tree.tmp) == before, f"{key}.{verb} of an iterable made something"


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
def test_d1_a_bad_component_is_a_value_error_before_any_held_call(tree, call):
    """Writers use the owner's MINTING checks (a case-stable label; a case-stable token label),
    `wire_log` takes one component, and a draw index is a non-negative int. Each is a
    `ValueError` raised before the held root is called and with the tree unchanged, whether the
    check fires at the accessor or at the verb. Control: the matrices above."""
    rec_io = S.RecordingIo()
    with S.open_episode(tree.ep, io=rec_io) as episode:
        before = S.census(tree.tmp)
        with pytest.raises(ValueError, match=S.NAME_REFUSAL):
            call(episode)
        assert rec_io.calls == [], f"the held root was called before the name check: {rec_io.calls}"
        assert S.census(tree.tmp) == before

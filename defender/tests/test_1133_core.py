"""#1133 D1' — the rooted core in `defender/_io.py`: the held root (`hold`, `hold_new`, `Held`),
and the rev-1 durable append `rooted_write` keeps for `Run`. (Rev 1's `rooted_unlink` had no
caller once the handle's `delete` went through `Held.unlink`; it was removed, and the `Held`
matrix below pins the same unlink semantics.)

The held root, pinned here on the core itself (the `Episode` handle's matrices are in
`test_1133_episode_handle.py`):

* `hold(root)` opens the root following its spelling; a missing root is `FileNotFoundError`,
  a non-directory `NotADirectoryError`; nothing is ever made.
* `hold_new(parent, name)` makes a missing parent (following its spelling), then makes or adopts
  `name` off the parent's handle WITHOUT following it (a link, file or FIFO there is the core's
  folder refusal, left in place), holds the descriptor it made (a later rename of the name moves
  the held folder with it), and fsyncs the parent on an `O_RDONLY|O_DIRECTORY` handle — whether
  it made the directory or adopted one, the handle opened relative to the parent's descriptor
  (the parent is resolved by path once), and a failed sync failing the call.
* `Held.write` / `mkdir` / `unlink` against every plant: the core's refusal row (rev 3: a plant
  AT the name is `_io.NotPlainEntry`, one at a folder on the way is not), the tree unchanged,
  and a positive control on the same address. Rev 3 (R1) removes `Held.read`: reads are the
  view's, and the view's plant matrix and close race are in `test_1133_rev3.py`.
* One walk per write: during a verb every open is relative to a held descriptor (the root is
  never re-resolved by path) and each holding folder is opened once, made in the same walk.
* Durable append: the leaf is fsynced with every byte on it, then its holding folder on a
  directory handle opened `O_RDONLY|O_DIRECTORY` (an `O_PATH` handle cannot be fsynced). Every
  open is relative to a held descriptor, so after a rename the MOVED folder is the one synced;
  a failed folder sync fails the append. Rev 3 (R4): a durable append walks WITHOUT making a
  folder, so every durable row here writes into holding folders that already exist, and the
  one-walk row for a missing folder expects `FileNotFoundError`.
* No iterable `text`: anything but `str` / `bytes` is a `TypeError` before any I/O.
* The view: a `Bound` over the same handle, the readers' surface only, owning nothing.
* Lifetime (dup-per-verb): a verb in flight when `close()` lands keeps working off its own
  descriptor, even when the root's old number has been reused for another folder; a close
  landing just as a verb takes its dup cannot free the number under it (the dup and the close
  share one lock); a verb after `close()` raises `EBADF` and touches nothing.
* N-h: every descriptor is `O_CLOEXEC`; a child spawned while a root is held does not inherit it.
* O6: a held root that was removed refuses every write and is never recreated; one that was
  renamed is written in its new place.

Faults are real (plants, renames, removals, a reused descriptor number) or come through the
core's own `os_` seam; nothing is monkeypatched.

Red before rev 3 (on the rev-2 tree): every leaf-plant row (no `_io.NotPlainEntry`) and the
durable one-walk row over missing folders (rev 2's durable walk makes them). The `rooted_*`
tests and the folder-plant rows hold today and must keep holding.
"""
from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.tests import _spec1133 as S

DEEP = PurePosixPath("a/b/rec.jsonl")
PRIOR = "prior row\n"
ROW = '{"row": "durable"}\n'
#: The held-root suite's record: two holding folders below the root.
REC = "fa/fb/rec.jsonl"
REC_REL = PurePosixPath(REC)
WRITE_VERBS = ("create", "replace", "append", "append_durable")


class FsyncSpy(S.PassThroughOs):
    """The real `os`, handed in as `os_`. Each `fsync(fd)` is recorded with what the descriptor
    IS at that moment (its inode) and what the leaf holds on disk then, read by path from
    outside the call."""

    def __init__(self, leaf: Path) -> None:
        self.leaf = leaf
        self.fsyncs: list[dict[str, Any]] = []

    def fsync(self, fd: int) -> None:
        st = os.fstat(fd)
        leaf = os.lstat(self.leaf) if os.path.lexists(self.leaf) else None
        is_leaf = leaf is not None and (st.st_dev, st.st_ino) == (leaf.st_dev, leaf.st_ino)
        self.fsyncs.append({
            "fd": fd, "is_leaf": is_leaf,
            "on_disk": self.leaf.read_bytes() if is_leaf else None,
        })
        os.fsync(fd)


@pytest.fixture
def scratch(tmp_path: Path) -> tuple[Path, Path, Path]:
    """(root, the record at DEEP under it, a host folder outside it)."""
    root = tmp_path / "root"
    (root / DEEP.parent).mkdir(parents=True)
    host = tmp_path / "host"
    host.mkdir()
    return root, root / DEEP, host


@pytest.fixture
def tree(tmp_path: Path) -> tuple[Path, Path]:
    """(an empty root to hold, a host folder outside it)."""
    root = tmp_path / "root"
    root.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    return root, host


def _payload(verb: str, tag: str) -> str:
    return f"{verb} {tag}\n"


# =======================================================================================
# rooted_* — the rev-1 additions, kept for `Run` ("rooted_* keep their signatures and
# behaviour")
# =======================================================================================

@pytest.mark.parametrize("prior", ["absent", "plain"])
def test_d2_a_durable_append_fsyncs_the_leaf_after_its_bytes_are_flushed_then_closes_it(
        scratch, prior):
    """`rooted_write(..., mode="append", durable=True)` fsyncs the LEAF's own descriptor, and
    at that moment the leaf already holds every byte of this append; afterwards no descriptor of
    this process is open on the record. Control, same address: a plain append makes no fsync."""
    root, leaf, _host = scratch
    if prior == "plain":
        leaf.write_text(PRIOR, encoding="utf-8")
    before = PRIOR if prior == "plain" else ""
    spy = FsyncSpy(leaf)

    _io.rooted_write(root, DEEP, ROW, mode="append", durable=True, os_=spy)

    assert leaf.read_text(encoding="utf-8") == before + ROW, "the durable append did not land"
    synced = [f for f in spy.fsyncs if f["is_leaf"]]
    assert synced, f"no fsync reached the record's own descriptor: {spy.fsyncs}"
    assert synced[-1]["on_disk"] == (before + ROW).encode(), (
        "the leaf was fsynced before its bytes were flushed to it")
    assert S.open_fds_on(leaf) == [], "the durable append left the record's descriptor open"

    control = FsyncSpy(leaf)
    _io.rooted_write(root, DEEP, ROW, mode="append", os_=control)
    assert control.fsyncs == [], "a plain append fsynced; the durable flag is not what syncs"
    assert leaf.read_text(encoding="utf-8") == before + ROW + ROW


@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "fifo", "directory"])
def test_d2_a_durable_append_refuses_a_plant_at_the_leaf_in_the_cores_shape(scratch, kind):
    """A plant at the name gets the core's own refusal row, nothing is synced, and nothing
    changes on disk. Positive control: the plant removed, it lands."""
    root, leaf, host = scratch
    planted = S.plant_leaf(leaf, kind, host=host)
    spy = FsyncSpy(leaf)
    before = S.census(root.parent)

    raised = S.raised_by(
        lambda: _io.rooted_write(root, DEEP, ROW, mode="append", durable=True, os_=spy),
        fifo=planted.fifo)

    S.assert_refusal(raised, kind, where=f"a durable append into a {kind}")
    assert S.census(root.parent) == before, "a refused durable append changed the tree"
    assert spy.fsyncs == [], "a refused durable append synced something"
    planted.remove()
    _io.rooted_write(root, DEEP, ROW, mode="append", durable=True)
    assert leaf.read_text(encoding="utf-8") == ROW


# =======================================================================================
# hold — the root, following its spelling; nothing made
# =======================================================================================

@pytest.mark.parametrize("spelling", ["real", "symlinked"])
def test_d1_hold_opens_the_root_following_its_spelling_and_closes_it_on_exit(tree, spelling):
    """`hold(root)` answers a `Held` on the root, following a symlinked spelling (the operator's
    own, as `bind` follows it); it holds exactly one descriptor on the root while open, reads
    through it, and `with` releases it. The link at the root's spelling is left as it was."""
    root, _host = tree
    (root / "rec.txt").write_text("held\n", encoding="utf-8")
    spelled = root
    if spelling == "symlinked":
        spelled = root.parent / "root-alias"
        spelled.symlink_to(root, target_is_directory=True)

    with S.hold(spelled) as held:
        assert isinstance(held, _io.Held), f"hold answered {type(held).__name__}, not Held"
        assert len(S.open_fds_on(root)) == 1, "hold does not hold exactly one root descriptor"
        assert held.view().read("rec.txt").text == "held\n"
    assert S.open_fds_on(root) == [], "leaving the `with` did not release the root"
    if spelling == "symlinked":
        assert spelled.is_symlink()


@pytest.mark.parametrize(("kind", "exc"), [
    ("missing", FileNotFoundError), ("dangling-link", FileNotFoundError),
    ("file", NotADirectoryError), ("fifo", NotADirectoryError)])
def test_d1_hold_refuses_a_missing_root_or_a_non_directory_and_makes_nothing(tmp_path, kind, exc):
    """A missing root (or a link to nothing) is `FileNotFoundError`; a file or a FIFO at the
    root's spelling is `NotADirectoryError`, raised without blocking on the FIFO. Nothing is
    created, anywhere. Control on the same spelling: a real directory there is held."""
    root = tmp_path / "root"
    fifo = None
    if kind == "dangling-link":
        root.symlink_to(tmp_path / "nowhere", target_is_directory=True)
    elif kind == "file":
        root.write_bytes(S.HOST_BYTES)
    elif kind == "fifo":
        os.mkfifo(root)
        fifo = root
    before = S.census(tmp_path)

    raised = S.raised_by(lambda: S.hold(root).close(), fifo=fifo)

    assert isinstance(raised, exc), f"hold over a {kind} raised {raised!r}, not {exc.__name__}"
    assert S.census(tmp_path) == before, f"hold over a {kind} created something"

    if os.path.lexists(root):
        root.unlink()
    root.mkdir()
    with S.hold(root) as held:
        held.write("rec.txt", "control\n", mode="create")
    assert (root / "rec.txt").read_text(encoding="utf-8") == "control\n"


# =======================================================================================
# hold_new — made or adopted off the parent, never followed; held; the parent fsynced
# =======================================================================================

@pytest.mark.parametrize("kind", ["folder_link_outside", "folder_link_inside", "folder_file",
                                  "folder_fifo", "dangling_dir_link"])
def test_d1_hold_new_refuses_a_plant_at_the_name_and_leaves_it(tmp_path, kind):
    """`hold_new(parent, name)` judges `name` from the parent's handle: a link at the name (to a
    real folder outside the parent or beside it, or dangling), a file or a FIFO is the core's
    folder refusal row, left in place, and nothing is created where a link points.

    Control on the same address: the plant removed, `hold_new` makes a real directory and holds
    it (a write lands inside); over an existing real directory it adopts it, contents kept."""
    parent = tmp_path / "episodes"
    parent.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    name = "ep-1133"
    at = parent / name
    if kind == "dangling_dir_link":
        at.symlink_to(host / "not-yet", target_is_directory=True)
        planted, row = S.Planted("folder_link_outside", at), "folder_link_outside"
    else:
        planted = S.plant_folder(parent, PurePosixPath(name), PurePosixPath(name), kind,
                                 host=host)
        row = kind
    before = S.census(tmp_path)

    raised = S.raised_by(lambda: S.hold_new(parent, name).close(), fifo=planted.fifo)

    S.assert_refusal(raised, row, where=f"hold_new over a {kind}")
    assert S.census(tmp_path) == before, f"hold_new over a {kind} changed the tree"

    planted.remove()
    with S.hold_new(parent, name) as held:
        held.write("family.yaml", "made\n", mode="create")
    assert stat.S_ISDIR(os.lstat(at).st_mode)
    assert (at / "family.yaml").read_text(encoding="utf-8") == "made\n"
    with S.hold_new(parent, name) as held:
        assert held.view().read("family.yaml").text == "made\n", (
            "an existing real dir not adopted")
    assert (at / "family.yaml").read_text(encoding="utf-8") == "made\n"


def test_d1_hold_new_makes_a_missing_parent_following_the_parents_spelling(tmp_path):
    """A missing parent is made (every level); a parent spelled through a symlink is followed —
    the new directory lands in the link's target and the link stays."""
    deep = tmp_path / "missing" / "episodes"
    with S.hold_new(deep, "ep-1133") as held:
        held.write("rec.txt", "x\n", mode="create")
    assert (deep / "ep-1133" / "rec.txt").read_text(encoding="utf-8") == "x\n"

    real = tmp_path / "real-episodes"
    real.mkdir()
    alias = tmp_path / "episodes-alias"
    alias.symlink_to(real, target_is_directory=True)
    with S.hold_new(alias, "ep-1133") as held:
        held.write("rec.txt", "y\n", mode="create")
    assert (real / "ep-1133" / "rec.txt").read_text(encoding="utf-8") == "y\n"
    assert alias.is_symlink()


@pytest.mark.parametrize("when", ["after-return", "inside-hold_new"])
def test_d1_hold_new_holds_the_descriptor_it_made_not_the_name(tmp_path, when):
    """`hold_new` holds the very descriptor its step made or adopted, with no re-resolve by
    path. The name is swapped — the made directory renamed away and a link to a host folder put
    at the name — either after `hold_new` returns, or INSIDE it, the moment the step's open of
    the name returns (through the `os_` seam). Either way writes land in the made directory (at
    its new name) and nothing lands where the link points; a re-open of `parent/name` by path
    would have followed the link."""
    parent = tmp_path / "episodes"
    parent.mkdir()
    host = tmp_path / "host"
    host.mkdir()
    name = "ep-1133"

    def swap() -> None:
        (parent / name).rename(parent / "moved")
        (parent / name).symlink_to(host, target_is_directory=True)

    spy = S.OsSpy()
    if when == "inside-hold_new":
        def swap_after_step(path: str, dir_fd: int | None, _fd: int) -> None:
            if path == name and dir_fd is not None:
                spy.after_open = None
                swap()
        spy.after_open = swap_after_step
    with S.hold_new(parent, name, os_=spy) as held:
        if when == "after-return":
            swap()
        held.write("fa/rec.txt", "held\n", mode="create")
    assert (parent / "moved" / "fa" / "rec.txt").read_text(encoding="utf-8") == "held\n"
    assert list(host.iterdir()) == [], "the write followed the swapped name"


class ParentSyncSpy(S.OsSpy):
    """An `OsSpy` that also notes, at each fsync, whether the new directory already exists."""

    def __init__(self, made: Path) -> None:
        super().__init__()
        self.made = made
        self.made_at_sync: list[bool] = []

    def fsync(self, fd: int) -> None:
        self.made_at_sync.append(os.path.isdir(self.made))
        super().fsync(fd)


@pytest.mark.parametrize("dir_state", ["fresh", "adopted"])
def test_d1_hold_new_fsyncs_the_parent_on_an_o_rdonly_directory_handle(tmp_path, dir_state):
    """The new directory's own entry is made durable: `hold_new` fsyncs the PARENT (its inode),
    after the directory exists, on a handle that is a directory opened for reading — not the
    walk's `O_PATH` handle, whose fsync is `EBADF` (C12). It does so whether it made the
    directory or adopted one already there (`adopted`): an entry an earlier, crashed caller made
    may never have been synced, so finding it is no proof it is durable."""
    parent = tmp_path / "episodes"
    parent.mkdir()
    if dir_state == "adopted":
        (parent / "ep-1133").mkdir()
    spy = ParentSyncSpy(parent / "ep-1133")

    S.hold_new(parent, "ep-1133", os_=spy).close()

    on_parent = [(i, s) for i, s in enumerate(spy.fsyncs) if s.ino == S.inode(parent)]
    assert on_parent, f"the parent was never fsynced: {spy.fsyncs}"
    i, sync = on_parent[-1]
    assert spy.made_at_sync[i], "the parent was fsynced before the new directory existed"
    assert sync.is_dir
    assert not sync.getfl & S.O_PATH, "the parent was fsynced through an O_PATH handle"
    if sync.open_flags is not None:
        assert sync.open_flags & os.O_DIRECTORY, "the parent's sync handle is not O_DIRECTORY"
        assert sync.open_flags & os.O_ACCMODE == os.O_RDONLY


@pytest.mark.parametrize("name", ["a/b", "..", ".", "", "/abs"])
def test_d1_hold_new_takes_one_path_component(tmp_path, name):
    """`name` is the one component the new directory is called: a separator, `.`, `..`, empty
    or absolute name is a `ValueError` before anything is made or opened."""
    parent = tmp_path / "episodes"
    (parent / "a").mkdir(parents=True)
    before = S.census(tmp_path)
    with pytest.raises(ValueError, match=S.NAME_REFUSAL):
        S.hold_new(parent, name)
    assert S.census(tmp_path) == before


class DirSyncFails(S.PassThroughOs):
    """The real `os`, handed in as `os_`, except that an `fsync` of a DIRECTORY fails with
    `EIO`, as on a filesystem that cannot make a folder's entries durable."""

    def fsync(self, fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "injected directory fsync failure")
        os.fsync(fd)


def test_d1_a_failed_parent_sync_fails_hold_new_and_leaves_nothing_open(tmp_path):
    """The parent's fsync is what makes the new directory's entry durable, so its failure is
    `hold_new`'s: the `EIO` propagates (a best-effort sync that swallowed it would hand back a
    root whose entry may not survive a crash), and the descriptor on the new directory is closed
    before it does. Control: the same call with a working fsync holds the directory."""
    parent = tmp_path / "episodes"
    parent.mkdir()
    raised = S.raised_by(lambda: S.hold_new(parent, "ep-1133", os_=DirSyncFails()))
    assert isinstance(raised, OSError), f"a failed parent fsync did not fail hold_new: {raised!r}"
    assert raised.errno == errno.EIO, raised
    assert S.open_fds_on(parent / "ep-1133") == [], "hold_new left the new directory open"

    S.hold_new(parent, "ep-1133").close()


def test_d1_hold_new_opens_its_parent_by_path_once_and_everything_else_relative_to_it(tmp_path):
    """The parent is resolved by path once — `hold_new` follows the parent's spelling — and
    every later open (the new directory's step, the parent's sync handle) is relative to that
    descriptor: the parent is never re-resolved by name to be synced, so a parent swapped after
    the first open is not the folder synced."""
    parent = tmp_path / "episodes"
    parent.mkdir()
    spy = S.OsSpy()
    S.hold_new(parent, "ep-1133", os_=spy).close()
    by_path = [o for o in spy.opens if o.dir_fd is None or os.path.isabs(o.path)]
    assert [o.path for o in by_path] == [str(parent)], (
        f"hold_new opened by path more than its parent's one resolve: {by_path}")
    assert spy.opens[0].path == str(parent), spy.opens


# =======================================================================================
# Held verbs x plants
# =======================================================================================

def _held_matrix():
    for verb in (*WRITE_VERBS, "unlink"):
        for kind in S.LEAF_PLANTS:
            yield pytest.param(verb, kind, None, id=f"{verb}-{kind}")
        for site in S.holding_folders(REC_REL):
            for kind in S.FOLDER_PLANTS:
                yield pytest.param(verb, kind, site, id=f"{verb}-{kind}@{site}")


def _held_control(held: Any, verb: str, path: Path) -> None:
    """The same verb on the same address, nothing planted, then a plain file there. A durable
    append makes no folder (R4), so its holding folders are made real first."""
    if verb == "unlink":
        assert held.unlink(REC) is False
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("plain\n", encoding="utf-8")
        assert held.unlink(REC) is True
        assert not os.path.lexists(path)
        return
    if verb == "append_durable":
        path.parent.mkdir(parents=True, exist_ok=True)
    S.held_verb(held, verb, REC, _payload(verb, "landed"))
    assert path.read_text(encoding="utf-8") == _payload(verb, "landed")
    assert os.lstat(path).st_nlink == 1
    if verb == "create":
        with pytest.raises(FileExistsError) as taken:
            S.held_verb(held, verb, REC, _payload(verb, "again"))
        assert not getattr(taken.value, "write_guarded_alias", False)
        assert path.read_text(encoding="utf-8") == _payload(verb, "landed")
        return
    S.held_verb(held, verb, REC, _payload(verb, "again"))
    want = _payload(verb, "again") if verb == "replace" else (
        _payload(verb, "landed") + _payload(verb, "again"))
    assert path.read_text(encoding="utf-8") == want


@pytest.mark.parametrize(("verb", "kind", "site"), list(_held_matrix()))
def test_d1_a_held_verb_into_a_plant_is_refused_and_changes_nothing(tree, verb, kind, site):
    """O2 on the core's held root: a symlink (live or dangling), hard link, FIFO or directory
    at the name, or a link (outside or inside), file or FIFO at a holding folder, is the core's
    refusal row for every write verb and for `unlink` (R2: `NotPlainEntry` at the name, a plain
    folder refusal on the way); none blocks on a FIFO, and the whole tree is unchanged. Control
    on the same address: the plant removed, the verb lands (and over a plain file, too). The
    read rows moved to the view (`test_1133_rev3.py`)."""
    root, host = tree
    path = root / REC
    with S.hold(root) as held:
        planted = S.plant(root, REC_REL, site, kind, host=host)
        before = S.census(root.parent)
        raised = S.raised_by(lambda: S.held_verb(held, verb, REC), fifo=planted.fifo)
        S.assert_refusal(raised, "symlink" if kind == "dangling" else kind,
                         where=f"Held.{verb}{f' @{site}' if site else ''}")
        assert S.census(root.parent) == before, f"Held.{verb} into a {kind} changed the tree"
        planted.remove()
        _held_control(held, verb, path)


@pytest.mark.parametrize(("kind", "site"), [
    pytest.param(k, PurePosixPath(s), id=f"{k}@{s}")
    for s in ("fa", "fa/fb") for k in S.FOLDER_PLANTS])
def test_d1_held_mkdir_through_a_plant_is_refused_and_changes_nothing(tree, kind, site):
    """`Held.mkdir(folder)` walks without following: a link, file or FIFO at the folder or at a
    folder above it is the core's row, the tree unchanged (a link's target gains no subfolder).
    Control: the plant removed, `mkdir` leaves a real folder; a second `mkdir` is a no-op."""
    root, host = tree
    folder = PurePosixPath("fa/fb")
    with S.hold(root) as held:
        planted = S.plant_folder(root, folder, site, kind, host=host)
        before = S.census(root.parent)
        S.assert_refusal(S.raised_by(lambda: held.mkdir(str(folder)), fifo=planted.fifo),
                         kind, where=f"Held.mkdir @{site}")
        assert S.census(root.parent) == before
        planted.remove()
        held.mkdir(str(folder))
        assert stat.S_ISDIR(os.lstat(root / folder).st_mode)
        (root / folder / "keep").write_text("kept\n", encoding="utf-8")
        held.mkdir(str(folder))
        assert (root / folder / "keep").read_text(encoding="utf-8") == "kept\n"


# =======================================================================================
# One walk per write
# =======================================================================================

@pytest.mark.parametrize("folders", ["absent", "present"])
@pytest.mark.parametrize("verb", [*WRITE_VERBS, "mkdir"])
def test_d1_one_write_is_one_walk_off_the_held_root_that_makes_its_holding_folders(
        tree, verb, folders):
    """A write verb is ONE walk: every open it makes is relative to a held descriptor (the root
    is never re-opened by path), each holding folder is opened successfully exactly once, and a
    missing one is made in that same walk (`mkdir` of exactly the missing folders). Rev 1 made
    the folders in one `rooted_*` call and wrote in another, re-opening the root and every
    folder twice.

    Rev 3 (R4): a DURABLE append walks without making: over missing folders it is
    `FileNotFoundError`, it makes no folder and writes nothing."""
    root, _host = tree
    if folders == "present":
        (root / "fa" / "fb").mkdir(parents=True)
    spy = S.OsSpy()
    with S.hold(root, os_=spy) as held:
        opens_at, mkdirs_at = len(spy.opens), len(spy.mkdirs)
        target = "fa/fb" if verb == "mkdir" else REC
        if verb == "append_durable" and folders == "absent":
            before = S.census(root)
            with pytest.raises(FileNotFoundError):
                S.held_verb(held, verb, target, _payload(verb, "walk"))
            assert spy.mkdirs[mkdirs_at:] == [], (
                f"a durable append made folders: {spy.mkdirs[mkdirs_at:]}")
            assert S.census(root) == before, "a durable append into missing folders made something"
            assert [o for o in spy.opens[opens_at:] if o.dir_fd is None] == []
            return
        S.held_verb(held, verb, target, _payload(verb, "walk"))
        opens = spy.opens[opens_at:]
    by_path = [o for o in opens if o.dir_fd is None]
    assert by_path == [], f"Held.{verb} re-opened by path: {by_path}"
    for component in ("fa", "fb"):
        made = [o for o in opens if o.path == component and o.fd is not None]
        assert len(made) == 1, (
            f"Held.{verb} opened the holding folder {component!r} {len(made)} times — one "
            f"walk opens each once: {[o.path for o in opens]}")
    want_mkdirs = ["fa", "fb"] if folders == "absent" else []
    assert spy.mkdirs[mkdirs_at:] == want_mkdirs, spy.mkdirs[mkdirs_at:]
    if verb == "mkdir":
        assert stat.S_ISDIR(os.lstat(root / "fa" / "fb").st_mode)
    else:
        assert (root / REC).read_text(encoding="utf-8") == _payload(verb, "walk")


# =======================================================================================
# Durable append: the leaf, then its holding folder
# =======================================================================================

@pytest.mark.parametrize("rel", ["rec.jsonl", "fa/rec.jsonl"])
def test_d1_a_durable_append_fsyncs_the_leaf_then_its_holding_folder(tree, rel):
    """`write(name, text, mode="append", durable=True)` fsyncs the leaf (every byte of this
    append on it at that moment), then the folder holding it — the root itself for a top-level
    record — on a handle opened `O_RDONLY|O_DIRECTORY`, never an `O_PATH` one. Control, same
    address: a plain append fsyncs nothing."""
    root, _host = tree
    leaf = root / rel
    leaf.parent.mkdir(parents=True, exist_ok=True)  # R4: a durable append makes no folder
    spy = S.OsSpy(watch=leaf)
    with S.hold(root, os_=spy) as held:
        at = len(spy.fsyncs)
        held.write(rel, ROW, mode="append", durable=True)
        syncs = spy.fsyncs[at:]
        leaf_syncs = [i for i, s in enumerate(syncs) if s.ino == S.inode(leaf)]
        folder_syncs = [i for i, s in enumerate(syncs) if s.ino == S.inode(leaf.parent)]
        assert leaf_syncs, f"the leaf was not fsynced: {syncs}"
        assert syncs[leaf_syncs[0]].watched_bytes == ROW.encode(), (
            "the leaf was fsynced before its bytes were on it")
        assert folder_syncs, "the holding folder was not fsynced — the leaf's entry is not durable"
        assert folder_syncs[-1] > leaf_syncs[0], "the holding folder was fsynced before the leaf"
        folder = syncs[folder_syncs[-1]]
        assert folder.is_dir
        assert not folder.getfl & S.O_PATH, "the holding folder was fsynced through O_PATH"
        if folder.open_flags is not None:
            assert folder.open_flags & os.O_DIRECTORY
            assert folder.open_flags & os.O_ACCMODE == os.O_RDONLY
        assert S.open_fds_on(leaf) == [], "the durable append left the leaf open"

        at = len(spy.fsyncs)
        held.write(rel, ROW, mode="append")
        assert spy.fsyncs[at:] == [], "a plain append fsynced"
    assert leaf.read_text(encoding="utf-8") == ROW + ROW


@pytest.mark.parametrize("rel", ["rec.jsonl", "fa/rec.jsonl"])
def test_d1_a_failed_holding_folder_sync_fails_the_durable_append(tree, rel):
    """The holding folder's fsync is what makes the leaf's entry durable, so its failure is the
    durable append's: the `EIO` propagates, never swallowed as best-effort (the caller would
    otherwise take a record whose entry may not survive a crash for a durable one). Control on
    the same address: a plain append does not sync the folder, and succeeds."""
    root, _host = tree
    (root / rel).parent.mkdir(parents=True, exist_ok=True)  # R4: a durable append makes no folder
    with S.hold(root, os_=DirSyncFails()) as held:
        raised = S.raised_by(lambda: held.write(rel, ROW, mode="append", durable=True))
        assert isinstance(raised, OSError), (
            f"a failed holding-folder fsync did not fail the durable append: {raised!r}")
        assert raised.errno == errno.EIO, raised
        held.write(rel, ROW, mode="append")


@pytest.mark.parametrize("rel", ["rec.jsonl", "fa/fb/rec.jsonl"])
def test_d1_a_durable_append_opens_nothing_by_path(tree, rel):
    """Every open a durable append makes — each holding folder, the leaf, and the holding
    folder's sync handle — is a relative name off a held descriptor (`dir_fd`), never a path:
    the folder synced is the one the walk holds, not whatever the name resolves to now."""
    root, _host = tree
    (root / rel).parent.mkdir(parents=True, exist_ok=True)  # R4: a durable append makes no folder
    spy = S.OsSpy()
    with S.hold(root, os_=spy) as held:
        at = len(spy.opens)
        held.write(rel, ROW, mode="append", durable=True)
        opens = spy.opens[at:]
    assert opens, "the durable append opened nothing through its os_ seam"
    by_path = [o for o in opens if o.dir_fd is None or os.path.isabs(o.path)]
    assert by_path == [], f"the durable append opened by path: {by_path}"


@pytest.mark.parametrize("rel", ["rec.jsonl", "fa/rec.jsonl"])
def test_d1_a_durable_append_after_a_rename_syncs_the_moved_holding_folder(tmp_path, rel):
    """The root is held, not remembered, and so is the folder a durable append syncs: after the
    held root is renamed, the append lands in the moved tree and the folder fsynced is the moved
    holding folder (the root itself for a top-level record), on a directory handle — not a
    lookup of the old name, which no longer exists."""
    root = tmp_path / "root"
    (root / "fa").mkdir(parents=True)
    moved = tmp_path / "moved"
    spy = S.OsSpy()
    with S.hold(root, os_=spy) as held:
        root.rename(moved)
        at = len(spy.fsyncs)
        held.write(rel, ROW, mode="append", durable=True)
        syncs = spy.fsyncs[at:]
    folder = (moved / rel).parent
    assert (moved / rel).read_text(encoding="utf-8") == ROW
    assert not os.path.lexists(root), "the durable append recreated the old name"
    assert any(s.ino == S.inode(folder) and s.is_dir and not s.getfl & S.O_PATH
               for s in syncs), f"the moved holding folder {folder} was not fsynced: {syncs}"


@pytest.mark.parametrize("mode", ["create", "replace"])
def test_d1_durable_applies_to_the_append_mode_only(tree, mode):
    """`durable=True` with `create` or `replace` is a `ValueError` before anything is made."""
    root, _host = tree
    with S.hold(root) as held:
        before = S.census(root.parent)
        with pytest.raises(ValueError, match="durable"):
            held.write(REC, ROW, mode=mode, durable=True)
        assert S.census(root.parent) == before


# =======================================================================================
# No iterable text
# =======================================================================================

def _gen():
    yield "a line\n"


@pytest.mark.parametrize("verb", WRITE_VERBS)
@pytest.mark.parametrize("value", [
    pytest.param(lambda: ["a line\n"], id="list"),
    pytest.param(lambda: iter(["a line\n"]), id="iterator"),
    pytest.param(_gen, id="generator"),
    pytest.param(lambda: 7, id="int"),
    pytest.param(lambda: None, id="none"),
    pytest.param(lambda: {"a": 1}, id="dict"),
])
def test_d1_held_write_takes_str_or_bytes_and_refuses_anything_else_before_any_io(
        tree, verb, value):
    """`text` is `str | bytes`: a list, an iterator, a generator (which a fallback create would
    consume on its first pass and leave an empty file, C17), an int, `None` or a dict is a
    `TypeError` before anything is opened or made — the holding folders included. `bytearray`
    is not pinned either way. Control: `str` and `bytes` land (into holding folders that exist:
    a durable append makes none, R4)."""
    root, _host = tree
    (root / "fa" / "fb").mkdir(parents=True)
    with S.hold(root) as held:
        before = S.census(root.parent)
        with pytest.raises(TypeError):
            S.held_verb(held, verb, REC, value())
        assert S.census(root.parent) == before, f"a refused {verb} made something"
        S.held_verb(held, verb, REC, "text\n")
        S.held_verb(held, verb, "fa/other.bin", b"\x00bytes\n")
    assert (root / "fa" / "other.bin").read_bytes() == b"\x00bytes\n"


# =======================================================================================
# The view
# =======================================================================================

def test_o3_the_view_is_a_bound_over_the_same_handle_owning_nothing(tree, tmp_path):
    """`view()` is a `Bound` whose public surface is exactly the readers and `close`; it reads
    through the held handle (after the root is renamed it reads the moved folder); its `close()`
    releases nothing (the `Held` still writes); and once the `Held` closes, the view answers a
    refusal (`Bad file descriptor`), never text and never an exception."""
    root, _host = tree
    (root / "rec.txt").write_text("before\n", encoding="utf-8")
    held = S.hold(root)
    try:
        view = held.view()
        assert isinstance(view, _io.Bound), f"view() is {type(view).__name__}, not a Bound"
        public = {n for n in dir(view) if not n.startswith("_")}
        assert public == {"read", "read_jsonl", "entries", "under", "close"}, sorted(public)

        moved = tmp_path / "moved"
        root.rename(moved)
        (moved / "rec.txt").write_text("after the rename\n", encoding="utf-8")
        assert view.read("rec.txt").text == "after the rename\n", (
            "the view re-resolved the root by path instead of reading through the handle")

        view.close()
        held.write("more.txt", "still held\n", mode="create")
        assert (moved / "more.txt").read_text(encoding="utf-8") == "still held\n"
        assert view.read("rec.txt").text == "after the rename\n", "view.close() closed the root"
    finally:
        held.close()
    after = view.read("rec.txt")
    assert after.text is None, f"the view still reads after its Held closed: {after!r}"
    assert after.reason == os.strerror(errno.EBADF), (
        f"the closed view's read is not refused as a closed descriptor: {after!r}")


# =======================================================================================
# Lifetime: dup-per-verb
# =======================================================================================

#: Rev 3 has no `Held.read`: the view's own close race is in `test_1133_rev3.py`.
_LIFETIME_VERBS = (*WRITE_VERBS, "mkdir", "unlink")


def _lifetime_name(verb: str) -> str:
    return "fa/new" if verb == "mkdir" else "fa/rec.jsonl"


def _lifetime_trees(tmp_path: Path, verb: str) -> tuple[Path, Path]:
    """A root and a decoy folder of the same shape. The root holds the record (except for the
    verbs that make it); the decoy holds a record of its own at the same name wherever a
    misdirected verb would visibly act on it."""
    root = tmp_path / "root"
    decoy = tmp_path / "decoy"
    (root / "fa").mkdir(parents=True)
    (decoy / "fa").mkdir(parents=True)
    if verb not in ("create", "mkdir"):
        (root / "fa" / "rec.jsonl").write_bytes(b"ROOT\n")
        (decoy / "fa" / "rec.jsonl").write_bytes(b"DECOY\n")
    return root, decoy


def _assert_acted_on_root(root: Path, verb: str, got: Any) -> None:
    rec = root / "fa" / "rec.jsonl"
    if verb == "mkdir":
        assert stat.S_ISDIR(os.lstat(root / "fa" / "new").st_mode)
    elif verb == "unlink":
        assert got is True, f"the in-flight unlink answered {got!r}"
        assert not os.path.lexists(rec), "the in-flight unlink left the root's record"
    elif verb in ("create", "replace"):
        assert rec.read_text(encoding="utf-8") == _payload(verb, "in-flight")
    else:
        assert rec.read_text(encoding="utf-8") == "ROOT\n" + _payload(verb, "in-flight")


@pytest.mark.parametrize("verb", _LIFETIME_VERBS)
def test_d1_a_verb_in_flight_when_close_lands_keeps_working_off_its_own_descriptor(
        tmp_path, verb):
    """The route the held root adds to O2's asset: a write through a descriptor number the
    process closed and then reused. Each verb takes a private `dup` of the root, so:

    `close()` lands mid-verb (fired, through the `os_` seam, just before the verb's first
    relative operation) and returns promptly — it does not wait for the verb — and releases the
    root's descriptor. That number is then taken by a DECOY folder of the same shape (`dup2`),
    as another open in a live process would take it. The verb completes on the ROOT (the record
    written or removed there) and the decoy is untouched; afterwards the reused number
    still names the decoy (nothing closed it a second time).

    Then a verb after `close()` raises `OSError(EBADF)` and touches nothing — neither the root
    nor the decoy sitting on the old number."""
    root, decoy = _lifetime_trees(tmp_path, verb)
    decoy_before = S.census(decoy)
    spy = S.OsSpy()
    held = S.hold(root, os_=spy)
    [root_fd] = S.open_fds_on(root)
    state: dict[str, Any] = {}

    def close_mid_verb(_op: str, _args: tuple, _kwargs: dict) -> None:
        spy.hook = None
        state["closed_promptly"] = S.run_in_thread(held.close, timeout=1.0)
        if not state["closed_promptly"]:
            return
        state["open_after_close"] = S.open_fds_on(root)
        if root_fd not in state["open_after_close"]:
            # The lowest free number is usually the one just freed; `dup2` makes it certain.
            fd = os.open(decoy, os.O_RDONLY | os.O_DIRECTORY)
            if fd != root_fd:
                os.dup2(fd, root_fd, inheritable=False)
                os.close(fd)
            state["decoy_on"] = root_fd

    spy.hook = close_mid_verb
    try:
        got = S.held_verb(held, verb, _lifetime_name(verb), _payload(verb, "in-flight"))

        assert "closed_promptly" in state, (
            f"Held.{verb} made no relative operation through its os_ seam")
        assert state["closed_promptly"], (
            "close() waited for the verb in flight — a verb must work off its own dup, not "
            "hold the root's lock for its whole run")
        assert "decoy_on" in state, (
            f"close() released nothing while a verb ran (still open on the root: "
            f"{state['open_after_close']}); close closes the root, the verb keeps its dup")
        _assert_acted_on_root(root, verb, got)
        assert S.census(decoy) == decoy_before, (
            f"the in-flight {verb} acted through the root's old descriptor number, now the "
            "decoy's")
        assert S.inode(decoy) == (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino), (
            "something closed or replaced the reused descriptor number")

        root_before = S.census(root)
        after = S.raised_by(lambda: S.held_verb(held, verb, "fa/after.jsonl"
                                                if verb != "mkdir" else "fa/after"))
        assert isinstance(after, OSError), f"Held.{verb} after close raised {after!r}"
        assert after.errno == errno.EBADF, (
            f"Held.{verb} after close raised {after!r}, not OSError(EBADF)")
        assert S.census(root) == root_before, f"Held.{verb} after close touched the root"
        assert S.census(decoy) == decoy_before, f"Held.{verb} after close touched the decoy"
    finally:
        if "decoy_on" in state:
            os.close(state["decoy_on"])


#: How long the dup waits for a close started on another thread: ample for a close that is
#: not held off by the lock, and the only wait a correct `Held` costs.
_CLOSE_GRACE = 0.5


@pytest.mark.parametrize("verb", _LIFETIME_VERBS)
def test_d1_a_close_landing_as_a_verb_takes_its_dup_never_redirects_the_verb(tmp_path, verb):
    """The dup and the close are one critical section. Just as a verb asks for its private dup
    of the root (the `os_` seam's `dup`, handed the root's number), `close()` is started on
    another thread and given a grace period. Had the verb read the root's number outside
    `close`'s lock, that close would finish inside the grace period and free the number the verb
    is about to dup — and the next open in a live process takes it: here a DECOY folder of the
    same shape is put on it (`dup2`). The verb must still act on the ROOT (the record written
    or removed there), leave the decoy untouched, and the close completes once the verb holds
    its dup."""
    root, decoy = _lifetime_trees(tmp_path, verb)
    decoy_before = S.census(decoy)
    spy = S.OsSpy()
    held = S.hold(root, os_=spy)
    state: dict[str, Any] = {}

    def close_at_dup(fd: int) -> None:
        closer = threading.Thread(target=held.close, daemon=True)
        closer.start()
        closer.join(_CLOSE_GRACE)
        state["closer"] = closer
        if not closer.is_alive():
            # The close finished while the verb was about to dup the number it just freed.
            taken = os.open(decoy, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            if taken != fd:
                os.dup2(taken, fd, inheritable=False)
                os.close(taken)
            state["decoy_on"] = fd

    spy.before_dup = close_at_dup
    try:
        got = S.held_verb(held, verb, _lifetime_name(verb), _payload(verb, "in-flight"))
        assert "closer" in state, f"Held.{verb} took no dup through its os_ seam"
        state["closer"].join(S.DEADLINE)
        assert not state["closer"].is_alive(), "close() never completed once the verb had its dup"
        assert S.census(decoy) == decoy_before, (
            f"the {verb} acted through the root's number after close freed it (now the decoy's)")
        _assert_acted_on_root(root, verb, got)
    finally:
        if "decoy_on" in state:
            os.close(state["decoy_on"])


def test_d1_close_is_idempotent_and_the_with_exit_after_it_is_clean(tree):
    """A second `close()` (and the `with` exit after an explicit one) is a no-op: it never
    closes a descriptor number twice."""
    root, _host = tree
    with S.hold(root) as held:
        held.close()
        held.close()
    assert S.open_fds_on(root) == []


# =======================================================================================
# N-h: O_CLOEXEC
# =======================================================================================

def test_n_h_every_descriptor_a_held_root_opens_is_close_on_exec(tree):
    """The held root and every descriptor a verb opens (walk handles, the leaf, the durable
    folder handle, a dup) — and every one the view's reads open — carry `FD_CLOEXEC`, checked
    with `fcntl(F_GETFD)` the moment each is returned."""
    root, _host = tree
    spy = S.OsSpy()
    with S.hold(root, os_=spy) as held:
        [root_fd] = S.open_fds_on(root)
        assert S.fd_cloexec(root_fd), "the held root is inheritable"
        for verb in (*WRITE_VERBS, "unlink"):
            name = REC if verb != "create" else "fa/fb/created.jsonl"
            S.held_verb(held, verb, name, _payload(verb, "cloexec"))
        held.mkdir("fa/fc")
        # The view's reads open (and, rev 3, dup) through the same seam.
        held.view().read("fa/fb/created.jsonl")
        held.view().under("fa").entries()
    opened = [o for o in spy.opens if o.fd is not None]
    assert opened, "no open reached the os_ seam"
    inheritable = [o for o in opened if not o.cloexec]
    assert inheritable == [], f"inheritable descriptors: {inheritable}"
    # The descriptor a verb works off (its dup, then each walk handle), checked while it is live.
    with S.hold(root, os_=spy) as held:
        seen: list[bool] = []

        def check_dups(_op: str, _args: tuple, kwargs: dict) -> None:
            seen.append(S.fd_cloexec(kwargs["dir_fd"]))

        spy.hook = check_dups
        held.write("rec2.jsonl", "x\n", mode="append")
        spy.hook = None
    assert seen, "no relative operation reached the os_ seam"
    assert all(seen), "the descriptor a verb works off is inheritable"


_PROBE = ("import os\n"
          "for n in os.listdir('/proc/self/fd'):\n"
          "    try:\n"
          "        print(os.readlink('/proc/self/fd/' + n))\n"
          "    except OSError:\n"
          "        pass\n")


def _child_fds(**kw: Any) -> list[str]:
    out = subprocess.run([sys.executable, "-c", _PROBE], close_fds=False, capture_output=True,
                         text=True, check=True, timeout=30, **kw)
    return out.stdout.splitlines()


def test_n_h_a_child_spawned_while_a_root_is_held_does_not_inherit_it(tree):
    """N-h: a sibling spawned while the launcher holds an episode does not inherit the handle.
    A child started with `close_fds=False` (so every inheritable descriptor would pass) lists
    no descriptor on the held root. Control: an inheritable descriptor on the same folder IS
    listed by the same child probe."""
    root, _host = tree
    real = os.path.realpath(root)
    with S.hold(root):
        assert real not in _child_fds(), "the child inherited the held root"
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.set_inheritable(fd, True)
        assert real in _child_fds(), "control: the probe cannot see an inherited folder"
    finally:
        os.close(fd)


# =======================================================================================
# O6 on the core: a held root that was removed or renamed
# =======================================================================================

@pytest.mark.parametrize("rel", ["rec.jsonl", "fa/rec.jsonl"])
@pytest.mark.parametrize("verb", [*WRITE_VERBS, "mkdir"])
def test_o6_a_held_root_that_was_removed_refuses_every_write_and_is_never_recreated(
        tmp_path, verb, rel):
    """No held verb makes the root: once the held root is removed, every write verb (and
    `mkdir`) raises `OSError`, and the root's name stays absent. Control: a root that is still
    there takes the same verb."""
    root = tmp_path / "root"
    root.mkdir()
    with S.hold(root) as held:
        root.rmdir()
        raised = S.raised_by(lambda: S.held_verb(held, verb, rel if verb != "mkdir" else "fa"))
        assert isinstance(raised, OSError), f"Held.{verb} on a removed root: {raised!r}"
        assert not os.path.lexists(root), f"Held.{verb} recreated the removed root"
    root.mkdir()
    if verb == "append_durable":
        (root / rel).parent.mkdir(parents=True, exist_ok=True)  # R4: it makes no folder
    with S.hold(root) as held:
        S.held_verb(held, verb, rel if verb != "mkdir" else "fa")


@pytest.mark.parametrize("verb", [*WRITE_VERBS, "mkdir"])
def test_o6_a_held_root_that_was_renamed_is_written_in_its_new_place(tmp_path, verb):
    """The root is held, not remembered: after a rename, a write (or `mkdir`) lands in the
    moved folder and nothing reappears at the old name."""
    root = tmp_path / "root"
    root.mkdir()
    if verb == "append_durable":
        (root / "fa").mkdir()  # R4: a durable append makes no folder
    moved = tmp_path / "moved"
    with S.hold(root) as held:
        root.rename(moved)
        S.held_verb(held, verb, "fa/rec.jsonl" if verb != "mkdir" else "fa",
                    _payload(verb, "moved"))
    assert not os.path.lexists(root)
    if verb == "mkdir":
        assert (moved / "fa").is_dir()
    else:
        assert (moved / "fa" / "rec.jsonl").read_text(encoding="utf-8") == _payload(verb,
                                                                                       "moved")


# =======================================================================================
# The folder walk under an interrupt
# =======================================================================================

class InterruptAfterFirstClose(S.PassThroughOs):
    """The real `os`, handed in as `os_`: every `close` is recorded, and the first one (once
    armed) is followed by a `KeyboardInterrupt`, as a signal landing just after the walk
    released the folder it stepped out of."""

    def __init__(self) -> None:
        self.armed = True
        self.closed: list[int] = []
        self.failed: list[OSError] = []

    def close(self, fd: int) -> None:
        try:
            os.close(fd)
        except OSError as e:
            self.failed.append(e)
            raise
        self.closed.append(fd)
        if self.armed and len(self.closed) == 1:
            raise KeyboardInterrupt("mid-walk")


@pytest.mark.parametrize("op", ["write", "mkdir"])
def test_an_interrupt_mid_walk_never_closes_a_descriptor_twice(scratch, op):
    """Found while moving the episode page's write onto the core (#1133): each descriptor the
    walk opens is closed at most once, whatever the interrupt; the interrupt still propagates.
    Control, same address, no interrupt: the op completes."""
    root, leaf, _host = scratch
    leaf.write_text(PRIOR, encoding="utf-8")
    ops = {
        "write": lambda os_: _io.rooted_write(root, DEEP, ROW, mode="replace", os_=os_),
        "mkdir": lambda os_: _io.rooted_mkdir(root, DEEP.parent, os_=os_),
    }
    spy = InterruptAfterFirstClose()
    with pytest.raises(KeyboardInterrupt):
        ops[op](spy)
    assert spy.failed == [], f"{op}: a close failed after the interrupt: {spy.failed}"
    assert len(spy.closed) == len(set(spy.closed)), (
        f"{op}: a descriptor number was closed twice: {spy.closed}")

    control = S.PassThroughOs()
    ops[op](control)


@pytest.mark.parametrize("verb", ["replace", "append_durable", "unlink", "mkdir", "view_read"])
def test_an_interrupt_mid_walk_of_a_held_verb_never_closes_a_descriptor_twice(scratch, verb):
    """The same on the held root: a verb (or the view's read, rev 3's only read) interrupted
    just after its walk's first close closes no number twice (its dup included), the interrupt
    propagates, and the held root survives it — the next verb on the same `Held` lands."""
    root, leaf, _host = scratch
    leaf.write_text(PRIOR, encoding="utf-8")
    spy = InterruptAfterFirstClose()
    spy.armed = False
    held = S.hold(root, os_=spy)
    try:
        spy.armed = True
        def interrupted() -> None:
            if verb == "view_read":
                held.view().read(str(DEEP))
            else:
                S.held_verb(held, verb, str(DEEP) if verb != "mkdir" else "a/b/c",
                            _payload(verb, "interrupted"))

        with pytest.raises(KeyboardInterrupt):
            interrupted()
        spy.armed = False
        assert spy.failed == [], f"{verb}: a close failed after the interrupt: {spy.failed}"
        assert len(spy.closed) == len(set(spy.closed)), (
            f"{verb}: a descriptor number was closed twice: {spy.closed}")
        held.write("a/after.jsonl", "after\n", mode="create")
    finally:
        held.close()
    assert (root / "a" / "after.jsonl").read_text(encoding="utf-8") == "after\n"


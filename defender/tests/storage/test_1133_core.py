"""The rooted core in _io.py: hold / hold_new / Held verbs and the durable append (no-follow, descriptor-held, close-on-exec, interrupt-safe)."""
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
from defender.tests.support.storage import _spec1133 as S

DEEP = PurePosixPath("a/b/rec.jsonl")
PRIOR = "prior row\n"
ROW = '{"row": "durable"}\n'
#: The held-root suite's record: two holding folders below the root.
REC = "fa/fb/rec.jsonl"
REC_REL = PurePosixPath(REC)
WRITE_VERBS = ("create", "replace", "append", "durable_append")


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


@pytest.mark.parametrize("prior", ["absent", "plain"])
def test_d2_a_durable_append_fsyncs_the_leaf_after_its_bytes_are_flushed_then_closes_it(
        scratch, prior):
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


@pytest.mark.parametrize("spelling", ["real", "symlinked"])
def test_d1_hold_opens_the_root_following_its_spelling_and_closes_it_on_exit(tree, spelling):
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


@pytest.mark.parametrize("kind", ["folder_link_outside", "folder_link_inside", "folder_file",
                                  "folder_fifo", "dangling_dir_link"])
def test_d1_hold_new_refuses_a_plant_at_the_name_and_leaves_it(tmp_path, kind):
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


class DirSyncFails(S.PassThroughOs):
    """The real `os`, handed in as `os_`, except that an `fsync` of a DIRECTORY fails with
    `EIO`, as on a filesystem that cannot make a folder's entries durable."""

    def fsync(self, fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "injected directory fsync failure")
        os.fsync(fd)


def test_d1_a_failed_parent_sync_fails_hold_new_and_leaves_nothing_open(tmp_path):
    parent = tmp_path / "episodes"
    parent.mkdir()
    raised = S.raised_by(lambda: S.hold_new(parent, "ep-1133", os_=DirSyncFails()))
    assert isinstance(raised, OSError), f"a failed parent fsync did not fail hold_new: {raised!r}"
    assert raised.errno == errno.EIO, raised
    assert S.open_fds_on(parent / "ep-1133") == [], "hold_new left the new directory open"

    S.hold_new(parent, "ep-1133").close()


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
    if verb == "durable_append":
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


@pytest.mark.parametrize("folders", ["absent", "present"])
@pytest.mark.parametrize("verb", [*WRITE_VERBS, "mkdir"])
def test_d1_one_write_is_one_walk_off_the_held_root_that_makes_its_holding_folders(
        tree, verb, folders):
    root, _host = tree
    if folders == "present":
        (root / "fa" / "fb").mkdir(parents=True)
    spy = S.OsSpy()
    with S.hold(root, os_=spy) as held:
        opens_at, mkdirs_at = len(spy.opens), len(spy.mkdirs)
        target = "fa/fb" if verb == "mkdir" else REC
        if verb == "durable_append" and folders == "absent":
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


@pytest.mark.parametrize("rel", ["rec.jsonl", "fa/rec.jsonl"])
def test_d1_a_durable_append_fsyncs_the_leaf_then_its_holding_folder(tree, rel):
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
    root, _host = tree
    (root / rel).parent.mkdir(parents=True, exist_ok=True)  # R4: a durable append makes no folder
    with S.hold(root, os_=DirSyncFails()) as held:
        raised = S.raised_by(lambda: held.write(rel, ROW, mode="append", durable=True))
        assert isinstance(raised, OSError), (
            f"a failed holding-folder fsync did not fail the durable append: {raised!r}")
        assert raised.errno == errno.EIO, raised
        held.write(rel, ROW, mode="append")


@pytest.mark.parametrize("rel", ["rec.jsonl", "fa/rec.jsonl"])
def test_d1_a_durable_append_after_a_rename_syncs_the_moved_holding_folder(tmp_path, rel):
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


def test_n_h_every_descriptor_a_held_root_opens_is_close_on_exec(tree):
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


@pytest.mark.parametrize("rel", ["rec.jsonl", "fa/rec.jsonl"])
@pytest.mark.parametrize("verb", [*WRITE_VERBS, "mkdir"])
def test_o6_a_held_root_that_was_removed_refuses_every_write_and_is_never_recreated(
        tmp_path, verb, rel):
    root = tmp_path / "root"
    root.mkdir()
    with S.hold(root) as held:
        root.rmdir()
        raised = S.raised_by(lambda: S.held_verb(held, verb, rel if verb != "mkdir" else "fa"))
        assert isinstance(raised, OSError), f"Held.{verb} on a removed root: {raised!r}"
        assert not os.path.lexists(root), f"Held.{verb} recreated the removed root"
    root.mkdir()
    if verb == "durable_append":
        (root / rel).parent.mkdir(parents=True, exist_ok=True)  # R4: it makes no folder
    with S.hold(root) as held:
        S.held_verb(held, verb, rel if verb != "mkdir" else "fa")


@pytest.mark.parametrize("verb", [*WRITE_VERBS, "mkdir"])
def test_o6_a_held_root_that_was_renamed_is_written_in_its_new_place(tmp_path, verb):
    """The root is held, not remembered: after a rename, a write (or `mkdir`) lands in the
    moved folder and nothing reappears at the old name."""
    root = tmp_path / "root"
    root.mkdir()
    if verb == "durable_append":
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


@pytest.mark.parametrize("verb", ["replace", "durable_append", "unlink", "mkdir", "view_read"])
def test_an_interrupt_mid_walk_of_a_held_verb_never_closes_a_descriptor_twice(scratch, verb):
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

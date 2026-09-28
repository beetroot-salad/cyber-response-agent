"""#1133 D2 — the two additions to the rooted core in `defender/_io.py`.

* **Durable append.** `rooted_write(root, name, text, mode="append", durable=True)` writes,
  flushes and `fsync`s the leaf, then closes it (its own write-sync-close path: `_write_all`
  closes the fd itself). Observed through the core's `os_` seam: a pass-through `os` that
  records each `fsync`, and at that moment judges which file the descriptor is and what is
  already on disk there. So "flushed, then fsynced, the leaf's own descriptor" is a fact read
  off the real file, not off a flag.
* **`rooted_unlink(root, name) -> bool`.** Walks the folders without following links. An absent
  leaf or an absent holding folder is `False`; a plain file is unlinked and is `True`; a link
  or any other non-plain entry gets the core's own refusal (marked for a symlink or a hard
  link, unmarked otherwise: `test_1111_rooted_io.O6_ROWS`) and is LEFT IN PLACE, so the reap
  scan still sees it.

Red before #1133: `rooted_write` takes no `durable=` (a `TypeError`) and `_io` has no
`rooted_unlink` (an `AttributeError`). The controls (a plain append makes no `fsync`) hold today.
"""
from __future__ import annotations

import errno
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from defender import _io
from defender.tests import _spec1133 as S

DEEP = PurePosixPath("a/b/rec.jsonl")
PRIOR = "prior row\n"
ROW = '{"row": "durable"}\n'


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


# ---------------------------------------------------------------------------------------
# durable append
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("prior", ["absent", "plain"])
def test_d2_a_durable_append_fsyncs_the_leaf_after_its_bytes_are_flushed_then_closes_it(
        scratch, prior):
    """`durable=True` fsyncs the LEAF's own descriptor (its inode is the record's), and at the
    moment it does, the leaf already holds every byte of this append: flushed first, synced
    second. The append lands after whatever was there (an absent record is created). After the
    call no descriptor of this process is still open on the record: the path closes what it
    opened.

    Control, same address: a plain append (no `durable`) makes no fsync at all (claim C5), so
    the fsync above is the flag's doing."""
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
        "the leaf was fsynced before its bytes were flushed to it — a sync of an empty buffer "
        "makes nothing durable")
    assert S.open_fds_on(leaf) == [], "the durable append left the record's descriptor open"

    control = FsyncSpy(leaf)
    _io.rooted_write(root, DEEP, ROW, mode="append", os_=control)
    assert control.fsyncs == [], "a plain append fsynced; the durable flag is not what syncs"
    assert leaf.read_text(encoding="utf-8") == before + ROW + ROW


@pytest.mark.parametrize("kind", ["symlink", "dangling", "hardlink", "fifo", "directory"])
def test_d2_a_durable_append_refuses_a_plant_at_the_leaf_in_the_cores_shape(scratch, kind):
    """The durable path is the append lane with a sync on the end, not a new lane: a plant at
    the name gets the core's own refusal row, nothing is synced, and nothing changes on disk
    (a dangling link's target is not created). Positive control: the plant removed, it lands."""
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


# ---------------------------------------------------------------------------------------
# rooted_unlink
# ---------------------------------------------------------------------------------------

def test_d2_rooted_unlink_removes_a_plain_file_and_answers_true(scratch):
    root, leaf, _host = scratch
    leaf.write_text(PRIOR, encoding="utf-8")
    assert _io.rooted_unlink(root, DEEP) is True
    assert not os.path.lexists(leaf), "a plain file was reported unlinked but is still there"
    assert (root / DEEP.parent).is_dir(), "the unlink took the holding folder with it"


def test_d2_rooted_unlink_of_an_absent_leaf_or_holding_folder_or_root_is_false(scratch, tmp_path):
    """An absent leaf and an absent holding folder are `False` (the design's two rows) and
    create nothing. So is an absent root (this suite's reading: nothing is there to remove)."""
    root, _leaf, _host = scratch
    before = S.census(tmp_path)
    assert _io.rooted_unlink(root, DEEP) is False
    assert _io.rooted_unlink(root, PurePosixPath("missing/folder/rec.jsonl")) is False
    assert _io.rooted_unlink(tmp_path / "no-such-root", DEEP) is False
    assert S.census(tmp_path) == before, "an unlink of nothing changed the tree"


_UNLINK_PLANTS = [pytest.param(k, None, id=k) for k in S.LEAF_PLANTS] + [
    pytest.param(k, PurePosixPath(f), id=f"{k}@{f}")
    for f in ("a", "a/b") for k in S.FOLDER_PLANTS]


@pytest.mark.parametrize(("kind", "site"), _UNLINK_PLANTS)
def test_d2_rooted_unlink_refuses_a_non_plain_entry_and_leaves_it_in_place(scratch, kind, site):
    """A symlink (dangling or not), a hard link, a FIFO or a directory at the name, and a
    symlinked or non-directory holding folder, each get the core's refusal row, never block,
    and are left exactly where they were: the plant, whatever a link reaches, a hard link's
    other name and its link count. Positive control on the same address: the plant removed and
    a plain file put there, the unlink removes it and answers True."""
    root, leaf, host = scratch
    if site is not None:
        (root / DEEP.parent).rmdir()
        (root / "a").rmdir()
    planted = S.plant(root, DEEP, site, kind, host=host)
    before = S.census(root.parent)

    raised = S.raised_by(lambda: _io.rooted_unlink(root, DEEP), fifo=planted.fifo)

    S.assert_refusal(raised, kind, where=f"rooted_unlink of a {kind}")
    assert S.census(root.parent) == before, "a refused unlink changed the tree"
    assert os.path.lexists(planted.at), "the refused plant was removed"
    if kind == "hardlink":
        assert os.lstat(leaf).st_nlink == 2, "the hard link's other name lost a link"

    planted.remove()
    (root / DEEP.parent).mkdir(parents=True, exist_ok=True)
    leaf.write_text(PRIOR, encoding="utf-8")
    assert _io.rooted_unlink(root, DEEP) is True
    assert not os.path.lexists(leaf)


def test_d2_rooted_unlink_follows_the_roots_own_spelling(scratch, tmp_path):
    """The root is host territory, opened following its spelling, as every rooted call's is."""
    root, leaf, _host = scratch
    leaf.write_text(PRIOR, encoding="utf-8")
    alias = tmp_path / "root-alias"
    alias.symlink_to(root, target_is_directory=True)
    assert _io.rooted_unlink(alias, DEEP) is True
    assert not os.path.lexists(leaf)
    assert alias.is_symlink(), "the root's own link was touched"


@pytest.mark.parametrize("name", ["", ".", "..", "../rec.jsonl", "/abs/rec.jsonl",
                                  "a/../rec.jsonl", "a//rec.jsonl"])
def test_d2_rooted_unlink_refuses_a_name_outside_the_grammar_before_any_io(scratch, name):
    """The rooted name grammar (`_parse_name`): a `ValueError` before anything is opened, and
    nothing is removed — the sibling `rec.jsonl` a `..` would reach stays."""
    root, leaf, _host = scratch
    leaf.write_text(PRIOR, encoding="utf-8")
    (root / "rec.jsonl").write_text(PRIOR, encoding="utf-8")
    before = S.census(root.parent)
    with pytest.raises(ValueError, match=S.NAME_REFUSAL):
        _io.rooted_unlink(root / "a", name)
    assert S.census(root.parent) == before


def test_d2_rooted_unlink_is_judged_on_the_entry_not_by_following_it(scratch):
    """The judge is a no-follow stat of the entry: a symlink to a plain file is refused (marked
    ELOOP) even though what it points at is plain, and the target keeps its bytes and its
    single link."""
    root, leaf, host = scratch
    target = host / "plain-target"
    target.write_text(PRIOR, encoding="utf-8")
    leaf.symlink_to(target)
    with pytest.raises(OSError, match="aliased") as refused:
        _io.rooted_unlink(root, DEEP)
    assert refused.value.errno == errno.ELOOP
    assert getattr(refused.value, "write_guarded_alias", False) is True
    assert stat.S_ISLNK(os.lstat(leaf).st_mode)
    assert target.read_text(encoding="utf-8") == PRIOR
    assert os.lstat(target).st_nlink == 1

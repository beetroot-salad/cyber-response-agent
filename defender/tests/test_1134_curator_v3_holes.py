"""#1134 v3 curator step: the scoped adversary's holes, closed (tests only).

Each row is the discriminating test for one exploit the adversary greened against the
tests-only commit `078be401` (patches in the session scratchpad, `s5v3-adv-patches/`):

- A1: an empty before-state (`{}`) is still a before-state: both restores remove the agent's
  file over it (the exploit read `not snapshot` as "no snapshot").
- A2 / D677: a tracked lesson whose name git would quote (non-ASCII, a quote, a backslash, a
  tab) or that is not UTF-8 is in the before-state by its own name, and the settle restore puts
  it back (the exploits parsed `ls-tree` without `-z`, or decoded names strictly).
- A3 / D1090: the fault sweep lists no folder by any route (an audit hook sees no `os.scandir`
  / `os.listdir` / `glob` while it runs) and meets a link to an outside folder at a new name
  (git reports it; its unlink is refused and logged) — the exploit swept a plain `os.walk`.
- A4: on the settle, a created name below a linked holding folder propagates the core's plain
  `ELOOP` (the exploit skipped any name whose folder listing was refused).
- A5: outside the lane's mounts `_put_back` plain-unlinks only a file (a dangling link or a
  FIFO there is left).
- A8: the settle restore's folder test is the held listing's: a link to an outside folder at a
  created name is the leaf refusal, never `IsADirectoryError` through a stat of the link.

A7 (an `os` lookup by `getattr` in `_git.py`), A9 (the rc in the git-failure warnings) and
D1090's non-`*.log` ignored name are closed in `test_1134_curator_handle.py` /
`test_1134_curator_drain.py` beside the rows they tighten.
"""
from __future__ import annotations

import errno
import logging
import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from defender.learning.author import drain
from defender.tests._curator1134 import (
    LESSONS_REL,
    is_link_to,
    leaf_refusal,
    lesson_text,
    move_out_and_link,
    plant_fifo,
    plant_link,
    put,
    warnings_naming,
    world,
)
from defender.tests.test_1111_rooted_io import raised_by

# ---------------------------------------------------------------------------------------
# A1: an empty before-state still sweeps and removes
# ---------------------------------------------------------------------------------------


def test_an_empty_before_state_still_sweeps_and_removes_the_agents_files(tmp_path):
    """A corpus the tick-start commit carries no regular file under has the before-state `{}`,
    and `{}` is a before-state, not "no snapshot": the fault restore sweeps the agent's file (git
    reports it) and the settle restore removes an unapproved one. Control: `None` restores
    nothing.

    Catches: a restore that returns early on any falsy snapshot (`if not snapshot`), leaving the
    agent's files to wedge the next tick's clean gate."""
    w = world(tmp_path)
    put(w.corpus_dir / "made.md", b"the agent's own\n")
    drain._restore_corpus(w.repo, w.corpus_dir, None, corpus=w.corpus, head_before=w.head())
    assert (w.corpus_dir / "made.md").exists()

    drain._restore_corpus(w.repo, w.corpus_dir, {}, corpus=w.corpus, head_before=w.head())
    assert not os.path.lexists(w.corpus_dir / "made.md")

    put(w.corpus_dir / "made2.md", b"the agent's own\n")
    drain._restore_unapproved_files(w.cfg(), {}, {f"{LESSONS_REL}made2.md"},
                                    head_before=w.head())
    assert not os.path.lexists(w.corpus_dir / "made2.md")


# ---------------------------------------------------------------------------------------
# A2 / D677: names git would quote, and names that are not UTF-8
# ---------------------------------------------------------------------------------------

#: Names `git ls-tree` quotes without `-z` (core.quotePath), and one that is not UTF-8.
ODD_NAMES = {
    "non-ascii": "café.md",
    "quote": 'say "hi".md',
    "backslash": "back\\slash.md",
    "tab": "a\ttab.md",
    "not-utf8": os.fsdecode(b"bad\xff.md"),
}


@pytest.mark.parametrize("label", sorted(ODD_NAMES))
def test_a_tracked_lesson_with_an_odd_name_is_in_the_before_state_and_restored(tmp_path, label):
    """A tracked lesson whose name git would quote, or which is not UTF-8, is in the
    before-state under its own name (as the filesystem spells it) with its bytes, beside a plain
    one; the agent's unapproved edit of it is put back by the settle restore, and a faulted
    tick's undo writes it back rather than sweeping it.

    Catches: a before-state parsed from quoted `ls-tree` output (the name fails the prefix and is
    dropped, so the settle restore deletes a tracked lesson), or one that decodes names strictly
    (a raw `UnicodeDecodeError`, which no probe wrapper turns into a stuck `GitProbeError`)."""
    name = ODD_NAMES[label]
    w = world(tmp_path)
    put(w.corpus_dir / name, lesson_text("f0"))
    put(w.corpus_dir / "plain.md", lesson_text("f1"))
    w.commit()

    snapshot = drain._snapshot_corpus(w.repo, w.corpus_dir, w.head())

    assert snapshot.get(name) == lesson_text("f0").encode(), sorted(snapshot)
    assert snapshot.get("plain.md") == lesson_text("f1").encode()

    put(w.corpus_dir / name, b"the agent's unapproved edit\n")
    drain._restore_unapproved_files(w.cfg(), snapshot, {f"{LESSONS_REL}{name}"},
                                    head_before=w.head())
    assert (w.corpus_dir / name).read_text() == lesson_text("f0")

    put(w.corpus_dir / name, b"the agent's edit before a fault\n")
    drain._undo_agent_edits(w.cfg(), snapshot, [], w.head())
    assert (w.corpus_dir / name).read_text() == lesson_text("f0")


# ---------------------------------------------------------------------------------------
# A3 / D1090: the fault sweep lists no folder, by any route
# ---------------------------------------------------------------------------------------

#: The audit events a folder listing raises (`os.walk` and `Path.rglob` go through `os.scandir`,
#: `Path.iterdir` through `os.listdir`; `glob` raises its own).
_LISTING_EVENTS = frozenset({"os.scandir", "os.listdir", "glob.glob", "glob.glob/2"})
_ARMED: list[list[tuple[str, tuple]]] = []


def _audit(event: str, args: tuple) -> None:
    if _ARMED and event in _LISTING_EVENTS:
        _ARMED[-1].append((event, args))


_HOOKED: list[bool] = []


@contextmanager
def _listings() -> Iterator[list[tuple[str, tuple]]]:
    """Every folder listing this process makes while the block runs. The hook is added once per
    process and records nothing unless a block is open (a hook cannot be removed)."""
    if not _HOOKED:
        sys.addaudithook(_audit)
        _HOOKED.append(True)
    seen: list[tuple[str, tuple]] = []
    _ARMED.append(seen)
    try:
        yield seen
    finally:
        _ARMED.pop()


def test_the_fault_sweep_makes_no_folder_listing_and_meets_a_linked_folder(tmp_path, caplog):
    """C1, by any route: while `_restore_corpus` runs, the process lists no folder (no
    `os.scandir` / `os.listdir` / `glob` audit event — git's own walk runs in its own process),
    yet it sweeps the agent's stray, a nested stray and a stray under an ignored-looking name
    git does report, rewrites the changed lesson, and meets the link to an outside FOLDER the
    agent left at a new name: git reports it, its unlink is refused, logged by name, and the
    link is left.

    Catches: a sweep whose names come from a plain-path walk (`os.walk` + `lstat`, minus `git
    check-ignore`) behind a `git status` call made only to decide whether git answered: the walk
    lists folders, and files the linked folder under its folders, never meeting it."""
    caplog.set_level(logging.WARNING)
    w = world(tmp_path)
    put(w.corpus_dir / "a.md", lesson_text("fa"))
    w.commit()
    snapshot = drain._snapshot_corpus(w.repo, w.corpus_dir, w.head())
    held = w.corpus
    put(w.corpus_dir / "a.md", b"rewritten by the agent\n")
    put(w.corpus_dir / "stray.md", b"new\n")
    put(w.corpus_dir / "deep" / "er" / "x.md", b"new\n")
    put(w.corpus_dir / "notes.log", b"not ignored here, so git reports it\n")
    outdir = w.outside / "dir"
    outdir.mkdir(parents=True)
    plant_link(w.corpus_dir / "dirlink", outdir)

    with _listings() as seen:
        drain._restore_corpus(w.repo, w.corpus_dir, snapshot, corpus=held, head_before=w.head())

    assert seen == [], seen
    assert not os.path.lexists(w.corpus_dir / "stray.md")
    assert not os.path.lexists(w.corpus_dir / "deep" / "er" / "x.md")
    assert not os.path.lexists(w.corpus_dir / "notes.log")
    assert (w.corpus_dir / "a.md").read_text() == lesson_text("fa")
    assert is_link_to(w.corpus_dir / "dirlink", outdir)
    assert warnings_naming(caplog, "dirlink"), caplog.text


def test_the_listing_watch_sees_a_walk(tmp_path):
    """The positive control for the audit watch: an `os.walk` and a `Path.iterdir` inside the
    block are both recorded."""
    (tmp_path / "d").mkdir()
    with _listings() as seen:
        list(os.walk(tmp_path))
        list((tmp_path / "d").iterdir())
    events = [e for e, _ in seen]
    assert "os.scandir" in events, events  # os.walk
    assert "os.listdir" in events, events  # Path.iterdir (3.11)


# ---------------------------------------------------------------------------------------
# A4 / A8: the settle restore's kind check and unlink
# ---------------------------------------------------------------------------------------


def test_a_created_name_below_a_linked_folder_propagates_on_the_settle(tmp_path):
    """O5.3's non-fault rule: a created name (not in the before-state) below a holding folder
    the agent moved outside and linked back is handed to the corpus `unlink`, whose plain
    `OSError(ELOOP)` propagates; the link and what the moved folder holds are left.

    Catches: a settle restore that skips any name whose folder listing is refused, so the tick
    goes on and commits with the plant in place."""
    w = world(tmp_path)
    put(w.corpus_dir / "sub" / "keep.md", lesson_text("f0"))
    w.commit()
    snapshot = drain._snapshot_corpus(w.repo, w.corpus_dir, w.head())
    moved = w.outside / "moved-sub"
    move_out_and_link(w.corpus_dir / "sub", moved)
    put(moved / "new.md", lesson_text("f1"))

    exc = raised_by(lambda: drain._restore_unapproved_files(
        w.cfg(), snapshot, {f"{LESSONS_REL}sub/new.md"}, head_before=w.head()))

    assert isinstance(exc, OSError), repr(exc)
    assert exc.errno == errno.ELOOP, repr(exc)
    assert type(exc).__name__ != "NotPlainEntry"
    assert is_link_to(w.corpus_dir / "sub", moved)
    assert (moved / "new.md").read_text() == lesson_text("f1")


def test_a_link_to_a_folder_at_a_created_name_is_the_leaf_refusal_on_the_settle(tmp_path):
    """The settle restore's folder test is the held listing's (`entry_kind`): a symlink to an
    outside FOLDER at a created name is no folder there, so the corpus `unlink` refuses it
    (`NotPlainEntry`) and the link is left. Control: a real folder at a created name keeps
    `IsADirectoryError` (`test_an_unapproved_new_name_holding_a_folder_keeps_...`).

    Catches: a folder test that stats through the link (`os.path.isdir`), answering
    `IsADirectoryError`."""
    w = world(tmp_path)
    snapshot = drain._snapshot_corpus(w.repo, w.corpus_dir, w.head())
    outdir = w.outside / "dir"
    outdir.mkdir(parents=True)
    plant_link(w.corpus_dir / "dirlink.md", outdir)

    exc = raised_by(lambda: drain._restore_unapproved_files(
        w.cfg(), snapshot, {f"{LESSONS_REL}dirlink.md"}, head_before=w.head()))

    assert leaf_refusal(exc), repr(exc)
    assert is_link_to(w.corpus_dir / "dirlink.md", outdir)


# ---------------------------------------------------------------------------------------
# A5: outside the lane's mounts only a file is plain-unlinked
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["dangling link", "fifo", "plain file"])
def test_put_back_outside_the_mounts_unlinks_only_a_file(tmp_path, kind):
    """D3: an untracked name outside the lane's mounts keeps its plain path, and `_put_back`
    removes it only when it is a file (as main's `is_file()` did): a dangling link or a FIFO
    there is left. Positive control: a plain file at the same name is removed.

    Catches: a `_put_back` that plain-unlinks anything but a folder outside the mounts."""
    w = world(tmp_path)
    at = w.repo / "defender" / "stray-entry"
    if kind == "fifo":
        plant_fifo(at)
    elif kind == "dangling link":
        plant_link(at, w.outside / "nothing-here")
    else:
        put(at, b"a stray file\n")

    drain._put_back(w.repo, "defender/stray-entry", tree_for=w.tree_for)

    if kind == "plain file":
        assert not os.path.lexists(at)
        return
    assert os.path.lexists(at)
    if kind == "fifo":
        assert stat.S_ISFIFO(os.lstat(at).st_mode)
    else:
        assert os.path.islink(at)

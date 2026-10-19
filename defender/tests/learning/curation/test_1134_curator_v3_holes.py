"""#1134 curator step: adversary regressions (empty before-state still restores, odd lesson names, fault sweep
lists no folder, linked folders on the settle, put-back outside the mounts)."""
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
from defender.tests.support.learning.curation._curator1134 import (
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
from defender.tests.shared.filesystem.test_1111_rooted_io import raised_by


def test_an_empty_before_state_still_sweeps_and_removes_the_agents_files(tmp_path):
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


def test_a_created_name_below_a_linked_folder_propagates_on_the_settle(tmp_path):
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
    w = world(tmp_path)
    snapshot = drain._snapshot_corpus(w.repo, w.corpus_dir, w.head())
    outdir = w.outside / "dir"
    outdir.mkdir(parents=True)
    plant_link(w.corpus_dir / "dirlink.md", outdir)

    exc = raised_by(lambda: drain._restore_unapproved_files(
        w.cfg(), snapshot, {f"{LESSONS_REL}dirlink.md"}, head_before=w.head()))

    assert leaf_refusal(exc), repr(exc)
    assert is_link_to(w.corpus_dir / "dirlink.md", outdir)


@pytest.mark.parametrize("kind", ["dangling link", "fifo", "plain file"])
def test_put_back_outside_the_mounts_unlinks_only_a_file(tmp_path, kind):
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

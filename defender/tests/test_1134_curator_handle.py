from __future__ import annotations

import dataclasses
import errno
import logging
import os
import re
import shutil
import stat
from pathlib import Path

import pytest

from defender import _git
from defender._git import GitError
from defender._io import NotPlainEntry
from defender.learning.author import drain
from defender.learning.author import shared as author_shared
from defender.learning.author.lessons import run as lessons_run
from defender.learning.author.questioner import run as questioner_run
from defender.tests._curator1134 import (
    LESSONS_REL,
    OUT_MARK,
    SIBLING_REL,
    FailsOn,
    JournalHeld,
    RecordingOs,
    alias_left,
    clear,
    is_link_to,
    leaf_refusal,
    lesson_text,
    move_out_and_link,
    plant_alias,
    plant_fifo,
    plant_folder,
    plant_hardlink,
    plant_link,
    put,
    questioner_cfg,
    seamed_trees,
    warnings_naming,
    world,
)
from defender.tests._shared_readers_1134 import kernel_watch
from defender.tests.test_1111_rooted_io import census, in_time, raised_by


#: The lesson name every row plants at: distinctive, so a log line naming it names this entry.
PLANTED = "planted-lesson.md"
FIELD = "source_finding_ids"


def _no_mark_in(snapshot: dict[str, bytes] | None) -> bool:
    return not any(OUT_MARK.encode() in blob for blob in (snapshot or {}).values())


def _corpus_holds_mark(root: Path) -> list[str]:
    """Every regular file under `root` (never following a link) whose bytes carry the mark."""
    return [key for key, row in census(root).items()
            if row[0] == "file" and OUT_MARK.encode() in row[1]]


def _rel(name: str) -> str:
    return f"{LESSONS_REL}{name}"


def _snap(w) -> dict[str, bytes]:
    """The before-state the tick takes: `_snapshot_corpus` over the world's corpus at HEAD (the
    tick-start commit, once whatever the row set up is committed)."""
    return drain._snapshot_corpus(w.repo, w.corpus_dir, w.head())


def _drop_blob(w, rel: str) -> None:
    """Remove `rel`'s blob at HEAD from the object store (a loose object, in a fresh repo): git
    can no longer read it, while the worktree and the index's stat cache still say clean."""
    oid = w.git("rev-parse", f"HEAD:{rel}").stdout.strip()
    (w.repo / ".git" / "objects" / oid[:2] / oid[2:]).unlink()


def _watch_for(kind: str, target: Path):
    """The watch that sees a plant followed: no open of a symlink's (or a moved folder's)
    target; no read of a hard link's shared inode (which the no-follow open does reach)."""
    return kernel_watch(reads=[target]) if kind == "hard link" else kernel_watch(opens=[target])


def _plain_os_error(exc: BaseException | None, code: int) -> bool:
    """`exc` is an `OSError` carrying `code` that is NOT the core's leaf refusal: the kind of
    fault O5.3 never passes over."""
    return isinstance(exc, OSError) and type(exc) is not NotPlainEntry and exc.errno == code


def test_o3_a_lesson_linked_outside_is_not_snapshotted_and_the_undo_leaves_it(tmp_path, caplog):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    cfg = w.cfg()
    put(w.corpus_dir / "kept.md", lesson_text("f0"))
    w.commit()
    target = w.target("secret.md")
    link = w.corpus_dir / PLANTED
    plant_link(link, target)
    head_before = w.head()
    before = census(w.outside)

    with kernel_watch(opens=[target]) as events:
        snapshot = _snap(w)
        drain._undo_agent_edits(cfg, snapshot, [], head_before)
        seen = events()

    assert snapshot is not None
    assert PLANTED not in snapshot
    assert _no_mark_in(snapshot)
    assert snapshot["kept.md"] == lesson_text("f0").encode()
    assert seen == [], f"the link's target was opened or read: {seen}"
    assert census(w.outside) == before, "the link's target was written"
    assert is_link_to(link, target), "the planted link was not left in place"
    assert warnings_naming(caplog, PLANTED), caplog.text


@pytest.mark.parametrize("agent_did", ["replaced the link with a file", "deleted the link"])
def test_o3_no_restore_writes_the_targets_bytes_back_into_the_corpus(tmp_path, agent_did):
    w = world(tmp_path)
    cfg = w.cfg()
    target = w.target("secret.md")
    link = w.corpus_dir / PLANTED
    plant_link(link, target)
    head_before = w.head()
    before = census(w.outside)

    snapshot = _snap(w)
    clear(link)
    if agent_did == "replaced the link with a file":
        put(link, lesson_text("f1", mark="the agent's own bytes"))
    drain._undo_agent_edits(cfg, snapshot, [], head_before)

    assert _corpus_holds_mark(w.corpus_dir) == []
    assert not os.path.lexists(link), "a name the snapshot never held was not swept"
    assert census(w.outside) == before


def test_o3_control_a_plain_lesson_is_snapshotted_and_restored_byte_identically(tmp_path):
    """The positive control at the same name: a plain file is snapshotted with its exact bytes
    and, once the agent has changed it, the undo restores it byte for byte."""
    w = world(tmp_path)
    cfg = w.cfg()
    at = w.corpus_dir / PLANTED
    original = lesson_text("f1", mark=OUT_MARK).encode() + b"\r\n\x00tail"
    put(at, original)
    w.commit()
    head_before = w.head()

    snapshot = _snap(w)
    put(at, b"the agent rewrote it\n")
    drain._undo_agent_edits(cfg, snapshot, [], head_before)

    assert snapshot is not None
    assert snapshot[PLANTED] == original
    assert at.read_bytes() == original
    assert not at.is_symlink()


def test_the_before_state_is_every_regular_blob_head_carries_nested_and_byte_exact(tmp_path):
    w = world(tmp_path)
    files = {"top.md": b"top\n", "nested/deep/l1.md": b"deep\r\n",
             "notes.txt": b"\xff\xfe raw\x00"}
    for name, data in files.items():
        put(w.corpus_dir / name, data)
    put(w.corpus_dir / "run.sh", b"#!/bin/sh\n")
    os.chmod(w.corpus_dir / "run.sh", 0o755)
    put(w.sibling_dir / "s.md", b"sibling\n")
    w.commit()

    assert _snap(w) == {".gitkeep": b"", **files, "run.sh": b"#!/bin/sh\n"}


@pytest.mark.parametrize("kind", ["symlink", "hard link", "fifo", "plain rewrite", "removed"])
def test_the_before_state_reads_no_worktree_entry(tmp_path, kind):
    w = world(tmp_path)
    body = lesson_text("fa").encode()
    put(w.corpus_dir / "a.md", body)
    w.commit()
    at = w.corpus_dir / "a.md"
    target = w.target("secret.md")
    fifo = None
    if kind in ("symlink", "hard link"):
        plant_alias(kind, at, target)
    elif kind == "fifo":
        plant_fifo(at)
        fifo = at
    elif kind == "plain rewrite":
        put(at, b"the agent's bytes\n")
    else:
        clear(at)

    with _watch_for("hard link" if kind == "hard link" else "symlink", target) as events:
        snapshot = in_time(lambda: _snap(w), fifo=fifo)
        seen = events()

    assert snapshot == {".gitkeep": b"", "a.md": body}
    assert seen == [], f"the plant was followed: {seen}"


@pytest.mark.parametrize("agent_did", ["replaced the link with a file", "deleted the link"])
def test_a_tracked_symlink_is_not_in_the_before_state_and_never_restored_as_a_file(
    tmp_path, agent_did,
):
    w = world(tmp_path)
    target = w.target("secret.md")
    link = w.corpus_dir / PLANTED
    plant_link(link, target)
    w.commit()
    assert w.head_mode(_rel(PLANTED)) == "120000"
    head_before = w.head()
    before = census(w.outside)

    snapshot = _snap(w)
    clear(link)
    if agent_did == "replaced the link with a file":
        put(link, lesson_text("f1", mark="the agent's own bytes"))
    drain._undo_agent_edits(w.cfg(), snapshot, [], head_before)

    assert PLANTED not in snapshot
    assert not os.path.lexists(link)
    assert _corpus_holds_mark(w.corpus_dir) == []
    assert census(w.outside) == before


def test_a_submodule_entry_is_not_in_the_before_state(tmp_path):
    """A submodule (gitlink, mode 160000) committed under the corpus is no regular blob: it is
    left out of the before-state, beside a plain lesson that is in it."""
    w = world(tmp_path)
    put(w.corpus_dir / "a.md", b"plain\n")
    w.commit()
    w.git("update-index", "--add", "--cacheinfo", f"160000,{w.head()},{_rel('sm')}")
    w.git("commit", "-q", "-m", "a gitlink in the corpus")
    assert w.head_mode(_rel("sm")) == "160000"

    assert _snap(w) == {".gitkeep": b"", "a.md": b"plain\n"}


def test_the_before_state_is_the_commit_it_is_given(tmp_path):
    """`head` is the tick-start commit: a later commit that rewrites one lesson, adds another and
    removes a third does not change the before-state read at the earlier commit."""
    w = world(tmp_path)
    put(w.corpus_dir / "a.md", b"a at start\n")
    put(w.corpus_dir / "gone.md", b"removed later\n")
    w.commit()
    start = w.head()
    put(w.corpus_dir / "a.md", b"a later\n")
    put(w.corpus_dir / "new.md", b"added later\n")
    clear(w.corpus_dir / "gone.md")
    w.commit("later")

    assert drain._snapshot_corpus(w.repo, w.corpus_dir, start) == {
        ".gitkeep": b"", "a.md": b"a at start\n", "gone.md": b"removed later\n"}
    assert _snap(w) == {".gitkeep": b"", "a.md": b"a later\n", "new.md": b"added later\n"}


def test_a_corpus_the_commit_does_not_carry_is_an_empty_before_state(tmp_path):
    """A corpus folder the commit carries nothing under (never committed) is an empty
    before-state, not an error: every name the agent makes there is its own."""
    w = world(tmp_path)
    fresh = w.repo / "defender" / "lessons-fresh"
    put(fresh / "untracked.md", b"never committed\n")

    assert drain._snapshot_corpus(w.repo, fresh, w.head()) == {}


@pytest.mark.parametrize("fault", ["missing blob", "unknown commit"])
def test_a_before_state_git_cannot_read_raises(tmp_path, fault):
    w = world(tmp_path)
    put(w.corpus_dir / "a.md", lesson_text("fa"))
    put(w.corpus_dir / "b.md", lesson_text("fb"))
    w.commit()
    head = w.head()
    if fault == "missing blob":
        _drop_blob(w, _rel("a.md"))
    else:
        head = "0" * 40

    with pytest.raises(GitError):
        drain._snapshot_corpus(w.repo, w.corpus_dir, head)


def _baseline(w) -> dict[str, bytes]:
    """The corpus at tick start, committed, and its snapshot."""
    put(w.corpus_dir / "a.md", lesson_text("fa"))
    put(w.corpus_dir / "b.md", lesson_text("fb"))
    w.commit()
    snapshot = _snap(w)
    assert snapshot is not None
    return snapshot


def _restore(w, snapshot, corpus=None, head_before=None) -> None:
    """The fault path's `_restore_corpus` over the world's corpus; the before-state's commit is
    HEAD unless the row names another."""
    drain._restore_corpus(w.repo, w.corpus_dir, snapshot,
                          corpus=corpus if corpus is not None else w.corpus,
                          head_before=head_before if head_before is not None else w.head())


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_restore_sweep_leaves_a_stray_alias_logs_it_and_removes_a_plain_stray(
    tmp_path, kind, caplog,
):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    snapshot = _baseline(w)
    target = w.target("secret.md")
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)
    put(w.corpus_dir / "stray-plain.md", b"agent wrote this\n")
    before = census(w.outside)

    with _watch_for(kind, target) as events:
        _restore(w, snapshot)
        seen = events()

    assert alias_left(kind, at, target), f"the {kind} was deleted"
    assert not (w.corpus_dir / "stray-plain.md").exists()
    assert warnings_naming(caplog, PLANTED), caplog.text
    assert seen == []
    assert census(w.outside) == before


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_restore_leaves_an_alias_at_a_snapshot_name_and_restores_the_rest(
    tmp_path, kind, caplog,
):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    snapshot = _baseline(w)
    target = w.target("secret.md", lesson_text("fa", mark=OUT_MARK))
    at = w.corpus_dir / "a.md"
    plant_alias(kind, at, target)
    put(w.corpus_dir / "b.md", b"rewritten by the agent\n")
    before = census(w.outside)

    with _watch_for(kind, target) as events:
        _restore(w, snapshot)
        seen = events()

    assert (w.corpus_dir / "b.md").read_bytes() == snapshot["b.md"]
    assert alias_left(kind, at, target)
    assert warnings_naming(caplog, "a.md"), caplog.text
    if kind == "symlink":
        assert seen == []
    assert census(w.outside) == before
    assert [n for n in _corpus_holds_mark(w.corpus_dir) if n != "a.md"] == []


def test_the_restore_control_rewrites_a_changed_and_a_deleted_snapshot_file(tmp_path):
    w = world(tmp_path)
    snapshot = _baseline(w)
    put(w.corpus_dir / "a.md", b"rewritten\n")
    clear(w.corpus_dir / "b.md")
    put(w.corpus_dir / "c.md", b"new\n")

    _restore(w, snapshot)

    assert (w.corpus_dir / "a.md").read_bytes() == snapshot["a.md"]
    assert (w.corpus_dir / "b.md").read_bytes() == snapshot["b.md"]
    assert not (w.corpus_dir / "c.md").exists()


@pytest.mark.parametrize("at_snapshot_name", [True, False], ids=["snapshot-name", "stray-name"])
def test_a_fifo_in_the_corpus_is_passed_over_on_the_fault_path(tmp_path, at_snapshot_name, caplog):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    snapshot = _baseline(w)
    name = "a.md" if at_snapshot_name else PLANTED
    at = w.corpus_dir / name
    plant_fifo(at)
    put(w.corpus_dir / "b.md", b"rewritten by the agent\n")

    exc = raised_by(lambda: _restore(w, snapshot), fifo=at)

    assert exc is None, repr(exc)
    assert stat.S_ISFIFO(os.lstat(at).st_mode)
    assert (w.corpus_dir / "b.md").read_bytes() == snapshot["b.md"]
    assert bool(warnings_naming(caplog, name)) is at_snapshot_name, caplog.text


def test_a_folder_at_a_snapshot_name_is_passed_over_on_the_fault_path(tmp_path, caplog):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    snapshot = _baseline(w)
    plant_folder(w.corpus_dir / "a.md")
    put(w.corpus_dir / "b.md", b"rewritten by the agent\n")

    _restore(w, snapshot)

    assert (w.corpus_dir / "a.md").is_dir()
    assert (w.corpus_dir / "b.md").read_bytes() == snapshot["b.md"]
    assert warnings_naming(caplog, "a.md"), caplog.text


def test_a_linked_folder_holding_a_snapshot_name_replaces_the_fault(tmp_path, caplog):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    put(w.corpus_dir / "sub" / "a.md", lesson_text("fa"))
    w.commit()
    snapshot = _snap(w)
    moved = w.outside / "moved-sub"
    move_out_and_link(w.corpus_dir / "sub", moved)
    put(moved / "a.md", lesson_text("fa", mark=OUT_MARK))
    before = census(w.outside)

    exc = raised_by(lambda: _restore(w, snapshot))

    assert _plain_os_error(exc, errno.ELOOP), repr(exc)
    assert is_link_to(w.corpus_dir / "sub", moved)
    assert census(w.outside) == before


@pytest.mark.parametrize(("verb", "code"), [
    ("rename", errno.ENOSPC), ("unlink", errno.EIO), ("unlink", errno.EACCES),
], ids=["rewrite-ENOSPC", "sweep-EIO", "sweep-EACCES"])
def test_a_failing_disk_on_the_fault_path_restore_propagates(tmp_path, verb, code):
    w = world(tmp_path)
    snapshot = _baseline(w)
    if verb == "rename":
        put(w.corpus_dir / "a.md", b"rewritten by the agent\n")
    else:
        put(w.corpus_dir / PLANTED, b"agent wrote this\n")
    seam = FailsOn(verb, code)
    trees = seamed_trees(w.paths, seam)
    cfg = dataclasses.replace(w.cfg(), corpus=trees.mount(w.corpus_dir))

    exc = raised_by(lambda: drain._undo_agent_edits(cfg, snapshot, [], w.head()))

    assert _plain_os_error(exc, code), repr(exc)
    assert seam.raised >= 1


def test_the_restore_sweep_empties_a_new_folder_and_leaves_it(tmp_path):
    """A folder the agent made is left; the plain file in it, which the snapshot never held and
    git reports, is removed."""
    w = world(tmp_path)
    snapshot = _baseline(w)
    put(w.corpus_dir / "newdir" / "x.md", b"new\n")

    _restore(w, snapshot)

    assert (w.corpus_dir / "newdir").is_dir()
    assert not (w.corpus_dir / "newdir" / "x.md").exists()


def test_the_fault_restore_puts_back_nested_lessons_and_sweeps_nested_strays(tmp_path):
    w = world(tmp_path)
    put(w.corpus_dir / "nested" / "deep" / "l1.md", lesson_text("f0", mark="original"))
    put(w.corpus_dir / "nested" / "l2.md", b"second\r\n")
    w.commit()
    snapshot = _snap(w)
    put(w.corpus_dir / "nested" / "deep" / "l1.md", b"the agent's edit\n")
    clear(w.corpus_dir / "nested" / "l2.md")
    put(w.corpus_dir / "nested" / "deep" / "new.md", b"the agent's own\n")
    put(w.corpus_dir / "fresh" / "deeper" / "x.md", b"the agent's own\n")

    _restore(w, snapshot)

    assert (w.corpus_dir / "nested/deep/l1.md").read_bytes() == snapshot["nested/deep/l1.md"]
    assert (w.corpus_dir / "nested/l2.md").read_bytes() == b"second\r\n"
    assert not (w.corpus_dir / "nested/deep/new.md").exists()
    assert not (w.corpus_dir / "fresh/deeper/x.md").exists()
    assert w.git("status", "--porcelain", "--", str(w.corpus_dir)).stdout == ""


def test_a_gitignored_name_the_agent_made_survives_the_fault_restore(tmp_path):
    w = world(tmp_path)
    put(w.corpus_dir / ".gitignore", "*.log\n__pycache__/\n")
    snapshot = _baseline(w)
    put(w.corpus_dir / "x.log", b"ignored by git\n")
    put(w.corpus_dir / "__pycache__" / "y.cpython-311.pyc", b"ignored by git too\n")
    put(w.corpus_dir / "y.md", b"the agent's own\n")

    _restore(w, snapshot)

    assert (w.corpus_dir / "x.log").read_bytes() == b"ignored by git\n"
    assert (w.corpus_dir / "__pycache__" / "y.cpython-311.pyc").exists()
    assert not (w.corpus_dir / "y.md").exists()


@pytest.mark.parametrize("broken", ["index is a folder", "index is garbage"])
def test_a_broken_index_still_sweeps_through_gits_worktree_listing(tmp_path, broken, caplog):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    put(w.corpus_dir / ".gitignore", "*.log\n")
    target = w.target("secret.md")
    plant_link(w.corpus_dir / "tracked-link.md", target)
    snapshot = _baseline(w)
    put(w.corpus_dir / "a.md", b"rewritten by the agent\n")
    clear(w.corpus_dir / "b.md")
    put(w.corpus_dir / "stray.md", b"new\n")
    put(w.corpus_dir / "newdir" / "deep" / "x.md", b"new\n")
    put(w.corpus_dir / "x.log", b"ignored\n")
    index = w.repo / ".git" / "index"
    index.unlink()
    if broken == "index is a folder":
        index.mkdir()
    else:
        index.write_bytes(b"not an index\n")
    git_dir_before = sorted(p.name for p in (w.repo / ".git").iterdir())

    exc = raised_by(lambda: _restore(w, snapshot))

    assert exc is None, repr(exc)
    assert not (w.corpus_dir / "stray.md").exists()
    assert not (w.corpus_dir / "newdir" / "deep" / "x.md").exists()
    assert (w.corpus_dir / "x.log").read_bytes() == b"ignored\n"
    assert is_link_to(w.corpus_dir / "tracked-link.md", target)
    assert warnings_naming(caplog, "tracked-link.md"), caplog.text
    assert (w.corpus_dir / "a.md").read_bytes() == snapshot["a.md"]
    assert (w.corpus_dir / "b.md").read_bytes() == snapshot["b.md"]
    said = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(re.search(r"git status[^\n]*rc=\d+", m) for m in said), said
    assert not any(str(w.tmp) in m for m in said), said
    assert sorted(p.name for p in (w.repo / ".git").iterdir()) == git_dir_before


def test_a_restore_git_cannot_answer_at_all_sweeps_nothing_but_still_rewrites(tmp_path, caplog):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    snapshot = _baseline(w)
    put(w.corpus_dir / "a.md", b"rewritten by the agent\n")
    clear(w.corpus_dir / "b.md")
    put(w.corpus_dir / "stray.md", b"new\n")
    head = w.head()
    shutil.move(str(w.repo / ".git"), str(w.tmp / "git-moved-away"))

    exc = raised_by(lambda: _restore(w, snapshot, head_before=head))

    assert exc is None, repr(exc)
    assert (w.corpus_dir / "stray.md").read_bytes() == b"new\n"
    assert (w.corpus_dir / "a.md").read_bytes() == snapshot["a.md"]
    assert (w.corpus_dir / "b.md").read_bytes() == snapshot["b.md"]
    said = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(re.search(r"git status\D*rc=\d+", m) and re.search(r"ls-files\D*rc=\d+", m)
               for m in said), said
    assert any(re.search(r"git diff\D*rc=\d+", m) for m in said), said
    assert not any(str(w.tmp) in m for m in said), said


def test_the_restore_does_nothing_without_a_snapshot(tmp_path):
    """No snapshot (the corpus folder was absent at tick start): nothing is swept."""
    w = world(tmp_path)
    put(w.corpus_dir / "stray.md", b"new\n")
    _restore(w, None)
    assert (w.corpus_dir / "stray.md").read_bytes() == b"new\n"


def _unapproved(w, cfg, snapshot, *rels: str) -> None:
    """The settle restore over `rels`, the before-state's commit being HEAD."""
    drain._restore_unapproved_files(cfg, snapshot, set(rels), head_before=w.head())


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_an_unapproved_new_name_holding_a_link_is_refused_and_the_refusal_propagates(
    tmp_path, kind,
):
    w = world(tmp_path)
    cfg = w.cfg()
    snapshot = _snap(w)
    target = w.target("secret.md")
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)

    exc = raised_by(lambda: _unapproved(w, cfg, snapshot, _rel(PLANTED)))

    assert leaf_refusal(exc), repr(exc)
    assert alias_left(kind, at, target)


def test_an_unapproved_new_name_holding_a_fifo_is_refused(tmp_path):
    """A FIFO at an unapproved new name: `cfg.corpus.unlink` refuses it (`NotPlainEntry`), the
    refusal propagates, the FIFO is never opened and is left."""
    w = world(tmp_path)
    cfg = w.cfg()
    snapshot = _snap(w)
    at = w.corpus_dir / PLANTED
    plant_fifo(at)

    exc = raised_by(lambda: _unapproved(w, cfg, snapshot, _rel(PLANTED)),
                    fifo=at)

    assert leaf_refusal(exc), repr(exc)
    assert stat.S_ISFIFO(os.lstat(at).st_mode)


def test_an_unapproved_new_name_holding_a_folder_keeps_todays_is_a_directory_error(tmp_path):
    """A folder at an unapproved new name: `IsADirectoryError` exactly (today's type, pinned by
    `test_773_repair_pass`), and the folder is left."""
    w = world(tmp_path)
    cfg = w.cfg()
    snapshot = _snap(w)
    plant_folder(w.corpus_dir / PLANTED)

    exc = raised_by(lambda: _unapproved(w, cfg, snapshot, _rel(PLANTED)))

    assert type(exc) is IsADirectoryError, repr(exc)
    assert (w.corpus_dir / PLANTED).is_dir()


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_an_unapproved_changed_name_holding_a_link_is_refused_and_copied_nowhere(tmp_path, kind):
    w = world(tmp_path)
    cfg = w.cfg()
    put(w.corpus_dir / PLANTED, lesson_text("f0"))
    w.commit()
    snapshot = _snap(w)
    target = w.target("secret.md")
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)
    before = census(w.outside)

    with _watch_for(kind, target) as events:
        exc = raised_by(lambda: _unapproved(w, cfg, snapshot, _rel(PLANTED)))
        seen = events()

    assert leaf_refusal(exc), repr(exc)
    if kind == "symlink":
        assert seen == []
    assert alias_left(kind, at, target)
    assert census(w.outside) == before
    assert [n for n in _corpus_holds_mark(w.corpus_dir) if n != PLANTED] == []


def test_the_unapproved_restore_control_removes_new_and_rewrites_changed_plain_files(tmp_path):
    """The positive control at the same names: a new plain file is removed; a changed one, and
    one the agent deleted, are rewritten to their snapshot bytes; nothing is refused."""
    w = world(tmp_path)
    cfg = w.cfg()
    put(w.corpus_dir / "old.md", lesson_text("f0"))
    put(w.corpus_dir / "gone.md", lesson_text("f9"))
    w.commit()
    snapshot = _snap(w)
    put(w.corpus_dir / PLANTED, lesson_text("f1"))
    put(w.corpus_dir / "old.md", b"changed\n")
    clear(w.corpus_dir / "gone.md")

    _unapproved(w, cfg, snapshot, _rel(PLANTED), _rel("old.md"), _rel("gone.md"))

    assert not (w.corpus_dir / PLANTED).exists()
    assert (w.corpus_dir / "old.md").read_bytes() == snapshot["old.md"]
    assert (w.corpus_dir / "gone.md").read_bytes() == snapshot["gone.md"]


def _settle(step: str, cfg, snapshot, rel: str) -> None:
    assert step == "_restore_unapproved_files", step
    head = _git.git_head_sha(cfg.repo_root)
    drain._restore_unapproved_files(cfg, snapshot, {rel}, head_before=head)


@pytest.mark.parametrize("agent_left", ["nothing", "its own bytes"])
@pytest.mark.parametrize("step", ["_restore_unapproved_files"])
def test_a_settle_restore_below_a_linked_folder_is_refused_and_writes_nothing_outside(
    tmp_path, step, agent_left,
):
    w = world(tmp_path)
    put(w.corpus_dir / "sub" / "a.md", lesson_text("fa"))
    w.commit()
    cfg = w.cfg()
    snapshot = _snap(w)
    moved = w.outside / "moved-sub"
    move_out_and_link(w.corpus_dir / "sub", moved)
    if agent_left == "nothing":
        clear(moved / "a.md")
    else:
        put(moved / "a.md", lesson_text("fa", mark=OUT_MARK))
    before = census(w.outside)

    exc = raised_by(lambda: _settle(step, cfg, snapshot, _rel("sub/a.md")))

    assert _plain_os_error(exc, errno.ELOOP), repr(exc)
    assert is_link_to(w.corpus_dir / "sub", moved)
    assert census(w.outside) == before


def test_a_symlink_holding_head_identical_bytes_is_never_byte_identical(tmp_path):
    w = world(tmp_path)
    body = lesson_text("f0", mark=OUT_MARK)
    put(w.corpus_dir / "t.md", body)
    w.commit()
    target = w.target("same-bytes.md", body)
    plant_link(w.corpus_dir / "t.md", target)

    with kernel_watch(opens=[target]) as events:
        got = drain._byte_identical_to_head(w.repo, _rel("t.md"))
        seen = events()

    assert got is False
    assert seen == []
    assert is_link_to(w.corpus_dir / "t.md", target)


@pytest.mark.parametrize("bytes_held", ["head's", "other"])
def test_a_hard_link_is_compared_by_its_content_as_git_hashes_it(tmp_path, bytes_held):
    w = world(tmp_path)
    body = lesson_text("f0")
    put(w.corpus_dir / "t.md", body)
    w.commit()
    target = w.target("hard.md", body if bytes_held == "head's" else lesson_text("f9"))
    plant_hardlink(w.corpus_dir / "t.md", target)
    before = census(w.outside)

    got = drain._byte_identical_to_head(w.repo, _rel("t.md"))

    assert got is (bytes_held == "head's")
    assert os.stat(w.corpus_dir / "t.md").st_ino == os.stat(target).st_ino
    assert census(w.outside) == before


def test_a_mode_only_change_is_byte_identical_and_a_content_change_is_not(tmp_path):
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    os.chmod(w.corpus_dir / "t.md", 0o755)
    assert drain._byte_identical_to_head(w.repo, _rel("t.md")) is True
    put(w.corpus_dir / "t.md", lesson_text("f0") + " ")
    assert drain._byte_identical_to_head(w.repo, _rel("t.md")) is False
    put(w.corpus_dir / "u.md", lesson_text("f0"))
    assert drain._byte_identical_to_head(w.repo, _rel("u.md")) is False


def _crlf(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode()


def test_a_crlf_only_rewrite_of_a_tracked_lesson_is_not_byte_identical(tmp_path):
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    put(w.corpus_dir / "t.md", _crlf(lesson_text("f0")))

    assert drain._byte_identical_to_head(w.repo, _rel("t.md")) is False


@pytest.mark.parametrize("change", ["crlf only", "mode only"])
def test_the_settle_keeps_a_crlf_only_rewrite_as_changed_and_puts_back_a_mode_only_one(
    tmp_path, change,
):
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    cfg = w.cfg()
    state = drain._capture_pre_state(cfg)
    if change == "crlf only":
        put(w.corpus_dir / "t.md", _crlf(lesson_text("f0")))
    else:
        os.chmod(w.corpus_dir / "t.md", 0o755)

    tree = drain._settle_tree(cfg, state)

    if change == "crlf only":
        assert tree.changed == (_rel("t.md"),)
        assert (w.corpus_dir / "t.md").read_bytes() == _crlf(lesson_text("f0"))
    else:
        assert tree.changed == ()
        assert not os.stat(w.corpus_dir / "t.md").st_mode & stat.S_IXUSR
    assert tree.deleted == ()


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_settle_judges_a_link_at_a_modified_lesson_as_git_sees_it(tmp_path, kind):
    w = world(tmp_path)
    body = lesson_text("f0", mark=OUT_MARK)
    put(w.corpus_dir / "t.md", body)
    w.commit()
    cfg = w.cfg()
    state = drain._capture_pre_state(cfg)
    target = w.target("same-bytes.md", body)
    plant_alias(kind, w.corpus_dir / "t.md", target)
    if kind == "hard link":
        os.chmod(target, 0o755)
    w.git("status")  # git refreshes its index once, before the watch is armed
    before = census(w.outside)

    with kernel_watch(opens=[target]) as events:
        tree = drain._settle_tree(cfg, state)
        seen = events()

    assert tree.deleted == ()
    if kind == "symlink":
        assert seen == [], f"the symlink's target was opened: {seen}"
        assert tree.changed == (_rel("t.md"),)
        assert alias_left(kind, w.corpus_dir / "t.md", target)
        assert census(w.outside) == before
        return
    assert tree.changed == ()
    st = os.lstat(w.corpus_dir / "t.md")
    assert stat.S_ISREG(st.st_mode)
    assert st.st_ino != os.stat(target).st_ino
    assert (w.corpus_dir / "t.md").read_bytes() == body.encode()
    assert target.read_bytes() == body.encode()
    assert os.stat(target).st_mode & 0o777 == 0o755


def test_a_path_outside_the_lanes_mounts_is_compared_by_git_too(tmp_path):
    """`f.txt` at the repo root lies outside every author mount: git compares it like any other
    path (v3 read it by its plain path, D3) — identical, then CRLF-changed."""
    w = world(tmp_path)
    (w.repo / "f.txt").write_bytes(b"line\n")
    w.commit()
    assert drain._byte_identical_to_head(w.repo, "f.txt") is True
    (w.repo / "f.txt").write_bytes(b"line\r\n")
    assert drain._byte_identical_to_head(w.repo, "f.txt") is False


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_an_aliased_lesson_cites_nothing_and_reads_empty(tmp_path, kind):
    w = world(tmp_path)
    body = lesson_text("f1", mark=OUT_MARK)
    target = w.target("secret.md", body)
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)

    with _watch_for(kind, target) as events:
        cited = drain._cited_ids(w.view, PLANTED, FIELD)
        text = drain._read_or_empty(w.view, PLANTED)
        seen = events()

    assert cited == set()
    assert text == ""
    assert seen == []

    put(at, body)
    assert drain._cited_ids(w.view, PLANTED, FIELD) == {"f1"}
    assert drain._read_or_empty(w.view, PLANTED) == body


def test_an_absent_or_undecodable_lesson_cites_nothing_and_reads_empty(tmp_path):
    w = world(tmp_path)
    assert drain._cited_ids(w.view, "absent.md", FIELD) == set()
    assert drain._read_or_empty(w.view, "absent.md") == ""
    put(w.corpus_dir / "bad.md", b"---\nsource_finding_ids:\n- f1\n---\n\xff\xfe\n")
    assert drain._cited_ids(w.view, "bad.md", FIELD) == set()
    assert drain._read_or_empty(w.view, "bad.md") == ""


@pytest.mark.parametrize("rel", [f"{LESSONS_REL}stray.txt", f"{SIBLING_REL}stray.md"],
                         ids=["own-corpus", "sibling-corpus"])
@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_put_back_refuses_an_untracked_link_in_either_corpus(tmp_path, kind, rel):
    w = world(tmp_path)
    target = w.target("secret.md")
    at = w.repo / rel
    plant_alias(kind, at, target)

    exc = raised_by(lambda: drain._put_back(w.repo, rel, tree_for=w.tree_for))

    assert leaf_refusal(exc), repr(exc)
    assert alias_left(kind, at, target)

    put(at, b"plain stray\n")
    drain._put_back(w.repo, rel, tree_for=w.tree_for)
    assert not os.path.lexists(at)


def test_put_back_refuses_an_untracked_fifo(tmp_path):
    """A FIFO at an untracked name inside a mount is `"other"`: its unlink is the core's leaf
    refusal (`NotPlainEntry`), never an open, and the FIFO is left."""
    w = world(tmp_path)
    at = w.corpus_dir / "stray.fifo"
    plant_fifo(at)

    exc = raised_by(lambda: drain._put_back(w.repo, f"{LESSONS_REL}stray.fifo",
                                            tree_for=w.tree_for), fifo=at)

    assert leaf_refusal(exc), repr(exc)
    assert stat.S_ISFIFO(os.lstat(at).st_mode)


def test_put_back_checks_out_a_tracked_name_and_leaves_a_folder(tmp_path):
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    put(w.corpus_dir / "t.md", b"changed\n")
    drain._put_back(w.repo, _rel("t.md"), tree_for=w.tree_for)
    assert (w.corpus_dir / "t.md").read_text() == lesson_text("f0")

    put(w.corpus_dir / "newdir" / "keep.bin", b"x")
    drain._put_back(w.repo, _rel("newdir"), tree_for=w.tree_for)
    assert (w.corpus_dir / "newdir" / "keep.bin").exists()
    drain._put_back(w.repo, _rel("absent.txt"), tree_for=w.tree_for)

    put(w.repo / "defender" / "notes.txt", b"stray outside the mounts\n")
    drain._put_back(w.repo, "defender/notes.txt", tree_for=w.tree_for)
    assert not (w.repo / "defender" / "notes.txt").exists()


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_revert_strays_logs_a_link_it_cannot_remove_and_goes_on(tmp_path, kind, caplog):
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    target = w.target("secret.md")
    link = w.sibling_dir / PLANTED
    plant_alias(kind, link, target)
    put(w.sibling_dir / "stray-plain.md", b"agent wrote this\n")
    put(w.repo / "defender" / "baseline.txt", b"dirty before the tick\n")

    drain._revert_strays(w.repo, LESSONS_REL, ["defender/baseline.txt"], tree_for=w.tree_for)

    assert alias_left(kind, link, target)
    assert sorted([PLANTED, "stray-plain.md"])[0] == PLANTED
    assert not (w.sibling_dir / "stray-plain.md").exists()
    assert (w.repo / "defender" / "baseline.txt").exists()
    assert warnings_naming(caplog, PLANTED), caplog.text


def test_put_back_below_a_linked_folder_is_refused_and_removes_nothing(tmp_path):
    w = world(tmp_path)
    moved = w.outside / "moved-sub"
    put(moved / "x.md", lesson_text("f1", mark=OUT_MARK))
    plant_link(w.sibling_dir / "sub", moved)
    before = census(w.outside)

    exc = raised_by(lambda: drain._put_back(w.repo, f"{SIBLING_REL}sub/x.md",
                                            tree_for=w.tree_for))

    assert _plain_os_error(exc, errno.ELOOP), repr(exc)
    assert (moved / "x.md").read_text() == lesson_text("f1", mark=OUT_MARK)
    assert is_link_to(w.sibling_dir / "sub", moved)
    assert census(w.outside) == before


@pytest.mark.parametrize("code", [errno.EIO, errno.EACCES], ids=["EIO", "EACCES"])
def test_revert_strays_lets_a_failing_disks_error_through(tmp_path, code):
    w = world(tmp_path)
    put(w.sibling_dir / "stray.md", b"agent wrote this\n")
    seam = FailsOn("unlink", code)
    trees = seamed_trees(w.paths, seam)

    exc = raised_by(lambda: drain._revert_strays(w.repo, LESSONS_REL, [],
                                                 tree_for=trees.tree_for))

    assert _plain_os_error(exc, code), repr(exc)
    assert seam.raised >= 1
    assert (w.sibling_dir / "stray.md").exists()


def test_a_dangling_link_at_an_approved_path_counts_as_present(tmp_path):
    w = world(tmp_path)
    cfg = w.cfg()
    plant_link(w.corpus_dir / PLANTED, w.outside / "does-not-exist.md")

    sha = author_shared.commit_corpus_paths("msg", cfg, [_rel(PLANTED)], [])

    assert sha is not None
    assert sha == w.head()
    assert w.head_mode(_rel(PLANTED)) == "120000"


@pytest.mark.parametrize("listed_as", ["approved", "deleted"])
def test_a_member_below_a_linked_folder_counts_as_present_and_git_refuses_it(tmp_path, listed_as):
    w = world(tmp_path)
    put(w.corpus_dir / "sub" / "x.md", lesson_text("f0"))
    w.commit()
    cfg = w.cfg()
    moved = w.outside / "moved-sub"
    move_out_and_link(w.corpus_dir / "sub", moved)
    clear(moved / "x.md")
    head = w.head()
    approved, deleted = ([_rel("sub/x.md")], []) if listed_as == "approved" else (
        [], [_rel("sub/x.md")])

    with pytest.raises(GitError):
        author_shared.commit_corpus_paths("msg", cfg, approved, deleted)

    assert GitError in drain.RETIRE_SET
    assert w.head() == head
    assert w.head_text(_rel("sub/x.md")) == lesson_text("f0")


def test_the_commit_lands_an_approved_file_and_a_real_deletion(tmp_path):
    """The positive control: an approved plain file is committed with its bytes; a tracked file
    the curator deleted is committed as a deletion."""
    w = world(tmp_path)
    put(w.corpus_dir / "old.md", lesson_text("f0"))
    w.commit()
    cfg = w.cfg()
    clear(w.corpus_dir / "old.md")
    put(w.corpus_dir / "new.md", lesson_text("f1"))

    sha = author_shared.commit_corpus_paths("msg", cfg, [_rel("new.md")], [_rel("old.md")])

    assert sha == w.head()
    assert w.head_text(_rel("new.md")) == lesson_text("f1")
    assert w.head_text(_rel("old.md")) is None


def test_git_commit_paths_obeys_its_two_lists_and_tests_nothing_on_disk(tmp_path):
    w = world(tmp_path)
    put(w.corpus_dir / "kept.md", lesson_text("f0"))
    w.commit()
    plant_link(w.corpus_dir / "dangling.md", w.outside / "nothing.md")

    sha = _git.git_commit_paths(w.repo, [_rel("dangling.md")], [_rel("kept.md")], "msg")

    assert sha == w.head()
    assert w.head_mode(_rel("dangling.md")) == "120000"
    assert (w.corpus_dir / "kept.md").read_text() == lesson_text("f0")


def test_git_commit_paths_does_not_reclassify_a_present_path_that_is_gone(tmp_path):
    """A path named present that is gone from both worktree and index reaches `git add`, which
    refuses it: the function trusts its caller's split rather than re-deriving one."""
    w = world(tmp_path)
    with pytest.raises(GitError):
        _git.git_commit_paths(w.repo, [_rel("never-existed.md")], [], "msg")


def test_git_commit_paths_with_nothing_to_commit_never_calls_git(tmp_path):
    """Both lists empty: `None`, without running git (a non-repo cwd would make git fail)."""
    not_a_repo = tmp_path / "plain-folder"
    not_a_repo.mkdir()
    assert _git.git_commit_paths(not_a_repo, [], [], "msg") is None


def test_the_clean_gate_goes_through_the_held_corpus_and_passes_a_clean_tree(tmp_path):
    w = world(tmp_path)
    seam = RecordingOs()
    trees = seamed_trees(w.paths, seam)
    seam.clear()

    author_shared.assert_clean_corpus_dir(w.repo, w.corpus_dir, LESSONS_REL,
                                          corpus=trees.mount(w.corpus_dir))

    assert seam.descriptors() == {os.path.realpath(w.corpus_dir)}, seam.trace
    assert not {"mkdir", "open"} & set(seam.calls), seam.trace


def test_the_clean_gate_makes_nothing_where_the_held_root_was(tmp_path):
    w = world(tmp_path)
    held = w.corpus
    shutil.rmtree(w.corpus_dir)

    with pytest.raises(author_shared.AuthorError):
        author_shared.assert_clean_corpus_dir(w.repo, w.corpus_dir, LESSONS_REL, corpus=held)

    assert not os.path.lexists(w.corpus_dir)


def test_the_clean_gate_still_refuses_a_dirty_corpus(tmp_path):
    w = world(tmp_path)
    put(w.corpus_dir / "dirty.md", b"uncommitted\n")
    with pytest.raises(author_shared.AuthorError):
        author_shared.assert_clean_corpus_dir(w.repo, w.corpus_dir, LESSONS_REL, corpus=w.corpus)


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_idempotency_read_skips_an_aliased_lesson(tmp_path, kind):
    w = world(tmp_path)
    put(w.corpus_dir / "plain.md", lesson_text("f-plain"))
    body = lesson_text("f-out", mark=OUT_MARK)
    target = w.target("secret.md", body)
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)
    log: list = []
    cfg = w.cfg(corpus=JournalHeld(w.corpus_dir, log))

    assert author_shared.existing_finding_ids(cfg) == {"f-plain"}
    assert {("read", "plain.md"), ("read", PLANTED)} <= set(log), log

    put(at, body)
    assert author_shared.existing_finding_ids(cfg) == {"f-plain", "f-out"}


def test_the_idempotency_read_leaves_out_a_lesson_cfg_corpus_refuses(tmp_path):
    w = world(tmp_path)
    put(w.corpus_dir / "a.md", lesson_text("f-a"))
    put(w.corpus_dir / "b.md", lesson_text("f-b"))
    log: list = []
    refusing = w.cfg(corpus=JournalHeld(w.corpus_dir, log, refuse=("b.md",)))

    assert author_shared.existing_finding_ids(refusing) == {"f-a"}
    assert {("read", "a.md"), ("read", "b.md")} <= set(log), log

    plain = w.cfg(corpus=JournalHeld(w.corpus_dir, []))
    assert author_shared.existing_finding_ids(plain) == {"f-a", "f-b"}


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_manifest_shows_an_aliased_lesson_as_unavailable(tmp_path, kind):
    w = world(tmp_path)
    body = lesson_text("f1", mark=OUT_MARK, topic=OUT_MARK)
    target = w.target("secret.md", body)
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)

    with _watch_for(kind, target) as events:
        manifest = author_shared.build_corpus_manifest(w.view, where=w.corpus_dir)
        seen = events()

    stem = PLANTED.removesuffix(".md")
    assert f"## {stem}" in manifest
    assert "unavailable" in manifest
    assert OUT_MARK not in manifest
    assert seen == []

    put(at, body)
    rendered = author_shared.build_corpus_manifest(w.view, where=w.corpus_dir)
    assert f"topic: {OUT_MARK}" in rendered
    assert "unavailable" not in rendered


def _channel_prompt(w, channel):
    """`(corpus root, the channel's prompt builder, its config over the world's trees)`."""

    if channel == "lessons":
        return w.corpus_dir, lessons_run.build_user_prompt, w.cfg()
    return (w.sibling_dir, questioner_run.build_questioner_user_prompt,
            questioner_cfg(w.paths, trees=w.trees))


@pytest.mark.parametrize("channel", ["lessons", "questioner"])
def test_each_channel_prompt_shows_a_lesson_cfg_corpus_refuses_as_unavailable(tmp_path, channel):
    w = world(tmp_path)
    root, prompt_of, cfg = _channel_prompt(w, channel)
    put(root / "a.md", lesson_text("f-a", topic="topic-of-a"))
    put(root / "b.md", lesson_text("f-b", topic="topic-of-b"))
    log: list = []
    refusing = dataclasses.replace(cfg, corpus=JournalHeld(root, log, refuse=("b.md",)))

    prompt = prompt_of([{"finding_id": "f1"}], "batch-1", refusing)

    assert "topic-of-a" in prompt
    assert "topic-of-b" not in prompt
    assert "## b\n(unavailable" in prompt, prompt
    assert {("read", "a.md"), ("read", "b.md")} <= set(log), log

    plain = dataclasses.replace(cfg, corpus=JournalHeld(root, []))
    rendered = prompt_of([{"finding_id": "f1"}], "batch-1", plain)
    assert "topic-of-b" in rendered
    assert "unavailable" not in rendered

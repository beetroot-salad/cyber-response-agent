"""#1134 addendum 3 (owner-approved 2026-10-03), D1, at the curator: the three "is this file still
identical to the before-state?" checks ask git, not the handle and not a plain-path read.

The checks are the settle's `_byte_identical_to_head(repo_root, rel)` (against HEAD), the settle
restore `_restore_unapproved_files(cfg, snapshot, rels, *, head_before)` and the fault restore
`_restore_corpus(repo_root, corpus_dir, snapshot, *, corpus, head_before)` (against the commit the
before-state was read at). Each asks `_git.git_unchanged_since(cwd, rev, pathspec)`: the
repo-relative names of the regular files `rev` carries under `pathspec` that git still finds
unchanged in the working tree — the same bytes (no end-of-line or attribute conversion, whatever
the worktree's `.gitattributes` says), still a regular file (a symlink is a type change; a FIFO,
a folder or nothing at the name is a change), the executable bit ignored. A path `rev` does not
carry is never unchanged. A git failure raises `GitError`; it is never read as an answer.

Routing of a git failure in the comparison, per site:
- the settle's: `GitError` out of `_byte_identical_to_head`; inside `_settle_tree` (a git read)
  the tick's `GitProbeError`, recorded stuck, nothing committed;
- the settle restore's: `GitProbeError`, before anything is written or removed;
- the fault restore's: a WARNING naming the failed comparison (never the host path), and every
  before-state file is written back through the held corpus (an identical rewrite is harmless;
  the fault being unwound keeps its routing).

Writes, restores and deletes still go through the corpus `Held`; kinds still through
`entry_kind` / `kind_at` (unchanged rows elsewhere).

Declared (N-a): git hashes a hard-linked file's content where the handle refused it. A hard link
holding the before-state's exact bytes is judged unchanged: the settle puts it back with `git
checkout` from HEAD's blob (never from its target), it is never in `changed`, never committed; on
a restore it is left where it stands, unrefused and unlogged. Its target is never written, and
no host bytes are copied into the corpus, a commit or a prompt. A symlink is never judged
unchanged.

What stays out of Python entirely: no check opens a worktree path (an audit hook on `open` sees
none under the repo), runs anything but git, or calls a read verb (`read`, `read_bytes`,
`read_text`, `open`, ...); `lane_trees.read_bytes_at` is gone.

Red against `5dbb880c` (v3's curator): `_git.git_unchanged_since` does not exist, the restores
take no `head_before`, `_byte_identical_to_head` takes `tree_for` and refuses a hard link, and
`Bound.read_bytes` is gone from the core beneath it.
"""
from __future__ import annotations

import ast
import inspect
import logging
import os
import re
import shutil
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from defender import _git
from defender._git import GitError
from defender.learning.author import drain
from defender.learning.core import lane_trees
from defender.tests import _spec773 as S
from defender.tests._curator1134 import (
    LESSONS_REL,
    OUT_MARK,
    JournalHeld,
    clear,
    is_link_to,
    lesson_text,
    plant_fifo,
    plant_folder,
    plant_hardlink,
    plant_link,
    put,
    warnings_naming,
    world,
)
from defender.tests._shared_readers_1134 import kernel_watch
from defender.tests.test_1111_rooted_io import census, in_time, raised_by

#: A commit no repository holds.
UNKNOWN = "0" * 40


def _rel(name: str) -> str:
    return f"{LESSONS_REL}{name}"


def _crlf(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode()


def _unchanged(w, rev: str | None = None) -> frozenset[str]:
    """`git_unchanged_since` over the world's corpus, against HEAD unless `rev` is named."""
    return _git.git_unchanged_since(w.repo, rev or w.head(), LESSONS_REL.rstrip("/"))


def _snap(w) -> dict[str, bytes]:
    return drain._snapshot_corpus(w.repo, w.corpus_dir, w.head())


def _corpus_marked(root: Path, *, but: str = "") -> list[str]:
    """Every regular file under `root` (no link followed) carrying `OUT_MARK`, except `but`."""
    return [k for k, row in census(root).items()
            if row[0] == "file" and OUT_MARK.encode() in row[1] and k != but]


def _break_index(w) -> None:
    (w.repo / ".git" / "index").write_bytes(b"not an index\n")


# ---------------------------------------------------------------------------------------
# _git.git_unchanged_since: git's answer, from planted facts
# ---------------------------------------------------------------------------------------


def test_git_names_each_unchanged_regular_file_and_none_that_changed(tmp_path):
    """One tree, every case at once, each a REAL entry the agent could leave. Unchanged: a file
    left alone, one chmod-ed only, a nested one, one whose name git would quote, and a hard link
    to an outside file holding the exact committed bytes (declared, N-a). Changed: a one-byte
    edit, a CRLF-only rewrite, a nested edit, a symlink to an outside file holding the exact
    committed bytes (a type change), a deleted file, a FIFO and a folder where a file was. The
    FIFO is never opened (under the deadline), the symlink's target never opened, and the call
    leaves the worktree as it found it.

    Catches: a comparison by the handle (refuses the hard link), by a plain-path read (follows
    the symlink, blocks on the FIFO), by decoded text (CRLF equal), or by `git diff` without
    the executable bit ignored (the chmod-only file changed)."""
    w = world(tmp_path)
    names = ["same.md", "mode.md", "edit.md", "crlf.md", "sym.md", "gone.md", "fifo.md",
             "dir.md", "hard.md", "n/deep/same.md", "n/deep/edit.md", 'q "é\\x.md']
    for name in names:
        put(w.corpus_dir / name, lesson_text("f0", mark=name))
    w.commit()
    body = {name: lesson_text("f0", mark=name) for name in names}

    os.chmod(w.corpus_dir / "mode.md", 0o755)
    put(w.corpus_dir / "edit.md", body["edit.md"] + " ")
    put(w.corpus_dir / "crlf.md", _crlf(body["crlf.md"]))
    sym_target = w.target("sym-target.md", body["sym.md"])
    plant_link(w.corpus_dir / "sym.md", sym_target)
    clear(w.corpus_dir / "gone.md")
    plant_fifo(w.corpus_dir / "fifo.md")
    plant_folder(w.corpus_dir / "dir.md")
    hard_target = w.target("hard-target.md", body["hard.md"])
    plant_hardlink(w.corpus_dir / "hard.md", hard_target)
    put(w.corpus_dir / "n/deep/edit.md", b"changed\n")
    before = census(w.corpus_dir)

    with kernel_watch(opens=[sym_target]) as events:
        got = in_time(lambda: _unchanged(w), fifo=w.corpus_dir / "fifo.md")
        seen = events()

    assert got == {_rel(n) for n in
                   ("same.md", "mode.md", "hard.md", "n/deep/same.md", 'q "é\\x.md', ".gitkeep")}
    assert seen == [], seen
    assert census(w.corpus_dir) == before


def test_a_path_the_commit_does_not_carry_as_a_regular_file_is_never_unchanged(tmp_path):
    """A name the agent created (untracked: git's diff alone reports nothing for it), a tracked
    symlink left exactly as committed, and a name below the pathspec of another corpus are none
    of them in the answer: only a regular file `rev` carries can be "unchanged". Control: the
    committed plain file beside them is."""
    w = world(tmp_path)
    put(w.corpus_dir / "kept.md", lesson_text("f0"))
    plant_link(w.corpus_dir / "tracked-link.md", w.target("t.md"))
    put(w.sibling_dir / "s.md", lesson_text("f0"))
    w.commit()
    put(w.corpus_dir / "new.md", lesson_text("f0"))

    got = _unchanged(w)

    assert _rel("kept.md") in got
    assert _rel("new.md") not in got
    assert _rel("tracked-link.md") not in got
    assert not [p for p in got if not p.startswith(LESSONS_REL)], got


def test_the_answer_is_against_the_commit_named_not_head(tmp_path):
    """The comparison is with `rev`: a file committed differently after `rev` is unchanged
    against the later commit and changed against `rev`."""
    w = world(tmp_path)
    put(w.corpus_dir / "a.md", lesson_text("f0"))
    w.commit()
    first = w.head()
    put(w.corpus_dir / "a.md", lesson_text("f1"))
    w.commit()

    assert _rel("a.md") in _unchanged(w)
    assert _rel("a.md") not in _unchanged(w, first)


@pytest.mark.parametrize("attributes", [
    "* text eol=crlf\n", "*.md text\n", "* -text\n",
], ids=["eol-crlf", "text", "minus-text"])
def test_an_attributes_file_the_agent_writes_does_not_change_the_answer(tmp_path, attributes):
    """The agent writes a `.gitattributes` into the corpus (untracked) before a CRLF-only
    rewrite. Git compares raw bytes all the same: the rewrite is changed, the untouched file
    beside it unchanged. (Under `* text eol=crlf` git's own status would call the CRLF rewrite
    clean.) Needs git 2.42+ (`GIT_ATTR_SOURCE`).

    Catches: a comparison that lets the worktree's attributes normalise line ends, so a real
    content change is judged identical and `git checkout` (settle) or no rewrite (restore)
    follows."""
    w = world(tmp_path)
    put(w.corpus_dir / "a.md", lesson_text("f0"))
    put(w.corpus_dir / "b.md", lesson_text("f0"))
    w.commit()
    put(w.corpus_dir / ".gitattributes", attributes)
    put(w.corpus_dir / "a.md", _crlf(lesson_text("f0")))

    got = _unchanged(w)

    assert _rel("a.md") not in got
    assert _rel("b.md") in got


@pytest.mark.parametrize("fault", ["unknown commit", "broken index", "no repository"])
def test_git_unchanged_since_raises_when_git_cannot_answer(tmp_path, fault):
    """A commit git does not hold, an index it cannot read, a working copy that is no
    repository: `GitError`, never an empty or partial answer (which a caller would read as
    "everything changed" or "nothing did")."""
    w = world(tmp_path)
    put(w.corpus_dir / "a.md", lesson_text("f0"))
    w.commit()
    rev = w.head()
    if fault == "unknown commit":
        rev = UNKNOWN
    elif fault == "broken index":
        _break_index(w)
    else:
        shutil.move(str(w.repo / ".git"), str(w.tmp / "git-moved-away"))

    with pytest.raises(GitError):
        _git.git_unchanged_since(w.repo, rev, LESSONS_REL.rstrip("/"))


# ---------------------------------------------------------------------------------------
# The settle: _byte_identical_to_head
# ---------------------------------------------------------------------------------------


def test_the_settle_comparison_raises_rather_than_answer_when_git_cannot(tmp_path):
    """`_byte_identical_to_head` over a broken index: the `GitError` comes out (never `False`,
    which would send an unchanged lesson to judging, nor `True`, which would check out a
    changed one). Control: the same call with the index whole answers."""
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    os.chmod(w.corpus_dir / "t.md", 0o755)
    assert drain._byte_identical_to_head(w.repo, _rel("t.md")) is True

    _break_index(w)
    with pytest.raises(GitError):
        drain._byte_identical_to_head(w.repo, _rel("t.md"))


def test_a_fifo_at_a_tracked_lesson_is_never_identical_and_never_opened(tmp_path):
    """The agent replaced tracked `t.md` by a FIFO: not identical (git sees no regular file),
    answered under the deadline — nothing opened it."""
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    plant_fifo(w.corpus_dir / "t.md")

    got = in_time(lambda: drain._byte_identical_to_head(w.repo, _rel("t.md")),
                  fifo=w.corpus_dir / "t.md")

    assert got is False
    assert stat.S_ISFIFO(os.lstat(w.corpus_dir / "t.md").st_mode)


def _failing_git_diff(tmp_path: Path, patch) -> None:
    """Put a `git` first on `PATH` that fails every `git diff` not run with `--cached` (the
    commit's staged check) and runs the real git for everything else: the comparison fails,
    `git status`, `ls-tree`, `checkout` and the commit do not. A fault at the process boundary,
    for the one site whose revision (HEAD) a test cannot make unreadable alone."""
    real = shutil.which("git")
    assert real is not None
    bin_dir = tmp_path / "failing-git-bin"
    bin_dir.mkdir()
    shim = bin_dir / "git"
    shim.write_text(
        "#!/bin/sh\n"
        'for a in "$@"; do [ "$a" = "--cached" ] && exec ' + f'"{real}"' + ' "$@"; done\n'
        'for a in "$@"; do\n'
        '  if [ "$a" = "diff" ]; then echo "fatal: injected diff failure" >&2; exit 128; fi\n'
        "done\n"
        f'exec "{real}" "$@"\n', encoding="utf-8")
    shim.chmod(0o755)
    patch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def test_a_git_failure_in_the_settle_comparison_is_the_ticks_stuck_git_probe(
    tmp_path, monkeypatch,
):
    """Through the drain: the curator chmods seeded `SEEDED` (git reports it, so the settle
    compares it) and writes an attributable lesson; every `git diff` the comparison runs fails.
    The settle's git read turns the `GitError` into `GitProbeError` (not a retire member): it
    comes out of `run_batch`, recorded stuck under that class, the row not bumped, nothing
    committed, and the fault undo (whose own comparison fails too, so it writes every
    before-state file back) leaves `SEEDED` holding its committed bytes and removes the lesson.

    Catches: a settle that reads a failed comparison as "changed" (the tick judges and commits
    on) or as "identical"."""
    from defender.tests.test_1134_curator_drain import PLANTED, SEEDED, _run, _scene

    def chmod_seeded(rows, batch_id, cfg):
        os.chmod(cfg.corpus_dir / SEEDED, 0o755)

    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")},
                                                also=chmod_seeded))
    with monkeypatch.context() as patch:
        _failing_git_diff(tmp_path, patch)
        result, got = _run(sc)

    assert result == "raised", got
    assert type(got) is drain.GitProbeError, repr(got)
    assert [r.get("fault_class") for r in S.stuck_records(sc.channel)] == ["GitProbeError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert sc.head_files() == []
    assert (sc.corpus / SEEDED).read_text() == lesson_text("f0")
    assert not os.path.lexists(sc.corpus / PLANTED)


# ---------------------------------------------------------------------------------------
# The settle restore: _restore_unapproved_files
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("fault", ["unknown commit", "broken index"])
def test_a_git_failure_in_the_settle_restores_comparison_is_a_git_probe_before_any_change(
    tmp_path, fault,
):
    """The settle restore cannot ask git (its before-state commit unknown, or the index
    broken): `GitProbeError`, raised before anything is written or removed — the agent's new
    file and its rewrite both still stand (the fault undo that follows owns the corpus). The
    positive control, the same call able to ask: the new file removed, the rewrite put back.

    Catches: a failed comparison read as "unchanged" (the rewrite kept) or as "changed" with
    the rest of the restore carried on regardless, or a raw `GitError`, which no probe wrapper
    has turned into the tick's stuck class."""
    w = world(tmp_path)
    put(w.corpus_dir / "old.md", lesson_text("f0"))
    w.commit()
    head = w.head()
    cfg = w.cfg()
    snapshot = _snap(w)
    put(w.corpus_dir / "old.md", b"rewritten\n")
    put(w.corpus_dir / "new.md", lesson_text("f1"))
    rels = {_rel("old.md"), _rel("new.md")}
    if fault == "broken index":
        _break_index(w)

    exc = raised_by(lambda: drain._restore_unapproved_files(
        cfg, snapshot, rels, head_before=UNKNOWN if fault == "unknown commit" else head))

    assert type(exc) is drain.GitProbeError, repr(exc)
    assert (w.corpus_dir / "old.md").read_bytes() == b"rewritten\n"
    assert (w.corpus_dir / "new.md").exists()

    if fault == "broken index":
        w.git("read-tree", head)  # the index made whole again
    drain._restore_unapproved_files(cfg, snapshot, rels, head_before=head)
    assert (w.corpus_dir / "old.md").read_bytes() == snapshot["old.md"]
    assert not os.path.lexists(w.corpus_dir / "new.md")


def test_the_settle_restore_rewrites_what_git_says_changed_and_leaves_what_it_does_not(
    tmp_path,
):
    """Which before-state files the settle restore writes is git's answer: of three unapproved
    tracked names, the rewritten one and the deleted one are written back through `cfg.corpus`;
    the untouched one is not written at all (its inode is the one it had). Over a journalling
    `cfg.corpus`: a `write` for each changed name, none for the unchanged one, and no read of
    any of them through the view."""
    w = world(tmp_path)
    for name in ("same.md", "edit.md", "gone.md"):
        put(w.corpus_dir / name, lesson_text("f0", mark=name))
    w.commit()
    snapshot = _snap(w)
    log: list = []
    cfg = w.cfg(corpus=JournalHeld(w.corpus_dir, log))
    put(w.corpus_dir / "edit.md", b"rewritten\n")
    clear(w.corpus_dir / "gone.md")
    inode = os.stat(w.corpus_dir / "same.md").st_ino

    drain._restore_unapproved_files(
        cfg, snapshot, {_rel("same.md"), _rel("edit.md"), _rel("gone.md")}, head_before=w.head())

    assert (w.corpus_dir / "edit.md").read_bytes() == snapshot["edit.md"]
    assert (w.corpus_dir / "gone.md").read_bytes() == snapshot["gone.md"]
    assert os.stat(w.corpus_dir / "same.md").st_ino == inode
    writes = {name for verb, name in log if verb == "write"}
    assert writes == {"edit.md", "gone.md"}, log
    assert not [e for e in log if e[0] == "read"], log


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_settle_restore_judges_a_link_holding_the_before_state_bytes_as_git_does(
    tmp_path, kind,
):
    """An unapproved tracked name the agent replaced by a link to an outside file holding the
    before-state's exact bytes:

    - a symlink is a type change: the rewrite is attempted and the core refuses it
      (`NotPlainEntry` propagates, off the fault path), the link left, its target never opened;
    - a hard link holds the same bytes as a regular file: unchanged (declared, N-a), so nothing
      is written and nothing raised; the hard link stays, its target's bytes and link count as
      they were.

    Catches: a comparison that reads the worktree by its plain path (the symlink's target equal,
    so the plant is passed over silently) or through the held mount (the hard link refused, so
    the restore raises over an unchanged file)."""
    w = world(tmp_path)
    body = lesson_text("f0", mark=OUT_MARK)
    put(w.corpus_dir / "t.md", body)
    w.commit()
    cfg = w.cfg()
    snapshot = _snap(w)
    target = w.target("same-bytes.md", body)
    (plant_link if kind == "symlink" else plant_hardlink)(w.corpus_dir / "t.md", target)
    before = census(w.outside)

    with kernel_watch(opens=[target] if kind == "symlink" else []) as events:
        exc = raised_by(lambda: drain._restore_unapproved_files(
            cfg, snapshot, {_rel("t.md")}, head_before=w.head()))
        seen = events()

    assert census(w.outside) == before
    if kind == "symlink":
        assert type(exc).__name__ == "NotPlainEntry", repr(exc)
        assert seen == []
        assert is_link_to(w.corpus_dir / "t.md", target)
        return
    assert exc is None, repr(exc)
    assert os.stat(w.corpus_dir / "t.md").st_ino == os.stat(target).st_ino


# ---------------------------------------------------------------------------------------
# The fault restore: _restore_corpus
# ---------------------------------------------------------------------------------------


def _restore(w, snapshot, *, head_before: str, corpus=None) -> None:
    drain._restore_corpus(w.repo, w.corpus_dir, snapshot,
                          corpus=corpus if corpus is not None else w.corpus,
                          head_before=head_before)


def test_the_fault_restore_rewrites_only_what_git_says_changed(tmp_path):
    """Git answers: of the before-state's files, the rewritten, the deleted and the nested
    rewritten one are written back; the untouched ones (one nested) are not written at all
    (same inode). Over a journalling held corpus: the writes are exactly the changed names and
    no read goes through the view."""
    w = world(tmp_path)
    names = ("same.md", "edit.md", "gone.md", "n/deep/same.md", "n/deep/edit.md")
    for name in names:
        put(w.corpus_dir / name, lesson_text("f0", mark=name))
    w.commit()
    snapshot = _snap(w)
    put(w.corpus_dir / "edit.md", b"rewritten\n")
    clear(w.corpus_dir / "gone.md")
    put(w.corpus_dir / "n/deep/edit.md", b"rewritten\n")
    inodes = {n: os.stat(w.corpus_dir / n).st_ino for n in ("same.md", "n/deep/same.md")}
    log: list = []

    _restore(w, snapshot, head_before=w.head(), corpus=JournalHeld(w.corpus_dir, log))

    for name in names:
        assert (w.corpus_dir / name).read_bytes() == snapshot[name], name
    assert {n: os.stat(w.corpus_dir / n).st_ino for n in inodes} == inodes
    writes = {name for verb, name in log if verb == "write"}
    assert writes == {"edit.md", "gone.md", "n/deep/edit.md"}, log
    assert not [e for e in log if e[0] == "read"], log


def test_a_failed_comparison_on_the_fault_path_writes_every_before_state_file_back(
    tmp_path, caplog,
):
    """The fault restore's comparison fails (its before-state commit unknown; `git status` still
    answers, so the agent's stray is swept): one WARNING naming the failed comparison (not the
    host path), nothing raised, and every before-state file is written back through the held
    corpus — the rewritten one restored, the untouched one rewritten too (a new inode, the same
    bytes), and a hard link standing at a third name (which git would have judged unchanged)
    refused, logged by name and left, its target never written.

    Catches: a restore that lets the comparison's `GitError` replace the fault being unwound,
    one that reads the failure as "nothing changed" and restores nothing, or one that falls
    back to reading the worktree itself."""
    caplog.set_level(logging.WARNING)
    w = world(tmp_path)
    for name in ("same.md", "edit.md", "hard.md"):
        put(w.corpus_dir / name, lesson_text("f0", mark=name))
    w.commit()
    snapshot = _snap(w)
    put(w.corpus_dir / "edit.md", b"rewritten\n")
    put(w.corpus_dir / "stray.md", b"new\n")
    target = w.target("hard-target.md", snapshot["hard.md"])
    plant_hardlink(w.corpus_dir / "hard.md", target)
    inode = os.stat(w.corpus_dir / "same.md").st_ino
    before = census(w.outside)

    exc = raised_by(lambda: _restore(w, snapshot, head_before=UNKNOWN))

    assert exc is None, repr(exc)
    assert not os.path.lexists(w.corpus_dir / "stray.md")
    assert (w.corpus_dir / "edit.md").read_bytes() == snapshot["edit.md"]
    assert (w.corpus_dir / "same.md").read_bytes() == snapshot["same.md"]
    assert os.stat(w.corpus_dir / "same.md").st_ino != inode
    assert os.stat(w.corpus_dir / "hard.md").st_ino == os.stat(target).st_ino
    assert warnings_naming(caplog, "hard.md"), caplog.text
    assert census(w.outside) == before
    said = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(re.search(r"git diff\D*rc=\d+", m) for m in said), said
    assert not any(str(w.tmp) in m for m in said), said


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_fault_restore_judges_a_link_holding_the_before_state_bytes_as_git_does(
    tmp_path, kind, caplog,
):
    """A before-state name the agent replaced by a link to an outside file holding its exact
    bytes, on the fault path:

    - a symlink is a type change: the rewrite is refused, logged by name and passed over (O5.3),
      the link left, its target never opened;
    - a hard link is unchanged (declared, N-a): no write is attempted, nothing is logged for it
      and it is left, its target's bytes and link count as they were — the survivor addendum 3
      declares.

    Either way the other rewritten file is restored (the positive control, same call).

    Catches: a plain-path comparison, under which the symlink reads identical and is passed
    over unlogged; a handle comparison, under which the hard link is refused and logged."""
    caplog.set_level(logging.WARNING)
    w = world(tmp_path)
    body = lesson_text("f0", mark=OUT_MARK)
    put(w.corpus_dir / "t.md", body)
    put(w.corpus_dir / "b.md", lesson_text("fb"))
    w.commit()
    snapshot = _snap(w)
    target = w.target("same-bytes.md", body)
    (plant_link if kind == "symlink" else plant_hardlink)(w.corpus_dir / "t.md", target)
    put(w.corpus_dir / "b.md", b"rewritten\n")
    before = census(w.outside)

    with kernel_watch(opens=[target] if kind == "symlink" else []) as events:
        _restore(w, snapshot, head_before=w.head())
        seen = events()

    assert (w.corpus_dir / "b.md").read_bytes() == snapshot["b.md"]
    assert census(w.outside) == before
    if kind == "symlink":
        assert seen == []
        assert is_link_to(w.corpus_dir / "t.md", target)
        assert warnings_naming(caplog, "t.md"), caplog.text
        return
    assert os.stat(w.corpus_dir / "t.md").st_ino == os.stat(target).st_ino
    assert not warnings_naming(caplog, "t.md"), caplog.text


# ---------------------------------------------------------------------------------------
# Declared, through the drain: a hard link with the before-state's bytes is never committed
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["same mode", "made executable"])
def test_a_hard_link_holding_a_lessons_exact_bytes_is_never_committed(tmp_path, mode):
    """The curator writes an attributable lesson and replaces seeded `SEEDED` by a hard link to
    an outside file holding `SEEDED`'s exact committed bytes (left with its mode, or made
    executable so git reports it). The tick commits the lesson alone: `SEEDED` is never judged
    (no verifier call names it), never in the commit, and HEAD still carries its committed
    bytes; the outside file keeps its bytes. Made executable, the settle's git comparison
    judges it unchanged and puts it back from HEAD's blob (`git checkout`): `SEEDED` is then a
    plain file of its own. Left alone, git never reports it at all: the hard link stays
    (declared, N-a — the box's alias ban refuses hard-link creation in the first place).

    Catches: a settle that judges the hard link changed (the handle refuses it), sending it to
    attribution, which cites nothing and faults the tick; and any path that commits it."""
    from defender.tests.test_1134_curator_drain import PLANTED, SEEDED, _run, _scene

    holder: dict = {}

    def alias_seeded(rows, batch_id, cfg):
        at = cfg.corpus_dir / SEEDED
        target = tmp_path / "outside" / "seeded-copy.md"
        put(target, at.read_bytes())
        if mode == "made executable":
            os.chmod(target, 0o755)
        plant_hardlink(at, target)
        holder["target"] = target

    sc = _scene(tmp_path, curator=S.FakeCurator(writes={PLANTED: lesson_text("f1")},
                                                also=alias_seeded))

    assert _run(sc) == ("rc", 0)
    assert sc.head_files() == [f"defender/lessons/{PLANTED}"]
    assert sc.head_text(f"defender/lessons/{SEEDED}") == lesson_text("f0")
    assert not [c for c in sc.verifier.calls if Path(c.lesson_path).name == SEEDED]
    target = holder["target"]
    assert target.read_text() == lesson_text("f0")
    assert (sc.corpus / SEEDED).read_text() == lesson_text("f0")
    same_inode = os.stat(sc.corpus / SEEDED).st_ino == os.stat(target).st_ino
    assert same_inode is (mode == "same mode")


# ---------------------------------------------------------------------------------------
# Nothing in Python reads the worktree for a comparison; nothing but git runs
# ---------------------------------------------------------------------------------------

_EVENTS: list[list[tuple[str, tuple]]] = []
_HOOKED: list[bool] = []


def _audit(event: str, args: tuple) -> None:
    if _EVENTS and event in ("open", "subprocess.Popen", "os.posix_spawn", "os.exec",
                             "shutil.copyfile", "os.link", "os.symlink"):
        _EVENTS[-1].append((event, args))


@contextmanager
def _audited() -> Iterator[list[tuple[str, tuple]]]:
    """Every `open` / process-spawn / copy audit event this process raises while the block runs.
    The hook is added once per process and records nothing unless a block is open."""
    if not _HOOKED:
        sys.addaudithook(_audit)
        _HOOKED.append(True)
    seen: list[tuple[str, tuple]] = []
    _EVENTS.append(seen)
    try:
        yield seen
    finally:
        _EVENTS.pop()


def _plain_opens_under(seen: list[tuple[str, tuple]], root: Path) -> list[Any]:
    """Each `open` of a path spelled absolute and under `root` outside its git dir: a read (or
    write) by plain path. The held corpus opens a leaf by its name below a held descriptor, a
    relative spelling, so it never appears here."""
    out = []
    for event, args in seen:
        if event != "open" or not args or not isinstance(args[0], str | bytes | os.PathLike):
            continue
        spelled = os.fsdecode(args[0])
        if os.path.isabs(spelled) and Path(spelled).is_relative_to(root) \
                and not Path(spelled).is_relative_to(root / ".git"):
            out.append(spelled)
    return out


def _spawned_not_git(seen: list[tuple[str, tuple]]) -> list[Any]:
    """Each process started that is not git, and each copy or link made in Python."""
    out = []
    for event, args in seen:
        if event == "subprocess.Popen":
            argv = args[1]
            first = os.fsdecode(argv[0] if isinstance(argv, list | tuple) else argv)
            if Path(first).name != "git":
                out.append(argv)
        elif event in ("os.posix_spawn", "os.exec"):
            if Path(os.fsdecode(args[0])).name != "git":
                out.append((event, args))
        elif event in ("shutil.copyfile", "os.link", "os.symlink"):
            out.append((event, args))
    return out


def test_no_comparison_opens_a_worktree_path_or_runs_anything_but_git(tmp_path):
    """While each of the three checks runs — the settle's on a changed lesson, the settle
    restore and the fault restore each over a rewritten, a deleted and an untouched file — the
    process opens no path under the repo by its plain spelling (git's own reads run in git's
    process) and starts no process but git; no file is copied or linked in Python.

    Catches: a comparison that reads `repo_root / rel` itself (`Path.read_bytes()`, `open()`),
    reads it by another process (`cat`, `cmp`), or copies a link's target into the corpus."""
    w = world(tmp_path)
    for name in ("same.md", "edit.md", "gone.md"):
        put(w.corpus_dir / name, lesson_text("f0", mark=name))
    w.commit()
    head = w.head()
    snapshot = _snap(w)
    cfg = w.cfg()

    def agent_edits():
        put(w.corpus_dir / "edit.md", b"rewritten\n")
        clear(w.corpus_dir / "gone.md")

    agent_edits()
    with _audited() as seen:
        drain._byte_identical_to_head(w.repo, _rel("edit.md"))
    settle_seen = list(seen)
    with _audited() as seen:
        drain._restore_unapproved_files(
            cfg, snapshot, {_rel(n) for n in ("same.md", "edit.md", "gone.md")}, head_before=head)
    unapproved_seen = list(seen)
    agent_edits()
    with _audited() as seen:
        _restore(w, snapshot, head_before=head)
    fault_seen = list(seen)

    for label, events in (("settle", settle_seen), ("unapproved", unapproved_seen),
                          ("fault", fault_seen)):
        assert _plain_opens_under(events, w.repo) == [], label
        assert _spawned_not_git(events) == [], label
        assert any(e == "subprocess.Popen" for e, _ in events), (label, "git never ran")
    assert (w.corpus_dir / "edit.md").read_bytes() == snapshot["edit.md"]


def test_the_audit_watch_sees_a_plain_read_and_a_foreign_process(tmp_path):
    """The positive control for the watch: a `Path.read_bytes()` of a repo file and a `cat` of
    it inside the block are both caught."""
    import subprocess

    w = world(tmp_path)
    put(w.corpus_dir / "a.md", b"x\n")
    with _audited() as seen:
        (w.corpus_dir / "a.md").read_bytes()
        subprocess.run(["cat", str(w.corpus_dir / "a.md")], capture_output=True, check=True)
    assert _plain_opens_under(seen, w.repo) == [str(w.corpus_dir / "a.md")]
    assert len(_spawned_not_git(seen)) == 1


#: What reads bytes or text: the handle's and the plain path's read verbs, the drain's own
#: readers, and the openers.
_READ_VERBS = frozenset({"read", "read_bytes", "read_text", "open", "fdopen", "read_at",
                         "read_bytes_at", "read_text_soft", "read_guarded", "read_bytes_guarded",
                         "read_text_utf8", "_read_or_empty", "_cited_ids", "git_show_file",
                         "git_show_file_bytes", "git_show_head", "copyfile", "copy", "copy2"})


def _callees(fn_name: str) -> set[str]:
    tree = ast.parse(inspect.getsource(drain))
    [fn] = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fn_name]
    out = set()
    for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
        f = call.func
        out.add(f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute)
                else "")
    return out


@pytest.mark.parametrize("fn_name", ["_byte_identical_to_head", "_restore_unapproved_files",
                                     "_restore_corpus", "_unchanged_names"])
def test_each_comparison_calls_no_read_verb(fn_name):
    """None of the three checks (nor the restores' shared `_unchanged_names`) calls a read verb
    — the handle's `read`, a plain path's `read_bytes` / `read_text` / `open`, the drain's own
    readers, a blob read to compare in Python — or a copy; the comparison is git's. Positive
    control: the same scan finds each in a function that makes them."""
    assert not _READ_VERBS & _callees(fn_name), (fn_name, sorted(_READ_VERBS & _callees(fn_name)))

    planted = ast.parse("def f(p, v):\n    p.read_bytes()\n    v.read('x')\n    open(p)\n")
    found = {c.func.attr if isinstance(c.func, ast.Attribute) else c.func.id
             for c in ast.walk(planted) if isinstance(c, ast.Call)}
    assert {"read_bytes", "read", "open"} <= _READ_VERBS & found


def test_the_byte_read_helper_is_gone():
    """Addendum 3 drops `lane_trees.read_bytes_at` (and the core has no `Bound.read_bytes` for
    it to call): no byte read of a lane tree is left to reach for."""
    assert not hasattr(lane_trees, "read_bytes_at")
    assert "read_bytes_at" not in inspect.getsource(drain)

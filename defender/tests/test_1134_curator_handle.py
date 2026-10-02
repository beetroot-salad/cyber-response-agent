"""#1134 curator step (v3, ported from v2): every host touch of a curator corpus during the drain
goes through that corpus's held mount, the call-site guards, each with its positive control at
the same address.

The contract is the curator step's v2 contract over #1134's design (D4 "Curator engine", O3's
lesson regression, O5.1-O5.3), the 2026-10-01 addendum (A1: writes through `Held`, reads
through its view; A4: the shared readers take a `Bound`), and addendum 2 (2026-10-02, B2/B3: no
`Bound.kind` / `Bound.walk`; the fixed-shape helpers `_tree_listing.entry_kind` / `list_tree`
and the lead-author step's `lane_trees.kind_at` in their place; the curator calls neither
`list_tree` nor `entries()`). The shapes pinned here:

- Addendum 2's correction (2026-10-02, C1/C2): the curator lists no folder. The before-state
  is `drain._snapshot_corpus(repo_root, corpus_dir, head)`: git's read (`_git.git_tree_blobs`)
  of every regular blob the tick-start commit carries under the corpus, nested included; a
  tracked symlink (120000) is left out, never restored as a file; a git failure raises. What
  the agent made comes from `git status --untracked-files=all` over the corpus, so a name git
  does not report (gitignored, a FIFO, a socket) survives the fault undo (C2).
- `drain._restore_corpus(repo_root, corpus_dir, snapshot, *, corpus: Held)` (fault path),
  `_restore_unapproved_files` / `_restore_from_snapshot` through `cfg.corpus`,
  `_put_back(repo_root, rel, *, tree_for)`, `_revert_strays(..., *, tree_for)`,
  `_byte_identical_to_head(repo_root, rel, *, tree_for)` (bytes via `lane_trees.read_bytes_at`),
  `_cited_ids(view, name, field)`, `_read_or_empty(view, name)`.
- O5.3, inside `_undo_agent_edits` only: a per-entry `NotPlainEntry` (symlink, hard link, FIFO,
  folder AT the name) is logged at WARNING naming the entry and the loop goes on; anything else
  (a linked holding folder's plain `ELOOP`, EACCES, ENOSPC, EIO) propagates.
- `shared.assert_clean_corpus_dir(..., *, corpus: Held)` (`corpus.mkdir(".")`, which makes
  nothing), `existing_finding_ids(cfg)` over `cfg.corpus.view()`, `build_corpus_manifest(corpus:
  Bound | Path, *, where=None, seed=None)` (`iter_lessons`' where rule), `build_curator_user_prompt
  (..., *, corpus: Bound, corpus_dir: Path, ...)`, `commit_corpus_paths` split by
  `lane_trees.kind_at(cfg.repo_root, cfg.tree_for, p) != lane_trees.KIND_ABSENT`,
  `_git.git_commit_paths(cwd, present, absent, message)` with no filesystem test (and `_git.py`
  free of any), and `lane_trees.read_bytes_at(repo_root, tree_for, path)`.

What the handle buys, per call site: a symlink, hard link, FIFO or folder at a lesson name (or a
link at a folder holding it) is never followed, never read, never written through and never
deleted. Every plant is REAL (`os.symlink`, `os.link`, `os.mkfifo`, a folder moved outside and
linked back); link targets live outside the repo (under the test's tmp dir, so a hard link shares
a filesystem) and carry `OUT_MARK`, so following one would change the answer. "Not read" rows hold
`kernel_watch` (inotify, below Python) on the target: `opens=` for a symlink or folder plant (no
open either), `reads=` for a hard link (its shared inode is opened before `fstat` refuses it).
FIFO rows run under `test_1111`'s deadline. Faults no root process can make for real (EACCES,
EIO, ENOSPC) enter through the `os_` seam of `hold` / `DrainTrees.open` only.

Red before the step: the drain helpers still take paths (`_snapshot_corpus` takes the corpus
folder alone, and `_git.git_tree_blobs` does not exist), the new keywords (`corpus=`,
`tree_for=`, `trees=`) do not exist, and `lane_trees.read_bytes_at` is missing; each test fails
on its own line.
"""
from __future__ import annotations

import ast
import dataclasses
import errno
import inspect
import logging
import os
import shutil
import stat
from pathlib import Path

import pytest

from defender import _git
from defender._git import GitError
from defender._io import NotPlainEntry, hold
from defender.learning.author import _config as author_config
from defender.learning.author import drain
from defender.learning.author import shared as author_shared
from defender.learning.author.lessons import run as lessons_run
from defender.learning.author.questioner import run as questioner_run
from defender.learning.core import lane_trees
from defender.tests._by_path import import_lint_lib
from defender.tests._curator1134 import (
    LESSONS_REL,
    OUT_MARK,
    SIBLING_REL,
    FailsOn,
    JournalHeld,
    RecordingOs,
    SwapsAfterRead,
    alias_left,
    clear,
    corpus_view,
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

astlib = import_lint_lib("_astlib")

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


# ---------------------------------------------------------------------------------------
# O3: a lesson name linked outside is neither snapshotted nor restored from
# ---------------------------------------------------------------------------------------


def test_o3_a_lesson_linked_outside_is_not_snapshotted_and_the_undo_leaves_it(tmp_path, caplog):
    """O3 (D7's regression): with a lesson name linked to an outside file (the agent's: git
    reports it untracked), the before-state (git's, at the tick-start commit) lacks the name, and
    `_undo_agent_edits` then neither opens nor writes the target and leaves the link where it is
    (same target) for the scrub, logged at WARNING by name (O5.3: the sweep's unlink is refused
    and passed over).

    Catches: today's `rglob` + `read_bytes`, which records the target's bytes under the lesson
    name (C3) — the watch sees the open."""
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
    """O3, the restore half: the snapshot was taken over the link; the agent then replaced it
    with a plain file of its own, or removed it. The undo leaves no file in the corpus holding
    the target's bytes, sweeps the name the snapshot never held, and the outside file is
    untouched.

    Catches: today's snapshot holding the target's bytes under the lesson name, which the
    restore then writes into `lessons/<name>` — a host file's bytes copied into the corpus."""
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


# ---------------------------------------------------------------------------------------
# _snapshot_corpus(repo_root, corpus_dir, head): the before-state, read from git
# ---------------------------------------------------------------------------------------


def test_the_before_state_is_every_regular_blob_head_carries_nested_and_byte_exact(tmp_path):
    """C1: the before-state is git's read of the tick-start commit under the corpus: every
    regular file, nested folders included (#773's `nested/deep/l1.md` shape), with its exact
    stored bytes (CRLF, NUL, non-UTF-8), an executable one too, keyed by its name under the
    corpus mount — and nothing outside the corpus (the sibling corpus, the rest of the repo).

    Catches: a before-state from a depth-limited listing (no nested name, so the settle restore
    would delete a tracked nested lesson), or one decoded as text."""
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
    """The before-state never touches the worktree: tracked `a.md` replaced (uncommitted) by a
    symlink to an outside file, a hard link to it, a FIFO, a plain rewrite, or removed — the
    before-state still holds HEAD's bytes of `a.md`, the target is never read (kernel watch) and
    the FIFO never opened (under the deadline).

    Catches: a before-state read from the worktree (main's `rglob` + `read_bytes`, which follows
    the link — O3 — or the view's `read_bytes`, which leaves the plant's name out)."""
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
    """C1: a tracked symlink (mode 120000) at a lesson name, pointing outside, is not in the
    before-state. The agent replaced it with a plain file of its own, or removed it; the fault
    undo then leaves nothing at the name — the agent's file is swept (git reports the name, the
    before-state lacks it), and no file is written there, neither the link's spelling nor the
    target's bytes. The outside file is untouched.

    Catches: a before-state that keeps git's blob for the link (its target spelling) and
    restores it as a plain file, or one that reads the target's bytes through the link."""
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
    """Git cannot read the before-state — a lesson's blob is missing from the object store, or
    the commit is unknown: `_snapshot_corpus` raises `GitError` (the tick's `_capture_pre_state`
    turns it into a stuck `GitProbeError` before the agent runs) rather than answer a partial
    before-state, which would make the missing lesson look agent-made."""
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


# ---------------------------------------------------------------------------------------
# _restore_corpus(repo_root, corpus_dir, snapshot, *, corpus): the fault path's sweep + rewrite
# ---------------------------------------------------------------------------------------


def _baseline(w) -> dict[str, bytes]:
    """The corpus at tick start, committed, and its snapshot."""
    put(w.corpus_dir / "a.md", lesson_text("fa"))
    put(w.corpus_dir / "b.md", lesson_text("fb"))
    w.commit()
    snapshot = _snap(w)
    assert snapshot is not None
    return snapshot


def _restore(w, snapshot, corpus=None) -> None:
    drain._restore_corpus(w.repo, w.corpus_dir, snapshot,
                          corpus=corpus if corpus is not None else w.corpus)


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_restore_sweep_leaves_a_stray_alias_logs_it_and_removes_a_plain_stray(
    tmp_path, kind, caplog,
):
    """O5.2 / O5.3 at `_restore_corpus`: an entry the snapshot never held is swept. A symlink or
    hard link there is refused and left for the scrub, logged at WARNING by name, and the sweep
    goes on: the plain stray beside it (the positive control, same call) is removed.

    Catches: today's `is_file()` sweep, which follows the link and unlinks it; and a sweep that
    asks the view's kind and plain-unlinks a `"file"` (a hard link's kind, H1)."""
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
    """O5.3 at `_restore_corpus`: the agent replaced snapshot name `a.md` by a link (or a hard
    link) to an outside file and rewrote `b.md`. The alias is refused, logged by name and left;
    the loop carries on and `b.md` is restored byte for byte (the positive control, same call);
    the outside file is neither read nor written."""
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
    assert seen == []
    assert census(w.outside) == before


def test_the_restore_control_rewrites_a_changed_and_a_deleted_snapshot_file(tmp_path):
    """The positive control at the same names: `a.md` rewritten and `b.md` deleted by the agent,
    a new plain `c.md` written; the restore puts `a.md` and `b.md` back byte for byte and
    removes `c.md`."""
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
    """O5.3 widened (settled): a FIFO is the core's leaf refusal (`NotPlainEntry`, unmarked), so
    at a snapshot name the rewrite refuses it, and it is logged at WARNING by name and passed
    over like a link. At a name the snapshot never held, `git status` does not report a FIFO
    (C2: the sweep asks git which names the agent made), so the sweep never meets it: it is left,
    and nothing is logged for it. Either way it is never opened, nothing is raised, and the rest
    is restored.

    Catches: v1's alias-mark catch (`write_guarded_alias`), under which the FIFO's unmarked
    refusal replaced the fault being unwound."""
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
    """O5.3 widened (pinned): the agent replaced snapshot name `a.md` by a folder. The rewrite of
    `a.md` meets a folder AT the name — the core's leaf refusal (`NotPlainEntry`; today's
    `write_guarded` raised it and replaced the fault) — so it is logged at WARNING by name and
    passed over; `b.md` is still restored. The folder is left (its stray file swept)."""
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
    """The agent moved folder `sub/` (holding snapshot name `sub/a.md`) outside and linked it
    back. The sweep's unlink of `sub` (a symlink AT a name) is refused and passed over; the
    rewrite of `sub/a.md` then meets the linked HOLDING folder on the descent: a plain
    `OSError(ELOOP)`, no leaf refusal, so it propagates. Nothing is written into the outside
    folder and the link is left.

    Catches: an O5.3 catch widened to every `OSError` carrying `ELOOP`."""
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
    """H6: O5.3 passes over only the leaf refusal. The disk failing the restore — `ENOSPC` on the
    rename that lands a snapshot file's bytes back, `EIO` / `EACCES` on the sweep's unlink of a
    file the agent made — is no refusal of the tree's shape: that `OSError` propagates out of
    `_undo_agent_edits` (reached through `cfg.corpus`), in place of the fault being unwound.

    Catches: a catch wider than `NotPlainEntry` (every `OSError` but `ELOOP`/`ENOTDIR`), which
    logs the failure and leaves the corpus half-restored under the original fault."""
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
    """C1 on the fault path: tracked nested lessons (#773's shape) the agent rewrote or removed
    are written back byte for byte from the git before-state, and nested files it made (in a
    tracked folder and in a new one) are swept; nothing at depth 1 is special.

    Catches: a before-state or sweep limited to the corpus's own entries (a depth-1 listing),
    which leaves the nested rewrite, the nested removal and the nested strays as they are."""
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


def test_the_fault_restore_lists_no_folder(tmp_path):
    """C1: the restore asks git which names the agent made and reads each snapshot name by name;
    over a held corpus whose `os_` records its calls, it lists no folder (no `scandir` /
    `listdir` through it) while it still sweeps a stray and a nested stray and rewrites a
    changed lesson (the positive control, same call).

    Catches: a sweep that lists the corpus (`list_tree` / `entries()`, which `scandir` the held
    folders) to find what the agent made."""
    w = world(tmp_path)
    snapshot = _baseline(w)
    put(w.corpus_dir / "a.md", b"rewritten by the agent\n")
    put(w.corpus_dir / "stray.md", b"new\n")
    put(w.corpus_dir / "newdir" / "x.md", b"new\n")
    seam = RecordingOs()
    held = hold(w.corpus_dir, os_=seam)
    seam.clear()

    _restore(w, snapshot, corpus=held)

    assert not {"scandir", "listdir"} & set(seam.calls), seam.calls
    assert (w.corpus_dir / "a.md").read_bytes() == snapshot["a.md"]
    assert not (w.corpus_dir / "stray.md").exists()
    assert not (w.corpus_dir / "newdir" / "x.md").exists()
    assert "stray.md" in seam.touched("unlink"), seam.trace


def test_a_gitignored_name_the_agent_made_survives_the_fault_restore(tmp_path):
    """C2 (declared): a name the corpus's `.gitignore` covers (`x.log`) is invisible to `git
    status`, so the sweep — which asks git which names the agent made — leaves it (main's
    recursive sweep deleted it). Positive control in the same call: the agent's `y.md`, which git
    reports, is swept."""
    w = world(tmp_path)
    put(w.corpus_dir / ".gitignore", "*.log\n")
    snapshot = _baseline(w)
    put(w.corpus_dir / "x.log", b"ignored by git\n")
    put(w.corpus_dir / "y.md", b"the agent's own\n")

    _restore(w, snapshot)

    assert (w.corpus_dir / "x.log").read_bytes() == b"ignored by git\n"
    assert not (w.corpus_dir / "y.md").exists()


@pytest.mark.parametrize("broken", ["index is a folder", "index is garbage"])
def test_a_broken_index_still_sweeps_through_gits_worktree_listing(tmp_path, broken, caplog):
    """`git status` fails during the restore because the index is broken (the fault being
    unwound is often git's own; #719's `test_a_git_failure_in_a_read_only_probe_...` breaks it
    the first way). The sweep then asks git for every non-ignored worktree file under the corpus
    against an empty index (`_git.git_worktree_files`): the agent's stray and nested stray are
    swept, a gitignored file is left (C2), a tracked symlink is listed too and its unlink is
    refused and logged (declared residue), every changed or removed snapshot file is written
    back, one WARNING names `git status` (not the host path), and no index file is left behind.

    Catches: a restore that sweeps nothing (or raises) when `git status` fails, leaving the
    agent's files to wedge the next tick's clean gate."""
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
    assert any("git status" in m for m in said), said
    assert not any(str(w.tmp) in m for m in said), said
    assert sorted(p.name for p in (w.repo / ".git").iterdir()) == git_dir_before


def test_a_restore_git_cannot_answer_at_all_sweeps_nothing_but_still_rewrites(tmp_path, caplog):
    """Git cannot answer at all during the restore (the working copy is no repository any more:
    both `git status` and the worktree listing fail): one WARNING naming both (not the host
    path), no sweep (a stray is left: nothing is deleted on an answer the restore never got),
    and each changed or removed snapshot file is still written back through the held corpus.

    Catches: a restore that lets the git failure replace the fault, or one that skips the
    rewrite with the sweep."""
    w = world(tmp_path)
    caplog.set_level(logging.WARNING)
    snapshot = _baseline(w)
    put(w.corpus_dir / "a.md", b"rewritten by the agent\n")
    clear(w.corpus_dir / "b.md")
    put(w.corpus_dir / "stray.md", b"new\n")
    shutil.move(str(w.repo / ".git"), str(w.tmp / "git-moved-away"))

    exc = raised_by(lambda: _restore(w, snapshot))

    assert exc is None, repr(exc)
    assert (w.corpus_dir / "stray.md").read_bytes() == b"new\n"
    assert (w.corpus_dir / "a.md").read_bytes() == snapshot["a.md"]
    assert (w.corpus_dir / "b.md").read_bytes() == snapshot["b.md"]
    said = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("git status" in m and "ls-files" in m for m in said), said
    assert not any(str(w.tmp) in m for m in said), said


def test_the_restore_does_nothing_without_a_snapshot(tmp_path):
    """No snapshot (the corpus folder was absent at tick start): nothing is swept."""
    w = world(tmp_path)
    put(w.corpus_dir / "stray.md", b"new\n")
    _restore(w, None)
    assert (w.corpus_dir / "stray.md").read_bytes() == b"new\n"


# ---------------------------------------------------------------------------------------
# _restore_unapproved_files / _restore_from_snapshot: through cfg.corpus, refusals propagate
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_an_unapproved_new_name_holding_a_link_is_refused_and_the_refusal_propagates(
    tmp_path, kind,
):
    """O5.2 at `_restore_unapproved_files` (non-fault): a name the tick created, not approved,
    holding a symlink or a hard link: `cfg.corpus.unlink` refuses (`NotPlainEntry`) and the
    refusal propagates ("anything left must go" — never swallowed off the fault path); the link
    stays.

    Catches: today's `target.unlink()`, which deletes the link; and a delete that asks the
    view only for the kind and unlinks a `"file"` by its plain path (H1: a hard link's kind)."""
    w = world(tmp_path)
    cfg = w.cfg()
    snapshot = _snap(w)
    target = w.target("secret.md")
    at = w.corpus_dir / PLANTED
    plant_alias(kind, at, target)

    exc = raised_by(lambda: drain._restore_unapproved_files(cfg, snapshot, {_rel(PLANTED)}))

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

    exc = raised_by(lambda: drain._restore_unapproved_files(cfg, snapshot, {_rel(PLANTED)}),
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

    exc = raised_by(lambda: drain._restore_unapproved_files(cfg, snapshot, {_rel(PLANTED)}))

    assert type(exc) is IsADirectoryError, repr(exc)
    assert (w.corpus_dir / PLANTED).is_dir()


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_an_unapproved_changed_name_holding_a_link_is_refused_unread(tmp_path, kind):
    """A snapshot name the agent replaced by a link (or a hard link) to an outside file: the
    read of it is refused (nothing read through it), the rewrite refuses (`NotPlainEntry`) and
    the refusal propagates; the link and its target are left as they are."""
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
        exc = raised_by(lambda: drain._restore_unapproved_files(cfg, snapshot, {_rel(PLANTED)}))
        seen = events()

    assert leaf_refusal(exc), repr(exc)
    assert seen == []
    assert alias_left(kind, at, target)
    assert census(w.outside) == before


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

    drain._restore_unapproved_files(
        cfg, snapshot, {_rel(PLANTED), _rel("old.md"), _rel("gone.md")})

    assert not (w.corpus_dir / PLANTED).exists()
    assert (w.corpus_dir / "old.md").read_bytes() == snapshot["old.md"]
    assert (w.corpus_dir / "gone.md").read_bytes() == snapshot["gone.md"]


#: What lands a `replace` write of the held corpus on the name: the rename of the staged file.
#: A write made anywhere but through the held corpus's `os_` leaves none in its record.
LANDING_CALLS = {"rename"}


def _settle(step: str, cfg, snapshot, rel: str) -> None:
    getattr(drain, step)(cfg, snapshot, {rel} if step == "_restore_unapproved_files" else [rel])


def _recording_cfg(w):
    seam = RecordingOs()
    trees = seamed_trees(w.paths, seam)
    return seam, trees, dataclasses.replace(w.cfg(), corpus=trees.mount(w.corpus_dir))


@pytest.mark.parametrize("step", ["_restore_unapproved_files", "_restore_from_snapshot"])
def test_both_settle_restores_write_through_the_configs_held_corpus(tmp_path, step):
    """H3: `_restore_unapproved_files` and `_restore_from_snapshot` reach the corpus through
    `cfg.corpus`: over a held corpus whose `os_` records its calls, the restore lands (bytes on
    disk) and the call that landed it — the rename of the replace write, not just a read or a
    kind asked beforehand — is in the record.

    Catches: a restore that asks `cfg.corpus` what stands at the name and then writes the plain
    path (`mkdir(parents=True)` + a guarded write), which follows a linked holding folder."""
    w = world(tmp_path)
    put(w.corpus_dir / "old.md", lesson_text("f0"))
    w.commit()
    snapshot = _snap(w)
    seam, _trees, cfg = _recording_cfg(w)
    clear(w.corpus_dir / "old.md")

    _settle(step, cfg, snapshot, _rel("old.md"))

    assert (w.corpus_dir / "old.md").read_bytes() == snapshot["old.md"]
    landed = [n for verb in LANDING_CALLS for n in seam.touched(verb)]
    assert "old.md" in landed, (step, seam.trace)


def test_the_unapproved_restore_deletes_a_new_file_through_the_configs_held_corpus(tmp_path):
    """The delete half: a plain file at an unapproved new name is removed by `cfg.corpus`'s own
    `unlink` (in its `os_` record), not by the plain path after asking the view its kind."""
    w = world(tmp_path)
    snapshot = _snap(w)
    put(w.corpus_dir / PLANTED, lesson_text("f1"))
    seam, _trees, cfg = _recording_cfg(w)

    drain._restore_unapproved_files(cfg, snapshot, {_rel(PLANTED)})

    assert not os.path.lexists(w.corpus_dir / PLANTED)
    assert PLANTED in seam.touched("unlink"), seam.trace


@pytest.mark.parametrize("agent_left", ["nothing", "its own bytes"])
@pytest.mark.parametrize("step", ["_restore_unapproved_files", "_restore_from_snapshot"])
def test_a_settle_restore_below_a_linked_folder_is_refused_and_writes_nothing_outside(
    tmp_path, step, agent_left,
):
    """The agent moved folder `sub/` (holding snapshot name `sub/a.md`) outside, linked it back,
    and removed `a.md` there or rewrote it. The settle restore of `sub/a.md` meets the linked
    folder on the held corpus's descent: a plain `OSError(ELOOP)` propagates (not the fault
    path, so nothing is caught), the link is left, and nothing is written into the moved folder.

    Catches: a restore that writes `cfg.corpus_dir / name` after `parent.mkdir(parents=True,
    exist_ok=True)` — which accepts the linked folder — landing the snapshot bytes outside."""
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


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_repair_deletion_restore_refuses_a_link_at_the_name(tmp_path, kind):
    """`_restore_from_snapshot` (a deletion the repair spawn may not make): a link (or a hard
    link) standing at the name is refused (`NotPlainEntry`), and the target is untouched.
    Control: the name absent is rewritten with its exact snapshot bytes; a name the snapshot
    never held is left alone."""
    w = world(tmp_path)
    cfg = w.cfg()
    put(w.corpus_dir / "old.md", lesson_text("f0"))
    w.commit()
    snapshot = _snap(w)
    target = w.target("secret.md")
    plant_alias(kind, w.corpus_dir / "old.md", target)
    before = census(w.outside)

    exc = raised_by(lambda: drain._restore_from_snapshot(cfg, snapshot, [_rel("old.md")]))

    assert leaf_refusal(exc), repr(exc)
    assert alias_left(kind, w.corpus_dir / "old.md", target)
    assert census(w.outside) == before

    clear(w.corpus_dir / "old.md")
    drain._restore_from_snapshot(cfg, snapshot, [_rel("old.md"), _rel("never.md")])
    assert (w.corpus_dir / "old.md").read_bytes() == snapshot["old.md"]
    assert not (w.corpus_dir / "never.md").exists()


# ---------------------------------------------------------------------------------------
# _byte_identical_to_head: worktree bytes through tree_for; a link is never "identical"
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_a_lesson_aliased_to_head_identical_bytes_is_not_byte_identical(tmp_path, kind):
    """A tracked lesson replaced by a link (or hard link) to an outside file holding HEAD's exact
    bytes is NOT byte-identical to HEAD: the read through the held mount is refused, so the
    comparison fails, and the target is not read.

    Catches: today's `(repo_root / rel).read_bytes()`, which follows the link and answers True —
    and then `git checkout` papers over the plant."""
    w = world(tmp_path)
    body = lesson_text("f0", mark=OUT_MARK)
    put(w.corpus_dir / "t.md", body)
    w.commit()
    target = w.target("same-bytes.md", body)
    plant_alias(kind, w.corpus_dir / "t.md", target)

    with _watch_for(kind, target) as events:
        got = drain._byte_identical_to_head(w.repo, _rel("t.md"), tree_for=w.tree_for)
        seen = events()

    assert got is False
    assert seen == []


def test_a_mode_only_change_is_byte_identical_and_a_content_change_is_not(tmp_path):
    """The positive control at the same name: a chmod-only change reads through the held mount
    as byte-identical; a one-byte change does not; an untracked name has no HEAD bytes."""
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    os.chmod(w.corpus_dir / "t.md", 0o755)
    assert drain._byte_identical_to_head(w.repo, _rel("t.md"), tree_for=w.tree_for) is True
    put(w.corpus_dir / "t.md", lesson_text("f0") + " ")
    assert drain._byte_identical_to_head(w.repo, _rel("t.md"), tree_for=w.tree_for) is False
    put(w.corpus_dir / "u.md", lesson_text("f0"))
    assert drain._byte_identical_to_head(w.repo, _rel("u.md"), tree_for=w.tree_for) is False


def _crlf(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode()


def test_a_crlf_only_rewrite_of_a_tracked_lesson_is_not_byte_identical(tmp_path):
    """E02: a tracked lesson INSIDE `lessons/` rewritten with CRLF line ends and nothing else is
    not byte-identical to HEAD: the comparison is of raw bytes read through the held mount (the
    docstring's own reason — text decoding's universal newlines would call it equal).

    Catches: an in-mount comparison that reads text (`read_at`) and re-encodes it."""
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    put(w.corpus_dir / "t.md", _crlf(lesson_text("f0")))

    assert drain._byte_identical_to_head(w.repo, _rel("t.md"), tree_for=w.tree_for) is False


@pytest.mark.parametrize("change", ["crlf only", "mode only"])
def test_the_settle_keeps_a_crlf_only_rewrite_as_changed_and_puts_back_a_mode_only_one(
    tmp_path, change,
):
    """E02 at the settle (`_settle_tree`, step 4): after the pre-state is taken, the agent
    rewrites tracked `t.md` CRLF-only — the settle keeps it as CHANGED (content to judge) and
    leaves its bytes as written. The control is a chmod-only change at the same name: identical
    bytes, so it is put back (`git checkout`) and is not in `changed`.

    Catches: a CRLF-only rewrite judged byte-identical and checked out, so a real change escapes
    judgement."""
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    cfg = w.cfg()
    state = drain._capture_pre_state(cfg)
    if change == "crlf only":
        put(w.corpus_dir / "t.md", _crlf(lesson_text("f0")))
    else:
        os.chmod(w.corpus_dir / "t.md", 0o755)

    tree = drain._settle_tree(cfg, state, honoured_deletions=None)

    if change == "crlf only":
        assert tree.changed == (_rel("t.md"),)
        assert (w.corpus_dir / "t.md").read_bytes() == _crlf(lesson_text("f0"))
    else:
        assert tree.changed == ()
        assert not os.stat(w.corpus_dir / "t.md").st_mode & stat.S_IXUSR
    assert tree.deleted == ()


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_the_settle_never_judges_a_link_at_a_modified_lesson_byte_identical(tmp_path, kind):
    """Step 4 of the settle (`_settle_tree`), at its own call site: after the pre-state is taken,
    tracked `t.md` is replaced by a symlink (or a hard link) to an outside file holding HEAD's
    exact bytes. Git reports it modified — a typechange; for the hard link the shared inode is
    made executable, a mode change, since identical bytes alone report nothing. The settle asks
    the config's `tree_for`, whose held mount refuses the link: `t.md` stays CHANGED (content to
    judge), the plant is left where it stands, and the target is never read (for the symlink,
    never opened).

    Catches (#1134 v2 step 7 adversary, 02b): the settle handing `_byte_identical_to_head` a
    `tree_for` that misses every path — `**{"tree_for": lambda _p: None}` — so the plain
    fallback reads through the link, answers True, and `git checkout` papers over the plant."""
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

    with _watch_for(kind, target) as events:
        tree = drain._settle_tree(cfg, state, honoured_deletions=None)
        seen = events()

    assert seen == [], f"the plant's target was read through: {seen}"
    assert tree.changed == (_rel("t.md"),)
    assert alias_left(kind, w.corpus_dir / "t.md", target)


def test_byte_identity_keeps_the_bytes_its_read_saw_when_the_lesson_is_swapped_after(tmp_path):
    """E06 at `_byte_identical_to_head`: tracked `t.md` is read through the held mount, and the
    moment that read closes, it is swapped for a symlink to an outside file holding other bytes.
    The comparison is of the bytes the mount read (HEAD's: True), and the outside file is never
    opened. The seam firing is the positive control that the read went through the trees.

    Catches: a comparison that asks the mount and then reads `repo_root / rel` by its plain
    path, which follows the fresh link."""
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    target = w.target("secret.md")
    seam = SwapsAfterRead(w.corpus_dir / "t.md", lambda: plant_link(w.corpus_dir / "t.md", target))
    trees = seamed_trees(w.paths, seam)

    with kernel_watch(opens=[target]) as events:
        got = drain._byte_identical_to_head(w.repo, _rel("t.md"), tree_for=trees.tree_for)
        seen = events()

    assert seam.fired, "t.md was never read through the trees' seam"
    assert got is True
    assert seen == [], f"the swapped-in link's target was opened: {seen}"
    assert is_link_to(w.corpus_dir / "t.md", target)


def test_a_path_outside_the_lanes_mounts_keeps_its_plain_read(tmp_path):
    """`f.txt` at the repo root lies outside every author mount (the box's read-only area, D3):
    it is read by its plain path, identical and CRLF-changed alike."""
    w = world(tmp_path)
    (w.repo / "f.txt").write_bytes(b"line\n")
    w.commit()
    assert drain._byte_identical_to_head(w.repo, "f.txt", tree_for=w.tree_for) is True
    (w.repo / "f.txt").write_bytes(b"line\r\n")
    assert drain._byte_identical_to_head(w.repo, "f.txt", tree_for=w.tree_for) is False


def test_byte_identity_asks_the_tree_for_it_is_handed(tmp_path):
    """The worktree bytes come through the `tree_for` handed in: over trees whose `os_` records
    its calls, a lesson's comparison reads through them.

    Catches: `_byte_identical_to_head` taking `tree_for` and reading `repo_root / rel` anyway."""
    w = world(tmp_path)
    put(w.corpus_dir / "t.md", lesson_text("f0"))
    w.commit()
    seam = RecordingOs()
    trees = seamed_trees(w.paths, seam)
    seam.clear()

    assert drain._byte_identical_to_head(w.repo, _rel("t.md"), tree_for=trees.tree_for) is True
    assert "t.md" in seam.touched("open"), seam.trace


# ---------------------------------------------------------------------------------------
# lane_trees.read_bytes_at: the byte-exact read beside read_at
# ---------------------------------------------------------------------------------------


def test_read_bytes_at_reads_a_mount_path_through_its_held_mount_and_a_plain_path_outside(
    tmp_path,
):
    """`lane_trees.read_bytes_at(repo_root, tree_for, path)`: inside a mount (relative as git
    status spells it, or absolute), a plain file's exact bytes as `(data, None)`; a symlink, a
    hard link or a FIFO is `(None, reason)`, its target never read and the FIFO never blocking;
    nothing there is no data. Outside the mounts the plain path is read (`Path.read_bytes()`, an
    `OSError` folded into `(None, reason)`)."""
    w = world(tmp_path)
    raw = b"\xff\xfe binary\r\n\x00"
    put(w.corpus_dir / "raw.bin", raw)
    target = w.target("secret.md", lesson_text("f1", mark=OUT_MARK))
    plant_link(w.corpus_dir / "linked.md", target)
    plant_hardlink(w.sibling_dir / "hard.md", target)
    plant_fifo(w.corpus_dir / "pipe.md")
    put(w.repo / "defender" / "notes.bin", raw)

    def read(path):
        return lane_trees.read_bytes_at(w.repo, w.tree_for, path)

    assert read(_rel("raw.bin")) == (raw, None)
    assert read(w.corpus_dir / "raw.bin") == (raw, None)
    with kernel_watch(reads=[target]) as events:
        for rel in (_rel("linked.md"), f"{SIBLING_REL}hard.md"):
            data, reason = read(rel)
            assert data is None, rel
            assert reason, rel
        seen = events()
    assert seen == []
    data, reason = in_time(lambda: read(_rel("pipe.md")), fifo=w.corpus_dir / "pipe.md")
    assert data is None
    assert reason
    assert read(_rel("absent.md"))[0] is None

    assert read("defender/notes.bin") == (raw, None)
    data, reason = read("defender/absent.bin")
    assert data is None
    assert reason


# ---------------------------------------------------------------------------------------
# _cited_ids / _read_or_empty: on the VIEW; a refused read cites nothing and reads as ""
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_an_aliased_lesson_cites_nothing_and_reads_empty(tmp_path, kind):
    """O5.1: a lesson name holding a link (or hard link) to an outside lesson citing `f1` cites
    nothing (`_cited_ids(view, name, field)` -> `set()`) and reads as `""` (`_read_or_empty(view,
    name)`), without the target being read. The positive control is the same bytes as a plain
    file: it cites `f1` and reads as its text."""
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


# ---------------------------------------------------------------------------------------
# _put_back / _revert_strays: git-status names through tree_for
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("rel", [f"{LESSONS_REL}stray.txt", f"{SIBLING_REL}stray.md"],
                         ids=["own-corpus", "sibling-corpus"])
@pytest.mark.parametrize("kind", ["symlink", "hard link"])
def test_put_back_refuses_an_untracked_link_in_either_corpus(tmp_path, kind, rel):
    """O5.2 at `_put_back`: an untracked name inside either author mount (its own corpus or the
    sibling, both mounts of the label) holding a symlink or a hard link is judged through that
    mount's `Held`: the unlink refuses (`NotPlainEntry`; no catch here: the caller decides), and
    the link is left. The positive control is the same name as a plain untracked file: removed.

    Catches: today's `is_file()` + `unlink()`, which follows the link and removes it; and a
    `_put_back` that asks the view the kind and unlinks a `"file"` by its plain path (H1)."""
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
    """Tracked: git puts the committed bytes back. An untracked folder (`"dir"`) and an absent
    name are left alone. Outside the label's mounts (`defender/notes.txt`) the plain path is
    kept (D3): an untracked plain file there is removed."""
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
    """O5.3 at `_revert_strays` (fault path only): a stray link (or hard link) in the sibling
    corpus is refused through the sibling's `Held`, logged at WARNING by name and left; the loop
    goes on and removes the plain stray beside it (named to sort AFTER the link, so a loop that
    stopped at the refusal would leave it); a baseline stray (dirty before the tick) is kept.
    (A FIFO never reaches this loop: `git status` does not list one.)"""
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


def test_put_back_removes_an_untracked_file_through_the_held_mount_tree_for_gives(tmp_path):
    """H2: `_put_back` removes an untracked plain file in a mount by that mount's own `unlink`,
    on the `Held` `tree_for` hands it: over trees whose `os_` records its calls, the file is gone
    and the `unlink` is in the record.

    Catches: a `_put_back` that ignores `tree_for` and judges the plain path itself, and one that
    asks the view the kind and then unlinks the plain path."""
    w = world(tmp_path)
    at = w.sibling_dir / "stray.md"
    put(at, b"plain stray\n")
    seam = RecordingOs()
    trees = seamed_trees(w.paths, seam)

    drain._put_back(w.repo, f"{SIBLING_REL}stray.md", tree_for=trees.tree_for)

    assert not os.path.lexists(at)
    assert "stray.md" in seam.touched("unlink"), seam.trace


def test_put_back_below_a_linked_folder_is_refused_and_removes_nothing(tmp_path):
    """H2: the sibling corpus's folder `sub/` is a link to an outside folder holding a plain
    `x.md`, and `_put_back` is handed the untracked name `sub/x.md` (a name git status spelled
    before the folder was swapped). The held mount's descent refuses the linked folder: a plain
    `OSError(ELOOP)` propagates, and the outside `x.md` and the link are left.

    Catches: a `_put_back` that judges the plain path itself — an `lstat` that follows the
    linked folder, finds a plain file with one link, and unlinks the OUTSIDE file."""
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
    """H6 at `_revert_strays`: only the leaf refusal is logged and passed over. The disk failing
    the removal of a plain stray (`EIO` / `EACCES` on the sibling mount's `unlink`) propagates.

    Catches: an O5.3 catch widened past `NotPlainEntry`."""
    w = world(tmp_path)
    put(w.sibling_dir / "stray.md", b"agent wrote this\n")
    seam = FailsOn("unlink", code)
    trees = seamed_trees(w.paths, seam)

    exc = raised_by(lambda: drain._revert_strays(w.repo, LESSONS_REL, [],
                                                 tree_for=trees.tree_for))

    assert _plain_os_error(exc, code), repr(exc)
    assert seam.raised >= 1
    assert (w.sibling_dir / "stray.md").exists()


# ---------------------------------------------------------------------------------------
# commit_corpus_paths / _git.git_commit_paths: present vs absent by kind, never by exists()
# ---------------------------------------------------------------------------------------


def test_a_dangling_link_at_an_approved_path_counts_as_present(tmp_path):
    """`commit_corpus_paths` splits present from absent with `kind_at` through `cfg.tree_for`: a
    dangling link is `"other"`, so present, and is staged as what it is (a symlink blob); the
    scrub then taints the batch on it.

    Catches: today's `(cwd / p).exists()`, which follows the link, calls it absent, and commits
    nothing."""
    w = world(tmp_path)
    cfg = w.cfg()
    plant_link(w.corpus_dir / PLANTED, w.outside / "does-not-exist.md")

    sha = author_shared.commit_corpus_paths("msg", cfg, [_rel(PLANTED)], [])

    assert sha is not None
    assert sha == w.head()
    assert w.head_mode(_rel(PLANTED)) == "120000"


@pytest.mark.parametrize("listed_as", ["approved", "deleted"])
def test_a_member_below_a_linked_folder_counts_as_present_and_git_refuses_it(tmp_path, listed_as):
    """H9: tracked `sub/x.md`; the agent moved `sub/` outside (without `x.md`) and linked it back.
    The split asks the held mount, which answers `"other"` for a name below a linked folder, so
    `sub/x.md` is present, and git refuses to stage a path beyond a symbolic link: a `GitError`
    (a `RETIRE_SET` member), nothing committed, `sub/x.md` still in HEAD. Approved or listed as a
    deletion, alike.

    Catches: a split by `os.path.lexists(repo_root / p)`, which follows the linked folder, finds
    no `x.md`, calls the path absent, and silently commits its deletion."""
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


def test_the_commit_split_asks_the_configs_tree_for(tmp_path):
    """The split consults `cfg.tree_for` for every path it commits, so a lesson path is judged
    through its mount's `Held`."""
    w = world(tmp_path)
    put(w.corpus_dir / "old.md", lesson_text("f0"))
    w.commit()
    asked: list[object] = []

    def spy(path):
        asked.append(path)
        return w.tree_for(path)

    cfg = w.cfg(tree_for=spy)
    clear(w.corpus_dir / "old.md")
    put(w.corpus_dir / "new.md", lesson_text("f1"))

    author_shared.commit_corpus_paths("msg", cfg, [_rel("new.md")], [_rel("old.md")])

    spelled = {Path(p).relative_to(w.repo).as_posix() for p in asked}
    assert spelled >= {_rel("new.md"), _rel("old.md")}, asked


def test_git_commit_paths_obeys_its_two_lists_and_tests_nothing_on_disk(tmp_path):
    """`_git.git_commit_paths(cwd, present, absent, message)`: `present` is `git add`ed and
    `absent` is `git rm --cached`, with no existence test of its own: a dangling link named
    present is committed as a symlink (the old `exists()` test called it absent). A tracked file
    named absent is left on disk (what the pathspec commit then records for it is git's own
    worktree read, N-a, so it is not pinned here)."""
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


#: A method call by any of these names touches the disk (`Path.exists()`, `.stat()`, `.open()`,
#: `.read_text()`, `.unlink()` and kin; `os.path`'s functions by the same names). A `read_*` /
#: `write_*` name counts too (`_DISK_PREFIXES`).
_DISK_METHODS = frozenset({
    "exists", "is_file", "is_dir", "is_symlink", "lstat", "stat", "lexists", "isfile", "isdir",
    "islink", "access", "open", "iterdir", "glob", "rglob", "scandir", "listdir", "walk",
    "unlink", "remove", "mkdir", "makedirs", "rmdir", "rename", "replace", "touch", "chmod",
    "readlink", "samefile",
})
_DISK_PREFIXES = ("read_", "write_")
#: Modules whose functions reach the filesystem; `_git.py` imports none of them, and calls none.
_DISK_MODULES = ("os", "shutil", "glob", "tempfile", "io")


def _disk_touches(tree: ast.Module) -> list[tuple[int, str]]:
    """Each place in `tree` that reaches the filesystem: an import of a disk module (or of `_io` /
    `lane_trees`); a call resolving (through `_astlib`, so an alias or a module-qualified call is
    the same call) to a disk module's function or to the builtin `open`; and any method call by a
    disk method's name, whatever its receiver (a `Path` is duck-typed, so the name is the fact)."""
    env = astlib.module_env(tree)
    found = []
    # `import os` for `os.environ` alone (a git child's environment) reaches no disk; any other
    # use of the module (a call, `os.path`, ...) keeps the import a touch.
    os_uses = {n.attr for n in ast.walk(tree)
               if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
               and n.value.id == "os"}
    environ_only = os_uses <= {"environ"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            spelled = [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            spelled += [a.name for a in node.names]
            roots = {part for name in spelled for part in name.split(".")}
            if environ_only and isinstance(node, ast.Import) and spelled == ["os"]:
                roots = set()
            if roots & {*_DISK_MODULES, "_io", "lane_trees"}:
                found.append((node.lineno, ast.unparse(node)))
        elif isinstance(node, ast.Call):
            origin = astlib.callee(node, env) or ""
            method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if (origin == "builtins.open" or origin.split(".")[0] in _DISK_MODULES
                    or method in _DISK_METHODS or method.startswith(_DISK_PREFIXES)):
                found.append((node.lineno, ast.unparse(node)))
    return found


def test_git_py_makes_no_filesystem_call_and_imports_no_handle():
    """`_git.py` judges nothing on disk (both `git_commit` and `git_commit_paths` leave that to
    git, N-a, and to their callers): no import of `os` (unless only `os.environ` is used, for a git
    child's environment), `shutil`, `glob`, `tempfile`, `io`, `_io` or `lane_trees`; no call to any of those modules' functions or to the builtin `open`; and no
    `Path` disk method (`exists`, `is_file`, `is_dir`, `stat`, `lstat`, `open`, `read_*`,
    `write_*`, `iterdir`, `glob`, `rglob`, `scandir`, `unlink`, `mkdir`, ...) anywhere in it. This
    is also the lead lane's pin: `commit_corpus` (unchanged) reaches `git_commit`, which has no
    host test. Positive control: the same check finds every touch in a snippet that makes them.

    Catches: today's `(cwd / p).exists()` in `git_commit_paths`; a split re-derived inside
    `_git.py` by a plain `lexists`; and (E08) an "absent" path revived because an
    `os.close(os.open(path, os.O_PATH))` finds it on disk."""
    assert _disk_touches(ast.parse(inspect.getsource(_git))) == []
    assert list(inspect.signature(_git.git_commit_paths).parameters)[:4] == [
        "cwd", "present", "absent", "message"]

    planted = ast.parse(
        "import os\n"
        "import os.path as osp\n"
        "from shutil import copy as cp\n"
        "def f(p):\n"
        "    os.close(os.open(p, os.O_PATH))\n"
        "    osp.lexists(p)\n"
        "    cp(p, p)\n"
        "    open(p)\n"
        "    (p / 'x').exists()\n"
        "    p.read_bytes()\n"
        "    p.iterdir()\n")
    lines = {line for line, _ in _disk_touches(planted)}
    assert lines == set(range(1, 12)) - {4}, _disk_touches(planted)
    environ_only = ast.parse("import os\nimport subprocess\n"
                             "def f():\n    subprocess.run(['git'], env={**os.environ})\n")
    assert _disk_touches(environ_only) == []


# ---------------------------------------------------------------------------------------
# V3-H7 for the curator (addendum 2 correction, C1): no folder is listed; git names the names
# ---------------------------------------------------------------------------------------

#: The curator modules: nothing in them lists or stats a corpus on its own.
_CURATOR_MODULES = {
    "drain": drain,
    "shared": author_shared,
    "lessons_run": lessons_run,
    "questioner_run": questioner_run,
    "author_config": author_config,
}
#: What a folder lister or a hand-rolled existence test calls (beside the plain-path
#: predicates): B2's own lister included, which the curator does not use (C1).
_LISTERS = frozenset({"list_tree", "entries", "under", "walk", "kind", "stat", "lstat",
                      "iterdir", "glob", "rglob", "scandir", "listdir", "exists", "lexists",
                      "is_file", "is_dir", "is_symlink"})


def _function(module, name: str) -> ast.FunctionDef:
    tree = ast.parse(inspect.getsource(module))
    [fn] = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
    return fn


def _callees(node: ast.AST) -> list[str]:
    """Every callee under `node`: a bare name, or an attribute's last component."""
    out: list[str] = []
    for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
        f = call.func
        out.append(f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute)
                   else "")
    return out


@pytest.mark.parametrize(("module", "name", "helper"), [
    (drain, "_snapshot_corpus", "git_tree_blobs"),
    (drain, "_restore_corpus", "git_status"),
    (drain, "_restore_unapproved_files", "entry_kind"),
    (drain, "_put_back", "kind_at"),
    (author_shared, "commit_corpus_paths", "kind_at"),
], ids=["snapshot", "restore_corpus", "restore_unapproved", "put_back", "commit_split"])
def test_each_curator_name_source_and_kind_check_has_one_owner(module, name, helper):
    """Addendum 2's correction (C1), in the lead-author step's V3-H7 shape: the before-state is
    git's read of the tick-start commit (`_git.git_tree_blobs`); the fault sweep asks `git
    status` which names the agent made; the settle restore's folder test asks `entry_kind`;
    `_put_back` and the commit's present / absent split ask `kind_at`. None lists a folder
    (`list_tree`, `entries()`, `scandir`, ...) or tests existence on its own.

    Catches: a before-state or sweep built from a folder listing (a depth-limited one misses
    #773's nested lessons, and the settle restore then deletes a tracked one), a hand-rolled
    `view.entries()` lister, and a plain `exists()` / `lexists()` / `is_file()` existence
    test."""
    calls = _callees(_function(module, name))
    assert helper in calls, (name, calls)
    assert not _LISTERS & set(calls), (name, sorted(_LISTERS & set(calls)))


@pytest.mark.parametrize("label", sorted(_CURATOR_MODULES))
def test_no_curator_module_lists_a_folder(label):
    """No function in the curator modules calls `list_tree`, `.entries()` or `.under()` on
    anything, and none imports `list_tree` (C1: git decides which names to touch, the handle how;
    `list_tree` stays the catalog reader's). Every read goes through the view's `read` /
    `read_bytes` by name. Positive control: the same scan finds each in a snippet that makes
    them."""
    tree = ast.parse(inspect.getsource(_CURATOR_MODULES[label]))
    banned = {"list_tree", "entries", "under"}
    assert not banned & set(_callees(tree)), label
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert "list_tree" not in imported, label
    planted = ast.parse("def f(v):\n    list_tree(v, depth=1)\n    v.under('x').entries()\n")
    assert banned <= set(_callees(planted))


# ---------------------------------------------------------------------------------------
# assert_clean_corpus_dir, existing_finding_ids, build_corpus_manifest, the curator prompt
# ---------------------------------------------------------------------------------------


def test_the_clean_gate_goes_through_the_held_corpus_and_passes_a_clean_tree(tmp_path):
    """`assert_clean_corpus_dir(repo_root, corpus_dir, rel, *, corpus)` reaches the corpus with
    the `Held`'s `mkdir(".")`, and a clean tree passes. What went through the held corpus's
    `os_`: calls on the held root's own descriptor and nothing else — no folder made, no entry
    opened by name (`mkdir(".")` makes nothing: a held root cannot be missing).

    Catches: a gate that makes the folder at its spelling and touches the held corpus only to
    look busy, and one that never reaches the held corpus at all."""
    w = world(tmp_path)
    seam = RecordingOs()
    trees = seamed_trees(w.paths, seam)
    seam.clear()

    author_shared.assert_clean_corpus_dir(w.repo, w.corpus_dir, LESSONS_REL,
                                          corpus=trees.mount(w.corpus_dir))

    assert seam.descriptors() == {os.path.realpath(w.corpus_dir)}, seam.trace
    assert not {"mkdir", "open"} & set(seam.calls), seam.trace


def test_the_clean_gate_makes_nothing_where_the_held_root_was(tmp_path):
    """`corpus.mkdir(".")` makes nothing (a held root cannot be missing): with the held corpus
    root removed since it was held, the gate makes no folder at its spelling, and the removal
    shows as dirt (the tracked `.gitkeep` deleted), so it refuses (`AuthorError`).

    Catches: today's `corpus_dir.mkdir(parents=True, exist_ok=True)`, kept beside the new
    keyword, which makes a fresh folder at the spelling the held root no longer is."""
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
    """`existing_finding_ids(cfg)` reads through `cfg.corpus.view()`: a lesson name holding a
    link (or hard link) to an outside lesson citing `f-out` contributes no id; a plain lesson's
    ids are collected; the reads went through the config's held corpus. The positive control is
    the same bytes as a plain file: `f-out` counted."""
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
    """E03: `existing_finding_ids(cfg)` collects ids from what `cfg.corpus`'s view reads. Over a
    held corpus whose view refuses `b.md` (a plain file on disk, so only a read through THIS view
    can miss it), `f-b` is not collected, `f-a` is, and the journal shows each lesson read
    through it. Control: the same corpus held without the refusal collects both.

    Catches: an idempotency read that asks `cfg.corpus` whether the folder is there and then
    reads the corpus by its spelling (`iter_lessons(cfg.corpus_dir)`), which reads `b.md`."""
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
    """`build_corpus_manifest(view, where=corpus_dir)` (the drain's Bound form): an aliased
    lesson keeps its stem with the "unavailable" placeholder and none of the target's bytes; the
    plain control renders its frontmatter."""
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


def test_the_manifest_takes_where_with_a_bound_and_refuses_it_with_a_path(tmp_path):
    """A4's shared-reader rule, passed through from `iter_lessons`: the Bound form needs `where`
    (the folder it is spelled as), the Path form (N-h, callers outside the drain) refuses one;
    each is `ValueError`. The two forms over the same plain corpus render the same manifest."""
    w = world(tmp_path)
    put(w.corpus_dir / "one.md", lesson_text("f1", topic="first"))
    put(w.corpus_dir / "two.md", lesson_text("f2", topic="second"))

    with pytest.raises(ValueError):  # noqa: PT011 — iter_lessons' own where-rule refusal
        author_shared.build_corpus_manifest(w.view)
    with pytest.raises(ValueError):  # noqa: PT011 — iter_lessons' own where-rule refusal
        author_shared.build_corpus_manifest(w.corpus_dir, where=w.corpus_dir)

    bound = author_shared.build_corpus_manifest(w.view, where=w.corpus_dir, seed="s")
    path = author_shared.build_corpus_manifest(w.corpus_dir, seed="s")
    assert bound == path
    assert "topic: first" in bound
    assert "topic: second" in bound


def test_the_curator_prompt_requires_the_view_and_reads_the_manifest_from_it(tmp_path):
    """`build_curator_user_prompt(..., corpus=<view>, corpus_dir=<spelling>, ...)`: `corpus` is
    required (no Path form, owner decision 2), and the manifest is read from it; `corpus_dir` is
    the spelling only. With the view of one folder and the spelling of another, the prompt
    carries the viewed folder's lessons and none of the spelled one's.

    Catches: a builder that takes `corpus` and still reads `corpus_dir`."""
    viewed = tmp_path / "viewed"
    spelled = tmp_path / "spelled"
    put(viewed / "viewed-lesson.md", lesson_text("f1", topic="from-the-view"))
    put(spelled / "spelled-lesson.md", lesson_text("f2", topic="from-the-spelling"))
    kw = dict(corpus_dir_rel="defender/lessons/", label="findings", salt="5a")

    with pytest.raises(TypeError):
        author_shared.build_curator_user_prompt([{"finding_id": "f1"}], "batch-1",
                                                corpus_dir=spelled, **kw)

    prompt = author_shared.build_curator_user_prompt(
        [{"finding_id": "f1"}], "batch-1", corpus=corpus_view(viewed), corpus_dir=spelled, **kw)

    assert "viewed-lesson" in prompt
    assert "from-the-view" in prompt
    assert "spelled-lesson" not in prompt
    assert "from-the-spelling" not in prompt


@pytest.mark.parametrize("channel", ["lessons", "questioner"])
def test_the_curator_prompts_manifest_reads_through_cfg_corpus(tmp_path, channel):
    """Each channel's curator prompt builds its corpus manifest from `cfg.corpus.view()`: an
    aliased lesson shows as unavailable with none of its target's bytes, a plain lesson's
    frontmatter is rendered, and each lesson was read through the config's held corpus."""
    w = world(tmp_path)
    root, prompt_of, cfg = _channel_prompt(w, channel)
    plant_link(root / PLANTED, w.target("secret.md", lesson_text("f9", topic=OUT_MARK)))
    put(root / "plain.md", lesson_text("f0", topic="plain-topic"))
    log: list = []
    cfg = dataclasses.replace(cfg, corpus=JournalHeld(root, log))

    prompt = prompt_of([{"finding_id": "f1"}], "batch-1", cfg)

    assert "plain-topic" in prompt
    assert OUT_MARK not in prompt
    assert PLANTED.removesuffix(".md") in prompt
    assert {("read", "plain.md"), ("read", PLANTED)} <= set(log), log


def _channel_prompt(w, channel):
    """`(corpus root, the channel's prompt builder, its config over the world's trees)`."""
    from defender.learning.author.lessons import run as lessons_run
    from defender.learning.author.questioner import run as questioner_run

    if channel == "lessons":
        return w.corpus_dir, lessons_run.build_user_prompt, w.cfg()
    return (w.sibling_dir, questioner_run.build_questioner_user_prompt,
            questioner_cfg(w.paths, trees=w.trees))


@pytest.mark.parametrize("channel", ["lessons", "questioner"])
def test_each_channel_prompt_shows_a_lesson_cfg_corpus_refuses_as_unavailable(tmp_path, channel):
    """E07: each channel's prompt manifest is what `cfg.corpus`'s view reads. Over a held corpus
    whose view refuses `b.md` (plain on disk), the manifest keeps `b`'s stem under the
    "unavailable" placeholder with none of its frontmatter, renders `a`'s, and the journal shows
    both read through that view. Control: held without the refusal, `b`'s topic is rendered and
    nothing is unavailable.

    Catches: a prompt builder that checks `cfg.corpus` and then reads the manifest from the
    corpus's spelling (`_corpus._viewed(cfg.corpus_dir)`), which reads `b.md` in full."""
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

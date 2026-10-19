from __future__ import annotations

import logging
import os
import re
import shutil
import stat
from pathlib import Path

import pytest

from defender import _git
from defender._git import GitError
from defender.learning.author import drain
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


def _break_index(w) -> None:
    (w.repo / ".git" / "index").write_bytes(b"not an index\n")


def test_git_names_each_unchanged_regular_file_and_none_that_changed(tmp_path):
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


def test_the_settle_comparison_raises_rather_than_answer_when_git_cannot(tmp_path):
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
    assert [r.get("fault_class") for r in S.stuck_records(sc.paths, sc.channel)] == ["GitProbeError"]
    assert sc.pending_by_id()["f1"].get("attempts") is None
    assert sc.head_files() == []
    assert (sc.corpus / SEEDED).read_text() == lesson_text("f0")
    assert not os.path.lexists(sc.corpus / PLANTED)


@pytest.mark.parametrize("fault", ["unknown commit", "broken index"])
def test_a_git_failure_in_the_settle_restores_comparison_is_a_git_probe_before_any_change(
    tmp_path, fault,
):
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


def _restore(w, snapshot, *, head_before: str, corpus=None) -> None:
    drain._restore_corpus(w.repo, w.corpus_dir, snapshot,
                          corpus=corpus if corpus is not None else w.corpus,
                          head_before=head_before)


def test_the_fault_restore_rewrites_only_what_git_says_changed(tmp_path):
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


@pytest.mark.parametrize("mode", ["same mode", "made executable"])
def test_a_hard_link_holding_a_lessons_exact_bytes_is_never_committed(tmp_path, mode):
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
    target = holder["target"]
    assert target.read_text() == lesson_text("f0")
    assert (sc.corpus / SEEDED).read_text() == lesson_text("f0")
    same_inode = os.stat(sc.corpus / SEEDED).st_ino == os.stat(target).st_ino
    assert same_inode is (mode == "same mode")

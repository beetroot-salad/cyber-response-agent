"""Unit tests for the shared git transaction layer (``_author_shared``).

The loop is the sole committer; the agent runs no git. These exercise the
corpus-agnostic helpers that ``author.py`` and ``_author_curator.py`` both adapt
over — ``commit_corpus`` (pathspec-scoped, optional provenance trailers),
``changes_outside`` (the stray scope-gate), ``corpus_dir_clean``,
``verify_agent_state``, ``git_head_sha``, ``_commit_message``, ``_result_list``.

The git layer takes the repo root as a parameter, so every test **injects** a
tmp repo directly — no monkeypatching of module globals (that was the smell the
#330 consolidation removed). The per-direction provenance round-trip (the actor
``Actor-Model:`` trailer the generation counter greps) and the full
``run_batch`` envelope live in ``test_author_actor.py`` /
``test_author_postflight.py``, which drive the adapters end-to-end.
"""
from __future__ import annotations

import errno
import subprocess
from pathlib import Path

import pytest

from defender.learning import _author_shared as shared  # type: ignore[import-not-found]

# Reference ``shared.AuthorError`` live (not a module-level alias): a sibling test's
# ``tmp_repo`` fixture reloads ``_author_shared``, which rebinds the class — a captured
# alias would go stale and stop matching freshly-raised errors. In production nothing
# reloads, so author.py / _author_curator.py / _author_shared all share one class.

CORPUS_REL = "defender/lessons/"


# ---------------------------------------------------------------------------
# Fixture helpers — a fresh tmp repo, injected as repo_root (no monkeypatch).
# ---------------------------------------------------------------------------


def _repo(tmp_path: Path) -> Path:
    """A fresh git repo with a seed commit and an empty corpus dir."""
    repo = tmp_path / "repo"
    (repo / CORPUS_REL).mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)
    (repo / "README").write_text("seed\n")
    subprocess.run(["git", "-C", str(repo), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "seed"], check=True)
    return repo


def _corpus(repo: Path) -> Path:
    return repo / CORPUS_REL


def _head_files(repo: Path) -> list[str]:
    return subprocess.run(
        ["git", "-C", str(repo), "show", "--name-only", "--pretty=format:", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.split()


def _head_message(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "log", "-1", "--pretty=%B", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout


def _status(repo: Path, path: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain", "--", path],
        capture_output=True, text=True, check=True,
    ).stdout


# ---------------------------------------------------------------------------
# commit_corpus — pathspec-scoped commit, optional trailers, no-op, guard
# ---------------------------------------------------------------------------


def test_commit_corpus_commits_only_corpus(tmp_path):
    """The author path (no trailers): an uncommitted corpus edit is committed, the new sha
    returned, the working tree left clean, and no provenance trailer is stamped."""
    repo = _repo(tmp_path)
    (_corpus(repo) / "x.md").write_text("hello\n")  # agent edit, uncommitted
    sha = shared.commit_corpus(repo, _corpus(repo), CORPUS_REL, "lesson batch")
    assert sha == shared.git_head_sha(repo)
    assert _head_files(repo) == ["defender/lessons/x.md"]
    assert shared.changes_outside(repo, CORPUS_REL) == []
    assert "Generation:" not in _head_message(repo)


def test_commit_corpus_stages_only_corpus(tmp_path):
    """#321: a file already **staged** outside the corpus (a sibling author's ``_draft/``
    deposit left in the shared index) must NOT ride into the pathspec-scoped commit. A
    bare index-global ``git commit`` would sweep it in; ``-- <corpus_dir>`` bounds it."""
    repo = _repo(tmp_path)
    (_corpus(repo) / "x.md").write_text("hello\n")
    (repo / "stray.txt").write_text("stray\n")  # outside the corpus
    subprocess.run(["git", "-C", str(repo), "add", "stray.txt"], check=True)

    shared.commit_corpus(repo, _corpus(repo), CORPUS_REL, "lesson batch")
    files = _head_files(repo)
    assert files == ["defender/lessons/x.md"]
    assert "stray.txt" not in files
    # The stray stays staged-but-uncommitted, untouched by the lesson commit.
    assert _status(repo, "stray.txt").startswith("A  ")


def test_commit_corpus_no_op_when_nothing_authored(tmp_path):
    """Empty index ⇒ no commit, returns None (the all-skip batch); HEAD unchanged."""
    repo = _repo(tmp_path)
    head_before = shared.git_head_sha(repo)
    assert shared.commit_corpus(repo, _corpus(repo), CORPUS_REL, "msg") is None
    assert shared.git_head_sha(repo) == head_before


def test_commit_corpus_appends_trailers(tmp_path):
    """When ``trailers`` is given (the actor/env provenance path) each lands on the commit
    at creation time, and the commit is still pathspec-scoped to the corpus."""
    repo = _repo(tmp_path)
    (_corpus(repo) / "x.md").write_text("hello\n")
    shared.commit_corpus(
        repo, _corpus(repo), CORPUS_REL, "lesson batch",
        trailers=[("Generation", "3"), ("Actor-Model", "claude-x")],
    )
    msg = _head_message(repo)
    assert "Generation: 3" in msg
    assert "Actor-Model: claude-x" in msg
    assert _head_files(repo) == ["defender/lessons/x.md"]


def test_commit_corpus_rejects_message_carrying_trailers(tmp_path):
    """If the agent put its own trailers in the message, ``git --trailer`` would *append* a
    second set that shadows the loop's for first-match readers — refuse before staging
    anything (HEAD unchanged, queue intact for retry). The guard derives from the trailer
    keys, so it fires on either ``Generation:`` or the model label."""
    repo = _repo(tmp_path)
    (_corpus(repo) / "x.md").write_text("hello\n")
    head_before = shared.git_head_sha(repo)
    with pytest.raises(shared.AuthorError, match="already carries"):
        shared.commit_corpus(
            repo, _corpus(repo), CORPUS_REL,
            "batch\n\nGeneration: 99\nActor-Model: wrong",
            trailers=[("Generation", "3"), ("Actor-Model", "claude-x")],
        )
    assert shared.git_head_sha(repo) == head_before


def test_commit_corpus_no_trailers_skips_the_dup_guard(tmp_path):
    """No trailers ⇒ no dup-guard: the author path (which stamps none) commits its message
    verbatim even if the body happens to contain a ``Generation:`` line — there is no
    loop-owned trailer for it to shadow."""
    repo = _repo(tmp_path)
    (_corpus(repo) / "x.md").write_text("hello\n")
    sha = shared.commit_corpus(
        repo, _corpus(repo), CORPUS_REL, "batch\n\nGeneration: not-a-trailer",
    )
    assert sha == shared.git_head_sha(repo)


def test_commit_corpus_commit_failure_is_atomic(tmp_path):
    """#321: a failing commit (here a rejecting pre-commit hook, the issue's exact trigger)
    raises ``AuthorError`` and leaves HEAD untouched — no un-stamped lesson commit lands,
    so the caller can keep the queue intact for retry."""
    repo = _repo(tmp_path)
    hooks = repo / ".git" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    hook = hooks / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o755)
    (_corpus(repo) / "x.md").write_text("hello\n")
    head_before = shared.git_head_sha(repo)
    with pytest.raises(shared.AuthorError, match="failed to commit"):
        shared.commit_corpus(repo, _corpus(repo), CORPUS_REL, "lesson batch")
    assert shared.git_head_sha(repo) == head_before


# ---------------------------------------------------------------------------
# changes_outside / corpus_dir_clean — the scope-gate primitives
# ---------------------------------------------------------------------------


def test_changes_outside_flags_only_non_corpus_paths(tmp_path):
    """A corpus ``*.md`` edit is in-scope; anything else (incl. a non-``.md`` file inside
    the corpus dir) is stray. ``--untracked-files=all`` reports each stray individually."""
    repo = _repo(tmp_path)
    (_corpus(repo) / "x.md").write_text("hello\n")       # in scope
    (repo / "scratch.txt").write_text("nope\n")          # stray (outside)
    (_corpus(repo) / "notes.txt").write_text("nope\n")   # stray (wrong suffix)
    assert shared.changes_outside(repo, CORPUS_REL) == [
        "defender/lessons/notes.txt",
        "scratch.txt",
    ]


def test_corpus_dir_clean(tmp_path):
    repo = _repo(tmp_path)
    assert shared.corpus_dir_clean(repo, _corpus(repo)) is True
    (_corpus(repo) / "x.md").write_text("hello\n")
    assert shared.corpus_dir_clean(repo, _corpus(repo)) is False


# ---------------------------------------------------------------------------
# verify_agent_state — the post-flight working-tree cross-check
# ---------------------------------------------------------------------------


def test_verify_rejects_change_outside_corpus(tmp_path):
    """Scope gate: a working-tree change outside the corpus (a stray the path-scoped commit
    would ignore) fails verification rather than committing silently."""
    repo = _repo(tmp_path)
    (repo / "scratch.txt").write_text("stray\n")  # uncommitted, outside the corpus
    result = {"committed": [], "commit_message": None}
    with pytest.raises(shared.AuthorError, match="outside"):
        shared.verify_agent_state(repo, result, _corpus(repo), CORPUS_REL, "findings", [])


def test_verify_tolerates_baseline_stray(tmp_path):
    """A stray already present in the pre-agent ``baseline_stray`` is not blamed on the
    agent — only *new* out-of-corpus changes fail the gate."""
    repo = _repo(tmp_path)
    (repo / "scratch.txt").write_text("stray\n")
    baseline = shared.changes_outside(repo, CORPUS_REL)
    result = {"committed": [], "commit_message": None}
    # No new stray beyond baseline, corpus clean, committed empty ⇒ passes (no raise).
    shared.verify_agent_state(
        repo, result, _corpus(repo), CORPUS_REL, "findings", baseline
    )


def test_verify_rejects_no_commit_with_corpus_edits(tmp_path):
    """``committed`` empty but the corpus is dirty ⇒ inconsistent; refuse to rotate."""
    repo = _repo(tmp_path)
    (_corpus(repo) / "x.md").write_text("hello\n")
    result = {"committed": [], "commit_message": None}
    with pytest.raises(shared.AuthorError, match="left edits"):
        shared.verify_agent_state(repo, result, _corpus(repo), CORPUS_REL, "findings", [])


def test_verify_rejects_committed_with_clean_corpus_using_noun(tmp_path):
    """``committed`` non-empty but the corpus is clean ⇒ inconsistent; refuse to rotate. The
    error embeds the corpus's ``noun`` (the one error line that differs between corpora)."""
    repo = _repo(tmp_path)
    result = {"committed": ["a/0"], "commit_message": "m"}
    with pytest.raises(shared.AuthorError, match="committed observations but left"):
        shared.verify_agent_state(
            repo, result, _corpus(repo), CORPUS_REL, "observations", []
        )


# ---------------------------------------------------------------------------
# git_head_sha / _commit_message / _result_list — the small lifted helpers
# ---------------------------------------------------------------------------


def test_git_head_sha_matches_rev_parse(tmp_path):
    repo = _repo(tmp_path)
    expected = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert shared.git_head_sha(repo) == expected


def test_commit_message_returns_the_message():
    assert shared._commit_message({"commit_message": "hi"}, "findings") == "hi"


@pytest.mark.parametrize("noun", ["findings", "observations"])
def test_commit_message_rejects_empty_with_corpus_noun(noun):
    """The missing/empty-message error names the corpus's unit of work — the single token
    that differs between the two corpora, proven here against one shared implementation."""
    with pytest.raises(shared.AuthorError, match=f"committed {noun} without"):
        shared._commit_message({"commit_message": ""}, noun)


def test_result_list_normalizes_and_validates():
    assert shared._result_list({}, "committed") == []
    assert shared._result_list({"committed": None}, "committed") == []
    assert shared._result_list({"committed": ["a"]}, "committed") == ["a"]
    with pytest.raises(shared.AuthorError, match="must be a list"):
        shared._result_list({"committed": "x"}, "committed")


# ---------------------------------------------------------------------------
# flock_or_skip — the scoped non-blocking flock (author-drain / lesson-revert).
# ---------------------------------------------------------------------------


def test_flock_or_skip_acquires_then_releases(tmp_path: Path):
    """Yields True when uncontended, mkdir's the parent, and releases on exit."""
    lock = tmp_path / "sub" / ".lock"
    with shared.flock_or_skip(lock) as locked:
        assert locked is True
        assert lock.parent.is_dir()  # parent created on the way in
    # released on block exit: a fresh non-blocking acquire now succeeds
    fh = shared.acquire_flock(lock)
    assert fh is not None
    shared.release_flock(fh)


def test_flock_or_skip_yields_false_when_held(tmp_path: Path):
    """A second entrant on a held lock yields False (skip) rather than blocking."""
    lock = tmp_path / ".lock"
    holder = shared.acquire_flock(lock)
    assert holder is not None
    try:
        with shared.flock_or_skip(lock) as locked:
            assert locked is False
    finally:
        shared.release_flock(holder)


def test_flock_or_skip_propagates_non_contention_oserror(tmp_path: Path, monkeypatch):
    """A genuine lock-subsystem failure (e.g. ENOLCK) propagates — it is NOT
    swallowed as contention. This is the contract #367 standardized on: only
    ``BlockingIOError`` means "someone else holds it"; everything else is a real
    error the caller should see, not a silent skip."""
    lock = tmp_path / ".lock"

    def _no_locks(_fd, _op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(shared.fcntl, "flock", _no_locks)
    with pytest.raises(OSError, match="No locks available") as excinfo, shared.flock_or_skip(lock):
        pass  # never reached — acquire raises before yielding
    assert excinfo.value.errno == errno.ENOLCK


def test_acquire_flock_closes_handle_when_error_propagates(tmp_path: Path, monkeypatch):
    """The fail-loud path (e.g. ENOLCK) must still close the lock-file handle:
    propagating must not leak the fd. The propagating traceback pins
    ``acquire_flock``'s frame (whose ``fh`` local references the handle), so
    without an explicit close the fd lingers — the inline dances this replaced
    closed it in their ``finally``. ``flock_or_skip`` can't recover it either, as
    ``acquire_flock`` raises before its ``try``/``finally`` is entered."""
    lock = tmp_path / ".lock"
    opened: list = []
    real_open = Path.open

    def _tracking_open(self, *a, **k):
        fh = real_open(self, *a, **k)
        opened.append(fh)
        return fh

    def _no_locks(_fd, _op):
        raise OSError(errno.ENOLCK, "No locks available")

    monkeypatch.setattr(Path, "open", _tracking_open)
    monkeypatch.setattr(shared.fcntl, "flock", _no_locks)
    with pytest.raises(OSError, match="No locks available"):
        shared.acquire_flock(lock)
    assert opened, "acquire_flock never opened the lock file"
    assert all(fh.closed for fh in opened), "acquire_flock leaked the lock-file handle"

"""Unit coverage for the shared git facade (``defender._git``).

Exercises the primitive against a real throwaway repo — git is local/deterministic, so
the facade is tested for real, not against a fake runner (the #389 / #460 philosophy).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender import _git  # type: ignore[import-not-found]


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git.git(["init", "-q", "-b", "main"], cwd=repo)
    _git.git(["config", "user.email", "t@t"], cwd=repo)
    _git.git(["config", "user.name", "t"], cwd=repo)
    (repo / "seed.md").write_text("seed\n")
    _git.git(["add", "-A"], cwd=repo)
    _git.git(["commit", "-q", "-m", "seed"], cwd=repo)
    return repo


def test_git_returns_stripped_stdout(tmp_path):
    repo = _repo(tmp_path)
    assert _git.git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo) == "main"


def test_git_raises_giterror_with_context_on_failure(tmp_path):
    repo = _repo(tmp_path)
    with pytest.raises(_git.GitError) as exc:
        _git.git(["rev-parse", "does-not-exist"], cwd=repo)
    assert exc.value.returncode != 0
    assert "rev-parse" in str(exc.value)


def test_git_check_false_swallows_nonzero(tmp_path):
    repo = _repo(tmp_path)
    # An unknown rev with --quiet prints nothing and exits nonzero; check=False → "".
    assert _git.git(["rev-parse", "--verify", "--quiet", "nope"], cwd=repo, check=False) == ""


def test_git_ok_is_a_predicate(tmp_path):
    repo = _repo(tmp_path)
    assert _git.git_ok(["cat-file", "-e", "HEAD:seed.md"], cwd=repo) is True
    assert _git.git_ok(["cat-file", "-e", "HEAD:ghost.md"], cwd=repo) is False


def test_git_status_z_handles_spaced_paths(tmp_path):
    """The ``-z`` reader keeps a path with spaces intact (the correctness upgrade over the
    old non-``-z`` ``line[3:]`` parser, which split on whitespace)."""
    repo = _repo(tmp_path)
    (repo / "a file with spaces.md").write_text("x\n")
    records = _git.git_status(repo)
    assert ("??", "a file with spaces.md") in records


def test_git_status_survives_non_utf8_path(tmp_path):
    """A non-UTF-8 untracked filename must not crash ``git_status`` (the ``-z`` form emits
    raw, unquoted path bytes, so a strict decode would ``UnicodeDecodeError``). It is
    surrogate-escaped and surfaces as an out-of-corpus record the scope gate quarantines."""
    repo = _repo(tmp_path)
    # Write a file whose *name* carries the raw byte 0xff (invalid UTF-8) — a bytes path, so
    # the filesystem stores the byte verbatim rather than re-encoding a decoded str to UTF-8.
    with open(os.path.join(os.fsencode(repo), b"stray-\xff.md"), "wb") as f:
        f.write(b"x\n")
    records = _git.git_status(repo)  # must not raise
    strays = [p for xy, p in records if xy == "??"]
    assert strays == ["stray-\udcff.md"]  # raw byte round-tripped via surrogateescape


def test_git_status_pathspec_scopes(tmp_path):
    repo = _repo(tmp_path)
    sub = repo / "sub"
    sub.mkdir()
    (sub / "x.md").write_text("x\n")
    (repo / "top.md").write_text("y\n")
    scoped = [p for _xy, p in _git.git_status(repo, pathspec=sub)]
    assert scoped == ["sub/x.md"]  # top.md excluded by the pathspec


def test_git_head_sha_and_rev_list_count(tmp_path):
    repo = _repo(tmp_path)
    assert len(_git.git_head_sha(repo)) == 40
    assert _git.git_rev_list_count(repo) == 1
    # a grep that matches nothing → 0
    assert _git.git_rev_list_count(repo, grep="^Nonexistent-Trailer:") == 0


def test_git_commit_pathspec_scoped_and_trailers(tmp_path):
    repo = _repo(tmp_path)
    (repo / "corpus").mkdir()
    (repo / "corpus" / "lesson.md").write_text("body\n")
    (repo / "stray.txt").write_text("stray\n")
    _git.git(["add", "stray.txt"], cwd=repo)  # staged outside the pathspec
    sha = _git.git_commit(
        repo, repo / "corpus", "batch", trailers=[("Generation", "3")]
    )
    assert sha == _git.git_head_sha(repo)
    files = _git.git(["show", "--name-only", "--pretty=format:", "HEAD"], cwd=repo).split()
    assert files == ["corpus/lesson.md"]  # stray.txt did NOT ride along
    assert "Generation: 3" in _git.git(["log", "-1", "--pretty=%B", "HEAD"], cwd=repo)


def test_git_commit_no_op_returns_none(tmp_path):
    repo = _repo(tmp_path)
    (repo / "corpus").mkdir()
    assert _git.git_commit(repo, repo / "corpus", "nothing staged") is None


def test_git_worktree_add_remove(tmp_path):
    repo = _repo(tmp_path)
    wt = tmp_path / "wt"
    _git.git_worktree_add(repo, wt, "HEAD", detach=True)
    assert (wt / "seed.md").is_file()
    assert _git.git_head_sha(wt) == _git.git_head_sha(repo)
    _git.git_worktree_remove(repo, wt)
    assert not wt.exists()


def test_git_worktree_add_branch(tmp_path):
    repo = _repo(tmp_path)
    wt = tmp_path / "wt"
    _git.git_worktree_add(repo, wt, "HEAD", branch="feature/x")
    assert _git.git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=wt) == "feature/x"

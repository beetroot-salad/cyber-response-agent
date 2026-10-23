"""Unit coverage for the shared git facade (`defender._git`) against a real throwaway repo."""
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
    repo = _repo(tmp_path)
    with open(os.path.join(os.fsencode(repo), b"stray-\xff.md"), "wb") as f:
        f.write(b"x\n")
    records = _git.git_status(repo)
    strays = [p for xy, p in records if xy == "??"]
    assert strays == ["stray-\udcff.md"]


def test_git_status_z_consumes_the_rename_origpath(tmp_path):
    repo = _repo(tmp_path)
    _git.git(["mv", "seed.md", "renamed.md"], cwd=repo)
    records = _git.git_status(repo)
    assert records == [("R ", "renamed.md")]


def test_git_status_z_rename_does_not_swallow_the_next_record(tmp_path):
    """Only the origPath field is consumed — a real record following the rename survives."""
    repo = _repo(tmp_path)
    (repo / "zz-other.md").write_text("x\n")
    _git.git(["mv", "seed.md", "renamed.md"], cwd=repo)
    records = _git.git_status(repo)
    assert ("R ", "renamed.md") in records
    assert ("??", "zz-other.md") in records
    assert len(records) == 2


def test_git_status_pathspec_scopes(tmp_path):
    repo = _repo(tmp_path)
    sub = repo / "sub"
    sub.mkdir()
    (sub / "x.md").write_text("x\n")
    (repo / "top.md").write_text("y\n")
    scoped = [p for _xy, p in _git.git_status(repo, pathspec=sub)]
    assert scoped == ["sub/x.md"]


def test_git_head_sha(tmp_path):
    repo = _repo(tmp_path)
    assert len(_git.git_head_sha(repo)) == 40


# #1108 P4 OD12(i): the cases for `_git.git_rev_list_count` (the `rev_list_count` half of the
# case above), `git_commit` (pathspec-scoped with trailers, and the no-op), `git_worktree_add`/
# `git_worktree_remove` (detached and on a branch), `git_push` (sets upstream) and `git_fetch`
# (advances the tracking ref) are deleted with those helpers: their only callers were the
# deleted `AuthorBranch` worktree delivery and the legacy checkout drains. Every corpus commit,
# push and fetch now goes through P3's delivery, pinned in `tests/tenancy/tenant_1108_delivery/`:
# `test_changes.py::test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files`
# and `::test_the_first_commit_makes_the_branch_and_never_takes_one_over` (the commit-maker's
# commit and branch), `test_delivery.py::test_finish_pushes_the_commit_maker_branch_and_opens_its_pr_without_product_write`
# (the push), and `test_publish.py::test_publish_writes_the_commits_blobs_and_points_current_at_them`
# (the fetch the publish exports).

#!/usr/bin/env python3
"""One-click lesson revert (platform-design §4.4 human control loop).

Lessons are recommend-only and reversible: the post-merge control is not pre-merge
sign-off but visibility (``trace_lesson.py``) + this one-click revert. Given a lesson
slug, opens a PR that ``git rm``s ``defender/lessons/<name>.md`` off freshly-fetched
``origin/main`` — reusing ``author_branch.AuthorBranch`` for the branch/PR machinery
(dirty-tree guard, HEAD restore). Not lease-gated: a revert may need to land while
another lessons PR is open.

Usage:
  revert_lesson.py <lesson_name>
"""
from __future__ import annotations

import contextlib
import fcntl
import sys

from _loop_config import DEFAULT_PATHS, LoopPaths
from author_branch import AuthorBranch, BranchError

LESSONS_REL = "defender/lessons"


def revert(
    lesson_name: str, *, branch: AuthorBranch | None = None, paths: LoopPaths = DEFAULT_PATHS
) -> int:
    """Open a one-click revert PR for ``defender/lessons/<lesson_name>.md``.

    Holds the author-drain flock for the duration so an in-flight ``author_drain``
    batch can't move the shared checkout out from under the ``checkout -B`` (and vice
    versa). Existence is verified against ``origin/main`` inside ``revert_lesson_pr``."""
    if branch is None:
        branch = AuthorBranch()
    rel = f"{LESSONS_REL}/{lesson_name}.md"

    lock_path = paths.author_drain_lock_file
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+")
    try:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print("[revert_lesson] an author drain is in progress — retry shortly",
                  file=sys.stderr)
            return 3
        try:
            pr = branch.revert_lesson_pr(rel, lesson_name)
        except BranchError as e:
            print(f"[revert_lesson] FATAL: {e}", file=sys.stderr)
            return 2
        print(f"opened revert PR: {pr}")
        return 0
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: revert_lesson.py <lesson_name>", file=sys.stderr)
        return 64
    return revert(argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

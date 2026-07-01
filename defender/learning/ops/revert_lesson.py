#!/usr/bin/env python3
"""One-click lesson revert (platform-design §4.4 human control loop).

Lessons are recommend-only and reversible: the post-merge control is not pre-merge
sign-off but visibility (``trace_lesson.py``) + this one-click revert. Given a lesson
slug, opens a PR that ``git rm``s ``defender/lessons/<name>.md`` off freshly-fetched
``origin/main`` — reusing ``author_branch.AuthorBranch`` for the branch/PR machinery
(its own throwaway worktree, so the dev checkout is never touched). Not lease-gated: a
revert may need to land while another lessons PR is open.

Usage:
  revert_lesson.py <lesson_name>
"""
from __future__ import annotations

import sys

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
from pathlib import Path
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import shared as _author_shared
from defender.learning.core.config import DEFAULT_PATHS, LoopPaths
from defender.learning.author.branch import AuthorBranch, BranchError

LESSONS_REL = "defender/lessons"


def revert(
    lesson_name: str, *, branch: AuthorBranch | None = None, paths: LoopPaths = DEFAULT_PATHS
) -> int:
    """Open a one-click revert PR for ``defender/lessons/<lesson_name>.md``.

    ``revert_lesson_pr`` is now HEAD-safe on its own (it runs in a throwaway worktree off
    ``origin/main``, never the dev checkout), so this flock is belt-and-suspenders — it
    serializes the revert against an in-flight ``author_drain`` at the process level
    rather than being the sole guard it was under the old in-place ``checkout -B``.
    Existence is verified against ``origin/main`` inside ``revert_lesson_pr``."""
    if branch is None:
        branch = AuthorBranch()
    rel = f"{LESSONS_REL}/{lesson_name}.md"

    with _author_shared.flock_or_skip(paths.author_drain_lock_file) as locked:
        if not locked:
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


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: revert_lesson.py <lesson_name>", file=sys.stderr)
        return 64
    return revert(argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

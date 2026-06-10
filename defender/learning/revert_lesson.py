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

import sys
from pathlib import Path

from author_branch import AuthorBranch, BranchError

REPO_ROOT = Path(__file__).resolve().parents[2]
LESSONS_REL = "defender/lessons"


def revert(lesson_name: str, *, branch: AuthorBranch | None = None) -> int:
    if branch is None:
        branch = AuthorBranch()
    lesson_path = REPO_ROOT / LESSONS_REL / f"{lesson_name}.md"
    if not lesson_path.is_file():
        print(f"no such lesson: {lesson_path}", file=sys.stderr)
        return 1
    rel = f"{LESSONS_REL}/{lesson_name}.md"
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

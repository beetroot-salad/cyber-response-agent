#!/usr/bin/env python3
from __future__ import annotations

import sys

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
        print(f"revert PR: {pr}")
        return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: revert_lesson.py <lesson_name>", file=sys.stderr)
        return 64
    return revert(argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

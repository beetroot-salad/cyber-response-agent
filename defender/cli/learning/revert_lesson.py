#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys

from pathlib import Path
if (_root := str(Path(__file__).resolve().parents[3])) not in sys.path:
    sys.path.insert(0, _root)

from defender.knowledge._knowledge import CHECKOUT_KNOWLEDGE, LESSONS
from defender.learning.core.cli import command_line_paths
from defender.learning.core.state import AUTHOR_DRAIN_LOCK, TRY_ONCE, LearningState
from defender.learning.author.branch import AuthorBranch, BranchError

_logger = logging.getLogger(__name__)

LESSONS_REL = CHECKOUT_KNOWLEDGE.rel(LESSONS).rstrip("/")


def revert(
    lesson_name: str, *, state: LearningState, branch: AuthorBranch | None = None,
) -> int:
    if branch is None:
        branch = AuthorBranch()
    rel = f"{LESSONS_REL}/{lesson_name}.md"

    with state.lock(AUTHOR_DRAIN_LOCK, wait=TRY_ONCE) as locked:
        if not locked:
            _logger.warning("an author drain is in progress — retry shortly")
            return 3
        try:
            pr = branch.revert_lesson_pr(rel, lesson_name)
        except BranchError as e:
            _logger.critical(f"{e}")
            return 2
        print(f"revert PR: {pr}")
        return 0


def main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Revert a lesson under its tenant's drain lock")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("lesson_name")
    args = parser.parse_args(argv)
    paths = command_line_paths(parser, args.tenant)
    with LearningState.open(paths) as state:
        return revert(args.lesson_name, state=state)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))

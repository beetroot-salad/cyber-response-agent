#!/usr/bin/env python3
from __future__ import annotations

import functools
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import curator as _curator
from defender.learning.author import shared as _shared
from defender.learning.core.config import (
    ACTOR_MODEL,
    AUTHOR_ACTOR_EFFORT,
    AUTHOR_ACTOR_MODEL,
    AUTHOR_ACTOR_REQUEST_LIMIT,
    AUTHOR_ACTOR_TIMEOUT,
    DEFAULT_PATHS,
    LoopPaths,
)



AuthorError = _curator.AuthorError


def invoke_agent(
    observations: list[dict],
    batch_id: str,
    cfg: _curator.CuratorConfig,
) -> dict:
    from defender.learning.author.verify_forward.checks import ACTOR_CHECK

    return _curator.invoke_curator_agent(
        cfg, observations, batch_id,
        check=ACTOR_CHECK,
        request_limit=AUTHOR_ACTOR_REQUEST_LIMIT,
    )


def build_actor_config(paths: LoopPaths = DEFAULT_PATHS) -> _curator.CuratorConfig:
    return _curator.CuratorConfig(
        repo_root=paths.repo_root,
        pending_dir=paths.pending_dir,
        runs_dir=paths.runs_dir,
        corpus_dir=paths.lessons_actor_dir,
        corpus_dir_rel=paths.lessons_actor_dir_rel,
        channel=paths.actor_observations,
        repo_lock_file=paths.author_lock_file,
        repo_lock_wait_seconds=_shared.REPO_LOCK_WAIT_SECONDS,
        outcome_author=frozenset({"caught", "incoherent"}),
        outcome_skip=frozenset({"survived", "undecidable"}),
        trailer_label="Actor-Model",
        generation_fn=functools.partial(_shared.actor_generation_count, paths.repo_root),
        actor_model=ACTOR_MODEL,
        log_prefix="author_actor",
        author_prompt=paths.learning_dir / "author" / "malicious_actor" / "prompt.md",
        author_model=AUTHOR_ACTOR_MODEL,
        author_timeout=AUTHOR_ACTOR_TIMEOUT,
        author_effort=AUTHOR_ACTOR_EFFORT,
        invoke_agent=invoke_agent,
    )


def run_batch(*, hold_committed: bool = False, paths: LoopPaths = DEFAULT_PATHS) -> int:
    return _curator.run_batch(hold_committed=hold_committed, cfg=build_actor_config(paths))


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))

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
    AUTHOR_ENV_EFFORT,
    AUTHOR_ENV_MODEL,
    AUTHOR_ENV_REQUEST_LIMIT,
    AUTHOR_ENV_TIMEOUT,
    BENIGN_ACTOR_MODEL,
    DEFAULT_PATHS,
    LoopPaths,
    QueueChannel,
)



AuthorError = _curator.AuthorError


def invoke_agent(
    observations: list[dict],
    batch_id: str,
    cfg: _curator.CuratorConfig,
) -> dict:
    from defender.learning.author.verify_forward.checks import ENV_CHECK

    return _curator.invoke_curator_agent(
        cfg, observations, batch_id,
        check=ENV_CHECK,
        request_limit=AUTHOR_ENV_REQUEST_LIMIT,
    )


def _env_config(  # noqa: PLR0913 — every parameter is the per-direction field that varies
    paths: LoopPaths,
    *,
    channel: QueueChannel,
    outcome_author: frozenset[str],
    outcome_skip: frozenset[str],
    trailer_label: str,
    generation_fn,
    actor_model: str,
    log_prefix: str,
) -> _curator.CuratorConfig:
    return _curator.CuratorConfig(
        repo_root=paths.repo_root,
        pending_dir=paths.pending_dir,
        runs_dir=paths.runs_dir,
        corpus_dir=paths.lessons_environment_dir,
        corpus_dir_rel=paths.lessons_environment_dir_rel,
        channel=channel,
        repo_lock_file=paths.author_lock_file,
        repo_lock_wait_seconds=_shared.REPO_LOCK_WAIT_SECONDS,
        outcome_author=outcome_author,
        outcome_skip=outcome_skip,
        trailer_label=trailer_label,
        generation_fn=generation_fn,
        actor_model=actor_model,
        log_prefix=log_prefix,
        author_prompt=paths.learning_dir / "author" / "benign_actor" / "prompt.md",
        author_model=AUTHOR_ENV_MODEL,
        author_timeout=AUTHOR_ENV_TIMEOUT,
        author_effort=AUTHOR_ENV_EFFORT,
        invoke_agent=invoke_agent,
    )


def build_benign_config(paths: LoopPaths = DEFAULT_PATHS) -> _curator.CuratorConfig:
    return _env_config(
        paths,
        channel=paths.environment_observations,
        outcome_author=frozenset({"survived"}),
        outcome_skip=frozenset({"refuted", "undecidable", "incoherent"}),
        trailer_label="Benign-Actor-Model",
        generation_fn=functools.partial(_shared.benign_generation_count, paths.repo_root),
        actor_model=BENIGN_ACTOR_MODEL,
        log_prefix="author_actor_benign",
    )


def build_adversarial_config(paths: LoopPaths = DEFAULT_PATHS) -> _curator.CuratorConfig:
    return _env_config(
        paths,
        channel=paths.actor_environment_observations,
        outcome_author=frozenset({"caught", "incoherent"}),
        outcome_skip=frozenset({"survived", "undecidable"}),
        trailer_label="Actor-Env-Model",
        generation_fn=functools.partial(_shared.actor_env_generation_count, paths.repo_root),
        actor_model=ACTOR_MODEL,
        log_prefix="author_actor_env",
    )


BENIGN_CONFIG = build_benign_config(DEFAULT_PATHS)
ADVERSARIAL_CONFIG = build_adversarial_config(DEFAULT_PATHS)


def run_batch(
    *,
    hold_committed: bool = False,
    paths: LoopPaths = DEFAULT_PATHS,
    cfg: _curator.CuratorConfig | None = None,
) -> int:
    if cfg is None:
        cfg = build_benign_config(paths)
    return _curator.run_batch(hold_committed=hold_committed, cfg=cfg)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_benign.py", file=sys.stderr)
        return 64
    return run_batch(cfg=BENIGN_CONFIG)


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""Adversarial environment-lessons curator entry point (issue #298).

Thin wrapper over ``author_actor_benign`` that drains the *adversarial* env
queue (``_pending/actor_environment_observations.jsonl``) into the SHARED
``defender/lessons-environment/`` corpus using ``ADVERSARIAL_CONFIG``. Exposing
it as its own module keeps the serial drain's uniform ``mod.run_batch(...)`` call
shape (``_loop_orchestrate._run_curator_module``) — the trigger names this module
and the config selection happens here, not in the caller.

The sibling ``author_actor_benign`` is imported via the ``defender.learning``
namespace package; the entry-point bootstrap below puts the workspace root on
``sys.path`` so that resolves whether this module is imported by the curator
dispatch (``_loop_orchestrate._run_curator_module``) or run directly.
"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author import curator as _curator
from defender.learning.author.benign_actor import run as _benign
from defender.learning.core.config import AUTHOR_ENV_REQUEST_LIMIT, DEFAULT_PATHS, LoopPaths


def invoke_agent(
    observations: list[dict], batch_id: str, cfg: _curator.CuratorConfig
) -> dict:
    """The adversarial env direction's curator spawn. Identical in SHAPE to the benign direction —
    both bind the same deterministic ``ENV_CHECK`` and write into the SHARED
    ``lessons-environment/`` corpus — but defined here (its own module) so the adversarial entry
    point self-contains its spawn rather than borrowing the benign module's; the two directions
    drain in separate serialized batches with distinct commit trailers + generation counters. The
    corpus and pending queue the check retrieves against ride on ``cfg``, so the two directions
    differ only in which queue they name."""
    from defender.learning.author.verify_forward.checks import ENV_CHECK

    return _curator.invoke_curator_agent(
        cfg, observations, batch_id,
        check=ENV_CHECK,
        request_limit=AUTHOR_ENV_REQUEST_LIMIT,
    )


def run_batch(*, hold_committed: bool = False, paths: LoopPaths = DEFAULT_PATHS) -> int:
    # The adversarial config defaults its ``invoke_agent`` to the benign module's (shared shape);
    # swap in THIS module's so the adversarial spawn runs through the adversarial entry point.
    cfg = replace(_benign.build_adversarial_config(paths), invoke_agent=invoke_agent)
    return _benign.run_batch(hold_committed=hold_committed, cfg=cfg)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_env.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))

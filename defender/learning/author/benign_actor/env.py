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
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
if (_root := str(Path(__file__).resolve().parents[4])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.author.benign_actor import run as _benign
from defender.learning.core.config import DEFAULT_PATHS, LoopPaths


def run_batch(*, hold_committed: bool = False, paths: LoopPaths = DEFAULT_PATHS) -> int:
    # No `invoke_agent` override: once the forward-check became data (`ENV_CHECK` bound onto the
    # deps), the two env directions' spawns are the SAME function — they differ only in the queue
    # `build_adversarial_config` names. `_env_config` already defaults `invoke_agent` to the
    # benign module's, so this direction inherits it rather than keeping a byte-identical copy.
    cfg = _benign.build_adversarial_config(paths)
    return _benign.run_batch(hold_committed=hold_committed, cfg=cfg)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_env.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))

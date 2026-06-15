#!/usr/bin/env python3
"""Adversarial environment-lessons curator entry point (issue #298).

Thin wrapper over ``author_actor_benign`` that drains the *adversarial* env
queue (``_pending/actor_environment_observations.jsonl``) into the SHARED
``defender/lessons-environment/`` corpus using ``ADVERSARIAL_CONFIG``. Exposing
it as its own module keeps the serial drain's uniform ``mod.run_batch(...)`` call
shape (``_loop_orchestrate._run_curator_module``) — the trigger names this module
and the config selection happens here, not in the caller.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import author_actor_benign as _benign  # type: ignore[import-not-found]
finally:
    sys.path.pop(0)


def run_batch(*, hold_committed: bool = False) -> int:
    return _benign.run_batch(hold_committed=hold_committed, cfg=_benign.ADVERSARIAL_CONFIG)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_env.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))

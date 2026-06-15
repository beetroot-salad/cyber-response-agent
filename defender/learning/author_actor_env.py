#!/usr/bin/env python3
"""Adversarial environment-lessons curator entry point (issue #298).

Thin wrapper over ``author_actor_benign`` that drains the *adversarial* env
queue (``_pending/actor_environment_observations.jsonl``) into the SHARED
``defender/lessons-environment/`` corpus using ``ADVERSARIAL_CONFIG``. Exposing
it as its own module keeps the serial drain's uniform ``mod.run_batch(...)`` call
shape (``_loop_orchestrate._run_curator_module``) — the trigger names this module
and the config selection happens here, not in the caller.

The sibling ``author_actor_benign`` resolves on ``sys.path`` because every importer
already puts the learning dir there first: ``_run_curator_module`` inserts it (under
a lock), a direct ``python author_actor_env.py`` run gets it as ``sys.path[0]``, and
the tests insert it before importing this module. So a plain top-level import
suffices — no per-module ``sys.path`` insert/``pop(0)`` (the positional pop the
orchestrator deliberately avoids, since it can drop another caller's entry).
"""
from __future__ import annotations

import sys

import author_actor_benign as _benign  # type: ignore[import-not-found]


def run_batch(*, hold_committed: bool = False) -> int:
    return _benign.run_batch(hold_committed=hold_committed, cfg=_benign.ADVERSARIAL_CONFIG)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: author_actor_env.py", file=sys.stderr)
        return 64
    return run_batch()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
